#!/usr/bin/env python3

import html
import json
import os
import secrets
import threading
import time
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, quote, urlencode, urljoin, urlparse

import httpx

HOST = os.getenv("LITEPYPROXY_HOST", "127.0.0.1")
PORT = int(os.getenv("LITEPYPROXY_PORT", "8880"))
BASE_PATH = os.getenv("LITEPYPROXY_BASE_PATH", "").strip()
TIMEOUT = 30.0
MAX_CONNECTIONS = int(os.getenv("LITEPYPROXY_MAX_CONNECTIONS", "6"))

if BASE_PATH:
    BASE_PATH = "/" + BASE_PATH.strip("/")

PROXY_ENDPOINT = f"{BASE_PATH}/proxy"
REWRITE_ATTRS = {"href", "src", "action"}
SKIP_SCHEMES = ("data:", "javascript:", "mailto:", "tel:")
FORWARDED_HEADERS = ("User-Agent", "Accept", "Accept-Language")

UPSTREAM_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)

SESSION_COOKIE = "litepyproxy_session"
SESSION_MAX_AGE = 60 * 60 * 8
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def new_http_client():
    return httpx.Client(
        follow_redirects=True,
        timeout=TIMEOUT,
        limits=httpx.Limits(
            max_connections=MAX_CONNECTIONS,
            max_keepalive_connections=MAX_CONNECTIONS,
        ),
    )


def get_session(session_id=None):
    now = time.time()

    with SESSIONS_LOCK:
        if session_id and session_id in SESSIONS:
            session = SESSIONS[session_id]
            session["last_used"] = now
            return session_id, session, False

        session_id = secrets.token_urlsafe(24)
        session = {
            "client": new_http_client(),
            "last_used": now,
        }
        SESSIONS[session_id] = session
        return session_id, session, True


def lpp_proxify_url(value, base_url):
    value = value.strip()
    if (
        not value
        or value.startswith("#")
        or value.lower().startswith(SKIP_SCHEMES)
    ):
        return value

    absolute = urljoin(base_url, value)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return value

    return f"{PROXY_ENDPOINT}?url={quote(absolute, safe='')}"


class HTMLRewriter(HTMLParser):
    def __init__(self, current_url):
        super().__init__(convert_charrefs=False)
        self.current_url = current_url
        self.parts = []

    def rewrite_attrs(self, attrs):
        rewritten = []
        for name, value in attrs:
            if value is not None and name.lower() in REWRITE_ATTRS:
                value = lpp_proxify_url(value, self.current_url)
            rewritten.append((name, value))
        return rewritten

    def attrs_text(self, attrs):
        parts = []
        for name, value in attrs:
            if value is None:
                parts.append(name)
            else:
                parts.append(f'{name}="{html.escape(value, quote=True)}"')
        return (" " + " ".join(parts)) if parts else ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "form":
            attr_map = {name.lower(): value for name, value in attrs}
            action = attr_map.get("action") or self.current_url
            absolute_action = urljoin(self.current_url, action)

            rewritten = []
            for name, value in attrs:
                if name.lower() == "action":
                    value = PROXY_ENDPOINT
                rewritten.append((name, value))

            if "action" not in attr_map:
                rewritten.append(("action", PROXY_ENDPOINT))

            self.parts.append(f"<{tag}{self.attrs_text(rewritten)}>")
            self.parts.append(
                f'<input type="hidden" name="url" '
                f'value="{html.escape(absolute_action, quote=True)}">'
            )
            return

        self.parts.append(f"<{tag}{self.attrs_text(self.rewrite_attrs(attrs))}>")

    def handle_startendtag(self, tag, attrs):
        self.parts.append(f"<{tag}{self.attrs_text(self.rewrite_attrs(attrs))} />")

    def handle_endtag(self, tag):
        self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append(f"&{name};")

    def handle_charref(self, name):
        self.parts.append(f"&#{name};")

    def handle_comment(self, data):
        self.parts.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.parts.append(f"<!{decl}>")

    def handle_pi(self, data):
        self.parts.append(f"<?{data}>")

    def unknown_decl(self, data):
        self.parts.append(f"<![{data}]>")

    def output(self):
        return "".join(self.parts)


def lpp_runtime_script(current_url):
    return f"""<script>
(function() {{
    "use strict";

    const LPP_PROXY_ENDPOINT = {json.dumps(PROXY_ENDPOINT)};
    const LPP_BASE_URL = {json.dumps(current_url)};

    function lppProxifyUrl(value) {{
        if (typeof value !== "string") return value;

        const trimmed = value.trim();
        if (
            !trimmed ||
            trimmed.startsWith("#") ||
            /^(?:data|javascript|mailto|tel):/i.test(trimmed)
        ) {{
            return value;
        }}

        try {{
            const absolute = new URL(trimmed, LPP_BASE_URL);
            if (absolute.protocol !== "http:" && absolute.protocol !== "https:") {{
                return value;
            }}
            const logicalOrigin = new URL(LPP_BASE_URL).origin;
            return LPP_PROXY_ENDPOINT
                + "?url=" + encodeURIComponent(absolute.href)
                + "&lpp_origin=" + encodeURIComponent(logicalOrigin);
        }} catch (_) {{
            return value;
        }}
    }}

    const nativeFetch = window.fetch;
    if (nativeFetch) {{
        window.fetch = function(input, init) {{
            if (typeof input === "string") {{
                input = lppProxifyUrl(input);
            }} else if (input instanceof URL) {{
                input = lppProxifyUrl(input.href);
            }}
            return nativeFetch.call(this, input, init);
        }};
    }}

    const nativeXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {{
        const args = Array.prototype.slice.call(arguments);
        if (typeof url === "string") {{
            args[1] = lppProxifyUrl(url);
        }} else if (url instanceof URL) {{
            args[1] = lppProxifyUrl(url.href);
        }}
        return nativeXhrOpen.apply(this, args);
    }};
}})();
</script>"""


class LitePyProxyHandler(BaseHTTPRequestHandler):
    def get_upstream_headers(self, logical_origin=None):
        headers = {}
        for name in FORWARDED_HEADERS:
            value = self.headers.get(name)
            if value:
                headers[name] = value
        if logical_origin:
            parsed_origin = urlparse(logical_origin)
            if (
                parsed_origin.scheme in ("http", "https")
                and parsed_origin.netloc
                and parsed_origin.path in ("", "/")
                and not parsed_origin.params
                and not parsed_origin.query
                and not parsed_origin.fragment
            ):
                headers["Origin"] = (
                    f"{parsed_origin.scheme}://{parsed_origin.netloc}"
                )

        return headers

    def get_proxy_session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            pass

        session_id = None
        if SESSION_COOKIE in cookie:
            session_id = cookie[SESSION_COOKIE].value

        return get_session(session_id)

    def get_target(self, include_form_query=False):
        request = urlparse(self.path)
        if request.path != "/proxy":
            return None

        pairs = parse_qsl(request.query, keep_blank_values=True)
        target = ""
        logical_origin = None
        form_pairs = []

        for name, value in pairs:
            if name == "url" and not target:
                target = value.strip()
            elif name == "lpp_origin" and logical_origin is None:
                logical_origin = value.strip()
            else:
                form_pairs.append((name, value))

        if include_form_query and target and form_pairs:
            separator = "&" if urlparse(target).query else "?"
            target += separator + urlencode(form_pairs, doseq=True)

        return target, logical_origin

    def do_GET(self):
        result = self.get_target(include_form_query=True)
        if result is not None:
            target, logical_origin = result
            self.proxy(target, head_only=False, logical_origin=logical_origin)
            return

        self.home()

    def do_POST(self):
        result = self.get_target()
        if result is None:
            self.send_error(404)
            return

        target, logical_origin = result

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        body = self.rfile.read(content_length)
        self.proxy(
            target,
            head_only=False,
            method="POST",
            request_body=body,
            request_content_type=self.headers.get("Content-Type"),
            logical_origin=logical_origin,
        )

    def do_HEAD(self):
        result = self.get_target()
        if result is not None:
            target, logical_origin = result
            self.proxy(target, head_only=True, logical_origin=logical_origin)
            return

        self.home(head_only=True)

    def home(self, error="", head_only=False):
        error_html = ""
        if error:
            error_html = f"<p><strong>Error:</strong> {html.escape(error)}</p>"

        body = f"""<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>LitePyProxy</title>
</head>
<body>
    <h1>LitePyProxy</h1>
    <form action="{html.escape(PROXY_ENDPOINT, quote=True)}" method="get">
        <label for="url">URL:</label>
        <input id="url" name="url" type="url" size="70"
               placeholder="https://example.com" required>
        <button type="submit">GO</button>
    </form>
    {error_html}
</body>
</html>
""".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def proxy(
        self,
        target,
        head_only=False,
        method="GET",
        request_body=None,
        request_content_type=None,
        logical_origin=None,
    ):
        if not target:
            self.home("No URL supplied.", head_only=head_only)
            return

        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self.home(
                "Only complete http:// or https:// URLs are supported.",
                head_only=head_only,
            )
            return

        session_id, session, new_session = self.get_proxy_session()
        client = session["client"]
        upstream_headers = self.get_upstream_headers(logical_origin)
        if request_content_type:
            upstream_headers["Content-Type"] = request_content_type

        try:
            with UPSTREAM_SLOTS:
                if head_only:
                    response = client.head(target, headers=upstream_headers)
                elif method == "POST":
                    response = client.post(
                        target,
                        content=request_body or b"",
                        headers=upstream_headers,
                    )
                else:
                    response = client.get(target, headers=upstream_headers)
        except httpx.HTTPError as exc:
            self.send_error(502, f"Upstream request failed: {exc}")
            return

        content_type = response.headers.get(
            "content-type", "application/octet-stream"
        )

        if head_only:
            body = b""
            content_length = response.headers.get("content-length")
        elif "text/html" in content_type.lower():
            current_url = str(response.url)
            rewriter = HTMLRewriter(current_url)
            rewriter.feed(response.text)
            rewriter.close()
            page = rewriter.output()

            toolbar = f"""<style>
#litepyproxy-bar {{
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    box-sizing: border-box;
    padding: 6px 10px;
    background: #eee;
    border-bottom: 1px solid #999;
    color: #111;
    font: 14px sans-serif;
}}
#litepyproxy-bar form {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
}}
#litepyproxy-bar input {{
    flex: 1;
    min-width: 0;
    padding: 4px 6px;
    font: 14px sans-serif;
}}
#litepyproxy-bar button {{
    padding: 4px 10px;
}}
html {{
    padding-top: 42px !important;
}}
</style>
<div id="litepyproxy-bar">
    <form action="{html.escape(PROXY_ENDPOINT, quote=True)}" method="get">
        <strong>LitePyProxy</strong>
        <input name="url" type="url"
               value="{html.escape(current_url, quote=True)}" required>
        <button type="submit">GO</button>
    </form>
</div>"""

            runtime_script = lpp_runtime_script(current_url)
            lower_page = page.lower()
            head_pos = lower_page.find("<head")
            if head_pos != -1:
                head_end = page.find(">", head_pos)
                if head_end != -1:
                    page = (
                        page[:head_end + 1]
                        + runtime_script
                        + page[head_end + 1:]
                    )
                else:
                    page = runtime_script + page
            else:
                page = runtime_script + page

            lower_page = page.lower()
            body_pos = lower_page.find("<body")
            if body_pos != -1:
                body_end = page.find(">", body_pos)
                if body_end != -1:
                    page = page[:body_end + 1] + toolbar + page[body_end + 1:]
                else:
                    page = toolbar + page
            else:
                page = toolbar + page

            body = page.encode("utf-8")
            content_type = "text/html; charset=utf-8"
            content_length = str(len(body))
        else:
            body = response.content
            content_length = str(len(body))

        self.send_response(response.status_code)
        self.send_header("Content-Type", content_type)
        if content_length is not None:
            self.send_header("Content-Length", content_length)
        if new_session:
            cookie_path = BASE_PATH or "/"
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={session_id}; Path={cookie_path}; "
                f"Max-Age={SESSION_MAX_AGE}; HttpOnly; SameSite=Lax",
            )
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), LitePyProxyHandler)
    print(f"LitePyProxy listening on http://{HOST}:{PORT}", flush=True)
    print(f"Maximum upstream connections: {MAX_CONNECTIONS}", flush=True)
    if BASE_PATH:
        print(f"Public base path: {BASE_PATH}/", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        with SESSIONS_LOCK:
            for session in SESSIONS.values():
                session["client"].close()
