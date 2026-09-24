#!/usr/bin/env python3

import html
import os
import threading
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urljoin, urlparse

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

UPSTREAM_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)
HTTP_CLIENT = httpx.Client(
    follow_redirects=True,
    timeout=TIMEOUT,
    headers={"User-Agent": "LitePyProxy/0.1"},
    limits=httpx.Limits(
        max_connections=MAX_CONNECTIONS,
        max_keepalive_connections=MAX_CONNECTIONS,
    ),
)


def proxy_url(current_url, value):
    value = value.strip()
    if (
        not value
        or value.startswith("#")
        or value.lower().startswith(SKIP_SCHEMES)
    ):
        return value

    absolute = urljoin(current_url, value)
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
                value = proxy_url(self.current_url, value)
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


class LitePyProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urlparse(self.path)

        if request.path == "/proxy":
            params = parse_qs(request.query)
            target = params.get("url", [""])[0].strip()
            self.proxy(target)
            return

        self.home()

    def home(self, error=""):
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
        self.wfile.write(body)

    def proxy(self, target):
        if not target:
            self.home("No URL supplied.")
            return

        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self.home("Only complete http:// or https:// URLs are supported.")
            return

        try:
            with UPSTREAM_SLOTS:
                response = HTTP_CLIENT.get(target)
        except httpx.HTTPError as exc:
            self.send_error(502, f"Upstream request failed: {exc}")
            return

        content_type = response.headers.get(
            "content-type", "application/octet-stream"
        )

        if "text/html" in content_type.lower():
            rewriter = HTMLRewriter(str(response.url))
            rewriter.feed(response.text)
            rewriter.close()
            body = rewriter.output().encode("utf-8")
            content_type = "text/html; charset=utf-8"
        else:
            body = response.content

        self.send_response(response.status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
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
        HTTP_CLIENT.close()
