#!/usr/bin/env python3

import html
import json
import os
import re
import secrets
import threading
import time
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse

import httpx

HOST = os.getenv("LITEPYPROXY_HOST", "127.0.0.1")
PORT = int(os.getenv("LITEPYPROXY_PORT", "8880"))
BASE_PATH = os.getenv("LITEPYPROXY_BASE_PATH", "").strip()
TIMEOUT = 30.0
MAX_CONNECTIONS = int(os.getenv("LITEPYPROXY_MAX_CONNECTIONS", "6"))

if BASE_PATH:
    BASE_PATH = "/" + BASE_PATH.strip("/")

PROXY_ENDPOINT = f"{BASE_PATH}/proxy"
REWRITE_ATTRS = {
    "href", "src", "action", "poster", "background", "cite", "longdesc",
    "usemap", "formaction", "manifest",
}
SKIP_SCHEMES = ("data:", "javascript:", "mailto:", "tel:")
REQUEST_HEADER_BLOCKLIST = {
    "host",
    "connection",
    "content-length",
    "cookie",
    "authorization",
    "proxy-authorization",
    "origin",
    "referer",
    "content-type",
    "accept-encoding",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}

UPSTREAM_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)

SESSION_COOKIE = "litepyproxy_session"
SESSION_MAX_AGE = 60 * 60 * 8
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def new_http_client():
    return httpx.Client(
        follow_redirects=False,
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


class LPPUrlContract:
    CONTROL_PARAMS = {"lpp_origin"}

    @classmethod
    def to_logical(cls, value):
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return value

        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        logical_pairs = [
            (name, item)
            for name, item in pairs
            if name not in cls.CONTROL_PARAMS
        ]
        if len(logical_pairs) == len(pairs):
            return value

        query = urlencode(logical_pairs, doseq=True)
        return parsed._replace(query=query).geturl()

    @classmethod
    def resolve(cls, value, base_url):
        value = value.strip()
        if (
            not value
            or value.startswith("#")
            or value.lower().startswith(SKIP_SCHEMES)
        ):
            return value

        absolute = urljoin(base_url, value)
        absolute = cls.to_logical(absolute)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return value

        return absolute

    @classmethod
    def to_physical(cls, value, base_url):
        logical_url = cls.resolve(value, base_url)
        parsed = urlparse(logical_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return logical_url

        return f"{PROXY_ENDPOINT}?url={quote(logical_url, safe='')}"

    @classmethod
    def from_physical(cls, value):
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return value
        if parsed.path != PROXY_ENDPOINT:
            return value

        for name, item in parse_qsl(parsed.query, keep_blank_values=True):
            if name == "url":
                return cls.to_logical(item.strip())

        return value

    @classmethod
    def form_target(cls, value, base_url):
        return cls.resolve(value or base_url, base_url)


LPP_URL = LPPUrlContract()


def normalize_user_url(value):
    value = value.strip()
    if not value:
        return value
    if value.lower().startswith("https://"):
        return value
    if value.lower().startswith("http://"):
        return "https://" + value[7:]
    return "https://" + value


class HTMLRewriter(HTMLParser):
    def __init__(self, current_url):
        super().__init__(convert_charrefs=False)
        self.current_url = current_url
        self.parts = []

    def rewrite_srcset(self, value):
        candidates = []
        for candidate in value.split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            pieces = candidate.split()
            pieces[0] = LPP_URL.to_physical(pieces[0], self.current_url)
            candidates.append(" ".join(pieces))
        return ", ".join(candidates)

    def rewrite_meta_refresh(self, value):
        match = re.match(r"^(\\s*\\d+(?:\\.\\d+)?\\s*;\\s*url\\s*=\\s*)(.*)$", value, re.I)
        if not match:
            return value
        target = match.group(2).strip()
        quote_char = ""
        if len(target) >= 2 and target[0] in ("\\'", '"') and target[-1] == target[0]:
            quote_char = target[0]
            target = target[1:-1]
        target = LPP_URL.to_physical(target, self.current_url)
        return match.group(1) + quote_char + target + quote_char

    def rewrite_attrs(self, tag, attrs):
        rewritten = []
        is_refresh = False
        if tag.lower() == "meta":
            attr_map = {name.lower(): value for name, value in attrs}
            is_refresh = (attr_map.get("http-equiv") or "").lower() == "refresh"

        for name, value in attrs:
            lname = name.lower()
            if value is not None:
                if lname in REWRITE_ATTRS:
                    value = LPP_URL.to_physical(value, self.current_url)
                elif lname == "srcset":
                    value = self.rewrite_srcset(value)
                elif is_refresh and lname == "content":
                    value = self.rewrite_meta_refresh(value)
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
            absolute_action = LPP_URL.form_target(action, self.current_url)

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

        self.parts.append(f"<{tag}{self.attrs_text(self.rewrite_attrs(tag, attrs))}>")

    def handle_startendtag(self, tag, attrs):
        self.parts.append(f"<{tag}{self.attrs_text(self.rewrite_attrs(tag, attrs))} />")

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

    class LPPRuntime {{
        constructor() {{
            this.url = Object.freeze({{
        logicalBase: LPP_BASE_URL,
        logicalOrigin: new URL(LPP_BASE_URL).origin,

        toLogical: function(value) {{
            if (typeof value !== "string") return value;

            try {{
                const physical = new URL(value, window.location.href);

                if (physical.origin === window.location.origin) {{
                    if (physical.pathname === LPP_PROXY_ENDPOINT) {{
                        const logical = physical.searchParams.get("url");
                        if (logical) return logical;
                    }}

                    const leakedPrefix = LPP_PROXY_ENDPOINT + "/";
                    if (physical.pathname.startsWith(leakedPrefix)) {{
                        const logicalPath = physical.pathname.slice(
                            LPP_PROXY_ENDPOINT.length
                        );
                        return new URL(
                            logicalPath + physical.search + physical.hash,
                            this.logicalOrigin
                        ).href;
                    }}

                    return new URL(
                        physical.pathname + physical.search + physical.hash,
                        this.logicalOrigin
                    ).href;
                }}
            }} catch (_) {{
                // Leave values outside the URL contract unchanged.
            }}

            return value;
        }},

        stripControlParams: function(value) {{
            if (typeof value !== "string") return value;

            try {{
                const logical = new URL(value);
                logical.searchParams.delete("lpp_origin");
                return logical.href;
            }} catch (_) {{
                return value;
            }}
        }},

        resolve: function(value) {{
            const logical = this.stripControlParams(this.toLogical(value));
            if (typeof logical !== "string") return logical;

            const trimmed = logical.trim();
            if (
                !trimmed ||
                trimmed.startsWith("#") ||
                /^(?:data|javascript|mailto|tel):/i.test(trimmed)
            ) {{
                return logical;
            }}

            try {{
                const absolute = new URL(trimmed, this.logicalBase);
                if (absolute.protocol !== "http:" && absolute.protocol !== "https:") {{
                    return logical;
                }}
                return absolute.href;
            }} catch (_) {{
                return logical;
            }}
        }},

        toPhysical: function(value) {{
            const logical = this.resolve(value);
            if (typeof logical !== "string") return logical;

            try {{
                const absolute = new URL(logical);
                if (absolute.protocol !== "http:" && absolute.protocol !== "https:") {{
                    return logical;
                }}
                return LPP_PROXY_ENDPOINT
                    + "?url=" + encodeURIComponent(absolute.href)
                    + "&lpp_origin=" + encodeURIComponent(this.logicalOrigin);
            }} catch (_) {{
                return logical;
            }}
        }}
            }});
        }}

        toPhysical(value) {{
            return this.url.toPhysical(value);
        }}

        installNavigation() {{
            const runtime = this;

            const nativeWindowOpen = window.open;
            if (nativeWindowOpen) {{
                window.open = function(url) {{
                    const args = Array.prototype.slice.call(arguments);
                    if (typeof url === "string" || url instanceof URL) {{
                        args[0] = runtime.toPhysical(String(url));
                    }}
                    return nativeWindowOpen.apply(this, args);
                }};
            }}

            lppInstallUrlProperty(HTMLAnchorElement.prototype, "href");
            lppInstallUrlProperty(HTMLFormElement.prototype, "action");

            const nativeAnchorClick = HTMLAnchorElement.prototype.click;
            HTMLAnchorElement.prototype.click = function() {{
                const href = this.getAttribute("href");
                if (href) {{
                    this.setAttribute("href", runtime.toPhysical(href));
                }}
                return nativeAnchorClick.apply(this, arguments);
            }};

            const nativeFormSubmit = HTMLFormElement.prototype.submit;
            HTMLFormElement.prototype.submit = function() {{
                const action = this.getAttribute("action");
                if (action) {{
                    this.setAttribute("action", runtime.toPhysical(action));
                }}
                return nativeFormSubmit.apply(this, arguments);
            }};

            if (HTMLFormElement.prototype.requestSubmit) {{
                const nativeRequestSubmit = HTMLFormElement.prototype.requestSubmit;
                HTMLFormElement.prototype.requestSubmit = function() {{
                    const action = this.getAttribute("action");
                    if (action) {{
                        this.setAttribute("action", runtime.toPhysical(action));
                    }}
                    return nativeRequestSubmit.apply(this, arguments);
                }};
            }}
        }}

        install() {{
            installRuntime(this);
            this.installNavigation();
        }}
    }}

    const lppRuntime = new LPPRuntime();
    const lppUrl = lppRuntime.url;

    function lppProxifyUrl(value) {{
        return lppRuntime.toPhysical(value);
    }}

    function lppNavigate(value, replace) {{
        const proxied = lppProxifyUrl(value);
        if (replace) {{
            window.location.replace(proxied);
        }} else {{
            window.location.assign(proxied);
        }}
    }}

    Object.defineProperty(window, "__LPP__", {{
        configurable: false,
        enumerable: false,
        writable: false,
        value: Object.freeze({{
            navigate: function(value, replace) {{
                lppNavigate(value, !!replace);
            }},
            toPhysical: function(value) {{
                return lppProxifyUrl(value);
            }}
        }})
    }});

    function installRuntime(runtime) {{
        const nativeLocationAssign = window.location.assign.bind(window.location);
        const nativeLocationReplace = window.location.replace.bind(window.location);

        try {{
            window.location.assign = function(url) {{
                nativeLocationAssign(lppProxifyUrl(String(url)));
            }};
            window.location.replace = function(url) {{
                nativeLocationReplace(lppProxifyUrl(String(url)));
            }};
        }} catch (_) {{
            // Some browsers expose Location methods as non-writable.
        }}

        function lppExposeLogicalScriptIdentity(script) {{
            if (!script) return script;

            const src = script.getAttribute("src");
            if (!src) return script;

            const logicalSrc = lppUrl.toLogical(script.src);
            if (logicalSrc === script.src) return script;

            return new Proxy(script, {{
                get: function(target, property, receiver) {{
                    if (property === "src") return logicalSrc;
                    return Reflect.get(target, property, receiver);
                }}
            }});
        }}

        try {{
            const currentScriptDescriptor = Object.getOwnPropertyDescriptor(
                Document.prototype,
                "currentScript"
            );
            if (currentScriptDescriptor && currentScriptDescriptor.get) {{
                Object.defineProperty(document, "currentScript", {{
                    configurable: true,
                    get: function() {{
                        return lppExposeLogicalScriptIdentity(
                            currentScriptDescriptor.get.call(document)
                        );
                    }}
                }});
            }}
        }} catch (_) {{
            // Keep native currentScript semantics if the browser forbids wrapping it.
        }}

        function lppInstallUrlProperty(proto, property) {{
            try {{
                const descriptor = Object.getOwnPropertyDescriptor(proto, property);
                if (!descriptor || !descriptor.set || !descriptor.get) return;

                Object.defineProperty(proto, property, {{
                    configurable: descriptor.configurable,
                    enumerable: descriptor.enumerable,
                    get: descriptor.get,
                    set: function(value) {{
                        if (typeof value === "string") {{
                            value = lppProxifyUrl(value);
                        }} else if (value instanceof URL) {{
                            value = lppProxifyUrl(value.href);
                        }}
                        return descriptor.set.call(this, value);
                    }}
                }});
            }} catch (_) {{
                // Keep native DOM behavior when a URL property cannot be wrapped.
            }}
        }}

        [
            [HTMLIFrameElement.prototype, "src"],
            [HTMLScriptElement.prototype, "src"],
            [HTMLImageElement.prototype, "src"],
            [HTMLLinkElement.prototype, "href"]
        ].forEach(function(entry) {{
            lppInstallUrlProperty(entry[0], entry[1]);
        }});

        const nativeSetAttribute = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {{
            if (
                typeof name === "string" &&
                /^(?:src|href|action)$/i.test(name) &&
                (typeof value === "string" || value instanceof URL)
            ) {{
                value = lppProxifyUrl(String(value));
            }}
            return nativeSetAttribute.call(this, name, value);
        }};

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

    }}

    lppRuntime.install();
}})();
</script>"""


class JavaScriptRewriter:
    NAVIGATION_PATTERNS = (
        (
            re.compile(r"(?<![\\w$.])(?:window\\s*\\.\\s*)?location\\s*\\.\\s*(?:assign|replace)\\s*\\(([^)]*)\\)"),
            lambda match: "window.__LPP__.navigate(" + match.group(1) + ", "
            + ("true" if re.search(r"\\.\\s*replace\\s*\\(", match.group(0)) else "false")
            + ")",
        ),
        (
            re.compile(r"(?<![\\w$.])(?:window\\s*\\.\\s*)?(?:document\\s*\\.\\s*)?location\\s*\\.\\s*href\\s*=\\s*([^;\\n]+)"),
            lambda match: "lppNavigate(" + match.group(1).rstrip() + ", false)",
        ),
        (
            re.compile(r"(?<![\\w$.])(?:window\\s*\\.\\s*)?location\\s*=\\s*([^;\\n]+)"),
            lambda match: "lppNavigate(" + match.group(1).rstrip() + ", false)",
        ),
        (
            re.compile(r"(?<![\\w$.])document\\s*\\.\\s*location\\s*=\\s*([^;\\n]+)"),
            lambda match: "lppNavigate(" + match.group(1).rstrip() + ", false)",
        ),
    )

    @classmethod
    def rewrite(cls, source):
        for pattern, replacement in cls.NAVIGATION_PATTERNS:
            source = pattern.sub(replacement, source)
        return source


class LPPTransformer:
    @classmethod
    def transform_html(cls, response):
        current_url = response.url
        rewriter = HTMLRewriter(current_url)
        rewriter.feed(response.text)
        rewriter.close()
        return rewriter.output()

    @classmethod
    def transform_javascript(cls, response):
        return JavaScriptRewriter.rewrite(response.text)

    @classmethod
    def transform(cls, response, content_type):
        lowered = content_type.lower()
        if "text/html" in lowered:
            return cls.transform_html(response)
        if (
            "javascript" in lowered
            or "application/ecmascript" in lowered
            or "text/ecmascript" in lowered
        ):
            return cls.transform_javascript(response)
        return None


class LPPRequest:
    def __init__(
        self,
        method,
        physical_url,
        logical_url,
        logical_origin=None,
        logical_referer=None,
        headers=None,
        body=None,
        content_type=None,
        head_only=False,
    ):
        self.method = method
        self.physical_url = physical_url
        self.logical_url = logical_url
        self.logical_origin = logical_origin
        self.logical_referer = logical_referer
        self.headers = headers or {}
        self.body = body
        self.content_type = content_type
        self.head_only = head_only

    @classmethod
    def from_browser(
        cls,
        method,
        physical_url,
        body=None,
        content_type=None,
        head_only=False,
        include_form_query=False,
        browser_headers=None,
    ):
        physical = urlparse(physical_url)
        if physical.path != "/proxy":
            return None

        pairs = parse_qsl(physical.query, keep_blank_values=True)
        logical_url = ""
        logical_origin = None
        forwarded_query = []

        for name, value in pairs:
            if name == "url" and not logical_url:
                logical_url = value.strip()
            elif name == "lpp_origin" and logical_origin is None:
                logical_origin = value.strip()
            else:
                forwarded_query.append((name, value))

        if include_form_query and logical_url and forwarded_query:
            separator = "&" if urlparse(logical_url).query else "?"
            logical_url += separator + urlencode(forwarded_query, doseq=True)

        logical_url = LPP_URL.to_logical(logical_url) if logical_url else logical_url

        browser_headers = browser_headers or {}
        referer = browser_headers.get("Referer")
        logical_referer = LPP_URL.from_physical(referer) if referer else None

        semantic_headers = {}
        for name, value in browser_headers.items():
            if name.lower() not in REQUEST_HEADER_BLOCKLIST:
                semantic_headers[name] = value

        return cls(
            method=method,
            physical_url=physical_url,
            logical_url=logical_url,
            logical_origin=logical_origin,
            logical_referer=logical_referer,
            headers=semantic_headers,
            body=body,
            content_type=content_type,
            head_only=head_only,
        )


class LPPResponse:
    def __init__(self, upstream):
        self.upstream = upstream
        self.status_code = upstream.status_code
        self.headers = upstream.headers
        self.url = str(upstream.url)
        self.content = upstream.content
        self.text = upstream.text

    def header(self, name, default=None):
        return self.headers.get(name, default)

    def proxified_location(self):
        location = self.header("location")
        if not location:
            return None
        return LPP_URL.to_physical(location, self.url)


class LitePyProxyHandler(BaseHTTPRequestHandler):
    def get_upstream_headers(self, request):
        headers = dict(request.headers)

        if request.logical_origin:
            parsed_origin = urlparse(request.logical_origin)
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

        if request.logical_referer:
            parsed_referer = urlparse(request.logical_referer)
            if parsed_referer.scheme in ("http", "https") and parsed_referer.netloc:
                headers["Referer"] = request.logical_referer

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

    def do_GET(self):
        request = LPPRequest.from_browser(
            method="GET",
            physical_url=self.path,
            include_form_query=True,
            browser_headers=self.headers,
        )
        if request is not None:
            physical = urlparse(self.path)
            query_names = [name for name, _ in parse_qsl(physical.query, keep_blank_values=True)]
            if query_names == ["url"]:
                request.logical_url = normalize_user_url(request.logical_url)
            self.proxy(request)
            return

        self.home()

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type")
        request = LPPRequest.from_browser(
            method="POST",
            physical_url=self.path,
            body=body,
            content_type=content_type,
            browser_headers=self.headers,
        )
        if request is None:
            self.send_error(404)
            return

        if (
            not request.logical_url
            and content_type
            and content_type.lower().split(";", 1)[0].strip()
                == "application/x-www-form-urlencoded"
        ):
            try:
                form_pairs = parse_qsl(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                )
            except UnicodeDecodeError:
                form_pairs = []

            target = ""
            forwarded_pairs = []
            for name, value in form_pairs:
                if name == "url" and not target:
                    target = value.strip()
                else:
                    forwarded_pairs.append((name, value))

            if target:
                request.logical_url = LPP_URL.to_logical(target)
                request.body = urlencode(forwarded_pairs, doseq=True).encode("utf-8")

        self.proxy(request)

    def do_HEAD(self):
        request = LPPRequest.from_browser(
            method="HEAD",
            physical_url=self.path,
            head_only=True,
            browser_headers=self.headers,
        )
        if request is not None:
            self.proxy(request)
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
        <input id="url" name="url" type="text" size="70"
               placeholder="example.com" required>
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

    def proxy(self, request):
        target = request.logical_url
        head_only = request.head_only

        if not target:
            self.home("No URL supplied.", head_only=head_only)
            return

        if "://" not in target:
            target = normalize_user_url(target)
            request.logical_url = target

        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self.home(
                "Only complete http:// or https:// URLs are supported.",
                head_only=head_only,
            )
            return

        session_id, session, new_session = self.get_proxy_session()
        client = session["client"]
        upstream_headers = self.get_upstream_headers(request)
        if request.content_type:
            upstream_headers["Content-Type"] = request.content_type

        try:
            with UPSTREAM_SLOTS:
                if head_only:
                    response = client.head(target, headers=upstream_headers)
                elif request.method == "POST":
                    response = client.post(
                        target,
                        content=request.body or b"",
                        headers=upstream_headers,
                    )
                else:
                    response = client.get(target, headers=upstream_headers)
        except httpx.HTTPError as exc:
            self.send_error(502, f"Upstream request failed: {exc}")
            return

        response = LPPResponse(response)

        content_type = response.header(
            "content-type", "application/octet-stream"
        )

        if head_only:
            body = b""
            content_length = response.header("content-length")
        elif "text/html" in content_type.lower():
            current_url = response.url
            page = LPPTransformer.transform(response, content_type)

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
            transformed = LPPTransformer.transform(response, content_type)
            if transformed is not None:
                body = transformed.encode("utf-8")
                content_length = str(len(body))
            else:
                body = response.content
                content_length = str(len(body))

        self.send_response(response.status_code)
        self.send_header("Content-Type", content_type)
        location = response.proxified_location()
        if location:
            self.send_header("Location", location)
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
