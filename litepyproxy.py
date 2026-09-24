#!/usr/bin/env python3

import html
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import httpx

HOST = os.getenv("LITEPYPROXY_HOST", "127.0.0.1")
PORT = int(os.getenv("LITEPYPROXY_PORT", "8880"))
TIMEOUT = 30.0


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
    <form action="/proxy" method="get">
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
            with httpx.Client(
                follow_redirects=True,
                timeout=TIMEOUT,
                headers={"User-Agent": "LitePyProxy/0.1"},
            ) as client:
                response = client.get(target)
        except httpx.HTTPError as exc:
            self.send_error(502, f"Upstream request failed: {exc}")
            return

        body = response.content
        content_type = response.headers.get(
            "content-type", "application/octet-stream"
        )

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

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
