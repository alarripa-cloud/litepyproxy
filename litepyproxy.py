#!/usr/bin/env python3

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("LITEPYPROXY_HOST", "127.0.0.1")
PORT = int(os.getenv("LITEPYPROXY_PORT", "8880"))


class LitePyProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"""<!doctype html>
<html>
<head><title>LitePyProxy</title></head>
<body>
<h1>LitePyProxy</h1>
<p>LitePyProxy is running.</p>
</body>
</html>
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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
