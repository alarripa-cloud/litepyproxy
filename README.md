# litepyproxy

A small Python web proxy inspired by classic CGI/PHProxy-style browsing.

The goal is simple:

- run as a lightweight local service
- listen on `127.0.0.1:8880`
- sit behind nginx
- fetch remote HTTP/HTTPS pages
- rewrite links so browsing continues through the proxy
- keep dependencies and resource usage low

Planned architecture:

```text
Browser
  ↓
nginx
  ↓
127.0.0.1:8880
  ↓
litepyproxy
  ↓
remote website
```

The service will run under its own unprivileged system user and be managed by systemd.

Early project — first target is a minimal working proxy with a URL bar, GET requests, link rewriting, and static asset passthrough.

## Historical note

> *“Certbot independently rediscovered the Tonyex deployment model.”*
