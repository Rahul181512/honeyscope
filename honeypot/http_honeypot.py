"""HTTP decoy service.

Serves a realistic-looking (but entirely fake) router administration login
page. Every request - method, path, query string, headers and body - is
recorded; POSTs to /login are captured as credential-stuffing attempts.
The service only ever returns static strings.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qs, unquote, urlparse

MAX_BODY = 16384

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Router Configuration Panel</title>
<style>
 body{font-family:Arial,Helvetica,sans-serif;background:#e8ecf1;margin:0;
      display:flex;align-items:center;justify-content:center;height:100vh}
 .box{background:#fff;border:1px solid #cfd6de;border-radius:8px;padding:34px 40px;
      width:340px;box-shadow:0 2px 10px rgba(20,40,70,.15)}
 h1{font-size:18px;color:#123a6d;margin:0 0 4px}
 p.sub{color:#68788f;font-size:12px;margin:0 0 22px}
 label{display:block;font-size:12px;color:#3c4a5e;margin-bottom:4px}
 input{width:100%;padding:9px 10px;margin-bottom:14px;border:1px solid #b9c3cf;
       border-radius:4px;box-sizing:border-box;font-size:13px}
 button{width:100%;padding:10px;background:#1259a8;color:#fff;border:0;
        border-radius:4px;font-size:14px;cursor:pointer}
 button:hover{background:#0e4a8d}
 .foot{margin-top:16px;font-size:11px;color:#93a2b5;text-align:center}
</style></head>
<body><div class="box">
 <h1>Router Configuration Panel</h1>
 <p class="sub">Model RT-AC1200 &middot; Firmware 3.0.0.4</p>
 <form method="post" action="/login">
   <label>Username</label><input name="username" autocomplete="off">
   <label>Password</label><input type="password" name="password">
   <button type="submit">Sign In</button>
 </form>
 <div class="foot">&copy; Network Systems Inc.</div>
</div></body></html>"""

ERROR_PAGE = """<!DOCTYPE html><html><head><title>Login failed</title></head>
<body style="font-family:Arial;background:#e8ecf1;text-align:center;
             padding-top:15vh">
<div style="background:#fff;display:inline-block;padding:36px 48px;
            border-radius:8px;border:1px solid #cfd6de">
<h2 style="color:#b3261e">Invalid username or password</h2>
<p style="color:#68788f">Please try again.</p>
<a href="/" style="color:#1259a8">Back to login</a>
</div></body></html>"""

NOT_FOUND_PAGE = ("<!DOCTYPE html><html><head><title>404</title></head>"
                  "<body style='font-family:Arial;text-align:center;"
                  "padding-top:12vh'><h1 style='color:#123a6d'>404 Not Found"
                  "</h1><hr><p>Nginx/1.24.0</p></body></html>")


def make_handler(on_event: Callable[[dict], None], port: int):
    class HoneypotHandler(BaseHTTPRequestHandler):
        server_version = "nginx/1.24.0"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # silence default stderr logging
        def log_message(self, fmt, *args):    # noqa: ANN001
            pass

        def do_GET(self):      self._common("GET")       # noqa: E701
        def do_POST(self):     self._common("POST")      # noqa: E701
        def do_HEAD(self):     self._common("HEAD")      # noqa: E701
        def do_PUT(self):      self._common("PUT")       # noqa: E701
        def do_DELETE(self):   self._common("DELETE")    # noqa: E701
        def do_PATCH(self):    self._common("PATCH")     # noqa: E701
        def do_OPTIONS(self):  self._common("OPTIONS")   # noqa: E701

        def _read_body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                length = 0
            if length <= 0:
                return b""
            return self.rfile.read(min(length, MAX_BODY))

        def _respond(self, code: int, body: str,
                     content_type: str = "text/html; charset=utf-8",
                     head_only: bool = False) -> None:
            payload = body.encode("utf-8")
            try:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.end_headers()
                if not head_only:
                    self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _common(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = unquote(parsed.path)[:512]
            query = parsed.query[:1024]
            body = self._read_body()
            user_agent = (self.headers.get("User-Agent") or "")[:256]

            event = {
                "service": "http",
                "event_type": "http_request",
                "src_ip": self.client_address[0],
                "src_port": self.client_address[1],
                "dst_port": port,
                "user_agent": user_agent or None,
                "payload": f"{method} {path}"
                           + (f"?{query}" if query else "")
                           + (f" | body={body[:512].decode('utf-8',
                              errors='replace')}" if body else ""),
            }

            head_only = method == "HEAD"

            # credential capture on the decoy login endpoint
            if method == "POST" and path.rstrip("/") == "/login":
                form = parse_qs(body.decode("utf-8", errors="replace"))
                username = (form.get("username") or [""])[0][:128] or None
                password = (form.get("password") or [""])[0][:128] or None
                event.update({
                    "event_type": "login_attempt",
                    "username": username,
                    "password": password,
                    "payload": f"HTTP login form POST user={username!r}",
                })
                on_event(event)
                self._respond(401, ERROR_PAGE, head_only=head_only)
                return

            on_event(event)

            if method in ("GET", "HEAD") and path.rstrip("/") in (
                    "/", "/index.html", "/admin", "/admin/", "/login"):
                self._respond(200, LOGIN_PAGE, head_only=head_only)
            elif method == "POST":
                self._respond(200, NOT_FOUND_PAGE, head_only=head_only)
            else:
                self._respond(404, NOT_FOUND_PAGE, head_only=head_only)

    return HoneypotHandler


class HTTPHoneypot(threading.Thread):
    service_name = "http"

    def __init__(self, port: int, on_event: Callable[[dict], None],
                 bind_host: str = "127.0.0.1"):
        super().__init__(daemon=True, name=f"http-{port}")
        self.label = "HTTP decoy"
        self.port = int(port)
        handler = make_handler(on_event, self.port)
        self.httpd = ThreadingHTTPServer((bind_host, self.port), handler)
        self.httpd.daemon_threads = True
        self.requests_seen = 0

    def run(self) -> None:
        self.httpd.serve_forever(poll_interval=0.5)

    def stop(self) -> None:
        threading.Thread(target=self.httpd.shutdown, daemon=True).start()
