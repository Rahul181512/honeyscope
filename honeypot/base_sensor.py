"""Base TCP sensor plus FTP and Telnet decoy services.

Every component records interactions through an ``on_event(dict)`` callback
(the collection pipeline) and never executes anything it receives.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable, Optional


def preview(data: Optional[bytes], limit: int = 256) -> Optional[str]:
    """Human-safe printable preview of raw bytes."""
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    out = []
    for ch in text:
        if ch.isprintable() or ch in "\r\n\t":
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}")
    cleaned = "".join(out).strip()
    return cleaned[:limit] or None


def _read_line(conn: socket.socket, buffer: bytearray, deadline: float,
               max_len: int = 512) -> Optional[str]:
    """Read one CRLF/LF-terminated line using *buffer*, respecting *deadline*."""
    while b"\n" not in buffer:
        remaining = deadline - _now()
        if remaining <= 0:
            return None
        conn.settimeout(min(remaining, 5.0))
        try:
            chunk = conn.recv(256)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buffer.extend(chunk)
        if len(buffer) > max_len * 4:
            return None
    raw, _, rest = bytes(buffer).partition(b"\n")
    buffer.clear()
    buffer.extend(rest)
    return raw.decode("utf-8", errors="replace").strip("\r\n\x00")[:max_len] or ""


def _now() -> float:
    import time
    return time.monotonic()


class TCPSensor(threading.Thread):
    """Generic silent TCP listener: any connection is logged as a probe."""

    service_name = "sensor"
    default_event = "port_probe"

    def __init__(self, name: str, port: int, on_event: Callable[[dict], None],
                 bind_host: str = "127.0.0.1", banner: Optional[bytes] = None,
                 idle_timeout: int = 6):
        super().__init__(daemon=True, name=f"{self.service_name}-{port}")
        self.label = name
        self.port = int(port)
        self.on_event = on_event
        self.bind_host = bind_host
        self.banner = banner
        self.idle_timeout = idle_timeout
        self.stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None
        self.connections_seen = 0
        self.bind_error: Optional[str] = None

    # ------------------------------------------------------------------ utils
    def emit(self, event_type: str, addr, **kwargs) -> None:
        event = {
            "service": self.service_name,
            "event_type": event_type,
            "src_ip": addr[0],
            "src_port": addr[1],
            "dst_port": self.port,
        }
        event.update(kwargs)
        try:
            self.on_event(event)
        except Exception:
            pass

    def handle_session(self, conn: socket.socket, addr) -> None:
        """Default behaviour: capture whatever the client sends, stay quiet."""
        data = b""
        try:
            conn.settimeout(self.idle_timeout)
            data = conn.recv(256)
        except (socket.timeout, OSError):
            pass
        if self.banner:
            try:
                conn.sendall(self.banner)
                try:
                    data += conn.recv(256)
                except (socket.timeout, OSError):
                    pass
            except OSError:
                pass
        self.emit(self.default_event, addr, payload=preview(data))

    # ------------------------------------------------------------------- loop
    def run(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.bind_host, self.port))
            self._sock.listen(16)
            self._sock.settimeout(1.0)
        except OSError as exc:
            self.bind_error = str(exc)
            return
        while not self.stop_event.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections_seen += 1
            threading.Thread(
                target=self._safe_handle, args=(conn, addr), daemon=True,
                name=f"{self.service_name}-conn").start()

    def _safe_handle(self, conn: socket.socket, addr) -> None:
        try:
            self.handle_session(conn, addr)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self.stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


class FtpSensor(TCPSensor):
    """Decoy FTP service that captures USER/PASS credential attempts."""

    service_name = "ftp"

    def __init__(self, port: int, on_event, bind_host: str = "127.0.0.1"):
        super().__init__("FTP decoy", port, on_event, bind_host,
                         banner=b"220 Welcome to FTP Archive Service\r\n")

    def handle_session(self, conn: socket.socket, addr) -> None:
        if self.banner:
            self._send(conn, self.banner.decode().strip())
        buffer = bytearray()
        deadline = _now() + 45
        user: Optional[str] = None
        while _now() < deadline and not self.stop_event.is_set():
            line = _read_line(conn, buffer, deadline)
            if line is None:
                break
            verb, _, arg = line.partition(" ")
            verb_u = verb.strip().upper()
            if verb_u == "USER":
                user = arg.strip()[:128] or None
                self._send(conn, "331 Please specify the password.")
            elif verb_u == "PASS":
                self.emit("login_attempt", addr, username=user,
                          password=arg.strip()[:128] or None,
                          payload=f"FTP USER={user!r} PASS={'*' * len(arg)}")
                self._send(conn, "530 Login incorrect.")
                user = None
            elif verb_u == "QUIT":
                self._send(conn, "221 Goodbye.")
                break
            elif verb_u == "SYST":
                self._send(conn, "215 UNIX Type: L8")
            elif verb_u == "":
                break
            else:
                self._send(conn, "502 Command not implemented.")

    @staticmethod
    def _send(conn: socket.socket, text: str) -> None:
        try:
            conn.sendall(f"{text}\r\n".encode())
        except OSError:
            pass


_IAC = 0xFF


def strip_telnet_iac(data: bytes) -> bytes:
    """Remove telnet negotiation sequences (IAC + option bytes)."""
    out, i = [], 0
    while i < len(data):
        b = data[i]
        if b == _IAC:
            i += 3 if i + 2 < len(data) else len(data)
            continue
        out.append(b)
        i += 1
    return bytes(out)


class TelnetSensor(TCPSensor):
    """Decoy Telnet service with a classic login prompt."""

    service_name = "telnet"

    def __init__(self, port: int, on_event, bind_host: str = "127.0.0.1"):
        super().__init__("Telnet decoy", port, on_event, bind_host)

    def handle_session(self, conn: socket.socket, addr) -> None:
        buffer = bytearray()
        deadline = _now() + 60
        self._send(conn, "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux "
                         "5.15.0-88-generic x86_64)\r\n\r\nlocalhost login: ")
        for _round in range(3):
            username = self._read_input(conn, buffer, deadline)
            if username is None:
                return
            if username == "":
                self._send(conn, "\r\nlocalhost login: ")
                continue
            self._send(conn, "Password: ")
            password = self._read_input(conn, buffer, deadline)
            if password is None:
                return
            self.emit("login_attempt", addr, username=username[:128] or None,
                      password=password[:128] or None,
                      payload=f"Telnet login user={username!r}")
            self._send(conn, "\r\nLogin incorrect\r\n\r\nlocalhost login: ")

    def _read_input(self, conn: socket.socket, buffer: bytearray,
                    deadline: float) -> Optional[str]:
        while b"\n" not in buffer and b"\r" not in buffer:
            remaining = deadline - _now()
            if remaining <= 0:
                return None
            conn.settimeout(min(remaining, 5.0))
            try:
                chunk = conn.recv(128)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buffer.extend(strip_telnet_iac(chunk))
        raw = bytes(buffer)
        for sep in (b"\r\n", b"\n", b"\r"):
            if sep in raw:
                head, _, rest = raw.partition(sep)
                break
        buffer.clear()
        buffer.extend(rest)
        return head.decode("utf-8", errors="replace").strip()[:128]

    @staticmethod
    def _send(conn: socket.socket, text: str) -> None:
        try:
            conn.sendall(text.encode())
        except OSError:
            pass
