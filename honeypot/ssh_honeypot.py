"""SSH decoy service.

* With ``paramiko`` installed: a real SSH server handshake is performed and
  every password-authentication attempt is recorded.
  If ``accept_any_credentials`` is enabled the decoy *accepts* the login and
  serves a completely sandboxed fake shell whose replies are hard-coded
  strings - commands are LOGGED ONLY, never executed anywhere.
* Without paramiko: a plain-TCP fallback that records the client banner.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from core.config import DATA_DIR

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:          # graceful degradation - lab machines without it
    paramiko = None
    HAS_PARAMIKO = False

HOST_KEY_PATH = DATA_DIR / "ssh_host_ed25519.key"
FAKE_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

# ---------------------------------------------------------------- fake shell
MOTD = (
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    "Last login: " + time.strftime("%a %b %d %H:%M:%S %Y") + "\r\n")

CANNED_OUTPUTS: dict[str, str] = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname": "Linux ubuntu-lab 5.15.0-88-generic #1-Ubuntu SMP x86_64 GNU/Linux",
    "pwd": "/root",
    "hostname": "ubuntu-lab",
    "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  root  tmp  var",
    "cat /etc/passwd":
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000::/home/admin:/bin/bash",
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "ps": "  PID TTY          TIME CMD\n"
          "  842 pts/0    00:00:00 bash\n"
          " 1337 pts/0    00:00:00 ps",
    "ifconfig": "eth0: inet 10.0.2.15  netmask 255.255.255.0",
    "netstat": "tcp  0  0 0.0.0.0:22   0.0.0.0:*  LISTEN",
    "free": "              total        used        free\n"
            "Mem:        2048000      512000     1536000",
    "history": "    1  whoami\n    2  ls",
}


class FakeShell:
    """Pure string-matching shell emulation. NOTHING here touches the OS."""

    def __init__(self, emit_command: Callable[[str], None]):
        self.emit_command = emit_command

    def respond(self, command: str) -> Optional[str]:
        cmd = command.strip()
        if not cmd:
            return ""
        low = cmd.lower()
        if low in ("exit", "logout", "quit"):
            return None
        for canned_cmd, output in CANNED_OUTPUTS.items():
            if low == canned_cmd or low.startswith(canned_cmd + " "):
                if canned_cmd == "ls" and low != "ls":
                    return "ls: cannot access: No such file or directory"
                return output
        if low.startswith(("wget ", "curl ")):
            return "100%[====================>]  1,048,576   --.--K/s   in 0.001s"
        if low.startswith(("apt ", "apt-get ", "yum ", "dnf ")):
            return "Reading package lists... Done"
        if low.startswith("cd "):
            return ""
        return f"bash: {cmd.split()[0]}: command not found"


if HAS_PARAMIKO:
    class _ServerInterfaceBase(paramiko.ServerInterface):
        """Inherit every default method (get_banner, check_auth_none, ...)."""
else:
    class _ServerInterfaceBase:      # pragma: no cover - fallback shape
        pass


class _ServerInterface(_ServerInterfaceBase):
    """Honeypot auth callbacks; records every password attempt."""

    def __init__(self, honeypot: "SSHHoneypot", addr):
        self.hp = honeypot
        self.addr = addr
        self.auth_count = 0
        self.last_auth_at = 0.0

    def get_allowed_auths(self, username):        # noqa: ANN201
        return "password"

    def check_auth_password(self, username, password):   # noqa: ANN201
        import time as _time
        self.auth_count += 1
        self.last_auth_at = _time.time()
        self.hp.record_login(self.addr, username or "", password or "")
        if self.hp.accept_any_credentials and HAS_PARAMIKO:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):       # noqa: ANN201
        if HAS_PARAMIKO and kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return (paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                if HAS_PARAMIKO else 2)

    def check_channel_pty_request(self, *args):          # noqa: ANN201
        return True

    def check_channel_shell_request(self, channel):      # noqa: ANN201
        return True


class SSHHoneypot(threading.Thread):
    service_name = "ssh"

    def __init__(self, port: int, on_event: Callable[[dict], None],
                 bind_host: str = "127.0.0.1",
                 accept_any_credentials: bool = False):
        super().__init__(daemon=True, name=f"ssh-{port}")
        self.label = "SSH decoy"
        self.port = int(port)
        self.on_event = on_event
        self.bind_host = bind_host
        self.accept_any_credentials = accept_any_credentials
        self.stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._transports: list = []
        self.host_key = None
        self.auth_attempts = 0
        self.commands_captured = 0

    # ------------------------------------------------------------------ keys
    def ensure_host_key(self) -> None:
        if not HAS_PARAMIKO:
            return
        if HOST_KEY_PATH.exists():
            for loader in (
                    lambda: paramiko.ECDSAKey.from_private_key_file(
                        str(HOST_KEY_PATH)),
                    lambda: paramiko.RSAKey(filename=str(HOST_KEY_PATH))):
                try:
                    self.host_key = loader()
                    return
                except Exception:
                    continue
        try:
            self.host_key = paramiko.ECDSAKey.generate()   # fast, modern
        except Exception:
            self.host_key = paramiko.RSAKey.generate(2048)
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            self.host_key.write_private_key_file(str(HOST_KEY_PATH))
        except OSError:
            pass

    # ------------------------------------------------------------- recording
    def record_login(self, addr, username: str, password: str) -> None:
        self.auth_attempts += 1
        accepted = self.accept_any_credentials
        self.on_event({
            "service": "ssh",
            "event_type": "login_success" if accepted else "login_attempt",
            "src_ip": addr[0], "src_port": addr[1], "dst_port": self.port,
            "username": username[:128] or None,
            "password": password[:128] or None,
            "payload": f"SSH auth user={username!r} "
                       f"pass={'*' * len(password)}",
        })

    def record_command(self, addr, command: str) -> None:
        self.commands_captured += 1
        self.on_event({
            "service": "ssh", "event_type": "command",
            "src_ip": addr[0], "src_port": addr[1], "dst_port": self.port,
            "payload": command[:1024],
        })

    # ------------------------------------------------------------------- run
    def run(self) -> None:
        self.ensure_host_key()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind((self.bind_host, self.port))
            self._sock.listen(16)
            self._sock.settimeout(1.0)
        except OSError:
            return
        while not self.stop_event.is_set():
            try:
                sock, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_client,
                             args=(sock, addr), daemon=True).start()

    def _serve_client(self, sock: socket.socket, addr) -> None:
        try:
            if not HAS_PARAMIKO:
                self._fallback_banner(sock, addr)
                return
            transport = paramiko.Transport(sock)
            with threading.Lock():
                self._transports.append(transport)
            # paramiko >= 4 expects local_version as a plain str
            transport.local_version = FAKE_BANNER.decode().strip()
            if self.host_key is not None:
                transport.add_server_key(self.host_key)
            interface = _ServerInterface(self, addr)
            try:
                # returns after key exchange; auth callbacks fire afterwards
                transport.start_server(server=interface)
            except Exception as exc:
                import sys
                print(f"[ssh-decoy] handshake error from {addr[0]}: {exc}",
                      file=sys.stderr, flush=True)
                return

            # Wait for the client's authentication attempts (clients usually
            # disconnect themselves after failures - see docs/architecture.md).
            deadline = time.time() + 45
            while (not self.stop_event.is_set()
                   and transport.is_active()
                   and time.time() < deadline):
                if transport.is_authenticated():
                    break
                if (interface.auth_count
                        and time.time() - interface.last_auth_at > 1.5):
                    break          # last auth attempt has settled
                time.sleep(0.1)

            if transport.is_authenticated() and self.accept_any_credentials:
                channel = transport.accept(timeout=10)
                if channel is not None:
                    self._fake_shell(channel, addr)
            try:
                self._transports.remove(transport)
            except ValueError:
                pass
            transport.close()
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _fake_shell(self, channel, addr) -> None:
        shell = FakeShell(lambda command: self.record_command(addr, command))
        try:
            channel.send(MOTD.encode())
            buffer = b""
            while not self.stop_event.is_set():
                channel.send(b"root@ubuntu-lab:~# ")
                deadline = time.time() + 120
                while b"\n" not in buffer and b"\r" not in buffer:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        return
                    channel.settimeout(min(remaining, 10.0))
                    chunk = channel.recv(256)
                    if not chunk:
                        return
                    buffer += chunk
                line, _, rest = bytes(buffer).partition(b"\r")
                if b"\n" in rest:
                    rest = b""
                buffer = rest + (bytes(buffer).partition(b"\n")[2]
                                 if b"\n" in bytes(buffer) else b"")
                command = line.decode("utf-8", errors="replace").strip()
                if not command:
                    continue
                self.record_command(addr, command)
                reply = shell.respond(command)
                if reply is None:
                    channel.send(b"\r\nlogout\r\n")
                    channel.close()
                    return
                if reply:
                    channel.send(reply.replace("\n", "\r\n").encode()
                                 + b"\r\n")
        except Exception:
            pass
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def _fallback_banner(self, sock: socket.socket, addr) -> None:
        sock.settimeout(5)
        data = b""
        try:
            data = sock.recv(256)
            sock.sendall(FAKE_BANNER)
            data += sock.recv(256)
        except (socket.timeout, OSError):
            pass
        self.on_event({
            "service": "ssh", "event_type": "banner_grab",
            "src_ip": addr[0], "src_port": addr[1], "dst_port": self.port,
            "payload": data.decode("utf-8", errors="replace")[:256] or None,
        })

    def stop(self) -> None:
        self.stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        for transport in list(self._transports):
            try:
                transport.close()
            except Exception:
                pass
