#!/usr/bin/env python3
"""
Transparent proxy bridge for QwikCAP.

Sits between iptables REDIRECT and Burp Suite. For each connection:
  - HTTPS: peeks at TLS ClientHello, extracts SNI
  - HTTP:  reads request line + Host header
  - If the host is in the exception list → connects directly to original destination
  - Otherwise → forwards to Burp (invisible proxying)

SO_ORIGINAL_DST recovers the pre-REDIRECT destination so excepted hosts
can be forwarded to the right IP:port without DNS re-lookup.
"""

import json
import os
import select
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

BURP_HOST  = os.environ.get("BURP_HOST", "host.docker.internal")
BURP_PORT  = int(os.environ.get("BURP_PORT", "8080"))
HTTP_PORT  = int(os.environ.get("HTTP_LISTEN", "8079"))
HTTPS_PORT = int(os.environ.get("HTTPS_LISTEN", "8443"))
CTRL_PORT  = int(os.environ.get("CTRL_PORT", "9292"))

# Comma-separated list of exact hostnames or .suffix patterns (e.g. ".apple.com")
_raw = os.environ.get("EXCEPTION_HOSTS", "")
EXCEPTION_HOSTS: set = set(h.strip().lower() for h in _raw.split(",") if h.strip())

SO_ORIGINAL_DST = 80

# --- Thread-safe stats and exception lock ---
_stats_lock = threading.Lock()
_exc_lock   = threading.Lock()

_stats = {
    "conn_proxied":   0,
    "conn_bypassed":  0,
    "bytes_proxied":  0,
    "bytes_bypassed": 0,
    "active":         0,
}


def _inc(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] += n


def _stats_snapshot() -> dict:
    with _stats_lock:
        return dict(_stats)


def is_excepted(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    with _exc_lock:
        snapshot = set(EXCEPTION_HOSTS)
    if hostname in snapshot:
        return True
    for rule in snapshot:
        if rule.startswith(".") and (hostname.endswith(rule) or hostname == rule.lstrip(".")):
            return True
    return False


def original_dst(conn: socket.socket):
    """Return (ip_str, port) of destination before iptables REDIRECT, or (None, None)."""
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", raw[2:4])[0]
        ip   = socket.inet_ntoa(raw[4:8])
        return ip, port
    except Exception:
        return None, None


def relay(a: socket.socket, b: socket.socket, category: str = "proxied") -> None:
    """Bidirectional byte relay; counts bytes toward the given category."""
    bytes_key = f"bytes_{category}"
    _inc("active")
    a.settimeout(60)
    b.settimeout(60)
    try:
        while True:
            ready, _, _ = select.select([a, b], [], [], 60)
            if not ready:
                break
            for src in ready:
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                _inc(bytes_key, len(data))
                dst.sendall(data)
    except Exception:
        pass
    finally:
        _inc("active", -1)
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def extract_sni(data: bytes):
    """Parse SNI from a TLS ClientHello. Returns hostname string or None."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32          # handshake hdr + version + random
        sid_len = data[pos]; pos += 1 + sid_len
        cs_len  = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2 + cs_len
        cm_len  = data[pos]; pos += 1 + cm_len
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack(">H", data[pos:pos+2])[0]
            ext_len  = struct.unpack(">H", data[pos+2:pos+4])[0]
            if ext_type == 0 and pos + 4 + ext_len <= len(data):
                sni_blob = data[pos+4:pos+4+ext_len]
                if len(sni_blob) >= 5:
                    name_len = struct.unpack(">H", sni_blob[3:5])[0]
                    return sni_blob[5:5+name_len].decode("utf-8", errors="ignore")
            pos += 4 + ext_len
    except Exception:
        pass
    return None


def extract_http_host(data: bytes):
    """Return bare hostname from the HTTP Host header (strips port)."""
    try:
        for line in data.decode("utf-8", errors="ignore").split("\r\n")[1:]:
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip().split(":")[0]
    except Exception:
        pass
    return None


def connect_upstream(host, port, fallback_ip, fallback_port) -> socket.socket:
    target_host = host or fallback_ip
    target_port = port or fallback_port
    return socket.create_connection((target_host, target_port), timeout=10)


def handle_https(conn: socket.socket) -> None:
    try:
        orig_ip, orig_port = original_dst(conn)
        conn.settimeout(5)
        data = conn.recv(4096, socket.MSG_PEEK)
        conn.settimeout(None)
        sni = extract_sni(data)

        if is_excepted(sni):
            _inc("conn_bypassed")
            upstream = connect_upstream(sni, orig_port or 443, orig_ip, 443)
            relay(conn, upstream, "bypassed")
        else:
            _inc("conn_proxied")
            upstream = connect_upstream(BURP_HOST, BURP_PORT, None, None)
            relay(conn, upstream, "proxied")
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def handle_http(conn: socket.socket) -> None:
    try:
        orig_ip, orig_port = original_dst(conn)
        conn.settimeout(5)
        data = conn.recv(4096)
        conn.settimeout(None)
        host = extract_http_host(data)

        if is_excepted(host):
            _inc("conn_bypassed")
            upstream = connect_upstream(host, orig_port or 80, orig_ip, 80)
            upstream.sendall(data)
            relay(conn, upstream, "bypassed")
        else:
            _inc("conn_proxied")
            upstream = connect_upstream(BURP_HOST, BURP_PORT, None, None)
            upstream.sendall(data)
            relay(conn, upstream, "proxied")
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def serve(port: int, handler) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(256)
    while True:
        try:
            conn, _ = srv.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()
        except Exception:
            pass


# --- Control / stats HTTP server ---

class _CtrlHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send_json(self, obj: object, status: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/stats":
            self._send_json(_stats_snapshot())
        elif path == "/exceptions":
            with _exc_lock:
                exc_list = sorted(EXCEPTION_HOSTS)
            self._send_json(exc_list)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/exceptions":
            hosts = json.loads(self._read_body() or b"[]")
            if isinstance(hosts, str):
                hosts = [hosts]
            with _exc_lock:
                for h in hosts:
                    EXCEPTION_HOSTS.add(h.strip().lower())
            self._send_json({"added": hosts})
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path == "/exceptions":
            hosts = json.loads(self._read_body() or b"[]")
            if isinstance(hosts, str):
                hosts = [hosts]
            with _exc_lock:
                for h in hosts:
                    EXCEPTION_HOSTS.discard(h.strip().lower())
            self._send_json({"removed": hosts})
        else:
            self.send_response(404)
            self.end_headers()


def _start_ctrl_server() -> None:
    srv = HTTPServer(("0.0.0.0", CTRL_PORT), _CtrlHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


if __name__ == "__main__":
    _start_ctrl_server()
    print(f"proxy: HTTP={HTTP_PORT} HTTPS={HTTPS_PORT} burp={BURP_HOST}:{BURP_PORT} ctrl=:{CTRL_PORT}", flush=True)
    print(f"proxy: exceptions={EXCEPTION_HOSTS or '(none)'}", flush=True)
    threading.Thread(target=serve, args=(HTTP_PORT, handle_http), daemon=True).start()
    serve(HTTPS_PORT, handle_https)
