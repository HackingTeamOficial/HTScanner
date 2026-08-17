#!/usr/bin/env python3
"""control_plane.py - HT Control Plane: registry + heartbeat de workers."""
import json, os, time, socket, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "control_state.json"
PORT = 47999
MAGIC = "HTCONTROL/1"

# ---------- estado ----------
if STATE_PATH.exists():
    try:
        _state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        _state = {}
else:
    _state = {}


def _save():
    STATE_PATH.write_text(json.dumps(_state, indent=2, ensure_ascii=False), encoding="utf-8")


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------- HTTP API ----------
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/devices":
            devices = []
            for iid, info in _state.items():
                devices.append({
                    "installation_id": iid,
                    "hostname": info.get("hostname", ""),
                    "os": info.get("os", ""),
                    "state": info.get("state", "unknown"),
                    "last_seen": info.get("last_seen", ""),
                    "capacity_percent": info.get("capacity_percent"),
                })
            self._json({"devices": devices, "count": len(devices)})
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        try:
            data = json.loads(body)
        except Exception:
            self._json({"ok": False, "error": "invalid json"}, 400)
            return

        iid = data.get("installation_id") or data.get("installationId") or ""
        if not iid:
            self._json({"ok": False, "error": "missing installation_id"}, 400)
            return

        entry = {
            "hostname": data.get("hostname", ""),
            "os": data.get("os", ""),
            "state": "active",
            "last_seen": _now(),
            "capacity_percent": data.get("capacity_percent"),
            "product_id": data.get("product_id"),
            "product_version": data.get("product_version"),
        }
        _state[iid] = entry
        _save()
        self._json({"ok": True, "state": entry})

    def log_message(self, format, *args):
        try:
            msg = format % args
            if "register" in msg or "heartbeat" in msg or "/v1/" in msg:
                print("[CP]", msg)
        except Exception:
            pass

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------- UDP beacon ----------
def _udp_beacon():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", PORT))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            obj = json.loads(data.decode("utf-8", "replace"))
            if obj.get("magic") == MAGIC and obj.get("discover"):
                host = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME", "htscanner")
                resp = json.dumps({
                    "magic": MAGIC,
                    "host": host,
                    "port": 8787,
                    "state": "ok",
                }).encode()
                sock.sendto(resp, (addr[0], obj.get("port", PORT)))
        except Exception:
            pass


def run():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=_udp_beacon, daemon=True).start()
    print(f"[Control Plane] activo en http://0.0.0.0:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
