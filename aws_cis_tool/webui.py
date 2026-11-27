"""Local web dashboard for the AWS CIS tool (stdlib only, binds to 127.0.0.1)."""
import json
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .auth import AWSAuth
from .runner import run_scan, summarize, write_reports

WEB_DIR = Path(__file__).resolve().parent / "web"


class ScanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop_flag = False
        self.reset()

    def reset(self):
        self.state = "idle"  # idle | authenticating | running | done | error | stopped
        self.error = None
        self.identity = {}
        self.progress = 0
        self.total = 0
        self.current = ""
        self.results = []
        self.summary = {}
        self.files = {}
        self.out_dir = None

    def snapshot(self, since=0):
        with self.lock:
            return {
                "state": self.state, "error": self.error, "identity": self.identity,
                "progress": self.progress, "total": self.total, "current": self.current,
                "results": self.results[since:], "offset": since,
                "summary": self.summary,
                "files": {k: os.path.basename(v) for k, v in self.files.items()},
            }


STATE = ScanState()
TOKEN = secrets.token_urlsafe(24)  # required on every API call (blocks drive-by requests)


def _scan_worker(params):
    s = STATE
    try:
        auth = AWSAuth(
            profile_name=params.get("profile") if params.get("mode") == "profile" else None,
            region_name=params.get("region"),
            aws_access_key_id=params.get("access_key") if params.get("mode") == "keys" else None,
            aws_secret_access_key=params.get("secret_key") if params.get("mode") == "keys" else None,
            aws_session_token=params.get("session_token") if params.get("mode") == "keys" else None,
        )
        if not auth.authenticate():
            with s.lock:
                s.state, s.error = "error", auth.last_error or "Authentication failed."
            return
        with s.lock:
            s.identity = {**auth.identity, "Region": auth.region_name}
            s.state = "running"

        def progress(i, total, r):
            with s.lock:
                s.progress, s.total = i, total
                s.current = f"{r['check_id']} {r['title']}"
                s.results.append(r)

        results = run_scan(auth, on_progress=progress, should_stop=lambda: s.stop_flag)
        out_dir = params.get("out_dir") or "reports"
        formats = [f for f in params.get("formats", []) if f in ("json", "html", "pdf")]
        files = {}
        if formats and results:
            try:
                files = write_reports(results, auth.account_id, out_dir, formats)
            except Exception as e:  # noqa: BLE001
                with s.lock:
                    s.error = f"Scan finished but report generation failed: {e}"
        with s.lock:
            s.summary = summarize(results)
            s.files = files
            s.out_dir = os.path.abspath(out_dir)
            s.state = "stopped" if s.stop_flag else "done"
    except Exception as e:  # noqa: BLE001
        with s.lock:
            s.state, s.error = "error", f"Unexpected error: {e}"


def _list_profiles():
    try:
        import boto3
        return sorted(boto3.session.Session().available_profiles)
    except Exception:  # noqa: BLE001
        return []


class Handler(BaseHTTPRequestHandler):
    server_version = "AWSCIS/" + __version__

    def log_message(self, *a):  # keep the terminal quiet
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        host_ok = self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")
        return host_ok and self.headers.get("X-Token") == TOKEN

    def do_GET(self):
        path = urlparse(self.path)
        if path.path == "/":
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            html = html.replace("__TOKEN__", TOKEN).replace("__VERSION__", __version__)
            return self._send(200, html.encode(), "text/html; charset=utf-8")
        if path.path == "/api/profiles":
            if not self._authorized():
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"profiles": _list_profiles()})
        if path.path == "/api/status":
            if not self._authorized():
                return self._send(403, {"error": "forbidden"})
            since = int((path.query.split("since=")[-1] if "since=" in path.query else "0") or 0)
            return self._send(200, STATE.snapshot(since))
        if path.path.startswith("/api/report/"):
            name = os.path.basename(path.path)
            if not self._authorized() and "t=" + TOKEN not in path.query:
                return self._send(403, {"error": "forbidden"})
            match = next((p for p in STATE.files.values() if os.path.basename(p) == name), None)
            if not match or not os.path.isfile(match):
                return self._send(404, {"error": "not found"})
            ctype = {".json": "application/json", ".html": "text/html; charset=utf-8",
                     ".pdf": "application/pdf"}.get(Path(match).suffix, "application/octet-stream")
            return self._send(200, Path(match).read_bytes(), ctype,
                              {"Content-Disposition": f'inline; filename="{name}"'})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return self._send(403, {"error": "forbidden"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            params = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid json"})
        if self.path == "/api/scan":
            if STATE.state in ("authenticating", "running"):
                return self._send(409, {"error": "A scan is already running."})
            if params.get("mode") == "keys" and not (
                    (params.get("access_key") or "").strip() and (params.get("secret_key") or "").strip()):
                return self._send(400, {"error": "Access Key ID and Secret Access Key are required."})
            STATE.reset()
            STATE.stop_flag = False
            STATE.state = "authenticating"
            threading.Thread(target=_scan_worker, args=(params,), daemon=True).start()
            return self._send(200, {"ok": True})
        if self.path == "/api/stop":
            STATE.stop_flag = True
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})


def serve(host="127.0.0.1", port=0, open_browser=True):
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"AWS CIS Benchmark Scanner v{__version__} running at {url}  (Ctrl+C to quit)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")
    finally:
        httpd.server_close()
