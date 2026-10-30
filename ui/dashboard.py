"""
Local browser dashboard server built using Python's standard http.server module.

Exposes a local-only JSON API on 127.0.0.1 so users can select files, generate
SHA-256 baselines, run integrity scans, and watch live modifications visually.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from urllib.parse import parse_qs, urlparse
import webbrowser

from core.monitor import IntegrityMonitor
from ui.cli_display import open_native_dialog

WEB_ASSETS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web",
)

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


def create_handler(monitor: IntegrityMonitor):
    """Bind an IntegrityMonitor instance to an HTTP request handler class."""

    class DashboardRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format_str, *args):
            # Keep terminal output quiet during routine UI polling
            return

        def _send_json(self, payload: dict, status_code: int = 200) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            body = self.rfile.read(length).decode("utf-8")
            return json.loads(body) if body else {}

        def _serve_static_file(self, rel_name: str) -> None:
            safe_name = os.path.basename(rel_name)
            full_path = os.path.join(WEB_ASSETS_DIR, safe_name)
            if not os.path.isfile(full_path):
                self._send_json({"error": "Asset not found"}, status_code=404)
                return

            ext = os.path.splitext(safe_name)[1].lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")
            with open(full_path, "rb") as asset_file:
                content = asset_file.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            route = parsed.path

            if route in ("/", "/index.html"):
                self._serve_static_file("index.html")
                return
            if route in ("/style.css", "/app.js"):
                self._serve_static_file(route.lstrip("/"))
                return

            if route == "/api/state":
                params = parse_qs(parsed.query)
                run_scan = params.get("scan", ["0"])[0] == "1"
                if run_scan:
                    report = monitor.check_all()
                    self._send_json(
                        {
                            "seal_valid": report["seal_valid"],
                            "checked_at": report["checked_at"],
                            "counts": report["counts"],
                            "files": report["results"],
                            "audit": monitor.get_audit_history(limit=40),
                        }
                    )
                else:
                    stored = monitor.list_monitored_files()
                    seal_ok = monitor.is_baseline_seal_valid()
                    formatted_files = [_stored_entry_to_view(item, seal_ok) for item in stored]
                    counts = _summarize_views(formatted_files)
                    self._send_json(
                        {
                            "seal_valid": seal_ok,
                            "checked_at": None,
                            "counts": counts,
                            "files": formatted_files,
                            "audit": monitor.get_audit_history(limit=40),
                        }
                    )
                return

            self._send_json({"error": "Unknown endpoint"}, status_code=404)

        def do_POST(self) -> None:
            route = urlparse(self.path).path
            try:
                body = self._read_json_body()
            except json.JSONDecodeError:
                self._send_json({"error": "Invalid JSON request body"}, status_code=400)
                return

            try:
                if route == "/api/browse-file":
                    chosen = open_native_dialog(select_folder=False)
                    self._send_json({"path": chosen})
                    return

                if route == "/api/browse-folder":
                    chosen = open_native_dialog(select_folder=True)
                    self._send_json({"path": chosen})
                    return

                if route == "/api/add":
                    target = body.get("path", "").strip()
                    if not target:
                        self._send_json({"error": "Please provide a file path."}, status_code=400)
                        return
                    if os.path.isdir(target.strip('"').strip("'")):
                        summary = monitor.register_directory(target, recursive=True)
                        self._send_json(
                            {
                                "ok": True,
                                "mode": "directory",
                                "added_count": len(summary["added"]),
                                "directory": summary["directory"],
                            }
                        )
                    else:
                        record = monitor.register_file(target)
                        self._send_json({"ok": True, "mode": "file", "record": record})
                    return

                if route == "/api/add-folder":
                    target = body.get("path", "").strip()
                    if not target:
                        self._send_json({"error": "Please provide a folder path."}, status_code=400)
                        return
                    summary = monitor.register_directory(target, recursive=True)
                    self._send_json(
                        {
                            "ok": True,
                            "added_count": len(summary["added"]),
                            "directory": summary["directory"],
                        }
                    )
                    return

                if route == "/api/check":
                    target = body.get("path", "").strip()
                    res = monitor.check_file(target)
                    self._send_json({"ok": True, "result": res})
                    return

                if route == "/api/check-all":
                    report = monitor.check_all()
                    self._send_json(
                        {
                            "ok": True,
                            "seal_valid": report["seal_valid"],
                            "checked_at": report["checked_at"],
                            "counts": report["counts"],
                            "files": report["results"],
                            "audit": monitor.get_audit_history(limit=40),
                        }
                    )
                    return

                if route == "/api/rebaseline":
                    target = body.get("path", "").strip()
                    rec = monitor.rebaseline_file(target)
                    self._send_json({"ok": True, "record": rec})
                    return

                if route == "/api/remove":
                    target = body.get("path", "").strip()
                    removed = monitor.remove_file(target)
                    self._send_json({"ok": removed})
                    return

                if route == "/api/reset":
                    monitor.reset_baseline()
                    self._send_json({"ok": True})
                    return

                self._send_json({"error": "Unknown API endpoint"}, status_code=404)

            except (FileNotFoundError, KeyError, ValueError, RuntimeError, OSError) as exc:
                self._send_json({"error": str(exc)}, status_code=400)

    return DashboardRequestHandler


def _stored_entry_to_view(entry: dict, seal_ok: bool) -> dict:
    block_report = entry.get("last_block_report")
    if not block_report:
        blocks = entry.get("blocks", [])
        bsize = entry.get("block_size", 64)
        fsize = entry.get("size", 0)
        block_report = IntegrityMonitor._intact_block_report(bsize, blocks, fsize)

    delta = entry.get("last_size_delta", 0)
    return {
        "path": entry["path"],
        "file_name": entry["file_name"],
        "reference_hash": entry["sha256"],
        "current_hash": entry.get("last_current_hash", entry["sha256"]),
        "status": entry.get("last_status", "INTACT"),
        "seal_valid": seal_ok,
        "reference_size": entry["size"],
        "current_size": entry["size"] + delta if entry.get("last_status") != "MISSING" else None,
        "size_delta": delta,
        "reference_mtime": entry.get("mtime_readable", ""),
        "current_mtime": entry.get("mtime_readable", ""),
        "moved_to": entry.get("moved_to"),
        "block_report": block_report,
        "diagnosis": entry.get("last_diagnosis", "Reference baseline established"),
        "checked_at": entry.get("last_checked", entry.get("added_at", "")),
    }


def _summarize_views(views: list[dict]) -> dict:
    counts = {
        "total": len(views),
        "intact": 0,
        "modified": 0,
        "renamed": 0,
        "missing": 0,
        "errors": 0,
    }
    for item in views:
        st = item.get("status", "INTACT")
        if st == "INTACT":
            counts["intact"] += 1
        elif st == "MODIFIED":
            counts["modified"] += 1
        elif st == "RENAMED":
            counts["renamed"] += 1
        elif st == "MISSING":
            counts["missing"] += 1
        else:
            counts["errors"] += 1
    return counts


def start_dashboard(
    monitor: IntegrityMonitor,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> None:
    """Start the local HTTP server and optionally open the user's browser."""
    handler_cls = create_handler(monitor)
    server = None
    chosen_port = port

    # Automatically try the next few ports if 8765 is already occupied
    for candidate_port in range(port, port + 10):
        try:
            server = ThreadingHTTPServer((host, candidate_port), handler_cls)
            chosen_port = candidate_port
            break
        except OSError:
            continue

    if server is None:
        raise RuntimeError(f"Could not bind local server on ports {port}-{port + 9}.")

    url = f"http://{host}:{chosen_port}"
    print(f"\n  Local Web Dashboard running at: {url}")
    print("  Press Ctrl+C in this terminal to stop the server.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down dashboard server...")
    finally:
        server.server_close()

