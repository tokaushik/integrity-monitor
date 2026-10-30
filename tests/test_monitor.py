"""
Unit tests for SHA-256 hashing, block-level tamper localization,
rename detection, and baseline seal verification.

Run with:
    python -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import tempfile
import unittest

from core.hasher import compare_block_maps, compute_block_map, compute_sha256
from core.monitor import IntegrityMonitor
from ui.dashboard import create_handler


class TestHasherAndBlocks(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_known_sha256_vectors(self):
        empty_file = os.path.join(self.root, "empty.bin")
        with open(empty_file, "wb") as f:
            f.write(b"")
        self.assertEqual(
            compute_sha256(empty_file),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

        abc_file = os.path.join(self.root, "abc.txt")
        with open(abc_file, "wb") as f:
            f.write(b"abc")
        self.assertEqual(
            compute_sha256(abc_file),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_large_chunked_file_sha256(self):
        # Exceeds 64 KB READ_CHUNK_SIZE to exercise multi-chunk streaming
        payload = os.urandom(150_000)
        large_path = os.path.join(self.root, "random_blob.bin")
        with open(large_path, "wb") as f:
            f.write(payload)

        expected = hashlib.sha256(payload).hexdigest()
        self.assertEqual(compute_sha256(large_path), expected)

    def test_block_map_localizes_middle_edit_and_append(self):
        target = os.path.join(self.root, "blocks.dat")
        original = b"".join([bytes([i]) * 64 for i in range(8)])  # 8 blocks x 64 B = 512 B
        with open(target, "wb") as f:
            f.write(original)

        block_size, ref_blocks = compute_block_map(target)
        self.assertEqual(block_size, 64)
        self.assertEqual(len(ref_blocks), 8)

        # Modify only Block 4 (index 3: bytes 192..256) in place
        mutated = bytearray(original)
        mutated[200] = 255
        with open(target, "wb") as f:
            f.write(mutated)

        report = compare_block_maps(target, block_size, ref_blocks, len(original))
        states = [seg["state"] for seg in report["segments"]]
        self.assertEqual(
            states,
            ["intact", "intact", "intact", "modified", "intact", "intact", "intact", "intact"],
        )

        # Restore original and append 64 new bytes at end
        with open(target, "wb") as f:
            f.write(original + (b"Z" * 64))

        append_report = compare_block_maps(target, block_size, ref_blocks, len(original))
        append_states = [seg["state"] for seg in append_report["segments"]]
        self.assertEqual(append_states[:8], ["intact"] * 8)
        self.assertEqual(append_states[8], "appended")


class TestIntegrityMonitorWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.temp_dir.name, "files")
        self.db_dir = os.path.join(self.temp_dir.name, "db")
        os.makedirs(self.workspace, exist_ok=True)
        self.monitor = IntegrityMonitor(storage_dir=self.db_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_register_verify_modify_and_rebaseline(self):
        sample = os.path.join(self.workspace, "settings.conf")
        with open(sample, "w", encoding="utf-8") as f:
            f.write("mode=production\n")

        reg = self.monitor.register_file(sample)
        self.assertEqual(reg["last_status"], "INTACT")

        # Unchanged check
        res_ok = self.monitor.check_file(sample)
        self.assertEqual(res_ok["status"], "INTACT")
        self.assertTrue(res_ok["seal_valid"])
        self.assertEqual(res_ok["reference_hash"], res_ok["current_hash"])

        # Modify file content
        with open(sample, "w", encoding="utf-8") as f:
            f.write("mode=debug_unsafe\n")

        res_mod = self.monitor.check_file(sample)
        self.assertEqual(res_mod["status"], "MODIFIED")
        self.assertNotEqual(res_mod["reference_hash"], res_mod["current_hash"])
        self.assertGreater(res_mod["size_delta"], 0)

        # Re-baseline authorized edit
        self.monitor.rebaseline_file(sample)
        res_after = self.monitor.check_file(sample)
        self.assertEqual(res_after["status"], "INTACT")
        self.assertEqual(res_after["reference_hash"], res_mod["current_hash"])

    def test_detects_rename_vs_missing(self):
        doc = os.path.join(self.workspace, "report_v1.txt")
        with open(doc, "w", encoding="utf-8") as f:
            f.write("Quarterly IEEE Sensor Workshop Summary\n")

        self.monitor.register_file(doc)

        renamed_doc = os.path.join(self.workspace, "report_final.txt")
        os.rename(doc, renamed_doc)

        res_renamed = self.monitor.check_file(doc)
        self.assertEqual(res_renamed["status"], "RENAMED")
        self.assertEqual(
            os.path.normcase(res_renamed["moved_to"]),
            os.path.normcase(renamed_doc),
        )

        # Now delete the renamed file completely
        os.remove(renamed_doc)
        res_missing = self.monitor.check_file(doc)
        self.assertEqual(res_missing["status"], "MISSING")

    def test_baseline_json_tampering_breaks_seal_persistently(self):
        secret_file = os.path.join(self.workspace, "credentials.env")
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("API_ROLE=viewer\n")

        self.monitor.register_file(secret_file)

        # Modify file AND try to fake the stored SHA-256 directly inside baseline.json
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("API_ROLE=superadmin\n")
        forged_hash = compute_sha256(secret_file)

        with open(self.monitor.baseline_path, "r", encoding="utf-8") as f:
            db = json.load(f)
        for key in db["files"]:
            db["files"][key]["sha256"] = forged_hash
        with open(self.monitor.baseline_path, "w", encoding="utf-8") as f:
            json.dump(db, f)

        self.assertFalse(self.monitor.is_baseline_seal_valid())
        check1 = self.monitor.check_file(secret_file)
        self.assertFalse(check1["seal_valid"])

        # Ensure checking did NOT re-sign the forged baseline
        check2 = self.monitor.check_file(secret_file)
        self.assertFalse(check2["seal_valid"])


class _InMemorySocket:
    """Minimal socket stub to exercise BaseHTTPRequestHandler without OS network calls."""

    def __init__(self, raw_request: bytes):
        import io

        self._rfile = io.BytesIO(raw_request)
        self.wfile = io.BytesIO()

    def makefile(self, mode: str, *args, **kwargs):
        return self._rfile if "r" in mode else self.wfile

    def sendall(self, data: bytes) -> None:
        self.wfile.write(data)


class TestDashboardHTTPAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.temp_dir.name, "files")
        self.db_dir = os.path.join(self.temp_dir.name, "db")
        os.makedirs(self.workspace, exist_ok=True)

        self.monitor = IntegrityMonitor(storage_dir=self.db_dir)
        self.handler_cls = create_handler(self.monitor)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _request(self, path: str, method: str = "GET", payload: dict | None = None):
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else b""
        lines = [
            f"{method} {path} HTTP/1.1",
            "Host: 127.0.0.1:8765",
        ]
        if payload is not None:
            lines.append("Content-Type: application/json")
            lines.append(f"Content-Length: {len(body_bytes)}")
        raw_req = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body_bytes

        sock = _InMemorySocket(raw_req)
        self.handler_cls(sock, ("127.0.0.1", 55000), None)
        raw_resp = sock.wfile.getvalue().decode("utf-8")
        header_part, resp_body = raw_resp.split("\r\n\r\n", 1)
        status_code = int(header_part.splitlines()[0].split()[1])
        return status_code, resp_body

    def test_static_assets_and_api_lifecycle(self):
        status_html, html_body = self._request("/")
        self.assertEqual(status_html, 200)
        self.assertIn("File Integrity Workbench", html_body)

        sample = os.path.join(self.workspace, "app.cfg")
        with open(sample, "w", encoding="utf-8") as f:
            f.write("port=8080\n")

        _, add_raw = self._request("/api/add", method="POST", payload={"path": sample})
        add_json = json.loads(add_raw)
        self.assertTrue(add_json["ok"])

        with open(sample, "w", encoding="utf-8") as f:
            f.write("port=9999\n")

        _, scan_raw = self._request("/api/check-all", method="POST", payload={})
        scan_json = json.loads(scan_raw)
        self.assertEqual(scan_json["counts"]["modified"], 1)
        self.assertEqual(scan_json["files"][0]["status"], "MODIFIED")


if __name__ == "__main__":
    unittest.main()
