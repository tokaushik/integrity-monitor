"""
Core File Integrity Monitor engine.

Manages reference SHA-256 baselines, performs on-demand and batch integrity
comparisons, detects file renames within the same directory, and maintains an
audit trail of security events.
"""

from datetime import datetime
import json
import os

from core.hasher import (
    compare_block_maps,
    compute_block_map,
    compute_sha256,
    get_file_metadata,
    normalize_path,
    path_key,
)
from core.seal import (
    compute_baseline_seal,
    get_or_create_seal_key,
    verify_baseline_seal,
)

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".integrity_data",
    "demo_workspace",
    ".venv",
    "venv",
    "env",
    "node_modules",
}

MAX_AUDIT_ENTRIES = 250


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_mtime(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds).strftime("%Y-%m-%d %H:%M:%S")


class IntegrityMonitor:
    """Tracks selected files by comparing stored SHA-256 baselines against live hashes."""

    def __init__(self, storage_dir: str | None = None):
        if storage_dir is None:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            storage_dir = os.path.join(project_root, ".integrity_data")

        self.storage_dir = normalize_path(storage_dir)
        self.baseline_path = os.path.join(self.storage_dir, "baseline.json")
        self.audit_path = os.path.join(self.storage_dir, "audit_log.json")
        os.makedirs(self.storage_dir, exist_ok=True)
        self._secret_key = get_or_create_seal_key(self.storage_dir)

    # ------------------------------------------------------------------
    # Internal persistence helpers
    # ------------------------------------------------------------------

    def _load_baseline(self) -> dict:
        if not os.path.exists(self.baseline_path):
            empty_files = {}
            now = _timestamp()
            return {
                "version": "1.0",
                "created_at": now,
                "updated_at": now,
                "seal": compute_baseline_seal(empty_files, self._secret_key),
                "files": empty_files,
            }

        try:
            with open(self.baseline_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                if "files" not in data or not isinstance(data["files"], dict):
                    data["files"] = {}
                return data
        except (json.JSONDecodeError, OSError):
            return {
                "version": "1.0",
                "created_at": _timestamp(),
                "updated_at": _timestamp(),
                "seal": "CORRUPTED_JSON",
                "files": {},
            }

    def _save_baseline(self, data: dict, update_seal: bool = False) -> None:
        data["updated_at"] = _timestamp()
        if update_seal:
            data["seal"] = compute_baseline_seal(data["files"], self._secret_key)

        with open(self.baseline_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def is_baseline_seal_valid(self, baseline_data: dict | None = None) -> bool:
        """Return False if baseline.json was edited outside the monitor."""
        data = baseline_data if baseline_data is not None else self._load_baseline()
        return verify_baseline_seal(
            data.get("files", {}),
            data.get("seal", ""),
            self._secret_key,
        )

    def _record_audit_event(
        self,
        event_type: str,
        file_path: str,
        status: str,
        details: str,
        reference_hash: str = "",
        current_hash: str = "",
    ) -> None:
        history = self.get_audit_history(limit=MAX_AUDIT_ENTRIES)
        entry = {
            "timestamp": _timestamp(),
            "event": event_type,
            "file_name": os.path.basename(file_path) if file_path else "-",
            "path": file_path,
            "status": status,
            "details": details,
            "reference_hash": reference_hash,
            "current_hash": current_hash,
        }
        history.insert(0, entry)
        history = history[:MAX_AUDIT_ENTRIES]

        with open(self.audit_path, "w", encoding="utf-8") as handle:
            json.dump(history, handle, indent=2)

    def get_audit_history(self, limit: int = 50) -> list[dict]:
        """Return recent integrity events, newest first."""
        if not os.path.exists(self.audit_path):
            return []
        try:
            with open(self.audit_path, "r", encoding="utf-8") as handle:
                entries = json.load(handle)
                if isinstance(entries, list):
                    return entries[:limit]
        except (json.JSONDecodeError, OSError):
            pass
        return []

    # ------------------------------------------------------------------
    # Baseline creation & file management
    # ------------------------------------------------------------------

    def _is_internal_storage_file(self, abs_path: str) -> bool:
        storage_prefix = path_key(self.storage_dir) + os.sep
        target_key = path_key(abs_path)
        return target_key == path_key(self.storage_dir) or target_key.startswith(storage_prefix)

    def register_file(self, file_path: str) -> dict:
        """
        Select a file for monitoring, compute its reference SHA-256 and block hashes,
        and persist the sealed baseline entry.
        """
        abs_path = normalize_path(file_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found: {abs_path}")
        if not os.path.isfile(abs_path):
            raise ValueError(f"Path is not a regular file: {abs_path}")
        if self._is_internal_storage_file(abs_path):
            raise ValueError("Cannot monitor internal baseline database files.")

        data = self._load_baseline()
        if data["files"] and not self.is_baseline_seal_valid(data):
            raise RuntimeError(
                "Baseline seal check failed! The database appears tampered. "
                "Inspect or reset the baseline before adding new hashes."
            )

        key = path_key(abs_path)
        already_existed = key in data["files"]

        sha256_digest = compute_sha256(abs_path)
        metadata = get_file_metadata(abs_path)
        block_size, blocks = compute_block_map(abs_path)
        now = _timestamp()

        record = {
            "path": abs_path,
            "file_name": os.path.basename(abs_path),
            "sha256": sha256_digest,
            "size": metadata["size"],
            "mtime": metadata["mtime"],
            "mtime_readable": format_mtime(metadata["mtime"]),
            "block_size": block_size,
            "blocks": blocks,
            "added_at": data["files"][key]["added_at"] if already_existed else now,
            "updated_at": now,
            "last_checked": now,
            "last_status": "INTACT",
            "last_current_hash": sha256_digest,
            "last_size_delta": 0,
            "last_diagnosis": "Reference baseline established",
            "moved_to": None,
            "check_count": data["files"][key].get("check_count", 0) if already_existed else 0,
        }

        data["files"][key] = record
        self._save_baseline(data, update_seal=True)

        action = "BASELINE_UPDATED" if already_existed else "BASELINE_CREATED"
        msg = (
            f"Updated reference SHA-256 ({metadata['size']:,} bytes)"
            if already_existed
            else f"Registered file for monitoring ({metadata['size']:,} bytes)"
        )
        self._record_audit_event(
            event_type=action,
            file_path=abs_path,
            status="INTACT",
            details=msg,
            reference_hash=sha256_digest,
            current_hash=sha256_digest,
        )

        result = dict(record)
        result["was_updated"] = already_existed
        return result

    def register_directory(self, directory_path: str, recursive: bool = True) -> dict:
        """Register all eligible files inside a directory."""
        abs_dir = normalize_path(directory_path)
        if not os.path.exists(abs_dir):
            raise FileNotFoundError(f"Directory not found: {abs_dir}")
        if not os.path.isdir(abs_dir):
            raise ValueError(f"Not a directory: {abs_dir}")

        added = []
        skipped = []

        if recursive:
            for root, dirs, files in os.walk(abs_dir):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                for fname in sorted(files):
                    full_path = os.path.join(root, fname)
                    if self._is_internal_storage_file(full_path):
                        continue
                    try:
                        added.append(self.register_file(full_path))
                    except (OSError, ValueError) as exc:
                        skipped.append({"path": full_path, "reason": str(exc)})
        else:
            for fname in sorted(os.listdir(abs_dir)):
                full_path = os.path.join(abs_dir, fname)
                if not os.path.isfile(full_path) or self._is_internal_storage_file(full_path):
                    continue
                try:
                    added.append(self.register_file(full_path))
                except (OSError, ValueError) as exc:
                    skipped.append({"path": full_path, "reason": str(exc)})

        return {"directory": abs_dir, "added": added, "skipped": skipped}

    def rebaseline_file(self, file_path: str) -> dict:
        """Accept an authorized modification by updating the stored reference hash."""
        abs_path = normalize_path(file_path)
        key = path_key(abs_path)
        data = self._load_baseline()

        if key not in data["files"]:
            raise KeyError(f"File is not currently monitored: {abs_path}")

        return self.register_file(abs_path)

    def remove_file(self, file_path: str) -> bool:
        """Stop monitoring a file and remove its reference entry from the baseline."""
        abs_path = normalize_path(file_path)
        key = path_key(abs_path)
        data = self._load_baseline()

        if key not in data["files"]:
            return False

        if not self.is_baseline_seal_valid(data):
            raise RuntimeError(
                "Baseline seal check failed! Reset or inspect baseline before removing entries."
            )

        removed_entry = data["files"].pop(key)
        self._save_baseline(data, update_seal=True)

        self._record_audit_event(
            event_type="MONITORING_STOPPED",
            file_path=removed_entry["path"],
            status="REMOVED",
            details="Removed file from integrity baseline",
            reference_hash=removed_entry["sha256"],
        )
        return True

    def reset_baseline(self) -> None:
        """Clear all monitored files and initialize a fresh sealed baseline."""
        empty_data = {
            "version": "1.0",
            "created_at": _timestamp(),
            "updated_at": _timestamp(),
            "seal": "",
            "files": {},
        }
        self._save_baseline(empty_data, update_seal=True)
        self._record_audit_event(
            event_type="BASELINE_RESET",
            file_path="",
            status="RESET",
            details="Cleared all monitored files and generated a fresh database seal",
        )

    def list_monitored_files(self) -> list[dict]:
        """Return all currently tracked file records."""
        data = self._load_baseline()
        records = list(data.get("files", {}).values())
        records.sort(key=lambda item: item.get("file_name", "").lower())
        return records

    # ------------------------------------------------------------------
    # Integrity checking & tamper detection
    # ------------------------------------------------------------------

    def check_file(self, file_path: str, _shared_baseline: dict | None = None) -> dict:
        """
        Generate a fresh SHA-256 hash for a monitored file and compare it with
        the stored baseline hash to determine its integrity status.
        """
        abs_path = normalize_path(file_path)
        key = path_key(abs_path)

        standalone_call = _shared_baseline is None
        data = self._load_baseline() if standalone_call else _shared_baseline
        seal_ok = self.is_baseline_seal_valid(data)

        if key not in data["files"]:
            raise KeyError(f"File is not registered for monitoring: {abs_path}")

        entry = data["files"][key]
        tracked_keys = set(data["files"].keys())
        checked_at = _timestamp()
        ref_hash = entry["sha256"]
        ref_size = entry["size"]
        ref_block_size = entry.get("block_size", 64)
        ref_blocks = entry.get("blocks", [])

        result = {
            "path": entry["path"],
            "file_name": entry["file_name"],
            "reference_hash": ref_hash,
            "current_hash": None,
            "status": "UNKNOWN",
            "seal_valid": seal_ok,
            "reference_size": ref_size,
            "current_size": None,
            "size_delta": 0,
            "reference_mtime": entry.get("mtime_readable", ""),
            "current_mtime": None,
            "metadata_touched": False,
            "moved_to": None,
            "block_report": None,
            "diagnosis": "",
            "checked_at": checked_at,
        }

        # Case 1: File missing at original path -> check if renamed in same directory
        if not os.path.exists(entry["path"]):
            renamed_target = self._find_renamed_candidate(
                original_path=entry["path"],
                expected_sha256=ref_hash,
                expected_size=ref_size,
                tracked_keys=tracked_keys,
            )
            if renamed_target:
                result["status"] = "RENAMED"
                result["current_hash"] = ref_hash
                result["current_size"] = ref_size
                result["moved_to"] = renamed_target
                result["diagnosis"] = (
                    f"Missing at original path, but identical SHA-256 found at "
                    f"'{os.path.basename(renamed_target)}'"
                )
            else:
                result["status"] = "MISSING"
                result["diagnosis"] = "File was deleted or moved outside its parent folder"

        # Case 2: File exists -> re-hash and compare against reference SHA-256
        else:
            try:
                current_hash = compute_sha256(entry["path"])
                meta = get_file_metadata(entry["path"])
                result["current_hash"] = current_hash
                result["current_size"] = meta["size"]
                result["size_delta"] = meta["size"] - ref_size
                result["current_mtime"] = format_mtime(meta["mtime"])
                result["metadata_touched"] = abs(meta["mtime"] - entry.get("mtime", 0)) > 0.05

                if current_hash == ref_hash:
                    result["status"] = "INTACT"
                    result["block_report"] = self._intact_block_report(
                        ref_block_size, ref_blocks, ref_size
                    )
                    if result["metadata_touched"]:
                        result["diagnosis"] = (
                            "SHA-256 verified intact (file timestamp changed, 0 bytes altered)"
                        )
                    else:
                        result["diagnosis"] = "SHA-256 hash matches reference value"
                else:
                    result["status"] = "MODIFIED"
                    block_report = compare_block_maps(
                        file_path=entry["path"],
                        ref_block_size=ref_block_size,
                        ref_blocks=ref_blocks,
                        ref_size=ref_size,
                    )
                    result["block_report"] = block_report
                    result["diagnosis"] = block_report["diagnosis"]

            except PermissionError:
                result["status"] = "ACCESS_DENIED"
                result["diagnosis"] = "Permission denied while trying to read file"
            except OSError as exc:
                result["status"] = "ERROR"
                result["diagnosis"] = f"OS read error: {exc}"

        if not seal_ok:
            result["diagnosis"] = (
                "CRITICAL: Baseline database seal is invalid (baseline.json was altered!) | "
                + result["diagnosis"]
            )

        # Update runtime check stats in baseline without touching the cryptographic seal
        previous_status = entry.get("last_status", "INTACT")
        entry["last_checked"] = checked_at
        entry["last_status"] = result["status"]
        entry["last_current_hash"] = result["current_hash"]
        entry["last_size_delta"] = result["size_delta"]
        entry["last_diagnosis"] = result["diagnosis"]
        entry["last_block_report"] = result["block_report"]
        entry["moved_to"] = result["moved_to"]
        entry["check_count"] = entry.get("check_count", 0) + 1

        if standalone_call:
            self._save_baseline(data, update_seal=False)

        # Log state transitions, alerts, or standalone manual checks
        should_log = (
            standalone_call
            or result["status"] != "INTACT"
            or previous_status != result["status"]
            or not seal_ok
        )
        if should_log:
            event_label = "INTEGRITY_ALERT" if result["status"] != "INTACT" or not seal_ok else "FILE_VERIFIED"
            self._record_audit_event(
                event_type=event_label,
                file_path=entry["path"],
                status=result["status"],
                details=result["diagnosis"],
                reference_hash=ref_hash,
                current_hash=result["current_hash"] or "",
            )

        return result

    def check_all(self) -> dict:
        """Check every monitored file and return aggregated summary + individual results."""
        data = self._load_baseline()
        seal_ok = self.is_baseline_seal_valid(data)
        results = []

        counts = {
            "total": len(data["files"]),
            "intact": 0,
            "modified": 0,
            "renamed": 0,
            "missing": 0,
            "errors": 0,
        }

        for entry in list(data["files"].values()):
            res = self.check_file(entry["path"], _shared_baseline=data)
            results.append(res)
            status = res["status"]
            if status == "INTACT":
                counts["intact"] += 1
            elif status == "MODIFIED":
                counts["modified"] += 1
            elif status == "RENAMED":
                counts["renamed"] += 1
            elif status == "MISSING":
                counts["missing"] += 1
            else:
                counts["errors"] += 1

        if data["files"]:
            self._save_baseline(data, update_seal=False)

        results.sort(key=lambda item: (item["status"] == "INTACT", item["file_name"].lower()))

        return {
            "checked_at": _timestamp(),
            "seal_valid": seal_ok,
            "counts": counts,
            "results": results,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _intact_block_report(block_size: int, ref_blocks: list[str], ref_size: int) -> dict:
        segments = []
        for idx in range(len(ref_blocks)):
            segments.append(
                {
                    "index": idx + 1,
                    "state": "intact",
                    "start_byte": idx * block_size,
                    "end_byte": min((idx + 1) * block_size, ref_size),
                }
            )
        return {
            "block_size": block_size,
            "total_blocks": len(ref_blocks),
            "modified_blocks": 0,
            "appended_blocks": 0,
            "truncated_blocks": 0,
            "segments": segments,
            "diagnosis": "All blocks match stored SHA-256 digests",
        }

    @staticmethod
    def _find_renamed_candidate(
        original_path: str,
        expected_sha256: str,
        expected_size: int,
        tracked_keys: set[str],
    ) -> str | None:
        """
        Look in the parent folder for an untracked file of identical byte size
        whose SHA-256 matches the missing file's reference hash.
        Checking os.path.getsize() first avoids hashing unrelated large files.
        """
        parent_dir = os.path.dirname(original_path)
        if not parent_dir or not os.path.isdir(parent_dir):
            return None

        try:
            entries = os.listdir(parent_dir)
        except OSError:
            return None

        for name in entries:
            candidate = normalize_path(os.path.join(parent_dir, name))
            if path_key(candidate) in tracked_keys:
                continue
            if not os.path.isfile(candidate):
                continue
            try:
                if os.path.getsize(candidate) != expected_size:
                    continue
                if compute_sha256(candidate) == expected_sha256:
                    return candidate
            except OSError:
                continue

        return None

