"""
Tamper-evident seal for the baseline database itself.

If someone modifies a monitored file and also edits baseline.json in a text editor
to replace the stored reference hash, the baseline seal verification will fail.
"""

import hashlib
import json
import os


def get_or_create_seal_key(storage_dir: str) -> str:
    """
    Load the local 256-bit secret key used to sign baseline records,
    creating one with os.urandom() on first run.
    """
    os.makedirs(storage_dir, exist_ok=True)
    key_path = os.path.join(storage_dir, ".seal_key")

    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as key_file:
            existing = key_file.read().strip()
            if len(existing) >= 32:
                return existing

    fresh_key = os.urandom(32).hex()
    with open(key_path, "w", encoding="utf-8") as key_file:
        key_file.write(fresh_key)
    return fresh_key


def compute_baseline_seal(files_dict: dict, secret_key: str) -> str:
    """
    Compute a keyed SHA-256 seal over the canonicalized baseline file entries.
    Only immutable baseline fields (path, sha256, size, block_size, blocks) are sealed
    so verify-only metadata or formatting whitespace cannot bypass verification.
    """
    protected_payload = {}
    for key in sorted(files_dict.keys()):
        entry = files_dict[key]
        protected_payload[key] = {
            "path": entry.get("path", ""),
            "sha256": entry.get("sha256", ""),
            "size": entry.get("size", 0),
            "block_size": entry.get("block_size", 0),
            "blocks": entry.get("blocks", []),
        }

    canonical_json = json.dumps(protected_payload, sort_keys=True, separators=(",", ":"))
    material = f"{secret_key}:{canonical_json}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_baseline_seal(files_dict: dict, stored_seal: str, secret_key: str) -> bool:
    """Verify that the baseline records match the stored cryptographic seal."""
    if not stored_seal:
        return False
    expected_seal = compute_baseline_seal(files_dict, secret_key)
    return expected_seal == stored_seal

