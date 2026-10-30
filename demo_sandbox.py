"""
Self-running demonstration of the File Integrity Monitor.

Creates a temporary sandbox folder, registers sample files, verifies their
initial SHA-256 hashes, and walks through five realistic tampering scenarios
(in-place edit, data append, file rename, deletion, and baseline DB tampering).
"""

import json
import os
import shutil
import time

from core.monitor import IntegrityMonitor
from ui.cli_display import (
    Style,
    colorize,
    print_check_result,
    print_registration_card,
    print_summary_report,
)


def _step_header(step_num: int, title: str) -> None:
    print("\n" + colorize("=" * 76, Style.BLUE))
    print(colorize(f"  DEMO STEP {step_num}: {title}", Style.BOLD, Style.BLUE))
    print(colorize("=" * 76, Style.BLUE))


def run_demo(pause_seconds: float = 0.0, cleanup: bool = True) -> None:
    project_root = os.path.dirname(os.path.abspath(__file__))
    sandbox_dir = os.path.join(project_root, "demo_workspace")
    files_dir = os.path.join(sandbox_dir, "sample_files")
    db_dir = os.path.join(sandbox_dir, "db")

    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir)
    os.makedirs(files_dir, exist_ok=True)

    config_path = os.path.join(files_dir, "server_config.ini")
    ledger_path = os.path.join(files_dir, "club_treasury.csv")
    notes_path = os.path.join(files_dir, "meeting_minutes.txt")
    keys_path = os.path.join(files_dir, "access_tokens.key")

    # Populate sample files (server_config.ini > 256 bytes so multiple 64-byte blocks form)
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(
            "[network]\n"
            "host = 10.20.0.15\n"
            "port = 8443\n"
            "tls_required = true\n\n"
            "[security]\n"
            "allow_guest_admin = false\n"
            "max_login_attempts = 3\n"
            "session_timeout_minutes = 15\n\n"
            "[logging]\n"
            "audit_level = strict\n"
            "archive_dir = /var/log/ieee_portal\n"
            "retain_days = 90\n"
        )

    # Pad club_treasury.csv to an exact multiple of 64 bytes (128 bytes) so an append cleanly adds '+'
    base_csv = (
        "id,member,role,amount_inr\n"
        "101,Aarav,Treasurer,2500\n"
        "102,Diya,Secretary,1800\n"
    )
    padded_csv = base_csv + ("#" * max(0, 127 - len(base_csv))) + "\n"
    with open(ledger_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(padded_csv)

    with open(notes_path, "w", encoding="utf-8") as f:
        f.write("IEEE Student Branch - Weekly Sync\nAgenda: Finalize workshop kits and speakers.\n")

    with open(keys_path, "w", encoding="utf-8") as f:
        f.write("TOKEN_PRIMARY=9f86d081884c7d659a2feaa0c55ad015\n")

    try:
        monitor = IntegrityMonitor(storage_dir=db_dir)

        _step_header(1, "Select Files & Generate Reference SHA-256 Baselines")
        for sample in (config_path, ledger_path, notes_path, keys_path):
            rec = monitor.register_file(sample)
            print_registration_card(rec)
        if pause_seconds:
            time.sleep(pause_seconds)

        _step_header(2, "Initial Verification Scan (No Changes Made Yet)")
        initial_report = monitor.check_all()
        print_summary_report(initial_report)
        if pause_seconds:
            time.sleep(pause_seconds)

        _step_header(3, "Simulate Unauthorized File Modifications, Rename & Deletion")
        print("  -> Flipping 'allow_guest_admin = false' to 'true' inside server_config.ini...")
        with open(config_path, "r", encoding="utf-8") as f:
            cfg_text = f.read()
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(cfg_text.replace("allow_guest_admin = false", "allow_guest_admin = true "))

        print("  -> Appending an unauthorized transaction row to club_treasury.csv...")
        with open(ledger_path, "a", encoding="utf-8", newline="\n") as f:
            f.write("999,Unknown,External,50000\n")

        renamed_notes = os.path.join(files_dir, "meeting_minutes_archived.txt")
        print("  -> Renaming meeting_minutes.txt -> meeting_minutes_archived.txt...")
        os.rename(notes_path, renamed_notes)

        print("  -> Deleting access_tokens.key...")
        os.remove(keys_path)

        tamper_report = monitor.check_all()
        print_summary_report(tamper_report)
        if pause_seconds:
            time.sleep(pause_seconds)

        _step_header(4, "Simulate Attacker Editing baseline.json Directly to Hide Tracks")
        print("  -> Overwriting stored SHA-256 inside baseline.json with the tampered file's hash...")
        with open(monitor.baseline_path, "r", encoding="utf-8") as f:
            raw_db = json.load(f)
        for key, entry in raw_db["files"].items():
            if entry["file_name"] == "server_config.ini":
                entry["sha256"] = entry["last_current_hash"]
        with open(monitor.baseline_path, "w", encoding="utf-8") as f:
            json.dump(raw_db, f, indent=2)

        seal_test_result = monitor.check_file(config_path)
        print_check_result(seal_test_result)

        print(
            "\n  "
            + colorize(
                "Demo finished! Even though the fake hash matched, the Baseline Seal caught the database edit.",
                Style.BOLD,
                Style.TEAL,
            )
        )

    finally:
        if cleanup and os.path.exists(sandbox_dir):
            shutil.rmtree(sandbox_dir)
            print("  Cleaned up temporary demo_workspace/ directory.\n")


if __name__ == "__main__":
    run_demo(pause_seconds=0.4, cleanup=True)

