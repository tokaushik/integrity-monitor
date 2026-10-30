"""
Terminal presentation, interactive file selection, and formatting helpers.
"""

import os
import subprocess
import sys


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")
    return True


USE_COLOR = _supports_color()


class Style:
    RESET = "\033[0m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""
    BLUE = "\033[94m" if USE_COLOR else ""
    TEAL = "\033[36m" if USE_COLOR else ""
    RED = "\033[91m" if USE_COLOR else ""
    AMBER = "\033[33m" if USE_COLOR else ""


def colorize(text: str, *codes: str) -> str:
    if not USE_COLOR or not codes:
        return text
    return "".join(codes) + str(text) + Style.RESET


def group_sha256(hex_digest: str | None) -> str:
    """Format a 64-char SHA-256 hex string into eight readable 8-char words."""
    if not hex_digest:
        return "UNAVAILABLE"
    clean = hex_digest.strip()
    if len(clean) != 64:
        return clean
    return " ".join(clean[i : i + 8] for i in range(0, 64, 8))


def status_badge(status: str) -> str:
    status_upper = (status or "UNKNOWN").upper()
    if status_upper == "INTACT":
        return colorize("[ VERIFIED : INTACT ]", Style.BOLD, Style.TEAL)
    if status_upper == "MODIFIED":
        return colorize("[ ALERT : HASH MISMATCH ]", Style.BOLD, Style.RED)
    if status_upper == "RENAMED":
        return colorize("[ NOTICE : MOVED / RENAMED ]", Style.BOLD, Style.AMBER)
    if status_upper == "MISSING":
        return colorize("[ ALERT : FILE MISSING ]", Style.BOLD, Style.RED)
    return colorize(f"[ {status_upper} ]", Style.BOLD, Style.AMBER)


def format_bytes(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "N/A"
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB ({num_bytes:,} B)"
    return f"{num_bytes / (1024 * 1024):.2f} MB ({num_bytes:,} B)"


def format_size_delta(delta: int) -> str:
    if delta == 0:
        return "no size change"
    if delta > 0:
        return colorize(f"+{delta:,} B", Style.AMBER)
    return colorize(f"{delta:,} B", Style.RED)


def render_block_strip(block_report: dict | None) -> str:
    """Render numbered block statuses (e.g. B01:ok B02:DIFF B03:ok)."""
    if not block_report:
        return "N/A"
    segments = block_report.get("segments", [])
    if not segments:
        return "[empty file - 0 blocks]"

    tokens = []
    for seg in segments:
        idx_str = f"B{seg['index']:02d}"
        state = seg.get("state")
        if state == "intact":
            tokens.append(colorize(f"{idx_str}:ok", Style.DIM))
        elif state == "modified":
            tokens.append(colorize(f"{idx_str}:DIFF", Style.BOLD, Style.RED))
        elif state == "appended":
            tokens.append(colorize(f"{idx_str}:+NEW", Style.BOLD, Style.AMBER))
        elif state == "truncated":
            tokens.append(colorize(f"{idx_str}:CUT", Style.BOLD, Style.RED))
        else:
            tokens.append(f"{idx_str}:?")

    block_sz = block_report.get("block_size", 0)
    joined = "  ".join(tokens)
    return f"{joined}  (~{block_sz:,} B/block)"


def print_banner(tracked_count: int, seal_valid: bool) -> None:
    rule = "-" * 76
    seal_label = (
        colorize("SEALED & VALID", Style.BOLD, Style.TEAL)
        if seal_valid
        else colorize("SEAL BROKEN (TAMPERED)", Style.BOLD, Style.RED)
    )
    print("\n" + colorize(rule, Style.BLUE))
    print(
        "  "
        + colorize("FILE INTEGRITY WORKBENCH", Style.BOLD, Style.BLUE)
        + "  //  SHA-256 Cryptographic Inspection Tool"
    )
    print(f"  Tracked Registry: {tracked_count} file(s)   |   Baseline Seal: {seal_label}")
    print(colorize(rule, Style.BLUE))


def print_registration_card(record: dict) -> None:
    heading = (
        "BASELINE UPDATED (AUTHORIZED CHANGE ACCEPTED)"
        if record.get("was_updated")
        else "REFERENCE SHA-256 BASELINE RECORDED"
    )
    border = "-" * 76
    print("\n" + border)
    print("  " + colorize(heading, Style.BOLD, Style.BLUE))
    print(border)
    print(f"  File         : {colorize(record['file_name'], Style.BOLD)}")
    print(f"  Location     : {record['path']}")
    print(f"  Size         : {format_bytes(record['size'])} ({len(record.get('blocks', []))} block(s) @ {record['block_size']:,} B)")
    print(f"  Modified At  : {record['mtime_readable']}")
    print(f"  Ref SHA-256  : {colorize(group_sha256(record['sha256']), Style.TEAL)}")
    print(f"  State        : {colorize('REGISTERED IN SEALED BASELINE', Style.BOLD, Style.TEAL)}")
    print(border)


def print_check_result(result: dict) -> None:
    border = "-" * 76
    status = result["status"]
    seal_ok = result.get("seal_valid", True)
    badge_str = (
        colorize("[ UNTRUSTED : BASELINE SEAL BROKEN ]", Style.BOLD, Style.RED)
        if not seal_ok and status == "INTACT"
        else status_badge(status)
    )

    print("\n" + border)
    print(f"  File         : {colorize(result['file_name'], Style.BOLD)}   {badge_str}")
    print(f"  Location     : {result['path']}")

    if not seal_ok:
        print(
            "  Seal Alert   : "
            + colorize(
                "CRITICAL - baseline.json failed seal verification (external edit detected!)",
                Style.BOLD,
                Style.RED,
            )
        )

    print(f"  Stored Hash  : {group_sha256(result['reference_hash'])}")
    if result["current_hash"]:
        tone = Style.TEAL if (seal_ok and status in ("INTACT", "RENAMED")) else Style.RED
        print(f"  Current Hash : {colorize(group_sha256(result['current_hash']), tone)}")
    else:
        print(f"  Current Hash : {colorize('UNAVAILABLE (file missing at registered path)', Style.RED)}")

    if status == "RENAMED" and result.get("moved_to"):
        print(f"  Relocated To : {colorize(result['moved_to'], Style.BOLD, Style.AMBER)}")

    if result["current_size"] is not None:
        print(
            f"  Byte Size    : {format_bytes(result['reference_size'])} -> "
            f"{format_bytes(result['current_size'])} ({format_size_delta(result['size_delta'])})"
        )

    if result.get("current_mtime"):
        print(f"  Timestamp    : {result['current_mtime']}")

    if result.get("block_report") and status == "MODIFIED":
        print(f"  Block Matrix : {render_block_strip(result['block_report'])}")

    print(f"  Finding      : {result['diagnosis']}")
    print(border)


def print_summary_report(report: dict) -> None:
    counts = report["counts"]
    results = report["results"]

    if counts["total"] == 0:
        print("\n  No files are currently registered in the baseline.")
        return

    for res in results:
        print_check_result(res)

    print("\n" + "=" * 76)
    print(f"  INSPECTION SUMMARY  ({report['checked_at']})")
    print(
        f"  Total: {counts['total']}   |   "
        + colorize(f"Verified: {counts['intact']}", Style.TEAL)
        + "   |   "
        + colorize(f"Modified: {counts['modified']}", Style.RED if counts["modified"] else Style.DIM)
        + "   |   "
        + colorize(f"Renamed: {counts['renamed']}", Style.AMBER if counts["renamed"] else Style.DIM)
        + "   |   "
        + colorize(f"Missing: {counts['missing']}", Style.RED if counts["missing"] else Style.DIM)
    )
    if not report["seal_valid"]:
        print(
            "  "
            + colorize(
                "WARNING: Baseline database seal is INVALID. Stored hashes may have been altered.",
                Style.BOLD,
                Style.RED,
            )
        )
    print("=" * 76)


def print_monitored_table(records: list[dict]) -> None:
    if not records:
        print("\n  No files are currently monitored.")
        return

    print(f"\n  Registered Baseline Ledger ({len(records)}):")
    print("  " + "-" * 74)
    for idx, rec in enumerate(records, start=1):
        short_hash = rec["sha256"][:16] + "..."
        last_stat = rec.get("last_status", "INTACT")
        print(
            f"  [{idx:2d}] {colorize(rec['file_name'], Style.BOLD):<28} "
            f"{status_badge(last_stat)}  Ref: {short_hash}"
        )
        print(f"       {rec['path']}")
    print("  " + "-" * 74)


def print_audit_history(events: list[dict]) -> None:
    if not events:
        print("\n  Audit log is currently empty.")
        return

    print(f"\n  Audit Event Log (latest {len(events)}):")
    print("  " + "-" * 74)
    for ev in events:
        ts = ev.get("timestamp", "")
        kind = ev.get("event", "")
        fname = ev.get("file_name", "-")
        details = ev.get("details", "")
        tone = Style.RED if kind == "INTEGRITY_ALERT" else Style.BLUE
        print(f"  [{ts}] {colorize(kind, Style.BOLD, tone)} :: {fname}")
        print(f"       {details}")
    print("  " + "-" * 74)


# ----------------------------------------------------------------------
# Native File / Folder Selection Helpers
# ----------------------------------------------------------------------

def open_native_dialog(select_folder: bool = False) -> str:
    """
    Launch a native OS file/folder dialog in an isolated Python subprocess so
    Tkinter runs on a clean main thread and comes to the foreground.
    """
    if select_folder:
        dialog_call = 'filedialog.askdirectory(title="Select Folder to Monitor")'
    else:
        dialog_call = 'filedialog.askopenfilename(title="Select File to Monitor")'

    helper_code = (
        "import tkinter as tk\n"
        "from tkinter import filedialog\n"
        "root = tk.Tk()\n"
        "root.withdraw()\n"
        "try:\n"
        "    root.attributes('-topmost', True)\n"
        "except Exception:\n"
        "    pass\n"
        f"chosen = {dialog_call}\n"
        "root.destroy()\n"
        "if chosen:\n"
        "    print(chosen)\n"
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", helper_code],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if completed.returncode == 0:
            return completed.stdout.strip()
    except Exception:
        pass
    return ""


def prompt_user_for_file(allow_directory: bool = False) -> str:
    """Interactive helper letting the user pick via native dialog, folder list, or path."""
    if allow_directory:
        print("\n  Select folder method:")
        print("    [B] Open Folder Browser dialog")
        print("    [P] Enter folder path manually")
        choice = input("  Choice [B/P] (Enter = B): ").strip().upper() or "B"
        if choice == "B":
            print("  Opening folder selection window...")
            selected = open_native_dialog(select_folder=True)
            if selected:
                return selected
            print("  Dialog closed without selection. Enter path manually below.")
        return input("  Folder path: ").strip()

    print("\n  Select file method:")
    print("    [B] Open File Browser dialog (GUI)")
    print("    [L] Choose from current working directory")
    print("    [P] Type or paste file path")
    choice = input("  Choice [B/L/P] (Enter = B): ").strip().upper() or "B"

    if choice == "B":
        print("  Opening file selection window...")
        selected = open_native_dialog(select_folder=False)
        if selected:
            return selected
        print("  Dialog closed without selection. Enter path manually below.")
        return input("  File path: ").strip()

    if choice == "L":
        cwd = os.getcwd()
        candidates = [
            f
            for f in sorted(os.listdir(cwd))
            if os.path.isfile(os.path.join(cwd, f)) and not f.startswith(".")
        ]
        if not candidates:
            print("  No regular files found in current directory.")
            return input("  File path: ").strip()

        print(f"\n  Files in {cwd}:")
        for idx, name in enumerate(candidates, start=1):
            sz = os.path.getsize(os.path.join(cwd, name))
            print(f"    [{idx:2d}] {name:<32} ({format_bytes(sz)})")
        raw = input("  File number (or path): ").strip()
        if raw.isdigit():
            pos = int(raw) - 1
            if 0 <= pos < len(candidates):
                return os.path.join(cwd, candidates[pos])
        return raw

    return input("  File path: ").strip()


def prompt_select_monitored_file(records: list[dict], action_prompt: str) -> str:
    if not records:
        print("\n  No files are currently being monitored.")
        return ""

    print_monitored_table(records)
    raw = input(f"  {action_prompt} (1-{len(records)}, or path): ").strip()
    if not raw:
        return ""
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(records):
            return records[idx]["path"]
        print("  Invalid selection number.")
        return ""
    return raw
