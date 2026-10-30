"""
Integrity Monitor - Cryptographic File Tamper Detection Tool
Built with Python's hashlib and os standard libraries.

Usage:
  Interactive Mode : python main.py
  CLI Subcommands  : python main.py add <file>
                     python main.py check [file]
                     python main.py watch [--interval 2]
                     python main.py rebaseline <file>
                     python main.py remove <file>
                     python main.py list
                     python main.py history
                     python main.py ui [--port 8765]
                     python main.py demo
"""

import argparse
import os
import sys
import time

from core.monitor import IntegrityMonitor
from demo_sandbox import run_demo
from ui.cli_display import (
    Style,
    colorize,
    print_audit_history,
    print_banner,
    print_check_result,
    print_monitored_table,
    print_registration_card,
    print_summary_report,
    prompt_select_monitored_file,
    prompt_user_for_file,
    status_badge,
)
from ui.dashboard import start_dashboard


def run_live_watch(monitor: IntegrityMonitor, interval: float = 2.0) -> None:
    """Continuously re-hash monitored files and alert whenever status changes."""
    records = monitor.list_monitored_files()
    if not records:
        print("\n  Add at least one file before starting Live Watch Mode.")
        return

    print(
        f"\n  {colorize('LIVE WATCH ACTIVE', Style.BOLD, Style.BLUE)} "
        f"(scanning {len(records)} file(s) every {interval:.1f}s - press Ctrl+C to stop)\n"
    )

    last_seen: dict[str, tuple[str, str | None]] = {}
    try:
        while True:
            report = monitor.check_all()
            if not report["seal_valid"] and ("__seal__", "") not in last_seen:
                print(
                    f"  [{report['checked_at']}] "
                    + colorize("CRITICAL: Baseline database seal broken!", Style.BOLD, Style.RED)
                )
                last_seen["__seal__"] = ("BROKEN", None)

            for res in report["results"]:
                state_pair = (res["status"], res["current_hash"])
                prev_pair = last_seen.get(res["path"])

                if prev_pair is None:
                    # Initial snapshot printout
                    print(
                        f"  [{res['checked_at']}] {res['file_name']:<28} -> "
                        f"{status_badge(res['status'])}"
                    )
                elif prev_pair != state_pair:
                    # State or hash changed since previous poll!
                    print(
                        "\n  "
                        + colorize(f"CHANGE DETECTED AT {res['checked_at']}", Style.BOLD, Style.AMBER)
                    )
                    print_check_result(res)

                last_seen[res["path"]] = state_pair

            time.sleep(max(0.5, interval))
    except KeyboardInterrupt:
        print("\n  Stopped Live Watch Mode.")


def run_interactive_menu(monitor: IntegrityMonitor) -> None:
    """Interactive terminal loop for selecting, checking, and managing monitored files."""
    while True:
        records = monitor.list_monitored_files()
        seal_ok = monitor.is_baseline_seal_valid()
        print_banner(tracked_count=len(records), seal_valid=seal_ok)

        print("    [1] Select a File to Monitor      (Generate reference SHA-256)")
        print("    [2] Monitor an Entire Folder      (Register all files in directory)")
        print("    [3] Check Single File Integrity   (Re-hash & compare with baseline)")
        print("    [4] Check All Monitored Files     (Full integrity verification scan)")
        print("    [5] Live Watch Mode               (Continuous real-time monitoring)")
        print("    [6] Accept Authorized Change      (Update stored SHA-256 hash)")
        print("    [7] Remove File from Monitoring   (Stop tracking a file)")
        print("    [8] View Monitored Files & Audit  (Baseline list + event history)")
        print("    [9] Launch Local Web Dashboard    (Visual browser UI)")
        print("    [D] Run Automated Tamper Demo     (Simulate 5 attack scenarios)")
        print("    [0] Exit")

        choice = input("\n  Choose an option: ").strip().upper()

        try:
            if choice == "1":
                chosen = prompt_user_for_file(allow_directory=False)
                if chosen:
                    rec = monitor.register_file(chosen)
                    print_registration_card(rec)

            elif choice == "2":
                chosen_dir = prompt_user_for_file(allow_directory=True)
                if chosen_dir:
                    summary = monitor.register_directory(chosen_dir, recursive=True)
                    print(
                        f"\n  Registered {colorize(str(len(summary['added'])), Style.BOLD, Style.TEAL)} "
                        f"file(s) from {summary['directory']}"
                    )
                    if summary["skipped"]:
                        print(f"  Skipped {len(summary['skipped'])} unreadable item(s).")

            elif choice == "3":
                target = prompt_select_monitored_file(
                    records, "Select file to verify"
                )
                if target:
                    result = monitor.check_file(target)
                    print_check_result(result)

            elif choice == "4":
                report = monitor.check_all()
                print_summary_report(report)

            elif choice == "5":
                run_live_watch(monitor, interval=2.0)

            elif choice == "6":
                target = prompt_select_monitored_file(
                    records, "Select file whose current state you want to approve"
                )
                if target:
                    updated = monitor.rebaseline_file(target)
                    print_registration_card(updated)

            elif choice == "7":
                target = prompt_select_monitored_file(
                    records, "Select file to stop monitoring"
                )
                if target:
                    if monitor.remove_file(target):
                        print(f"\n  Removed from baseline: {target}")
                    else:
                        print("\n  File was not found in the baseline.")

            elif choice == "8":
                print_monitored_table(records)
                print_audit_history(monitor.get_audit_history(limit=15))

            elif choice == "9":
                start_dashboard(monitor, open_browser=True)

            elif choice == "D":
                run_demo(pause_seconds=0.3, cleanup=True)

            elif choice in ("0", "Q", "EXIT"):
                print("\n  Exiting Integrity Monitor.\n")
                break

            else:
                print("\n  Invalid option. Please enter 0-9 or D.")

        except (FileNotFoundError, KeyError, ValueError, RuntimeError, OSError) as exc:
            print("\n  " + colorize(f"Error: {exc}", Style.BOLD, Style.RED))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cryptographic File Integrity Monitor using SHA-256 (hashlib & os)."
    )
    sub = parser.add_subparsers(dest="command")

    p_add = sub.add_parser("add", help="Select a file or folder and generate its reference SHA-256")
    p_add.add_argument("path", nargs="?", help="File or directory path (omit to open picker)")

    p_check = sub.add_parser("check", help="Re-hash and verify one file or all monitored files")
    p_check.add_argument("path", nargs="?", help="Specific monitored file path (omit to check all)")

    p_watch = sub.add_parser("watch", help="Continuously check monitored files for changes")
    p_watch.add_argument("--interval", type=float, default=2.0, help="Seconds between scans (default: 2.0)")

    p_rebase = sub.add_parser("rebaseline", help="Update reference SHA-256 after an authorized edit")
    p_rebase.add_argument("path", help="Monitored file path")

    p_remove = sub.add_parser("remove", help="Stop monitoring a file")
    p_remove.add_argument("path", help="Monitored file path")

    sub.add_parser("list", help="List all currently monitored files and reference hashes")

    p_hist = sub.add_parser("history", help="Display recent integrity audit events")
    p_hist.add_argument("--limit", type=int, default=20, help="Number of entries to show")

    sub.add_parser("reset", help="Clear all monitored files and reset baseline database")

    p_ui = sub.add_parser("ui", help="Launch the local browser dashboard")
    p_ui.add_argument("--port", type=int, default=8765, help="Local port (default: 8765)")
    p_ui.add_argument("--no-browser", action="store_true", help="Do not auto-open browser window")

    sub.add_parser("demo", help="Run automated sandbox demonstration of tamper scenarios")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    monitor = IntegrityMonitor()

    if not args.command:
        try:
            run_interactive_menu(monitor)
        except KeyboardInterrupt:
            print("\n\n  Interrupted. Exiting.\n")
        return 0

    try:
        if args.command == "add":
            target = args.path or prompt_user_for_file(allow_directory=False)
            if not target:
                print("No file selected.")
                return 1
            cleaned = target.strip().strip('"').strip("'")
            if os.path.isdir(cleaned):
                summary = monitor.register_directory(cleaned, recursive=True)
                print(
                    f"Registered {len(summary['added'])} file(s) from {summary['directory']}"
                )
            else:
                rec = monitor.register_file(target)
                print_registration_card(rec)
            return 0

        if args.command == "check":
            if args.path:
                res = monitor.check_file(args.path)
                print_check_result(res)
                return 0 if res["status"] == "INTACT" and res["seal_valid"] else 1
            report = monitor.check_all()
            print_summary_report(report)
            all_ok = (
                report["seal_valid"]
                and report["counts"]["modified"] == 0
                and report["counts"]["missing"] == 0
                and report["counts"]["renamed"] == 0
            )
            return 0 if all_ok else 1

        if args.command == "watch":
            run_live_watch(monitor, interval=args.interval)
            return 0

        if args.command == "rebaseline":
            rec = monitor.rebaseline_file(args.path)
            print_registration_card(rec)
            return 0

        if args.command == "remove":
            if monitor.remove_file(args.path):
                print(f"Stopped monitoring: {args.path}")
                return 0
            print(f"File not in baseline: {args.path}")
            return 1

        if args.command == "list":
            print_monitored_table(monitor.list_monitored_files())
            return 0

        if args.command == "history":
            print_audit_history(monitor.get_audit_history(limit=args.limit))
            return 0

        if args.command == "reset":
            monitor.reset_baseline()
            print("Baseline cleared and cryptographic seal reset.")
            return 0

        if args.command == "ui":
            start_dashboard(monitor, port=args.port, open_browser=not args.no_browser)
            return 0

        if args.command == "demo":
            run_demo(pause_seconds=0.2, cleanup=True)
            return 0

    except (FileNotFoundError, KeyError, ValueError, RuntimeError, OSError) as exc:
        print(colorize(f"Error: {exc}", Style.BOLD, Style.RED), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
