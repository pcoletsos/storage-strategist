import os
import sys
import time
import json
import stat
import shutil
import sqlite3
import argparse
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path

DEFAULT_TARGET_DIR = r"F:\Aloha"
DEFAULT_DB_PATH = "media_inventory.db"
DEFAULT_LEDGER_PATH = "corrupted_media_ledger.db"
DEFAULT_QUARANTINE_DIR = r"F:\Aloha\.quarantine_corrupted"
DEFAULT_REPORT_PATH = "corrupted_media_quarantine_report.json"

VIDEO_EXTENSIONS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".m4v"}
FILE_ATTRIBUTE_NORMAL = 0x80


def get_ffprobe_path() -> str:
    """Locates ffprobe binary from static-ffmpeg or system PATH."""
    try:
        import static_ffmpeg
        paths = static_ffmpeg.run.get_or_fetch_platform_executables_else_raise()
        if "ffprobe" in paths:
            return paths["ffprobe"]
    except Exception:
        pass

    found = shutil_which("ffprobe")
    if found:
        return found

    candidates = [
        r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe",
        r"C:\ffmpeg\bin\ffprobe.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "ffprobe"


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


def clear_readonly(file_path: str) -> None:
    """Clears read-only file attributes using Windows kernel32 and os.chmod."""
    try:
        norm = to_extended_path(file_path)
        if os.path.exists(norm):
            os.chmod(norm, stat.S_IWRITE | stat.S_IREAD)
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(norm, FILE_ATTRIBUTE_NORMAL)
    except Exception:
        pass


def is_game_path(file_path: str) -> bool:
    """Checks whether path resides within isolated Games directory."""
    norm = file_path.replace("/", "\\")
    return "\\Aloha\\Games\\" in norm or norm.endswith("\\Aloha\\Games") or "\\Games\\" in norm


def init_ledger(ledger_path: str) -> sqlite3.Connection:
    """Initializes transactional SQLite ledger with WAL mode and schema."""
    conn = sqlite3.connect(ledger_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS corrupted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT UNIQUE NOT NULL,
                quarantine_path TEXT UNIQUE NOT NULL,
                file_size INTEGER NOT NULL,
                error_class TEXT NOT NULL,
                error_detail TEXT,
                original_mtime REAL,
                quarantined_at TEXT NOT NULL,
                status TEXT NOT NULL
            );
        """)
    return conn


def probe_file(file_path: str, ffprobe_bin: str) -> Tuple[bool, str, str]:
    """
    Probes media container with ffprobe to determine integrity.
    Returns (is_valid, error_class, error_detail).
    """
    norm_path = to_extended_path(file_path)
    if not os.path.exists(norm_path):
        return False, "file_missing", "File does not exist on disk"

    cmd = [
        ffprobe_bin,
        "-v", "error",
        "-show_format",
        "-show_streams",
        "-of", "json",
        file_path
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "probe_timeout", "ffprobe timed out after 30 seconds"
    except Exception as e:
        return False, "probe_exec_error", str(e)

    stderr = res.stderr.strip()
    stderr_lower = stderr.lower()

    if "moov atom not found" in stderr_lower:
        return False, "truncated_mp4_missing_moov", stderr
    if "ebml header parsing failed" in stderr_lower or "invalid as first byte of an ebml" in stderr_lower:
        return False, "corrupted_ebml_header", stderr
    if "invalid data found when processing input" in stderr_lower:
        return False, "invalid_container_data", stderr
    if res.returncode != 0:
        clean_err = stderr.replace("\n", " ")[:200] if stderr else f"exit code {res.returncode}"
        return False, "unparseable_container", clean_err

    # Parse JSON stdout to ensure format and streams are present
    try:
        data = json.loads(res.stdout)
        streams = data.get("streams", [])
        v_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
        fmt = data.get("format", {})
        if not v_stream and not streams:
            return False, "empty_container_no_streams", "Container contains no stream descriptors"
        dur = float(fmt.get("duration", 0.0) or 0.0)
        if dur <= 0.0 and v_stream and float(v_stream.get("duration", 0.0) or 0.0) <= 0.0:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in VIDEO_EXTENSIONS:
                return False, "zero_duration_video", "Video stream duration is zero or unreadable"
    except Exception as e:
        return False, "json_parse_error", f"Failed to parse ffprobe json output: {e}"

    return True, "valid", ""


def find_corrupted_candidates(
    target_dir: str = DEFAULT_TARGET_DIR,
    db_path: Optional[str] = DEFAULT_DB_PATH,
    ffprobe_bin: Optional[str] = None,
    check_all: bool = False,
) -> List[Dict[str, Any]]:
    """Discovers and confirms corrupted media files via ffprobe container analysis."""
    if not ffprobe_bin:
        ffprobe_bin = get_ffprobe_path()

    candidate_paths: List[Dict[str, Any]] = []

    if db_path and os.path.exists(db_path) and not check_all:
        print(f"[*] Querying database candidates from '{db_path}'...")
        conn = sqlite3.connect(db_path, timeout=60.0)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, file_path, file_size, mtime, v_codec, duration, width, error
            FROM media_files
            WHERE media_type = 'video' AND (v_codec IS NULL OR duration <= 0 OR width <= 0 OR error IS NOT NULL)
        """)
        for row in cur.fetchall():
            row_id, fpath, fsize, mtime, vcodec, dur, w, err = row
            if is_game_path(fpath):
                continue
            if not os.path.exists(to_extended_path(fpath)):
                continue
            candidate_paths.append({
                "db_id": row_id,
                "file_path": fpath,
                "file_size": fsize,
                "mtime": mtime or 0.0,
            })
        conn.close()
        print(f"[*] Found {len(candidate_paths)} candidate video records in database.")
    else:
        print(f"[*] Scanning filesystem tree at '{target_dir}' for video candidates...")
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and not d.startswith(".quarantine_")]
            if is_game_path(root) or ".quarantine_" in root.replace("/", "\\"):
                continue

            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in VIDEO_EXTENSIONS:
                    full_p = os.path.join(root, f)
                    try:
                        st = os.stat(to_extended_path(full_p))
                        candidate_paths.append({
                            "db_id": None,
                            "file_path": full_p,
                            "file_size": st.st_size,
                            "mtime": st.st_mtime,
                        })
                    except Exception:
                        pass
        print(f"[*] Found {len(candidate_paths)} filesystem video files to inspect.")

    confirmed_corrupted: List[Dict[str, Any]] = []
    total = len(candidate_paths)
    print(f"[*] Validating {total} candidates with ffprobe ({ffprobe_bin})...")

    for idx, item in enumerate(candidate_paths, 1):
        fpath = item["file_path"]
        is_valid, err_class, err_detail = probe_file(fpath, ffprobe_bin)
        if not is_valid:
            item["error_class"] = err_class
            item["error_detail"] = err_detail
            confirmed_corrupted.append(item)
            print(f"    [!] Detected corrupted item {len(confirmed_corrupted)} ({item['file_size']:,} bytes): {err_class}")
        else:
            print(f"    [+] Verified valid: item {idx}/{total}")

    return confirmed_corrupted


def execute_quarantine(
    candidates: List[Dict[str, Any]],
    ledger_conn: sqlite3.Connection,
    quarantine_base: str = DEFAULT_QUARANTINE_DIR,
    dry_run: bool = False,
) -> int:
    """Stages confirmed corrupted assets into safe reversible quarantine directory."""
    moved_count = 0
    now_str = datetime.now().isoformat()

    with ledger_conn:
        for idx, item in enumerate(candidates, 1):
            orig_path = item["file_path"]
            if is_game_path(orig_path):
                print(f"[SAFETY] Skipping game file: {orig_path}")
                continue

            norm_orig = to_extended_path(orig_path)
            if not os.path.exists(norm_orig):
                print(f"[WARN] Original file does not exist: {orig_path}")
                continue

            filename = os.path.basename(orig_path)
            subfolder = f"item_{idx:04d}_{item['error_class']}"
            item_quar_dir = os.path.join(quarantine_base, subfolder)
            dest_path = os.path.join(item_quar_dir, filename)
            norm_dest = to_extended_path(dest_path)

            if dry_run:
                moved_count += 1
                print(f"[DRY-RUN] Would quarantine item {moved_count} ({item['file_size']:,} bytes) [{item['error_class']}]")
                continue

            os.makedirs(item_quar_dir, exist_ok=True)

            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(norm_dest):
                dest_path = os.path.join(item_quar_dir, f"{base_name}_{counter}{ext}")
                norm_dest = to_extended_path(dest_path)
                counter += 1

            ledger_conn.execute("""
                INSERT OR REPLACE INTO corrupted_files
                (original_path, quarantine_path, file_size, error_class, error_detail, original_mtime, quarantined_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                orig_path,
                dest_path,
                item["file_size"],
                item["error_class"],
                item.get("error_detail", ""),
                item.get("mtime", 0.0),
                now_str,
                "quarantined",
            ))

            clear_readonly(norm_orig)
            shutil.move(norm_orig, norm_dest)

            mtime = item.get("mtime", 0.0)
            if mtime and mtime > 0:
                try:
                    os.utime(norm_dest, (mtime, mtime))
                except Exception:
                    pass

            moved_count += 1
            print(f"[QUARANTINE] Staged item {moved_count} ({item['file_size']:,} bytes) [{item['error_class']}]")

    return moved_count


def execute_rollback(
    ledger_conn: sqlite3.Connection,
    dry_run: bool = False,
    target_id: Optional[int] = None,
) -> int:
    """Restores quarantined corrupted files back to their exact original locations."""
    restored_count = 0
    cur = ledger_conn.cursor()

    if target_id is not None:
        cur.execute("""
            SELECT id, original_path, quarantine_path, original_mtime
            FROM corrupted_files
            WHERE id = ? AND status = 'quarantined'
        """, (target_id,))
    else:
        cur.execute("""
            SELECT id, original_path, quarantine_path, original_mtime
            FROM corrupted_files
            WHERE status = 'quarantined'
        """)

    rows = cur.fetchall()
    now_str = datetime.now().isoformat()

    with ledger_conn:
        for row in rows:
            rec_id, orig_path, quar_path, orig_mtime = row
            norm_quar = to_extended_path(quar_path)
            norm_orig = to_extended_path(orig_path)

            if not os.path.exists(norm_quar):
                print(f"[WARN] Quarantined file missing at '{quar_path}'")
                continue

            if dry_run:
                restored_count += 1
                print(f"[DRY-RUN] Would restore record {rec_id} back to original location")
                continue

            orig_dir = os.path.dirname(norm_orig)
            os.makedirs(orig_dir, exist_ok=True)

            clear_readonly(norm_quar)
            shutil.move(norm_quar, norm_orig)

            if orig_mtime and orig_mtime > 0:
                try:
                    os.utime(norm_orig, (orig_mtime, orig_mtime))
                except Exception:
                    pass

            ledger_conn.execute("""
                UPDATE corrupted_files
                SET status = 'restored'
                WHERE id = ?
            """, (rec_id,))

            restored_count += 1
            print(f"[RESTORE] Restored record {rec_id} back to original location")

    return restored_count


def main():
    parser = argparse.ArgumentParser(description="Corrupted Media Quarantine and Isolation Engine")
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR, help="Target root directory")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite inventory DB")
    parser.add_argument("--ledger", default=DEFAULT_LEDGER_PATH, help="Path to SQLite quarantine ledger")
    parser.add_argument("--quarantine-dir", default=DEFAULT_QUARANTINE_DIR, help="Quarantine staging root")
    parser.add_argument("--dry-run", action="store_true", help="Preview corrupted files without staging")
    parser.add_argument("--quarantine", action="store_true", help="Stage confirmed corrupted files into quarantine")
    parser.add_argument("--rollback", action="store_true", help="Restore quarantined files to original paths")
    parser.add_argument("--target-id", type=int, default=None, help="Target specific ledger record ID for rollback")
    parser.add_argument("--check-all", action="store_true", help="Perform full filesystem scan instead of DB query")
    parser.add_argument("--report", default=DEFAULT_REPORT_PATH, help="Path for JSON output report")
    args = parser.parse_args()

    t_start = time.time()
    print("=" * 70)
    print("         CORRUPTED AND TRUNCATED MEDIA QUARANTINE ENGINE")
    print("=" * 70)
    print(f"Target Directory:      {args.target_dir}")
    print(f"SQLite Inventory DB:   {args.db}")
    print(f"Quarantine Ledger DB:  {args.ledger}")
    print(f"Quarantine Directory:  {args.quarantine_dir}")
    print(f"Mode:                  {'ROLLBACK' if args.rollback else ('QUARANTINE' if args.quarantine else 'PREVIEW/DRY-RUN')}")
    print(f"Dry Run:               {args.dry_run}")
    print("=" * 70)

    ledger_conn = init_ledger(args.ledger)

    if args.rollback:
        print("\n[*] Executing rollback from ledger...")
        restored = execute_rollback(ledger_conn, dry_run=args.dry_run, target_id=args.target_id)
        print(f"\n[+] Rollback complete: {restored} files restored.")
        ledger_conn.close()
        return

    ffprobe_bin = get_ffprobe_path()
    print(f"[*] Using ffprobe: {ffprobe_bin}")

    candidates = find_corrupted_candidates(
        target_dir=args.target_dir,
        db_path=args.db,
        ffprobe_bin=ffprobe_bin,
        check_all=args.check_all,
    )

    total_bytes = sum(c["file_size"] for c in candidates)
    print(f"\n[+] Corrupted Candidates Discovered: {len(candidates)} files ({total_bytes / (1024**3):.2f} GB / {total_bytes:,} bytes)")

    # Error classification breakdown
    error_summary: Dict[str, int] = {}
    for c in candidates:
        err = c["error_class"]
        error_summary[err] = error_summary.get(err, 0) + 1

    print("[+] Error Classification Summary:")
    for err, cnt in sorted(error_summary.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {err:<30}: {cnt:>4} files")

    moved_count = 0
    if args.quarantine:
        print(f"\n[*] Executing quarantine staging into '{args.quarantine_dir}'...")
        moved_count = execute_quarantine(
            candidates,
            ledger_conn,
            quarantine_base=args.quarantine_dir,
            dry_run=args.dry_run,
        )
        print(f"\n[+] Successfully quarantined {moved_count} corrupted files.")
    elif not args.dry_run:
        print("\n[!] Neither --quarantine nor --dry-run specified. Running in inspection preview mode.")

    elapsed = time.time() - t_start
    print("\n" + "=" * 70)
    print(f"[+] Operation completed in {elapsed:.2f} seconds.")
    print("=" * 70)

    report_data = {
        "execution_time_seconds": round(elapsed, 2),
        "target_directory": args.target_dir,
        "database_path": args.db,
        "ledger_path": args.ledger,
        "quarantine_dir": args.quarantine_dir,
        "mode": "quarantine" if args.quarantine else "preview",
        "dry_run": args.dry_run,
        "total_corrupted_files": len(candidates),
        "total_corrupted_bytes": total_bytes,
        "error_classification": error_summary,
        "quarantined_files_count": moved_count,
    }

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Output report written to '{args.report}'.")

    ledger_conn.close()


if __name__ == "__main__":
    main()
