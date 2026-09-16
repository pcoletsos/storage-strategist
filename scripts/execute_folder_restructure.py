import os
import sys
import time
import sqlite3
import argparse
import shutil
from typing import Dict, Any, List, Tuple
from tqdm import tqdm

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path
from dir_structure_planner import plan_directory_restructure, print_summary_dashboard, CANONICAL_ROOTS

def init_dir_undo_ledger(ledger_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(ledger_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL,
                target_path TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                original_mtime REAL,
                file_size INTEGER,
                executed_at TEXT,
                status TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dir_status ON transactions(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dir_target ON transactions(target_path);")
    return conn

def safe_move_file(src: str, dst: str, original_mtime: float) -> None:
    src_ext = to_extended_path(src)
    dst_ext = to_extended_path(dst)
    dst_dir = os.path.dirname(dst_ext)

    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir, exist_ok=True)

    try:
        os.replace(src_ext, dst_ext)
    except Exception:
        shutil.move(src_ext, dst_ext)

    if original_mtime and original_mtime > 0:
        try:
            os.utime(dst_ext, (original_mtime, original_mtime))
        except Exception:
            pass

def prune_empty_directories(root_dir: str, protected_roots: List[str] = None) -> int:
    if protected_roots is None:
        protected_roots = [os.path.join(root_dir, r).lower() for r in CANONICAL_ROOTS]
    protected_roots.append(root_dir.lower())

    pruned_count = 0
    # Walk bottom-up
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=False):
        dirpath_lower = dirpath.lower()
        if dirpath_lower in protected_roots:
            continue
        dirpath_ext = to_extended_path(dirpath)
        try:
            entries = os.listdir(dirpath_ext)
            non_cache = [e for e in entries if e.lower() not in ("thumbs.db", "desktop.ini")]
            if len(non_cache) == 0:
                # Remove leftover cache files first
                for c in entries:
                    c_path = os.path.join(dirpath_ext, c)
                    try:
                        import stat
                        os.chmod(c_path, stat.S_IWRITE)
                        os.remove(c_path)
                    except Exception:
                        pass
                os.rmdir(dirpath_ext)
                pruned_count += 1
        except Exception:
            pass
    return pruned_count

def execute_restructure(root_dir: str, ledger_path: str, dry_run: bool = False, max_items: int = 0):
    relocations, stats = plan_directory_restructure(root_dir)
    print_summary_dashboard(stats)

    to_move = [r for r in relocations if r["is_moved"]]
    if max_items > 0:
        to_move = to_move[:max_items]

    print(f"[*] Total relocations to execute: {len(to_move):,}")

    if dry_run:
        print("[*] DRY-RUN MODE: Previewing first 20 operations:")
        for r in to_move[:20]:
            print(f"  MOVE: {r['relative_source']} -> {r['relative_target']}")
        if len(to_move) > 20:
            print(f"  ... and {len(to_move) - 20} more items.")
        print("[+] Dry-run completed. Zero disk changes made.")
        return

    conn = init_dir_undo_ledger(ledger_path)
    cur = conn.cursor()

    t0 = time.time()
    success_count = 0
    fail_count = 0

    print(f"[*] Executing atomic relocations with transactional logging in '{ledger_path}'...")
    for r in tqdm(to_move, desc="Relocating Media Assets", unit="file"):
        src = r["source_path"]
        dst = r["target_path"]
        mtime = r["mtime"]
        fsize = r["file_size"]
        now_ts = time.strftime("%Y-%m-%d %H:%M:%S")

        if not os.path.exists(src):
            fail_count += 1
            print(f"[!] Source not found on disk: {src}")
            continue

        if os.path.exists(dst):
            fail_count += 1
            print(f"[!] Destination collision already exists on disk: {dst}")
            continue

        # Insert transaction as pending
        with conn:
            cur.execute("""
                INSERT INTO transactions (source_path, target_path, operation_type, original_mtime, file_size, executed_at, status)
                VALUES (?, ?, 'file_move', ?, ?, ?, 'pending')
            """, (src, dst, mtime, fsize, now_ts))
            tx_id = cur.lastrowid

        # Perform atomic move
        try:
            safe_move_file(src, dst, mtime)
            with conn:
                cur.execute("UPDATE transactions SET status = 'completed' WHERE id = ?", (tx_id,))
            success_count += 1
        except Exception as e:
            fail_count += 1
            with conn:
                cur.execute("UPDATE transactions SET status = 'failed' WHERE id = ?", (tx_id,))
            print(f"[!] Failed moving '{src}' -> '{dst}': {e}")

    conn.close()
    elapsed = time.time() - t0

    # Prune verified empty folders
    print("[*] Pruning verified empty directories...")
    pruned = prune_empty_directories(root_dir)

    print("\n==================================================")
    print(f"Directory Restructure Completed in {elapsed:.2f}s")
    print(f"Successfully Relocated:  {success_count:,}/{len(to_move):,}")
    print(f"Failed / Skipped:        {fail_count:,}")
    print(f"Empty Folders Pruned:    {pruned:,}")
    print(f"Undo Ledger Saved:       {ledger_path}")
    print("==================================================")

def main():
    parser = argparse.ArgumentParser(description="Atomic Directory Restructure Engine for F:\\Aloha")
    parser.add_argument("--root", default=r"F:\Aloha", help="Root directory (default F:\\Aloha)")
    parser.add_argument("--ledger", default=r"dir_undo_ledger.db", help="Path to SQLite undo ledger")
    parser.add_argument("--dry-run", action="store_true", help="Preview moves without modifying filesystem")
    parser.add_argument("--max-items", type=int, default=0, help="Limit number of items to move (0 for all)")
    args = parser.parse_args()

    execute_restructure(args.root, args.ledger, dry_run=args.dry_run, max_items=args.max_items)

if __name__ == "__main__":
    main()
