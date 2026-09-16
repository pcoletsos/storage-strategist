import os
import sys
import time
import sqlite3
import argparse
import shutil
from tqdm import tqdm

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path
from execute_folder_restructure import prune_empty_directories

def rollback_directory_restructure(ledger_path: str, root_dir: str = r"F:\Aloha", dry_run: bool = False, verify_only: bool = False):
    if not os.path.exists(ledger_path):
        print(f"[!] Undo ledger database not found at '{ledger_path}'. Nothing to roll back.")
        return

    conn = sqlite3.connect(ledger_path, timeout=60.0)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, source_path, target_path, original_mtime, file_size, status
        FROM transactions
        WHERE status = 'completed'
        ORDER BY id DESC
    """)
    rows = cur.fetchall()

    if not rows:
        print("[+] No completed transactions found to roll back in ledger.")
        conn.close()
        return

    print(f"[*] Found {len(rows):,} completed transactions in '{ledger_path}'.")

    if verify_only:
        print("[*] Running ledger verification across disk...")
        present = 0
        missing = 0
        for row in rows:
            _, _, target_path, _, _, _ = row
            target_ext = to_extended_path(target_path)
            if os.path.exists(target_ext):
                present += 1
            else:
                missing += 1
                print(f"[!] Missing target on disk: {target_path}")
        print(f"[+] Verification result: {present:,} present, {missing:,} missing out of {len(rows):,} records.")
        conn.close()
        return

    if dry_run:
        print("[*] DRY-RUN MODE: Previewing rollback operations:")
        for row in rows[:20]:
            _, src_p, targ_p, _, _, _ = row
            print(f"  REVERT: {os.path.basename(targ_p)} -> {src_p}")
        if len(rows) > 20:
            print(f"  ... and {len(rows) - 20} more items.")
        conn.close()
        return

    success_count = 0
    fail_count = 0
    t0 = time.time()

    print(f"[*] Executing rollback of {len(rows):,} transactions in reverse chronological order...")
    for row in tqdm(rows, desc="Rolling Back Relocations", unit="file"):
        tx_id, src_p, targ_p, orig_mtime, size, status = row
        targ_ext = to_extended_path(targ_p)
        src_ext = to_extended_path(src_p)

        if not os.path.exists(targ_ext):
            print(f"[!] Cannot roll back: Target file not found on disk: {targ_p}")
            fail_count += 1
            continue

        src_dir = os.path.dirname(src_ext)
        if not os.path.exists(src_dir):
            os.makedirs(src_dir, exist_ok=True)

        try:
            os.replace(targ_ext, src_ext)
            if orig_mtime and orig_mtime > 0:
                try:
                    os.utime(src_ext, (orig_mtime, orig_mtime))
                except Exception:
                    pass
            with conn:
                cur.execute("UPDATE transactions SET status = 'reverted' WHERE id = ?", (tx_id,))
            success_count += 1
        except Exception:
            try:
                shutil.move(targ_ext, src_ext)
                if orig_mtime and orig_mtime > 0:
                    try:
                        os.utime(src_ext, (orig_mtime, orig_mtime))
                    except Exception:
                        pass
                with conn:
                    cur.execute("UPDATE transactions SET status = 'reverted' WHERE id = ?", (tx_id,))
                success_count += 1
            except Exception as e:
                print(f"[!] Rollback failed for {targ_p} -> {src_p}: {e}")
                fail_count += 1

    conn.close()
    elapsed = time.time() - t0

    # Prune any empty target directories left over
    print("[*] Pruning leftover empty target directories...")
    pruned = prune_empty_directories(root_dir)

    print("\n==================================================")
    print(f"Rollback Completed in {elapsed:.2f}s")
    print(f"Successfully Reverted: {success_count:,}/{len(rows):,}")
    print(f"Failed / Missing:      {fail_count:,}")
    print(f"Empty Folders Pruned:  {pruned:,}")
    print("==================================================")

def main():
    parser = argparse.ArgumentParser(description="Transactional Rollback Engine for Aloha Directory Restructure")
    parser.add_argument("--ledger", default=r"dir_undo_ledger.db", help="Path to undo ledger SQLite database")
    parser.add_argument("--root", default=r"F:\Aloha", help="Target root directory (default F:\\Aloha)")
    parser.add_argument("--dry-run", action="store_true", help="Preview rollback without modifying files")
    parser.add_argument("--verify", action="store_true", help="Verify presence of targets on disk")
    args = parser.parse_args()

    rollback_directory_restructure(args.ledger, root_dir=args.root, dry_run=args.dry_run, verify_only=args.verify)

if __name__ == "__main__":
    main()
