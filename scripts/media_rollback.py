import os
import sys
import time
import sqlite3
import argparse
import shutil
from typing import List, Tuple
from tqdm import tqdm

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def rollback_transactions(ledger_path: str, dry_run: bool = False, verify_only: bool = False):
    if not os.path.exists(ledger_path):
        print(f"[!] Undo ledger database not found at '{ledger_path}'. Nothing to roll back.")
        return

    conn = sqlite3.connect(ledger_path, timeout=30.0)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, original_path, target_path, original_mtime, file_size, status
        FROM transactions
        WHERE status = 'completed'
        ORDER BY id DESC
    """)
    rows = cur.fetchall()

    if not rows:
        print("[+] No completed transactions found to roll back.")
        conn.close()
        return

    print(f"[*] Found {len(rows)} completed transactions in '{ledger_path}'.")

    if verify_only:
        print("[*] Running ledger verification...")
        present = 0
        missing = 0
        for row in rows:
            _, _, target_path, _, _, _ = row
            if os.path.exists(target_path):
                present += 1
            else:
                missing += 1
                print(f"[!] Missing target on disk: {target_path}")
        print(f"[+] Verification result: {present} present, {missing} missing out of {len(rows)} records.")
        conn.close()
        return

    if dry_run:
        print("[*] DRY-RUN MODE: Previewing rollback operations:")
        for row in rows[:20]:
            _, orig_p, targ_p, _, _, _ = row
            print(f"  Rollback: {os.path.basename(targ_p)} -> {os.path.basename(orig_p)}")
        if len(rows) > 20:
            print(f"  ... and {len(rows) - 20} more items.")
        conn.close()
        return

    success_count = 0
    fail_count = 0
    t0 = time.time()

    for row in tqdm(rows, desc="Rolling Back Renames", unit="file"):
        tx_id, orig_p, targ_p, orig_mtime, size, status = row

        if not os.path.exists(targ_p):
            print(f"[!] Cannot roll back: Target file not found: {targ_p}")
            fail_count += 1
            continue

        try:
            # Revert move
            os.replace(targ_p, orig_p)
            # Restore mtime
            if orig_mtime and orig_mtime > 0:
                os.utime(orig_p, (orig_mtime, orig_mtime))
            
            with conn:
                conn.execute("UPDATE transactions SET status = 'reverted' WHERE id = ?", (tx_id,))
            success_count += 1
        except Exception as e:
            try:
                shutil.move(targ_p, orig_p)
                if orig_mtime and orig_mtime > 0:
                    os.utime(orig_p, (orig_mtime, orig_mtime))
                with conn:
                    conn.execute("UPDATE transactions SET status = 'reverted' WHERE id = ?", (tx_id,))
                success_count += 1
            except Exception as e2:
                print(f"[!] Rollback failed for {targ_p} -> {orig_p}: {e2}")
                fail_count += 1

    conn.close()
    elapsed = time.time() - t0
    print(f"\n==================================================")
    print(f"Rollback Completed in {elapsed:.2f}s")
    print(f"Successfully Reverted: {success_count}/{len(rows)}")
    print(f"Failed / Missing:      {fail_count}")
    print(f"==================================================")

def main():
    parser = argparse.ArgumentParser(description="Transactional Rollback Engine for Aloha Media Renames")
    parser.add_argument("--ledger", default=r"undo_ledger.db", help="Path to undo ledger SQLite database")
    parser.add_argument("--dry-run", action="store_true", help="Preview rollback operations without modifying files")
    parser.add_argument("--verify", action="store_true", help="Verify presence of files recorded in ledger")
    args = parser.parse_args()

    rollback_transactions(args.ledger, dry_run=args.dry_run, verify_only=args.verify)

if __name__ == "__main__":
    main()
