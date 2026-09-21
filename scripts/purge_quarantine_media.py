import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime
from typing import Dict, Any, List, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

try:
    from media_name_parser import to_extended_path
except ImportError:
    def to_extended_path(p: str) -> str:
        return p


def purge_quarantine(
    target_dir: str = r"F:\Aloha",
    dedup_ledger_path: str = "deduplication_ledger.db",
    corrupted_ledger_path: str = "corrupted_media_ledger.db",
    inventory_db_path: str = "media_inventory.db",
    dry_run: bool = True,
    output_report: str = "quarantine_purge_report.json"
) -> Dict[str, Any]:
    """Permanently purges staged quarantine files and updates audit ledgers."""
    quarantine_dupes = os.path.join(target_dir, ".quarantine_duplicates")
    quarantine_corrupted = os.path.join(target_dir, ".quarantine_corrupted")

    # Safety check: ensure quarantine paths are isolated
    norm_dupes = os.path.normpath(quarantine_dupes).lower()
    norm_corrupted = os.path.normpath(quarantine_corrupted).lower()

    # Safety check: ensure media_inventory.db has no references to quarantine
    if os.path.exists(inventory_db_path):
        conn_inv = sqlite3.connect(inventory_db_path)
        c_inv = conn_inv.cursor()
        c_inv.execute("SELECT COUNT(*) FROM media_files WHERE file_path LIKE ? OR file_path LIKE ?",
                      (f"{quarantine_dupes}%", f"{quarantine_corrupted}%"))
        quarantine_in_inv = c_inv.fetchone()[0]
        conn_inv.close()
        if quarantine_in_inv > 0:
            raise RuntimeError(f"Safety violation: media_inventory.db tracks {quarantine_in_inv} files inside quarantine!")

    # 1. Collect duplicate files from deduplication_ledger
    dupe_files_to_purge = []
    if os.path.exists(dedup_ledger_path):
        conn_d = sqlite3.connect(dedup_ledger_path)
        c_d = conn_d.cursor()
        c_d.execute("SELECT id, quarantine_path, file_size FROM duplicate_files WHERE status = 'quarantined'")
        dupe_files_to_purge = c_d.fetchall()
        conn_d.close()

    # 2. Collect corrupted files from corrupted_media_ledger
    corrupted_files_to_purge = []
    if os.path.exists(corrupted_ledger_path):
        conn_c = sqlite3.connect(corrupted_ledger_path)
        c_c = conn_c.cursor()
        c_c.execute("SELECT id, quarantine_path, file_size FROM corrupted_files WHERE status = 'quarantined'")
        corrupted_files_to_purge = c_c.fetchall()
        conn_c.close()

    # Verify paths lie strictly within quarantine directories
    purged_dupe_bytes = 0
    purged_corrupted_bytes = 0
    purged_dupe_count = 0
    purged_corrupted_count = 0

    now_str = datetime.now().isoformat()

    # Execute purge for duplicates
    for fid, qpath, sz in dupe_files_to_purge:
        if not qpath:
            continue
        norm_q = os.path.normpath(qpath).lower()
        if not norm_q.startswith(norm_dupes):
            raise RuntimeError(f"Safety violation: duplicate file path {qpath} is not inside {quarantine_dupes}")

        ext_path = to_extended_path(qpath)
        if os.path.exists(ext_path):
            purged_dupe_bytes += sz
            purged_dupe_count += 1
            if not dry_run:
                try:
                    os.chmod(ext_path, 0o777)
                except Exception:
                    pass
                os.remove(ext_path)

    # Execute purge for corrupted files
    for fid, qpath, sz in corrupted_files_to_purge:
        if not qpath:
            continue
        norm_q = os.path.normpath(qpath).lower()
        if not norm_q.startswith(norm_corrupted):
            raise RuntimeError(f"Safety violation: corrupted file path {qpath} is not inside {quarantine_corrupted}")

        ext_path = to_extended_path(qpath)
        if os.path.exists(ext_path):
            purged_corrupted_bytes += sz
            purged_corrupted_count += 1
            if not dry_run:
                try:
                    os.chmod(ext_path, 0o777)
                except Exception:
                    pass
                os.remove(ext_path)

    # Prune empty directories
    pruned_dirs_count = 0
    if not dry_run:
        for q_root in [quarantine_dupes, quarantine_corrupted]:
            if os.path.exists(q_root):
                for root, dirs, files in os.walk(q_root, topdown=False):
                    for d in dirs:
                        dp = os.path.join(root, d)
                        try:
                            if not os.listdir(dp):
                                os.rmdir(dp)
                                pruned_dirs_count += 1
                        except Exception:
                            pass
                # Check root itself
                try:
                    if not os.listdir(q_root):
                        os.rmdir(q_root)
                        pruned_dirs_count += 1
                except Exception:
                    pass

        # Update ledger records
        if os.path.exists(dedup_ledger_path):
            conn_d = sqlite3.connect(dedup_ledger_path)
            with conn_d:
                conn_d.execute("UPDATE duplicate_files SET status = 'purged', executed_at = ? WHERE status = 'quarantined'", (now_str,))
            conn_d.close()

        if os.path.exists(corrupted_ledger_path):
            conn_c = sqlite3.connect(corrupted_ledger_path)
            with conn_c:
                conn_c.execute("UPDATE corrupted_files SET status = 'purged' WHERE status = 'quarantined'")
            conn_c.close()

    total_bytes = purged_dupe_bytes + purged_corrupted_bytes
    total_mb = total_bytes / (1024 * 1024)
    total_gb = total_bytes / (1024 * 1024 * 1024)

    summary = {
        "timestamp": now_str,
        "dry_run": dry_run,
        "purged_duplicate_files": purged_dupe_count,
        "purged_duplicate_bytes": purged_dupe_bytes,
        "purged_corrupted_files": purged_corrupted_count,
        "purged_corrupted_bytes": purged_corrupted_bytes,
        "total_files_purged": purged_dupe_count + purged_corrupted_count,
        "total_bytes_reclaimed": total_bytes,
        "total_mb_reclaimed": round(total_mb, 2),
        "total_gb_reclaimed": round(total_gb, 2),
        "pruned_directories": pruned_dirs_count,
    }

    with open(output_report, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary


def main():
    parser = argparse.ArgumentParser(description="Permanently purge verified quarantine files on Aloha.")
    parser.add_argument("--target-dir", default=r"F:\Aloha", help="Target Aloha drive root")
    parser.add_argument("--dedup-ledger", default="deduplication_ledger.db", help="Path to deduplication_ledger.db")
    parser.add_argument("--corrupted-ledger", default="corrupted_media_ledger.db", help="Path to corrupted_media_ledger.db")
    parser.add_argument("--inventory-db", default="media_inventory.db", help="Path to media_inventory.db")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Preview files to purge without deleting")
    parser.add_argument("--commit", action="store_true", default=False, help="Execute permanent deletion and ledger updates")
    parser.add_argument("--output-report", default="quarantine_purge_report.json", help="Report output path")

    args = parser.parse_args()
    is_dry_run = not args.commit

    summary = purge_quarantine(
        target_dir=args.target_dir,
        dedup_ledger_path=args.dedup_ledger,
        corrupted_ledger_path=args.corrupted_ledger,
        inventory_db_path=args.inventory_db,
        dry_run=is_dry_run,
        output_report=args.output_report
    )

    print("==================================================")
    print("QUARANTINE PERMANENT PURGE AUDIT")
    print("==================================================")
    print(f"Mode:                      {'DRY RUN' if is_dry_run else 'COMMITTED - PERMANENTLY PURGED'}")
    print(f"Purged Duplicates:         {summary['purged_duplicate_files']} files ({summary['purged_duplicate_bytes'] / (1024*1024):.2f} MB)")
    print(f"Purged Corrupted Videos:   {summary['purged_corrupted_files']} files ({summary['purged_corrupted_bytes'] / (1024*1024):.2f} MB)")
    print(f"Total Files Purged:        {summary['total_files_purged']} files")
    print(f"Total Reclaimed Space:     {summary['total_bytes_reclaimed']:,} bytes ({summary['total_mb_reclaimed']} MB / {summary['total_gb_reclaimed']} GB)")
    if not is_dry_run:
        print(f"Pruned Empty Directories:  {summary['pruned_directories']}")
    print("==================================================")
    print(f"Audit certificate exported to {args.output_report}")


if __name__ == "__main__":
    main()
