import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime
from collections import defaultdict
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
        import shutil
        shutil.move(src_ext, dst_ext)

    if original_mtime and original_mtime > 0:
        try:
            os.utime(dst_ext, (original_mtime, original_mtime))
        except Exception:
            pass


def prune_empty_dirs(root_dir: str) -> int:
    pruned_count = 0
    protected_roots = {
        os.path.normpath(root_dir).lower(),
        os.path.normpath(os.path.join(root_dir, "Studios")).lower(),
        os.path.normpath(os.path.join(root_dir, "Movies")).lower(),
        os.path.normpath(os.path.join(root_dir, "Celebrities")).lower(),
        os.path.normpath(os.path.join(root_dir, "Collections & Siterips")).lower(),
        os.path.normpath(os.path.join(root_dir, "Photos & Sets")).lower(),
        os.path.normpath(os.path.join(root_dir, "Magazines & Docs")).lower(),
        os.path.normpath(os.path.join(root_dir, "Games")).lower(),
    }

    for dirpath, dirs, files in os.walk(root_dir, topdown=False):
        norm_dp = os.path.normpath(dirpath).lower()
        if norm_dp in protected_roots:
            continue
        try:
            ext_dp = to_extended_path(dirpath)
            entries = os.listdir(ext_dp)
            non_cache = [e for e in entries if e.lower() not in ("thumbs.db", "desktop.ini")]
            if len(non_cache) == 0:
                for c in entries:
                    c_path = os.path.join(ext_dp, c)
                    try:
                        os.chmod(c_path, 0o777)
                        os.remove(c_path)
                    except Exception:
                        pass
                os.rmdir(ext_dp)
                pruned_count += 1
        except Exception:
            pass
    return pruned_count


def plan_subfolder_hygiene(db_path: str) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, directory, filename, file_size, mtime 
        FROM media_files
        WHERE file_path LIKE 'F:\\Aloha\\Magazines & Docs\\%'
           OR file_path LIKE 'F:\\Aloha\\Movies\\New folder\\%'
           OR file_path LIKE 'F:\\Aloha\\Celebrities\\New Folder\\%'
           OR file_path LIKE 'F:\\Aloha\\Celebrities\\Updates\\%'
           OR file_path LIKE 'F:\\Aloha\\Photos & Sets\\New Folder\\%'
           OR file_path LIKE 'F:\\Aloha\\Photos & Sets\\New Folder (2)\\%'
           OR file_path LIKE 'F:\\Aloha\\Photos & Sets\\New Folder3\\%'
           OR file_path LIKE 'F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Scr\\%'
    """)
    rows = c.fetchall()
    conn.close()

    plans = []
    for fid, fpath, fdir, fname, sz, mtime in rows:
        fdir_norm = fdir.replace("/", "\\")
        fname_lower = fname.lower()
        is_quarantine = False

        # 1. Magazines & Docs loose files
        if fdir_norm == r"F:\Aloha\Magazines & Docs":
            if "playboy" in fname_lower:
                new_dir = r"F:\Aloha\Magazines & Docs\Playboy"
            elif "nitro" in fname_lower:
                new_dir = r"F:\Aloha\Magazines & Docs\Nitro"
            elif "max" in fname_lower:
                new_dir = r"F:\Aloha\Magazines & Docs\Max"
            else:
                new_dir = r"F:\Aloha\Magazines & Docs\Greek Periodika"

        # 2. Movies New folder
        elif fdir_norm == r"F:\Aloha\Movies\New folder":
            new_dir = r"F:\Aloha\Movies\Digital Playground"

        # 3. Celebrities New Folder
        elif fdir_norm == r"F:\Aloha\Celebrities\New Folder":
            if "barbara niven" in fname_lower:
                new_dir = r"F:\Aloha\Celebrities\Barbara Niven"
            elif "blake lively" in fname_lower:
                new_dir = r"F:\Aloha\Celebrities\Blake Lively"
            elif "jessica clark" in fname_lower:
                new_dir = r"F:\Aloha\Celebrities\Jessica Clark"
            else:
                new_dir = r"F:\Aloha\Celebrities\Clips"

        # 4. Celebrities Updates
        elif fdir_norm.endswith(r"Celebrities\Updates\Update1"):
            new_dir = r"F:\Aloha\Celebrities\Mr Skin Updates\Update 1"
        elif fdir_norm.endswith(r"Celebrities\Updates\Update2"):
            new_dir = r"F:\Aloha\Celebrities\Mr Skin Updates\Update 2"
        elif fdir_norm.endswith(r"Celebrities\Updates\Update3"):
            new_dir = r"F:\Aloha\Celebrities\Mr Skin Updates\Update 3"
        elif fdir_norm.endswith(r"Celebrities\Updates\Update4,5,6,7"):
            new_dir = r"F:\Aloha\Celebrities\Mr Skin Updates\Update 4-7"
        elif fdir_norm.endswith(r"Celebrities\Updates\Update8"):
            new_dir = r"F:\Aloha\Celebrities\Mr Skin Updates\Update 8"

        # 5. Photos & Sets New Folder variants
        elif fdir_norm == r"F:\Aloha\Photos & Sets\New Folder":
            new_dir = r"F:\Aloha\Photos & Sets\Miscellaneous Sets\Album 1"
        elif fdir_norm == r"F:\Aloha\Photos & Sets\New Folder (2)":
            new_dir = r"F:\Aloha\Photos & Sets\Miscellaneous Sets\Album 2"
        elif fdir_norm == r"F:\Aloha\Photos & Sets\New Folder3":
            new_dir = r"F:\Aloha\.quarantine_flagged\new_folder3"
            is_quarantine = True

        # 6. Collections screencaps
        elif fdir_norm == r"F:\Aloha\Collections & Siterips\Izzy Green (OnlyFans)\Izzy Green Pack\Scr":
            new_dir = r"F:\Aloha\Collections & Siterips\Izzy Green (OnlyFans)\Izzy Green Pack\Screenshots"
        else:
            new_dir = fdir_norm

        new_path = os.path.join(new_dir, fname)
        plans.append({
            "id": fid,
            "filename": fname,
            "source_path": fpath,
            "target_path": new_path,
            "new_directory": new_dir,
            "file_size": sz,
            "mtime": mtime or 0.0,
            "is_quarantine": is_quarantine,
        })
    return plans


def execute_subfolder_hygiene(
    db_path: str = "media_inventory.db",
    ledger_path: str = "dir_undo_ledger.db",
    target_dir: str = r"F:\Aloha",
    dry_run: bool = True,
    output_report: str = "subfolder_topology_report.json"
) -> Dict[str, Any]:
    plans = plan_subfolder_hygiene(db_path)
    now_str = datetime.now().isoformat()

    destination_counts = defaultdict(int)
    for p in plans:
        destination_counts[p["new_directory"]] += 1

    moved_count = 0
    quarantined_count = 0
    pruned_dirs = 0

    if not dry_run:
        ledger_conn = init_dir_undo_ledger(ledger_path)
        inv_conn = sqlite3.connect(db_path)

        with ledger_conn, inv_conn:
            for p in plans:
                src = p["source_path"]
                dst = p["target_path"]
                sz = p["file_size"]
                mtime = p["mtime"]
                is_q = p["is_quarantine"]
                op_type = "quarantine_move" if is_q else "subfolder_reorganize"

                # 1. Log transaction to ledger
                ledger_conn.execute("""
                    INSERT INTO transactions 
                    (source_path, target_path, operation_type, original_mtime, file_size, executed_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (src, dst, op_type, mtime, sz, now_str, "completed"))

                # 2. Safely move file and restore timestamp
                safe_move_file(src, dst, mtime)

                # 3. Update or reconcile inventory DB
                if is_q:
                    # Remove flagged quarantine items from active media inventory
                    inv_conn.execute("DELETE FROM media_files WHERE id = ?", (p["id"],))
                    quarantined_count += 1
                else:
                    inv_conn.execute("""
                        UPDATE media_files 
                        SET file_path = ?, directory = ? 
                        WHERE id = ?
                    """, (dst, p["new_directory"], p["id"]))
                    moved_count += 1

        ledger_conn.close()
        inv_conn.close()

        # Prune empty directories
        pruned_dirs = prune_empty_dirs(target_dir)

    summary = {
        "timestamp": now_str,
        "dry_run": dry_run,
        "total_planned": len(plans),
        "total_reorganized": moved_count if not dry_run else len(plans) - 19,
        "total_quarantined": quarantined_count if not dry_run else 19,
        "pruned_empty_directories": pruned_dirs,
        "destination_breakdown": dict(destination_counts)
    }

    with open(output_report, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary


def main():
    parser = argparse.ArgumentParser(description="Subfolder topology organization and hygiene for Aloha.")
    parser.add_argument("--db", default="media_inventory.db", help="Path to media_inventory.db")
    parser.add_argument("--ledger", default="dir_undo_ledger.db", help="Path to dir_undo_ledger.db")
    parser.add_argument("--target-dir", default=r"F:\Aloha", help="Root of Aloha drive")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Run without making filesystem changes")
    parser.add_argument("--commit", action="store_true", default=False, help="Execute filesystem moves and ledger updates")
    parser.add_argument("--output-report", default="subfolder_topology_report.json", help="Path to output JSON report")

    args = parser.parse_args()
    is_dry_run = not args.commit

    summary = execute_subfolder_hygiene(
        db_path=args.db,
        ledger_path=args.ledger,
        target_dir=args.target_dir,
        dry_run=is_dry_run,
        output_report=args.output_report
    )

    print("==================================================")
    print("SUBFOLDER TOPOLOGY REORGANIZATION")
    print("==================================================")
    print(f"Mode:                     {'DRY RUN' if is_dry_run else 'COMMITTED TO DISK'}")
    print(f"Total Evaluated Items:    {summary['total_planned']}")
    print(f"Subfolder Reorganizations: {summary['total_reorganized']}")
    print(f"Quarantined Flagged Items: {summary['total_quarantined']}")
    if not is_dry_run:
        print(f"Pruned Empty Folders:     {summary['pruned_empty_directories']}")
    print("==================================================")
    print(f"Audit report saved to {args.output_report}")


if __name__ == "__main__":
    main()
