import os
import sys
import csv
import time
import json
import sqlite3
import argparse
import shutil
from typing import Dict, Any, List, Tuple
from tqdm import tqdm

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Import local pipeline modules
from media_name_parser import parse_media_file, to_extended_path, sanitize_win_filename
from media_tagger import tag_media_file

def init_undo_ledger(ledger_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(ledger_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT UNIQUE,
                target_path TEXT,
                original_mtime REAL,
                file_size INTEGER,
                executed_at TEXT,
                status TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON transactions(status);")
    return conn

def plan_renames(db_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    query = """
        SELECT id, file_path, directory, filename, extension, media_type,
               file_size, mtime, v_codec, a_codec, width, height,
               duration, bitrate, resolution_tier, existing_title,
               existing_artist, existing_date, existing_comment,
               exif_datetime, exif_artist
        FROM media_files
        ORDER BY id ASC
    """
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()

    plans = []
    target_registry = {} # maps lower(target_path) -> count
    stats = {
        "total_records": len(rows),
        "renamed_count": 0,
        "unchanged_count": 0,
        "collisions_resolved": 0,
        "video_count": 0,
        "image_count": 0,
        "other_count": 0,
        "studios": {}
    }

    for row in rows:
        (rec_id, file_path, directory, filename, ext, media_type,
         file_size, mtime, v_codec, a_codec, width, height,
         duration, bitrate, resolution_tier, existing_title,
         existing_artist, existing_date, existing_comment,
         exif_datetime, exif_artist) = row

        meta = {
            "v_codec": v_codec,
            "a_codec": a_codec,
            "width": width,
            "height": height,
            "duration": duration,
            "bitrate": bitrate,
            "resolution_tier": resolution_tier,
            "existing_title": existing_title,
            "existing_artist": existing_artist,
            "existing_date": existing_date,
            "existing_comment": existing_comment,
            "exif_datetime": exif_datetime,
            "exif_artist": exif_artist
        }

        parsed = parse_media_file(file_path, media_type, meta)
        std_name = parsed["standardized_filename"]
        studio = parsed.get("studio") or "Unclassified"
        stats["studios"][studio] = stats["studios"].get(studio, 0) + 1

        if media_type == "video":
            stats["video_count"] += 1
        elif media_type == "image":
            stats["image_count"] += 1
        else:
            stats["other_count"] += 1

        # Check collision within target directory
        base_target = os.path.join(directory, std_name)
        target_key = base_target.lower()
        
        final_target = base_target
        if target_key in target_registry:
            target_registry[target_key] += 1
            idx = target_registry[target_key]
            stats["collisions_resolved"] += 1
            # Insert suffix before extension e.g. "Name (2).mp4"
            base_no_ext, ext_part = os.path.splitext(std_name)
            disambiguated_name = f"{base_no_ext} ({idx}){ext_part}"
            final_target = os.path.join(directory, disambiguated_name)
        else:
            target_registry[target_key] = 1

        is_renamed = (os.path.normpath(file_path).lower() != os.path.normpath(final_target).lower())
        if is_renamed:
            stats["renamed_count"] += 1
        else:
            stats["unchanged_count"] += 1

        plans.append({
            "id": rec_id,
            "original_path": file_path,
            "original_filename": filename,
            "target_path": final_target,
            "target_filename": os.path.basename(final_target),
            "media_type": media_type,
            "is_renamed": is_renamed,
            "file_size": file_size,
            "mtime": mtime,
            "parsed_info": parsed
        })

    return plans, stats

def export_preview(plans: List[Dict[str, Any]], stats: Dict[str, Any], preview_csv: str, preview_json: str):
    print(f"[*] Exporting Dry-Run Preview to '{preview_csv}' and '{preview_json}'...")
    
    # Write CSV
    with open(preview_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Media Type", "Is Renamed", "Original Filename", "Proposed Filename", "Studio", "Date", "Original Path", "Target Path"])
        for p in plans:
            info = p["parsed_info"]
            writer.writerow([
                p["id"],
                p["media_type"],
                "YES" if p["is_renamed"] else "NO",
                p["original_filename"],
                p["target_filename"],
                info.get("studio") or "",
                info.get("date") or "",
                p["original_path"],
                p["target_path"]
            ])

    # Write JSON summary + samples
    summary_data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "statistics": stats,
        "sample_transformations": [
            {
                "original_filename": p["original_filename"],
                "target_filename": p["target_filename"],
                "original_path": p["original_path"],
                "target_path": p["target_path"],
                "studio": p["parsed_info"].get("studio"),
                "date": p["parsed_info"].get("date"),
                "title": p["parsed_info"].get("title")
            }
            for p in plans if p["is_renamed"]][:50]
    }
    with open(preview_json, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(f"[+] Preview exports complete!")

def execute_pipeline(plans: List[Dict[str, Any]], ledger_path: str, apply_tags: bool = True):
    print(f"[*] Initializing Undo Ledger at '{ledger_path}'...")
    conn = init_undo_ledger(ledger_path)
    
    renames_to_execute = [p for p in plans if p["is_renamed"]]
    total = len(renames_to_execute)
    print(f"[*] Executing {total} atomic transformations with transactional logging...")

    success_count = 0
    fail_count = 0
    t0 = time.time()

    for item in tqdm(renames_to_execute, desc="Applying Renames", unit="file"):
        orig_p = item["original_path"]
        targ_p = item["target_path"]
        mtime = item["mtime"]
        size = item["file_size"]
        
        # Check source exists
        if not os.path.exists(orig_p):
            fail_count += 1
            print(f"[!] Source not found: {orig_p}")
            continue

        # Check target does not exist already
        if os.path.exists(targ_p) and os.path.normpath(orig_p).lower() != os.path.normpath(targ_p).lower():
            fail_count += 1
            print(f"[!] Collision safety halt: target already exists: {targ_p}")
            continue

        # 1. Record pending transaction in SQLite ledger
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO transactions (original_path, target_path, original_mtime, file_size, executed_at, status)
                VALUES (?, ?, ?, ?, ?, 'pending')
            """, (orig_p, targ_p, mtime, size, time.strftime("%Y-%m-%d %H:%M:%S")))

        # 2. Atomic Rename
        try:
            os.replace(orig_p, targ_p)
        except Exception as e:
            # Try shutil.move as fallback
            try:
                shutil.move(orig_p, targ_p)
            except Exception as e2:
                fail_count += 1
                print(f"[!] Rename failed for {orig_p} -> {targ_p}: {e2}")
                with conn:
                    conn.execute("UPDATE transactions SET status = 'failed' WHERE original_path = ?", (orig_p,))
                continue

        # 3. Apply Tagging if requested
        if apply_tags:
            tag_media_file(targ_p, item["parsed_info"])

        # 4. Mark transaction as completed
        with conn:
            conn.execute("UPDATE transactions SET status = 'completed' WHERE original_path = ?", (orig_p,))

        success_count += 1

    conn.close()
    elapsed = time.time() - t0
    print(f"\n==================================================")
    print(f"Execution Completed in {elapsed:.2f}s")
    print(f"Successfully Transformed: {success_count}/{total}")
    print(f"Failed / Skipped:         {fail_count}")
    print(f"Undo Ledger Saved:        {ledger_path}")
    print(f"==================================================")

def main():
    parser = argparse.ArgumentParser(description="Two-Phase Media Renaming & Metadata Enrichment Pipeline")
    parser.add_argument("--db", default=r"media_inventory.db", help="SQLite media inventory path")
    parser.add_argument("--ledger", default=r"undo_ledger.db", help="SQLite undo ledger path")
    parser.add_argument("--preview-csv", default=r"rename_preview.csv", help="Dry-run CSV preview output")
    parser.add_argument("--preview-json", default=r"rename_preview.json", help="Dry-run JSON preview output")
    parser.add_argument("--apply", action="store_true", help="Execute transformations (Defaults to Dry-Run)")
    parser.add_argument("--no-tags", action="store_true", help="Skip embedded tag writeback during apply")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"[!] Inventory database not found at '{args.db}'. Please run media_inventory_scanner.py first.")
        sys.exit(1)

    print(f"[*] Reading inventory from '{args.db}' and building transformation plan...")
    plans, stats = plan_renames(args.db)

    print(f"\n================ PLAN SUMMARY ================")
    print(f"Total Media Scanned:     {stats['total_records']}")
    print(f"  - Video Files:         {stats['video_count']}")
    print(f"  - Image Files:         {stats['image_count']}")
    print(f"  - Other Files:         {stats['other_count']}")
    print(f"Standardized / Renamed:  {stats['renamed_count']}")
    print(f"Unchanged:               {stats['unchanged_count']}")
    print(f"Collisions Resolved:     {stats['collisions_resolved']}")
    print(f"Top Studios Identified:  {dict(sorted(stats['studios'].items(), key=lambda x: x[1], reverse=True)[:10])}")
    print(f"==============================================\n")

    export_preview(plans, stats, args.preview_csv, args.preview_json)

    if args.apply:
        print("[!] --apply specified: Commencing atomic execution...")
        execute_pipeline(plans, args.ledger, apply_tags=not args.no_tags)
    else:
        print("[+] DRY-RUN MODE: No files were modified. To execute changes, run with --apply.")

if __name__ == "__main__":
    main()
