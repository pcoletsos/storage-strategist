import os
import re
import sys
import time
import json
import shutil
import sqlite3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple, Set

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_inventory_scanner import VIDEO_EXTS, IMAGE_EXTS, scan_worker, get_ffprobe_path

CANONICAL_ROOTS = [
    "Studios",
    "Movies",
    "Celebrities",
    "Collections & Siterips",
    "Photos & Sets",
    "Games",
    "Magazines & Docs"
]

LEGACY_FOLDERS = [
    "VIDEOS",
    "siterips",
    "temp",
    "Bangbus ALL 2010",
    "Bangbus ALL 2010 videos 720p",
    "Brazzers",
    "DigitalPlayground",
    "Torrents",
    "Celeb",
    "girls",
    "GIF",
    "L & S"
]

EXPECTED_COLUMNS = [
    ("id", "INTEGER"),
    ("file_path", "TEXT"),
    ("directory", "TEXT"),
    ("filename", "TEXT"),
    ("extension", "TEXT"),
    ("media_type", "TEXT"),
    ("file_size", "INTEGER"),
    ("mtime", "REAL"),
    ("v_codec", "TEXT"),
    ("a_codec", "TEXT"),
    ("width", "INTEGER"),
    ("height", "INTEGER"),
    ("duration", "REAL"),
    ("bitrate", "INTEGER"),
    ("resolution_tier", "TEXT"),
    ("existing_title", "TEXT"),
    ("existing_artist", "TEXT"),
    ("existing_date", "TEXT"),
    ("existing_comment", "TEXT"),
    ("exif_datetime", "TEXT"),
    ("exif_artist", "TEXT"),
    ("scanned_at", "TEXT"),
    ("error", "TEXT"),
    ("studio", "TEXT"),
    ("confidence_score", "REAL")
]

def verify_and_patch_schema(conn: sqlite3.Connection) -> List[str]:
    """Ensures media_files exists and contains all base, metadata, and additive columns."""
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='media_files'")
    if not cur.fetchone():
        raise RuntimeError("Table 'media_files' does not exist in target database.")

    cur.execute("PRAGMA table_info(media_files)")
    existing_cols = {row[1].lower(): row[2] for row in cur.fetchall()}

    added = []
    for col_name, col_type in EXPECTED_COLUMNS:
        if col_name.lower() not in existing_cols:
            conn.execute(f"ALTER TABLE media_files ADD COLUMN {col_name} {col_type}")
            added.append(col_name)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_media_file_path ON media_files(file_path);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_media_directory ON media_files(directory);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_media_studio ON media_files(studio);")
    return added

def create_backup(db_path: str, backup_path: str) -> str:
    """Creates an atomic backup copy of the target database."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")
    
    # Use SQLite backup API for atomic snapshot
    src_conn = sqlite3.connect(db_path)
    dst_conn = sqlite3.connect(backup_path)
    with dst_conn:
        src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()
    return backup_path

def load_undo_ledgers(
    undo_ledger_path: str,
    dir_undo_ledger_path: str
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Loads file rename and directory restructure transaction maps."""
    undo_map: Dict[str, str] = {}
    dir_map: Dict[str, str] = {}

    if os.path.exists(undo_ledger_path):
        conn = sqlite3.connect(undo_ledger_path)
        cur = conn.cursor()
        for orig, tgt in cur.execute("SELECT original_path, target_path FROM transactions WHERE status='completed'"):
            if orig and tgt:
                undo_map[orig.lower()] = tgt
        conn.close()

    if os.path.exists(dir_undo_ledger_path):
        conn = sqlite3.connect(dir_undo_ledger_path)
        cur = conn.cursor()
        for src, tgt in cur.execute("SELECT source_path, target_path FROM transactions WHERE status='completed'"):
            if src and tgt:
                dir_map[src.lower()] = tgt
        conn.close()

    return undo_map, dir_map

def normalize_canonical_path(path: str) -> str:
    """Standardizes casing of the 7 canonical roots under F:\\Aloha."""
    prefix = r"F:\Aloha"
    if path.lower().startswith(prefix.lower() + "\\"):
        rest = path[len(prefix) + 1:]
        parts = rest.split("\\", 1)
        root_name = parts[0]
        for c_root in CANONICAL_ROOTS:
            if root_name.lower() == c_root.lower():
                if len(parts) > 1:
                    return f"{prefix}\\{c_root}\\{parts[1]}"
                else:
                    return f"{prefix}\\{c_root}"
    return path

def resolve_live_path(
    path: str,
    undo_map: Dict[str, str],
    dir_map: Dict[str, str],
    verify_fs: bool = True
) -> Tuple[str, str]:
    """Resolves a pre-rename or pre-restructure path to live disk path.
    
    Returns:
        Tuple of (resolved_path, resolution_method)
    """
    p_low = path.lower()

    # If verify_fs is True and original path already exists on disk, keep it
    if verify_fs and os.path.exists(path):
        return normalize_canonical_path(path), "direct"

    # Step 1: Check file-level rename
    renamed = undo_map.get(p_low)
    if renamed:
        # Step 2: Check if renamed file also underwent directory move
        dir_moved = dir_map.get(renamed.lower())
        if dir_moved:
            if not verify_fs or os.path.exists(dir_moved):
                return normalize_canonical_path(dir_moved), "undo+dir"
        if not verify_fs or os.path.exists(renamed):
            return normalize_canonical_path(renamed), "undo"

    # Step 3: Check directory move directly (without file rename)
    dir_moved_direct = dir_map.get(p_low)
    if dir_moved_direct:
        if not verify_fs or os.path.exists(dir_moved_direct):
            return normalize_canonical_path(dir_moved_direct), "dir"

    # Fallback to direct path
    return normalize_canonical_path(path), "unresolved" if verify_fs else "direct"

def remap_database_paths(
    conn: sqlite3.Connection,
    undo_map: Dict[str, str],
    dir_map: Dict[str, str],
    dry_run: bool = False
) -> Dict[str, Any]:
    """Remaps file_path, directory, and filename in media_files using chained ledgers."""
    cur = conn.cursor()
    cur.execute("SELECT id, file_path FROM media_files")
    rows = cur.fetchall()

    updates: List[Tuple[str, str, str, int]] = []
    stats = {
        "total": len(rows),
        "direct": 0,
        "undo": 0,
        "undo+dir": 0,
        "dir": 0,
        "unresolved": 0,
        "updated": 0
    }

    for row_id, old_path in rows:
        live_path, method = resolve_live_path(old_path, undo_map, dir_map, verify_fs=True)
        stats[method] = stats.get(method, 0) + 1

        if live_path != old_path:
            new_dir = os.path.dirname(live_path)
            new_fname = os.path.basename(live_path)
            updates.append((live_path, new_dir, new_fname, row_id))

    stats["updated"] = len(updates)

    if not dry_run and updates:
        with conn:
            conn.executemany(
                """
                UPDATE media_files
                SET file_path = ?, directory = ?, filename = ?
                WHERE id = ?
                """,
                updates
            )

    return stats

def sync_visual_cache(
    conn: sqlite3.Connection,
    visual_cache_path: str,
    undo_map: Dict[str, str],
    dir_map: Dict[str, str],
    dry_run: bool = False
) -> Dict[str, Any]:
    """Synchronizes detected studio, confidence, and metadata from visual_enrichment_cache.db."""
    stats = {
        "total_cache_entries": 0,
        "matched_assets": 0,
        "studio_updated": 0,
        "metadata_updated": 0
    }

    if not os.path.exists(visual_cache_path):
        return stats

    v_conn = sqlite3.connect(visual_cache_path)
    v_cur = v_conn.cursor()
    v_rows = v_cur.execute("""
        SELECT file_path, detected_studio, confidence, detected_title, detected_performers, detected_date
        FROM visual_enrichment_cache
    """).fetchall()
    v_conn.close()

    stats["total_cache_entries"] = len(v_rows)
    cur = conn.cursor()

    # Build lookup of lower(file_path) -> id
    path_to_id: Dict[str, int] = {}
    for r in cur.execute("SELECT id, file_path FROM media_files"):
        path_to_id[r[1].lower()] = r[0]

    updates: List[Tuple[Any, ...]] = []
    for fpath, studio, conf, title, perfs, date in v_rows:
        # Resolve path to canonical live location
        live_path, _ = resolve_live_path(fpath, undo_map, dir_map, verify_fs=False)
        rec_id = path_to_id.get(live_path.lower()) or path_to_id.get(fpath.lower())

        if rec_id:
            stats["matched_assets"] += 1
            if studio and conf and conf > 0:
                stats["studio_updated"] += 1

            perf_str = None
            if perfs:
                try:
                    perf_list = json.loads(perfs)
                    if isinstance(perf_list, list) and perf_list:
                        perf_str = ", ".join(perf_list)
                except Exception:
                    pass

            if title or perf_str or date:
                stats["metadata_updated"] += 1

            updates.append((studio, conf, title, perf_str, date, rec_id))

    if not dry_run and updates:
        with conn:
            conn.executemany(
                """
                UPDATE media_files
                SET studio = COALESCE(?, studio),
                    confidence_score = COALESCE(?, confidence_score),
                    existing_title = CASE WHEN existing_title IS NULL OR existing_title = '' THEN COALESCE(?, existing_title) ELSE existing_title END,
                    existing_artist = CASE WHEN existing_artist IS NULL OR existing_artist = '' THEN COALESCE(?, existing_artist) ELSE existing_artist END,
                    existing_date = CASE WHEN existing_date IS NULL OR existing_date = '' THEN COALESCE(?, existing_date) ELSE existing_date END
                WHERE id = ?
                """,
                updates
            )

    return stats

def extract_mp4_tags_worker(file_path: str) -> Optional[Dict[str, Any]]:
    """Extracts MP4 container tags using mutagen."""
    try:
        from mutagen.mp4 import MP4
        mp4 = MP4(file_path)
        title = mp4.get("\xa9nam", [None])[0]
        artist = mp4.get("\xa9ART", [None])[0]
        date = mp4.get("\xa9day", [None])[0]
        comment = mp4.get("\xa9cmt", [None])[0]

        if title or artist or date or comment:
            return {
                "file_path": file_path,
                "title": str(title) if title else None,
                "artist": str(artist) if artist else None,
                "date": str(date) if date else None,
                "comment": str(comment) if comment else None
            }
    except Exception:
        pass
    return None

def sync_container_tags(
    conn: sqlite3.Connection,
    root_target: str,
    max_workers: int = 16,
    dry_run: bool = False
) -> Dict[str, Any]:
    """Reads container tags from MP4/M4V files on disk and synchronizes with media_files."""
    stats = {
        "mp4_files_scanned": 0,
        "tagged_files_found": 0,
        "database_records_updated": 0
    }

    # Gather live MP4 files from database
    cur = conn.cursor()
    cur.execute("""
        SELECT id, file_path
        FROM media_files
        WHERE extension IN ('.mp4', '.m4v')
    """)
    mp4_records = cur.fetchall()
    stats["mp4_files_scanned"] = len(mp4_records)

    path_to_id = {r[1].lower(): r[0] for r in mp4_records}
    all_paths = [r[1] for r in mp4_records if os.path.exists(r[1])]

    updates: List[Tuple[Optional[str], Optional[str], Optional[str], Optional[str], int]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(extract_mp4_tags_worker, p): p for p in all_paths}
        for future in as_completed(futures):
            res = future.result()
            if res:
                stats["tagged_files_found"] += 1
                rec_id = path_to_id.get(res["file_path"].lower())
                if rec_id:
                    updates.append((
                        res["title"],
                        res["artist"],
                        res["date"],
                        res["comment"],
                        rec_id
                    ))

    stats["database_records_updated"] = len(updates)

    if not dry_run and updates:
        with conn:
            conn.executemany(
                """
                UPDATE media_files
                SET existing_title = COALESCE(?, existing_title),
                    existing_artist = COALESCE(?, existing_artist),
                    existing_date = COALESCE(?, existing_date),
                    existing_comment = COALESCE(?, existing_comment)
                WHERE id = ?
                """,
                updates
            )

    return stats

def reconcile_filesystem_and_purge(
    conn: sqlite3.Connection,
    target_root: str,
    max_workers: int = 16,
    force_purge: bool = False,
    dry_run: bool = False
) -> Dict[str, Any]:
    """Scans filesystem for untracked media assets and identifies/purges stale records."""
    cur = conn.cursor()
    cur.execute("SELECT id, file_path FROM media_files")
    db_rows = cur.fetchall()

    db_path_set = {r[1].lower(): r[0] for r in db_rows}
    stats = {
        "total_db_records": len(db_rows),
        "fs_videos": 0,
        "fs_images": 0,
        "fs_total_media": 0,
        "untracked_discovered": 0,
        "stale_records_found": 0,
        "stale_records_purged": 0
    }

    # Step 1: Detect stale records
    stale_ids = []
    for row_id, fpath in db_rows:
        if not os.path.exists(fpath):
            stale_ids.append(row_id)

    stats["stale_records_found"] = len(stale_ids)
    if stale_ids and force_purge and not dry_run:
        with conn:
            conn.executemany("DELETE FROM media_files WHERE id = ?", [(i,) for i in stale_ids])
        stats["stale_records_purged"] = len(stale_ids)

    # Step 2: Walk filesystem for untracked assets
    ffprobe_bin = get_ffprobe_path()
    untracked_files = []

    for root, _, files in os.walk(target_root):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in VIDEO_EXTS:
                stats["fs_videos"] += 1
            elif ext in IMAGE_EXTS:
                stats["fs_images"] += 1
            else:
                continue

            stats["fs_total_media"] += 1
            full_path = os.path.join(root, f)
            if full_path.lower() not in db_path_set:
                untracked_files.append(full_path)

    stats["untracked_discovered"] = len(untracked_files)

    # Probe and insert any untracked files
    if untracked_files and not dry_run:
        new_records = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_worker, p, ffprobe_bin): p for p in untracked_files}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    new_records.append(res)

        if new_records:
            insert_sql = """
                INSERT OR REPLACE INTO media_files (
                    file_path, directory, filename, extension, media_type,
                    file_size, mtime, v_codec, a_codec, width, height,
                    duration, bitrate, resolution_tier, existing_title,
                    existing_artist, existing_date, existing_comment,
                    exif_datetime, exif_artist, scanned_at, error
                ) VALUES (
                    :file_path, :directory, :filename, :extension, :media_type,
                    :file_size, :mtime, :v_codec, :a_codec, :width, :height,
                    :duration, :bitrate, :resolution_tier, :existing_title,
                    :existing_artist, :existing_date, :existing_comment,
                    :exif_datetime, :exif_artist, :scanned_at, :error
                )
            """
            with conn:
                conn.executemany(insert_sql, new_records)

    return stats

def run_validation_queries(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Executes validation queries to confirm data integrity."""
    cur = conn.cursor()

    # Query 1: Distribution across canonical roots
    root_query = """
        SELECT 
            substr(directory, 10, instr(substr(directory, 10) || '\\', '\\') - 1) as root_folder,
            count(*) as asset_count,
            round(sum(file_size) / (1024.0 * 1024.0 * 1024.0), 2) as size_gb
        FROM media_files
        GROUP BY root_folder
        ORDER BY asset_count DESC;
    """
    root_distribution = []
    for r in cur.execute(root_query).fetchall():
        root_distribution.append({
            "root_folder": r[0] if r[0] else "(Root)",
            "asset_count": r[1],
            "size_gb": r[2] or 0.0
        })

    # Query 2: Legacy path check (obsolete top-level folders directly under Aloha root)
    legacy_patterns = [f"%\\Aloha\\{folder}\\%" for folder in LEGACY_FOLDERS] + [f"%\\Aloha\\{folder}" for folder in LEGACY_FOLDERS]
    placeholders = " OR ".join(["directory LIKE ?" for _ in legacy_patterns])
    legacy_query = f"SELECT count(*) FROM media_files WHERE {placeholders}"
    cur.execute(legacy_query, legacy_patterns)
    legacy_count = cur.fetchone()[0]

    # Query 3: Total record count
    cur.execute("SELECT count(*) FROM media_files")
    total_records = cur.fetchone()[0]

    # Query 4: Studio enrichment count
    cur.execute("SELECT count(*) FROM media_files WHERE studio IS NOT NULL")
    studio_records = cur.fetchone()[0]

    # Query 5: Tagged MP4 count
    cur.execute("""
        SELECT count(*) FROM media_files 
        WHERE extension IN ('.mp4', '.m4v') 
          AND (existing_title IS NOT NULL OR existing_artist IS NOT NULL OR existing_date IS NOT NULL OR existing_comment IS NOT NULL)
    """)
    tagged_mp4s = cur.fetchone()[0]

    return {
        "total_records": total_records,
        "legacy_path_records": legacy_count,
        "studio_enriched_records": studio_records,
        "tagged_mp4_records": tagged_mp4s,
        "root_distribution": root_distribution
    }

def refresh_media_inventory(
    db_path: str = "media_inventory.db",
    target_root: str = r"F:\Aloha",
    undo_ledger_path: str = "undo_ledger.db",
    dir_undo_ledger_path: str = "dir_undo_ledger.db",
    visual_cache_path: str = "visual_enrichment_cache.db",
    backup_path: str = "media_inventory_pre_refresh.bak",
    workers: int = 16,
    dry_run: bool = False,
    force_purge: bool = False,
    report_path: str = "media_inventory_refresh_report.json"
) -> Dict[str, Any]:
    """Orchestrates the 5-step media inventory refresh and synchronization."""
    t_start = time.time()
    print("=" * 70)
    print("      MEDIA INVENTORY DATABASE REFRESH & CANONICAL SYNCHRONIZATION")
    print("=" * 70)
    print(f"Target Directory:      {target_root}")
    print(f"SQLite Inventory DB:   {db_path}")
    print(f"File Rename Ledger:    {undo_ledger_path}")
    print(f"Dir Restructure Ledger:{dir_undo_ledger_path}")
    print(f"Visual Cache DB:       {visual_cache_path}")
    print(f"Dry Run:               {dry_run}")
    print("=" * 70)

    active_db_path = db_path
    temp_dryrun_path = None

    if dry_run:
        import tempfile
        temp_dryrun_path = os.path.join(tempfile.gettempdir(), f"media_inventory_dryrun_{int(time.time())}.db")
        shutil.copy2(db_path, temp_dryrun_path)
        active_db_path = temp_dryrun_path
        print(f"[*] Dry-run simulation sandbox initialized at '{temp_dryrun_path}'.")
    else:
        # Step 1: Safety Snapshot
        print("\n[*] Step 1: Safety Snapshot and Schema Verification...")
        if backup_path:
            create_backup(db_path, backup_path)
            print(f"[+] Created safety backup snapshot at '{backup_path}'.")

    conn = sqlite3.connect(active_db_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")

    added_cols = verify_and_patch_schema(conn)
    if added_cols:
        print(f"[+] Additive columns provisioned: {added_cols}")
    else:
        print("[+] Schema verified. All base, tag, and additive columns present.")

    # Step 2: Transactional Path Alignment via Ledgers
    print("\n[*] Step 2: Chained Ledger Path Realignment...")
    undo_map, dir_map = load_undo_ledgers(undo_ledger_path, dir_undo_ledger_path)
    print(f"[+] Loaded {len(undo_map):,} file-rename and {len(dir_map):,} dir-move mappings.")

    path_stats = remap_database_paths(conn, undo_map, dir_map, dry_run=False)
    print(f"[+] Path Realignment Results ({path_stats['total']:,} total records):")
    print(f"    - Direct disk matches:    {path_stats['direct']:>6,}")
    print(f"    - Via file rename:        {path_stats['undo']:>6,}")
    print(f"    - Via rename + dir move:  {path_stats['undo+dir']:>6,}")
    print(f"    - Via direct dir move:    {path_stats['dir']:>6,}")
    print(f"    - Unresolved:             {path_stats['unresolved']:>6,}")
    print(f"    - Total database updates: {path_stats['updated']:>6,}")

    # Step 3: Container Tag and Visual Metadata Sync
    print("\n[*] Step 3: Container Tag and Visual Metadata Sync...")
    visual_stats = sync_visual_cache(conn, visual_cache_path, undo_map, dir_map, dry_run=False)
    print(f"[+] Visual Cache Ingestion:")
    print(f"    - Entries processed:      {visual_stats['total_cache_entries']:>6,}")
    print(f"    - Assets matched in DB:   {visual_stats['matched_assets']:>6,}")
    print(f"    - Studio values updated:  {visual_stats['studio_updated']:>6,}")
    print(f"    - Metadata fields synced: {visual_stats['metadata_updated']:>6,}")

    tag_stats = sync_container_tags(conn, target_root, max_workers=workers, dry_run=False)
    print(f"[+] MP4 Container Tag Synchronization:")
    print(f"    - Containers checked:     {tag_stats['mp4_files_scanned']:>6,}")
    print(f"    - Tagged containers found:{tag_stats['tagged_files_found']:>6,}")
    print(f"    - DB records enriched:    {tag_stats['database_records_updated']:>6,}")

    # Step 4: Filesystem Scan for Untracked Assets and Stale Record Purge
    print("\n[*] Step 4: Filesystem Reconciliation and Audit...")
    audit_stats = reconcile_filesystem_and_purge(
        conn, target_root, max_workers=workers, force_purge=force_purge, dry_run=False
    )
    print(f"[+] Filesystem Reconciliation:")
    print(f"    - Physical media files:   {audit_stats['fs_total_media']:>6,} ({audit_stats['fs_videos']:,} video, {audit_stats['fs_images']:,} image)")
    print(f"    - Untracked discovered:   {audit_stats['untracked_discovered']:>6,}")
    print(f"    - Stale records found:    {audit_stats['stale_records_found']:>6,}")
    print(f"    - Stale records purged:   {audit_stats['stale_records_purged']:>6,}")

    # Step 5: Validation and Consistency Queries
    print("\n[*] Step 5: Consistency Validation Queries...")
    validation = run_validation_queries(conn)
    print(f"[+] Total Database Records:    {validation['total_records']:,}")
    print(f"[+] Legacy Path Violations:    {validation['legacy_path_records']:,}")
    print(f"[+] Studio-Enriched Records:   {validation['studio_enriched_records']:,}")
    print(f"[+] Tagged MP4 Records:        {validation['tagged_mp4_records']:,}")
    print("\n[+] Canonical Root Distribution:")
    for root_info in validation["root_distribution"]:
        print(f"    - {root_info['root_folder']:<25}: {root_info['asset_count']:>6,} assets ({root_info['size_gb']:>7.2f} GB)")

    conn.close()

    if temp_dryrun_path:
        for ext in ("", "-wal", "-shm"):
            try:
                os.remove(temp_dryrun_path + ext)
            except Exception:
                pass
        print(f"\n[+] Dry-run sandbox successfully removed. Original '{db_path}' remains untouched.")

    elapsed = time.time() - t_start
    print("\n" + "=" * 70)
    print(f"[+] Refresh completed successfully in {elapsed:.2f} seconds!")
    print("=" * 70)

    report_data = {
        "execution_time_seconds": round(elapsed, 2),
        "target_directory": target_root,
        "database_path": db_path,
        "dry_run": dry_run,
        "path_realignment": path_stats,
        "visual_enrichment": visual_stats,
        "container_tags": tag_stats,
        "filesystem_reconciliation": audit_stats,
        "validation": validation
    }

    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Synchronization report saved to '{report_path}'.")

    return report_data

def main():
    parser = argparse.ArgumentParser(description="Media Inventory Database Refresh & Canonical Synchronization")
    parser.add_argument("--db", default="media_inventory.db", help="Path to SQLite inventory DB")
    parser.add_argument("--target", default=r"F:\Aloha", help="Target root directory")
    parser.add_argument("--undo-ledger", default="undo_ledger.db", help="Path to file rename undo ledger")
    parser.add_argument("--dir-undo-ledger", default="dir_undo_ledger.db", help="Path to dir restructure undo ledger")
    parser.add_argument("--visual-cache", default="visual_enrichment_cache.db", help="Path to visual enrichment cache")
    parser.add_argument("--backup", default="media_inventory_pre_refresh.bak", help="Safety backup destination")
    parser.add_argument("--workers", type=int, default=16, help="Worker threads for container tagging/scanning")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without modifying DB")
    parser.add_argument("--force-purge", action="store_true", help="Purge confirmed stale records")
    parser.add_argument("--report", default="media_inventory_refresh_report.json", help="Path for output JSON report")
    args = parser.parse_args()

    refresh_media_inventory(
        db_path=args.db,
        target_root=args.target,
        undo_ledger_path=args.undo_ledger,
        dir_undo_ledger_path=args.dir_undo_ledger,
        visual_cache_path=args.visual_cache,
        backup_path=args.backup,
        workers=args.workers,
        dry_run=args.dry_run,
        force_purge=args.force_purge,
        report_path=args.report
    )

if __name__ == "__main__":
    main()
