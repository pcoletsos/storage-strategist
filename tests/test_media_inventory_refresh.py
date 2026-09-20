import os
import sys
import sqlite3
import pytest
import tempfile
import shutil

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from refresh_media_inventory import (
    verify_and_patch_schema,
    create_backup,
    load_undo_ledgers,
    resolve_live_path,
    remap_database_paths,
    sync_visual_cache,
    reconcile_filesystem_and_purge,
    run_validation_queries,
    refresh_media_inventory,
    CANONICAL_ROOTS
)

@pytest.fixture
def temp_env():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "media_inventory.db")
    undo_path = os.path.join(temp_dir, "undo_ledger.db")
    dir_undo_path = os.path.join(temp_dir, "dir_undo_ledger.db")
    visual_path = os.path.join(temp_dir, "visual_cache.db")

    # Initialize media_inventory.db with base columns only (simulate legacy schema)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            directory TEXT,
            filename TEXT,
            extension TEXT,
            media_type TEXT,
            file_size INTEGER,
            mtime REAL,
            v_codec TEXT,
            a_codec TEXT,
            width INTEGER,
            height INTEGER,
            duration REAL,
            bitrate INTEGER,
            resolution_tier TEXT,
            existing_title TEXT,
            existing_artist TEXT,
            existing_date TEXT,
            existing_comment TEXT,
            exif_datetime TEXT,
            exif_artist TEXT,
            scanned_at TEXT,
            error TEXT
        )
    """)
    conn.commit()
    conn.close()

    # Initialize undo_ledger.db
    u_conn = sqlite3.connect(undo_path)
    u_conn.execute("""
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT,
            target_path TEXT,
            original_mtime REAL,
            file_size INTEGER,
            executed_at TEXT,
            status TEXT
        )
    """)
    u_conn.commit()
    u_conn.close()

    # Initialize dir_undo_ledger.db
    d_conn = sqlite3.connect(dir_undo_path)
    d_conn.execute("""
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_path TEXT,
            target_path TEXT,
            operation_type TEXT,
            original_mtime REAL,
            file_size INTEGER,
            executed_at TEXT,
            status TEXT
        )
    """)
    d_conn.commit()
    d_conn.close()

    # Initialize visual_cache.db
    v_conn = sqlite3.connect(visual_path)
    v_conn.execute("""
        CREATE TABLE visual_enrichment_cache (
            file_path TEXT PRIMARY KEY,
            oshash TEXT,
            file_size INTEGER,
            duration REAL,
            detected_studio TEXT,
            detected_performers TEXT,
            detected_title TEXT,
            detected_date TEXT,
            confidence REAL,
            method TEXT,
            details_json TEXT,
            processed_at TEXT
        )
    """)
    v_conn.commit()
    v_conn.close()

    yield {
        "dir": temp_dir,
        "db": db_path,
        "undo": undo_path,
        "dir_undo": dir_undo_path,
        "visual": visual_path
    }

    shutil.rmtree(temp_dir, ignore_errors=True)

def test_verify_and_patch_schema(temp_env):
    conn = sqlite3.connect(temp_env["db"])
    added = verify_and_patch_schema(conn)
    assert "studio" in added
    assert "confidence_score" in added

    # Running a second time should add nothing
    added_second = verify_and_patch_schema(conn)
    assert len(added_second) == 0
    conn.close()

def test_backup_creation(temp_env):
    backup_file = os.path.join(temp_env["dir"], "backup.bak")
    res = create_backup(temp_env["db"], backup_file)
    assert os.path.exists(res)
    assert os.path.getsize(res) > 0

def test_chained_path_resolution(temp_env):
    undo_map = {
        r"f:\aloha\videos\old_file.mp4": r"F:\Aloha\VIDEOS\[Bangbus] Episode 101 [720p H264].mp4",
        r"f:\aloha\games\game_old.rar": r"F:\Aloha\Games\Clean Game.rar"
    }
    dir_map = {
        r"f:\aloha\videos\[bangbus] episode 101 [720p h264].mp4": r"F:\Aloha\Studios\Bangbus\[Bangbus] Episode 101 [720p H264].mp4",
        r"f:\aloha\magazines.rar": r"F:\Aloha\Magazines & Docs\Archives\Magazines.rar"
    }

    # 1. Chained: old -> renamed -> canonical
    res, method = resolve_live_path(r"F:\Aloha\VIDEOS\old_file.mp4", undo_map, dir_map, verify_fs=False)
    assert res == r"F:\Aloha\Studios\Bangbus\[Bangbus] Episode 101 [720p H264].mp4"
    assert method == "undo+dir"

    # 2. Rename only: old -> renamed
    res, method = resolve_live_path(r"F:\Aloha\Games\game_old.rar", undo_map, dir_map, verify_fs=False)
    assert res == r"F:\Aloha\Games\Clean Game.rar"
    assert method == "undo"

    # 3. Direct dir move: old -> canonical
    res, method = resolve_live_path(r"F:\Aloha\Magazines.rar", undo_map, dir_map, verify_fs=False)
    assert res == r"F:\Aloha\Magazines & Docs\Archives\Magazines.rar"
    assert method == "dir"

    # 4. Unresolved fallback
    res, method = resolve_live_path(r"F:\Aloha\Unknown.mp4", undo_map, dir_map, verify_fs=False)
    assert res == r"F:\Aloha\Unknown.mp4"
    assert method == "direct"

def test_remap_database_paths(temp_env):
    conn = sqlite3.connect(temp_env["db"])
    verify_and_patch_schema(conn)

    # Populate mock files in temp directory
    p1 = os.path.join(temp_env["dir"], "p1.mp4")
    p2 = os.path.join(temp_env["dir"], "p2.mp4")
    with open(p1, "wb") as f: f.write(b"data1")
    with open(p2, "wb") as f: f.write(b"data2")

    conn.execute(
        "INSERT INTO media_files (file_path, directory, filename) VALUES (?, ?, ?)",
        ("F:\\Aloha\\VIDEOS\\old1.mp4", "F:\\Aloha\\VIDEOS", "old1.mp4")
    )
    conn.commit()

    undo_map = {"f:\\aloha\\videos\\old1.mp4": p1}
    dir_map = {}

    stats = remap_database_paths(conn, undo_map, dir_map, dry_run=False)
    assert stats["updated"] == 1

    cur = conn.cursor()
    cur.execute("SELECT file_path, directory, filename FROM media_files WHERE id = 1")
    row = cur.fetchone()
    assert row[0] == p1
    assert row[1] == os.path.dirname(p1)
    assert row[2] == os.path.basename(p1)
    conn.close()

def test_sync_visual_cache(temp_env):
    conn = sqlite3.connect(temp_env["db"])
    verify_and_patch_schema(conn)

    fpath = "F:\\Aloha\\Studios\\Brazzers\\[Brazzers] Scene 1.mp4"
    conn.execute(
        "INSERT INTO media_files (file_path, directory, filename) VALUES (?, ?, ?)",
        (fpath, "F:\\Aloha\\Studios\\Brazzers", "[Brazzers] Scene 1.mp4")
    )
    conn.commit()

    # Populate visual cache
    v_conn = sqlite3.connect(temp_env["visual"])
    v_conn.execute(
        """
        INSERT INTO visual_enrichment_cache (
            file_path, detected_studio, confidence, detected_title, detected_performers, detected_date
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (fpath, "Brazzers", 0.95, "Scene 1", '["Angela White"]', "2021-01-01")
    )
    v_conn.commit()
    v_conn.close()

    stats = sync_visual_cache(conn, temp_env["visual"], {}, {}, dry_run=False)
    assert stats["matched_assets"] == 1
    assert stats["studio_updated"] == 1

    cur = conn.cursor()
    cur.execute("SELECT studio, confidence_score, existing_artist FROM media_files WHERE id = 1")
    row = cur.fetchone()
    assert row[0] == "Brazzers"
    assert row[1] == 0.95
    assert row[2] == "Angela White"
    conn.close()

def test_validation_queries(temp_env):
    conn = sqlite3.connect(temp_env["db"])
    verify_and_patch_schema(conn)

    # Insert 3 records: 2 in canonical roots, 1 with legacy folder
    conn.execute(
        """
        INSERT INTO media_files (file_path, directory, filename, file_size, studio)
        VALUES 
        ('F:\\Aloha\\Studios\\Brazzers\\s1.mp4', 'F:\\Aloha\\Studios\\Brazzers', 's1.mp4', 1048576, 'Brazzers'),
        ('F:\\Aloha\\Movies\\Feature.mp4', 'F:\\Aloha\\Movies', 'Feature.mp4', 2097152, NULL),
        ('F:\\Aloha\\VIDEOS\\Legacy.mp4', 'F:\\Aloha\\VIDEOS', 'Legacy.mp4', 524288, NULL)
        """
    )
    conn.commit()

    val = run_validation_queries(conn)
    assert val["total_records"] == 3
    assert val["studio_enriched_records"] == 1
    assert val["legacy_path_records"] == 1

    roots = {r["root_folder"]: r["asset_count"] for r in val["root_distribution"]}
    assert roots.get("Studios") == 1
    assert roots.get("Movies") == 1
    conn.close()

def test_reconcile_filesystem_and_purge(temp_env):
    conn = sqlite3.connect(temp_env["db"])
    verify_and_patch_schema(conn)

    # File 1 exists on disk
    f1 = os.path.join(temp_env["dir"], "exist.mp4")
    with open(f1, "wb") as f: f.write(b"video")

    # File 2 is missing from disk
    f2_missing = os.path.join(temp_env["dir"], "nonexistent.mp4")

    # File 3 is untracked on disk
    f3_untracked = os.path.join(temp_env["dir"], "untracked.jpg")
    with open(f3_untracked, "wb") as f: f.write(b"image")

    conn.execute(
        "INSERT INTO media_files (file_path, directory, filename) VALUES (?, ?, ?), (?, ?, ?)",
        (f1, temp_env["dir"], "exist.mp4", f2_missing, temp_env["dir"], "nonexistent.mp4")
    )
    conn.commit()

    stats = reconcile_filesystem_and_purge(
        conn, temp_env["dir"], max_workers=2, force_purge=True, dry_run=False
    )

    assert stats["stale_records_found"] == 1
    assert stats["stale_records_purged"] == 1
    assert stats["untracked_discovered"] == 1

    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM media_files")
    # Total should be: 2 (1 existing kept + 1 untracked inserted, 1 stale deleted)
    assert cur.fetchone()[0] == 2
    conn.close()


def test_reconcile_skips_quarantine_directory(temp_env):
    conn = sqlite3.connect(temp_env["db"])
    verify_and_patch_schema(conn)

    # Active file exists on disk
    f_active = os.path.join(temp_env["dir"], "active.mp4")
    with open(f_active, "wb") as f:
        f.write(b"active video")

    # Staged file inside .quarantine_duplicates
    quar_dir = os.path.join(temp_env["dir"], ".quarantine_duplicates", "cluster_001")
    os.makedirs(quar_dir, exist_ok=True)
    f_quar = os.path.join(quar_dir, "duplicate.mp4")
    with open(f_quar, "wb") as f:
        f.write(b"quarantined video")

    # DB record for stale original path
    stale_path = os.path.join(temp_env["dir"], "old_location", "duplicate.mp4")

    conn.execute(
        "INSERT INTO media_files (file_path, directory, filename) VALUES (?, ?, ?), (?, ?, ?)",
        (f_active, temp_env["dir"], "active.mp4", stale_path, os.path.join(temp_env["dir"], "old_location"), "duplicate.mp4")
    )
    conn.commit()

    stats = reconcile_filesystem_and_purge(
        conn, temp_env["dir"], max_workers=2, force_purge=True, dry_run=False
    )

    assert stats["stale_records_found"] == 1
    assert stats["stale_records_purged"] == 1
    # The file in .quarantine_duplicates must be completely ignored
    assert stats["untracked_discovered"] == 0

    cur = conn.cursor()
    cur.execute("SELECT file_path FROM media_files")
    paths = [r[0] for r in cur.fetchall()]
    assert len(paths) == 1
    assert paths[0] == f_active
    conn.close()


def test_refresh_media_inventory_reconcile_only(temp_env):
    report_file = os.path.join(temp_env["dir"], "test_report.json")
    backup_file = os.path.join(temp_env["dir"], "test_backup.bak")

    # Put an active file
    f_active = os.path.join(temp_env["dir"], "active.mp4")
    with open(f_active, "wb") as f:
        f.write(b"active video")

    # Put a stale entry in db
    conn = sqlite3.connect(temp_env["db"])
    verify_and_patch_schema(conn)
    stale_path = os.path.join(temp_env["dir"], "gone.mp4")
    conn.execute(
        "INSERT INTO media_files (file_path, directory, filename) VALUES (?, ?, ?)",
        (stale_path, temp_env["dir"], "gone.mp4")
    )
    conn.commit()
    conn.close()

    report = refresh_media_inventory(
        db_path=temp_env["db"],
        target_root=temp_env["dir"],
        undo_ledger_path=temp_env["undo"],
        dir_undo_ledger_path=temp_env["dir_undo"],
        visual_cache_path=temp_env["visual"],
        backup_path=backup_file,
        workers=2,
        dry_run=False,
        force_purge=True,
        reconcile_only=True,
        report_path=report_file
    )

    assert os.path.exists(report_file)
    assert report["filesystem_reconciliation"]["stale_records_purged"] == 1
    assert report["filesystem_reconciliation"]["untracked_discovered"] == 1
    # Ledgers and container tags should have been skipped
    assert report["path_realignment"]["total"] == 0
    assert report["container_tags"]["mp4_files_scanned"] == 0



