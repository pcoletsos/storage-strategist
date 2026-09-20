"""Unit tests for find_media_duplicates.py deduplication pipeline.

Validates partial and full SHA-256 calculation, BK-Tree Hamming distance metric
indexing, master selection hierarchy, quarantine staging and rollback
round-trip, game isolation safety guardrails, and ledger transactions.
"""

import os
import sys
import sqlite3
import tempfile
import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from find_media_duplicates import (
    compute_partial_hash,
    compute_full_hash,
    BKTree,
    DisjointSet,
    select_exact_master,
    select_image_master,
    select_video_master,
    is_game_path,
    init_ledger,
    execute_quarantine,
    execute_rollback,
    find_exact_duplicates,
)


def test_partial_and_full_sha256(tmp_path):
    """Verifies fast partial hash rejection and full SHA-256 accuracy."""
    # Create two identical files with >65536 byte headers and footers
    data_a = b"HEADER_DATA_" * 6000 + b"MIDDLE_DATA_" * 5000 + b"FOOTER_DATA_" * 6000
    file_1 = tmp_path / "file1.bin"
    file_2 = tmp_path / "file2.bin"
    file_1.write_bytes(data_a)
    file_2.write_bytes(data_a)

    # Create a third file with identical header & footer, but different middle
    data_b = b"HEADER_DATA_" * 6000 + b"DIFFERENT___" * 5000 + b"FOOTER_DATA_" * 6000
    file_3 = tmp_path / "file3.bin"
    file_3.write_bytes(data_b)

    # Partial hashes: 1 and 2 match; 1 and 3 also match (since first/last 64KB match)
    p1 = compute_partial_hash(str(file_1))
    p2 = compute_partial_hash(str(file_2))
    p3 = compute_partial_hash(str(file_3))
    assert p1 == p2
    assert p1 == p3

    # Full hashes: 1 and 2 match; 3 differs
    f1 = compute_full_hash(str(file_1))
    f2 = compute_full_hash(str(file_2))
    f3 = compute_full_hash(str(file_3))
    assert f1 == f2
    assert f1 != f3


def test_bk_tree_hamming_search():
    """Verifies BK-Tree metric space indexing and threshold querying."""
    tree = BKTree()
    # 64-bit integer hashes
    h_root = 0x0000000000000000
    h_dist1 = 0x0000000000000001  # Hamming distance 1
    h_dist3 = 0x0000000000000007  # Hamming distance 3
    h_dist5 = 0x000000000000001F  # Hamming distance 5
    h_far = 0xFFFFFFFFFFFFFFFF    # Hamming distance 64

    tree.add((h_root, "root"))
    tree.add((h_dist1, "dist1"))
    tree.add((h_dist3, "dist3"))
    tree.add((h_dist5, "dist5"))
    tree.add((h_far, "far"))

    # Search with max_dist = 3
    results = tree.find(h_root, max_dist=3)
    found_names = [item[1][1] for item in results]
    assert "root" in found_names
    assert "dist1" in found_names
    assert "dist3" in found_names
    assert "dist5" not in found_names
    assert "far" not in found_names


def test_disjoint_set_clustering():
    """Verifies connected component grouping using DisjointSet."""
    dset = DisjointSet()
    dset.union("fileA", "fileB")
    dset.union("fileB", "fileC")
    dset.union("fileX", "fileY")

    assert dset.find("fileA") == dset.find("fileC")
    assert dset.find("fileA") != dset.find("fileX")


def test_select_image_master():
    """Verifies image master selection prioritizes resolution, then file size."""
    rec_high_res = {
        "file_path": r"F:\Aloha\Photos & Sets\set1\img_4k.jpg",
        "width": 3840,
        "height": 2160,
        "file_size": 4500000,
        "mtime": 1600000000.0,
    }
    rec_low_res = {
        "file_path": r"F:\Aloha\Photos & Sets\set1\img_1080p.jpg",
        "width": 1920,
        "height": 1080,
        "file_size": 2000000,
        "mtime": 1600000000.0,
    }
    rec_compressed = {
        "file_path": r"F:\Aloha\Photos & Sets\set1\img_4k_compressed.jpg",
        "width": 3840,
        "height": 2160,
        "file_size": 1500000,
        "mtime": 1600000000.0,
    }

    master, duplicates = select_image_master([rec_low_res, rec_compressed, rec_high_res])
    assert master["file_path"] == rec_high_res["file_path"]
    assert len(duplicates) == 2


def test_select_video_master():
    """Verifies video master selection prioritizes resolution tier, then bitrate."""
    rec_1080p = {
        "file_path": r"F:\Aloha\Studios\Scene [1080p H264].mp4",
        "resolution_tier": "1080p",
        "bitrate": 6000000,
        "file_size": 800000000,
        "studio": "Brazzers",
    }
    rec_720p = {
        "file_path": r"F:\Aloha\Collections & Siterips\Scene [720p H264].mp4",
        "resolution_tier": "720p",
        "bitrate": 3000000,
        "file_size": 400000000,
        "studio": None,
    }

    master, duplicates = select_video_master([rec_720p, rec_1080p])
    assert master["file_path"] == rec_1080p["file_path"]
    assert len(duplicates) == 1
    assert duplicates[0]["file_path"] == rec_720p["file_path"]


def test_game_isolation_guardrail():
    """Verifies that files under Games are strictly detected and isolated."""
    assert is_game_path(r"F:\Aloha\Games\Cyberpunk\game.exe") is True
    assert is_game_path(r"F:\Aloha\Games\assets\data.pak") is True
    assert is_game_path(r"F:\Aloha\Studios\Scene.mp4") is False
    assert is_game_path(r"F:\Aloha\Photos & Sets\gallery\01.jpg") is False


def test_quarantine_and_rollback_roundtrip(tmp_path):
    """Verifies end-to-end quarantine staging and lossless rollback."""
    # Setup test workspace
    target_dir = tmp_path / "Aloha"
    studios_dir = target_dir / "Studios"
    studios_dir.mkdir(parents=True)

    file_master = studios_dir / "Master.mp4"
    file_dupe = studios_dir / "Duplicate.mp4"
    file_master.write_bytes(b"MASTER_CONTENT_12345")
    file_dupe.write_bytes(b"DUPE_CONTENT_12345")

    ledger_path = tmp_path / "test_ledger.db"
    conn = init_ledger(str(ledger_path))

    cluster = {
        "cluster_id": "cluster_test_001",
        "detection_type": "exact_byte",
        "master_path": str(file_master),
        "duplicate_count": 1,
        "potential_savings_bytes": file_dupe.stat().st_size,
        "duplicates": [
            {
                "original_path": str(file_dupe),
                "file_size": file_dupe.stat().st_size,
                "hash_signature": "sig12345",
                "hamming_distance": 0,
                "original_mtime": file_dupe.stat().st_mtime,
            }
        ],
    }

    # Execute quarantine
    moved = execute_quarantine([cluster], conn, target_dir=str(target_dir))
    assert moved == 1
    assert not file_dupe.exists()
    assert file_master.exists()

    quar_file = target_dir / ".quarantine_duplicates" / "cluster_test_001" / "Duplicate.mp4"
    assert quar_file.exists()

    # Execute rollback
    restored = execute_rollback(conn)
    assert restored == 1
    assert file_dupe.exists()
    assert not quar_file.exists()

    conn.close()


def test_find_exact_duplicates_mock_db(tmp_path):
    """Verifies exact duplicate detection querying SQLite inventory and hashing files."""
    db_path = tmp_path / "mock_inventory.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            file_size INTEGER,
            width INTEGER,
            height INTEGER,
            duration REAL,
            bitrate INTEGER,
            resolution_tier TEXT,
            existing_title TEXT,
            studio TEXT,
            mtime REAL
        )
    """)

    # Create physical files
    file_1 = tmp_path / "file1.mp4"
    file_2 = tmp_path / "file2.mp4"
    file_3 = tmp_path / "file3.mp4"

    content_dup = b"EXACT_MATCHING_BYTES" * 1000
    file_1.write_bytes(content_dup)
    file_2.write_bytes(content_dup)
    file_3.write_bytes(b"UNIQUE_BYTES_ONLY" * 1000)

    conn.execute("INSERT INTO media_files VALUES (1, ?, ?, 1920, 1080, 60.0, 5000, '1080p', 'Title 1', 'StudioA', 1000.0)", (str(file_1), len(content_dup)))
    conn.execute("INSERT INTO media_files VALUES (2, ?, ?, 1920, 1080, 60.0, 5000, '1080p', 'Title 2', 'StudioA', 1000.0)", (str(file_2), len(content_dup)))
    conn.execute("INSERT INTO media_files VALUES (3, ?, ?, 1920, 1080, 60.0, 5000, '1080p', 'Title 3', 'StudioA', 1000.0)", (str(file_3), file_3.stat().st_size))
    conn.commit()
    conn.close()

    clusters = find_exact_duplicates(str(db_path), target_dir=str(tmp_path), min_size=100)
    assert len(clusters) == 1
    assert clusters[0]["duplicate_count"] == 1
    assert clusters[0]["duplicates"][0]["original_path"] == str(file_2)


def test_quarantine_from_preview_json(tmp_path):
    """Verifies loading pre-computed clusters from JSON preview and staging into quarantine."""
    import json

    target_dir = tmp_path / "Aloha"
    studios_dir = target_dir / "Studios"
    studios_dir.mkdir(parents=True)

    master_file = studios_dir / "Video_Master.mp4"
    dupe_file = studios_dir / "Video_Dupe.mp4"
    master_file.write_bytes(b"MASTER_DATA_123")
    dupe_file.write_bytes(b"DUPE_DATA_123")

    preview_json = tmp_path / "preview.json"
    preview_data = {
        "generated_at": "2026-09-20T10:00:00",
        "clusters": [
            {
                "cluster_id": "cluster_prev_001",
                "detection_type": "video_keyframe",
                "master_path": str(master_file),
                "duplicate_count": 1,
                "potential_savings_bytes": dupe_file.stat().st_size,
                "duplicates": [
                    {
                        "original_path": str(dupe_file),
                        "file_size": dupe_file.stat().st_size,
                        "hash_signature": "sig_prev",
                        "hamming_distance": 2,
                        "original_mtime": dupe_file.stat().st_mtime,
                    }
                ],
            }
        ],
    }
    preview_json.write_text(json.dumps(preview_data), encoding="utf-8")

    ledger_path = tmp_path / "ledger.db"
    conn = init_ledger(str(ledger_path))

    with open(str(preview_json), "r", encoding="utf-8") as f:
        loaded = json.load(f)
    clusters = loaded["clusters"]

    moved = execute_quarantine(clusters, conn, target_dir=str(target_dir))
    assert moved == 1
    assert not dupe_file.exists()
    assert master_file.exists()

    quar_dest = target_dir / ".quarantine_duplicates" / "cluster_prev_001" / "Video_Dupe.mp4"
    assert quar_dest.exists()

    conn.close()

