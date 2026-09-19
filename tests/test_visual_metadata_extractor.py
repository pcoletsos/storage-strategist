import os
import sys
import json
import sqlite3
import tempfile
import pytest

# Ensure repo and scripts paths are accessible
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from visual_metadata_extractor import (
    parse_2257_statement,
    resolve_studio_from_ocr_tokens,
    detect_performers_from_text,
    quick_signature_match,
    parse_pool_argument,
    select_candidates_from_db,
    sync_to_inventory_db,
    tag_video_containers,
    ALL_CANONICAL_POOLS
)
import media_tagger

def test_parse_2257_statement_brazzers():
    text = (
        "18 U.S.C. 2257 Record-Keeping Requirements Compliance Statement\n"
        "Title: Big Tits In Uniform\n"
        "Produced on: 2021-05-18\n"
        "All records required by 18 U.S.C. 2257 are maintained by custodian\n"
        "at 625 Broadway, 11th Floor, New York, NY 10012."
    )
    res = parse_2257_statement(text)
    assert res.get("studio") == "Brazzers"
    assert res.get("date") == "2021-05-18"
    assert res.get("title") == "Big Tits In Uniform"

def test_parse_2257_statement_bangbros():
    text = (
        "Pursuant to 18 U.S.C. 2257, records custodian is Carol Santiago,\n"
        "6955 NW 52 Street, Miami, FL 33166. Produced on: 03/14/2019.\n"
        "Title: Bangbus Episode 42"
    )
    res = parse_2257_statement(text)
    assert res.get("studio") == "Bangbros"
    assert res.get("date") == "2019-03-14"
    assert "Bangbus" in res.get("title", "")

def test_parse_2257_statement_digital_playground():
    text = (
        "All visual depictions comply with 18 USC 2257.\n"
        "Records Custodian: Samir Savoy, Chatsworth, CA 91311.\n"
        "Title: Island Fever"
    )
    res = parse_2257_statement(text)
    assert res.get("studio") == "Digital Playground"
    assert res.get("title") == "Island Fever"

def test_parse_2257_statement_jules_jordan():
    text = (
        "Records maintained pursuant to 18 U.S.C. 2257 by custodian\n"
        "at Jules Jordan Video, Van Nuys, CA."
    )
    res = parse_2257_statement(text)
    assert res.get("studio") == "Jules Jordan"

def test_resolve_studio_from_ocr_tokens():
    studio, conf = resolve_studio_from_ocr_tokens("Welcome to Brazzers Network Exclusive")
    assert studio == "Brazzers"
    assert conf >= 0.90

    studio2, conf2 = resolve_studio_from_ocr_tokens("A DigitalPlayground Production")
    assert studio2 == "Digital Playground"
    assert conf2 >= 0.90

    none_res = resolve_studio_from_ocr_tokens("Unrelated Random Text Card")
    assert none_res is None

def test_detect_performers_from_text():
    text = "Starring Lexi Belle and Riley Steele in an exotic adventure"
    perfs = detect_performers_from_text(text, "sample_video.mp4")
    assert "Lexi Belle" in perfs
    assert "Riley Steele" in perfs

    fname_perfs = detect_performers_from_text("", "Tori Black - Solo Session.mp4")
    assert "Tori Black" in fname_perfs

def test_quick_signature_match():
    res = quick_signature_match(r"F:\Aloha\Studios\Brazzers\btas_scene1.mp4")
    assert res is not None
    assert res["detected_studio"] == "Brazzers"
    assert res["confidence"] >= 0.90

    res2 = quick_signature_match(r"F:\Aloha\Collections & Siterips\Bangbros\di12345.mp4")
    assert res2 is not None
    assert res2["detected_studio"] == "Bangbros"

    res_none = quick_signature_match(r"F:\Aloha\Movies\unknown_indie_clip.mp4")
    assert res_none is None

def test_parse_pool_argument():
    # Default 'all'
    all_pools = parse_pool_argument("all")
    assert "Studios" in all_pools
    assert "Movies" in all_pools
    assert "Collections & Siterips" in all_pools

    # Specific canonical pool
    studios = parse_pool_argument("studios")
    assert studios == ["Studios"]

    # Comma-separated canonical pools
    multi = parse_pool_argument("studios,movies,collections")
    assert "Studios" in multi
    assert "Movies" in multi
    assert "Collections & Siterips" in multi

    # Strict isolation: games must never be accepted
    games = parse_pool_argument("games")
    assert "games" not in games
    assert "Games" not in games

def test_select_candidates_from_db_isolates_games(tmp_path):
    db_file = str(tmp_path / "test_media_inventory.db")
    conn = sqlite3.connect(db_file)
    with conn:
        conn.execute("""
            CREATE TABLE media_files (
                id INTEGER PRIMARY KEY,
                file_path TEXT UNIQUE,
                media_type TEXT,
                studio TEXT,
                existing_artist TEXT
            )
        """)
        # Insert sample rows including Games
        conn.execute("INSERT INTO media_files VALUES (1, 'F:\\Aloha\\Studios\\valid1.mp4', 'video', NULL, NULL)")
        conn.execute("INSERT INTO media_files VALUES (2, 'F:\\Aloha\\Games\\assets\\clip.mp4', 'video', NULL, NULL)")
        conn.execute("INSERT INTO media_files VALUES (3, 'F:\\Aloha\\Movies\\valid2.mp4', 'video', 'Existing Studio', 'Existing Artist')")
        conn.execute("INSERT INTO media_files VALUES (4, 'F:\\Aloha\\Movies\\valid3.mp4', 'video', NULL, 'Some Artist')")
    conn.close()

    # Create dummy files so os.path.exists passes for testing
    os.makedirs(str(tmp_path / "Aloha" / "Studios"), exist_ok=True)
    os.makedirs(str(tmp_path / "Aloha" / "Games" / "assets"), exist_ok=True)
    os.makedirs(str(tmp_path / "Aloha" / "Movies"), exist_ok=True)
    f1 = str(tmp_path / "Aloha" / "Studios" / "valid1.mp4")
    f2 = str(tmp_path / "Aloha" / "Games" / "assets" / "clip.mp4")
    f4 = str(tmp_path / "Aloha" / "Movies" / "valid3.mp4")
    for f in (f1, f2, f4):
        with open(f, "wb") as fh:
            fh.write(b"dummy")

    # Update DB paths to match temp paths
    conn = sqlite3.connect(db_file)
    with conn:
        conn.execute("UPDATE media_files SET file_path = ? WHERE id = 1", (f1,))
        conn.execute("UPDATE media_files SET file_path = ? WHERE id = 2", (f2,))
        conn.execute("UPDATE media_files SET file_path = ? WHERE id = 4", (f4,))
    conn.close()

    candidates = select_candidates_from_db(db_file, ALL_CANONICAL_POOLS)
    assert f1 in candidates
    assert f4 in candidates
    # Ensure games folder is strictly isolated
    assert f2 not in candidates

def test_sync_to_inventory_db_confidence_thresholds(tmp_path):
    db_file = str(tmp_path / "test_inventory.db")
    conn = sqlite3.connect(db_file)
    with conn:
        conn.execute("""
            CREATE TABLE media_files (
                id INTEGER PRIMARY KEY,
                file_path TEXT UNIQUE,
                studio TEXT,
                confidence_score REAL,
                existing_title TEXT,
                existing_artist TEXT,
                existing_date TEXT,
                needs_review INTEGER DEFAULT 0
            )
        """)
        conn.execute("INSERT INTO media_files VALUES (1, 'path/high.mp4', NULL, NULL, NULL, NULL, NULL, 0)")
        conn.execute("INSERT INTO media_files VALUES (2, 'path/medium.mp4', NULL, NULL, NULL, NULL, NULL, 0)")
        conn.execute("INSERT INTO media_files VALUES (3, 'path/low.mp4', NULL, NULL, NULL, NULL, NULL, 0)")
    conn.close()

    results = [
        # High confidence (>= 0.85): auto-updated, needs_review = 0
        {
            "file_path": "path/high.mp4",
            "detected_studio": "Brazzers",
            "confidence": 0.95,
            "detected_title": "High Title",
            "detected_performers": ["Lexi Belle"],
            "detected_date": "2021-01-01"
        },
        # Medium confidence (0.60 to 0.84): candidate update, needs_review = 1
        {
            "file_path": "path/medium.mp4",
            "detected_studio": "Vixen",
            "confidence": 0.75,
            "detected_title": "Medium Title",
            "detected_performers": [],
            "detected_date": None
        },
        # Low confidence (< 0.60): skipped completely, remains unassigned
        {
            "file_path": "path/low.mp4",
            "detected_studio": "Unknown Studio",
            "confidence": 0.40,
            "detected_title": None,
            "detected_performers": [],
            "detected_date": None
        }
    ]

    sync_to_inventory_db(db_file, results)

    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    row_high = cur.execute("SELECT studio, confidence_score, needs_review FROM media_files WHERE id = 1").fetchone()
    assert row_high[0] == "Brazzers"
    assert row_high[1] == 0.95
    assert row_high[2] == 0

    row_med = cur.execute("SELECT studio, confidence_score, needs_review FROM media_files WHERE id = 2").fetchone()
    assert row_med[0] == "Vixen"
    assert row_med[1] == 0.75
    assert row_med[2] == 1

    row_low = cur.execute("SELECT studio, confidence_score, needs_review FROM media_files WHERE id = 3").fetchone()
    assert row_low[0] is None
    assert row_low[1] is None
    conn.close()

def test_tag_video_containers_confidence_gating(monkeypatch, tmp_path):
    tagged_files = []

    def mock_tag_media_file(fpath, tag_dict):
        tagged_files.append(fpath)
        return {"file_path": fpath, "tagged": True}

    monkeypatch.setattr("visual_metadata_extractor.tag_media_file", mock_tag_media_file)

    high_file = str(tmp_path / "high.mp4")
    med_file = str(tmp_path / "med.mp4")
    with open(high_file, "wb") as f:
        f.write(b"data")
    with open(med_file, "wb") as f:
        f.write(b"data")

    results = [
        {"file_path": high_file, "confidence": 0.95, "detected_title": "T1"},
        {"file_path": med_file, "confidence": 0.75, "detected_title": "T2"}
    ]

    tag_video_containers(results)
    # Only high confidence file should be tagged
    assert high_file in tagged_files
    assert med_file not in tagged_files
