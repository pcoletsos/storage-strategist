"""Unit tests for tag_celebrities_media.py performer recognition and metadata tagging.

Validates subfolder attribution, Top 300 bracket and prefix parsing, multi-performer
formatting, attached clip token and surname resolution, studio classification,
legacy misattribution correction, and database synchronization.
"""

import os
import sys
import sqlite3
import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from tag_celebrities_media import (
    parse_celebrity_asset,
    clean_scene_title,
    parse_date_from_string,
    sync_to_database,
)


def test_clean_scene_title():
    """Verifies removal of technical resolution, codec brackets, and extensions."""
    assert clean_scene_title("[006 Katie Holmes] The Gift [480p AV1].mkv") == "[006 Katie Holmes] The Gift"
    assert clean_scene_title("Dirty Kaylynn1 Hi [H264].mp4") == "Dirty Kaylynn1 Hi"
    assert clean_scene_title("Aboutnight Moore Hd 01 Hd [720p H264].mp4") == "Aboutnight Moore Hd 01 Hd"


def test_parse_date_from_string():
    """Verifies date parsing from diverse filename formats."""
    assert parse_date_from_string("[Carrie Will Scare Your Pants Off] Mrskin Com - Oct 18, 2013 [H264].MP4") == "2013-10-18"
    assert parse_date_from_string("[-The Wait- is Over for Chloe Sevigny's Latest T&A] Jan 10, 2014 [H264].MP4") == "2014-01-10"
    assert parse_date_from_string("Random Scene Without Date [H264].mp4") is None


def test_subfolder_performer_attribution():
    """Verifies direct performer mapping for assets in dedicated performer folders."""
    res = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Sasha Grey\Sasha Grey 18 Year Old Com [AV1].mkv",
        filename="Sasha Grey 18 Year Old Com [AV1].mkv",
        directory=r"F:\Aloha\Celebrities\Sasha Grey",
        media_type="video",
    )
    assert res["detected_artist"] == "Sasha Grey"
    assert res["confidence"] == 0.98
    assert res["method"] == "subfolder"

    res_img = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Megan Fox\Megan Fox Transformers 01.jpg",
        filename="Megan Fox Transformers 01.jpg",
        directory=r"F:\Aloha\Celebrities\Megan Fox",
        media_type="image",
    )
    assert res_img["detected_artist"] == "Megan Fox"
    assert res_img["confidence"] == 0.98


def test_top300_bracket_and_prefix():
    """Verifies extraction of performer and title from Top 300 compilation files."""
    # Single performer bracket
    res1 = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Top 300 Celebrity Nude Scenes\[006 Katie Holmes] The Gift [480p AV1].mkv",
        filename="[006 Katie Holmes] The Gift [480p AV1].mkv",
        directory=r"F:\Aloha\Celebrities\Top 300 Celebrity Nude Scenes",
        media_type="video",
    )
    assert res1["detected_artist"] == "Katie Holmes"
    assert res1["detected_title"] == "The Gift"
    assert res1["detected_studio"] == "Mr Skin"
    assert res1["confidence"] == 0.95

    # Multi-performer bracket
    res2 = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Top 300 Celebrity Nude Scenes\[021 Dana Delany & Stephanie Niznik] Exit to Eden [480p AV1].mkv",
        filename="[021 Dana Delany & Stephanie Niznik] Exit to Eden [480p AV1].mkv",
        directory=r"F:\Aloha\Celebrities\Top 300 Celebrity Nude Scenes",
        media_type="video",
    )
    assert res2["detected_artist"] == "Dana Delany, Stephanie Niznik"
    assert res2["detected_title"] == "Exit to Eden"

    # Prefixed format without brackets
    res3 = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Top 300 Celebrity Nude Scenes\012 Eva Green the Dreamers 01 [480p AV1].mkv",
        filename="012 Eva Green the Dreamers 01 [480p AV1].mkv",
        directory=r"F:\Aloha\Celebrities\Top 300 Celebrity Nude Scenes",
        media_type="video",
    )
    assert res3["detected_artist"] == "Eva Green"
    assert res3["detected_title"] == "the Dreamers 01"


def test_known_celebrity_and_surname_tokens():
    """Verifies detection of celebrity names and attached clip tokens."""
    # Full name in playlist title
    res1 = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Updates\Update1\Courteney Cox Naked and Sexy Playlist 3 [H264].MP4",
        filename="Courteney Cox Naked and Sexy Playlist 3 [H264].MP4",
        directory=r"F:\Aloha\Celebrities\Updates\Update1",
        media_type="video",
    )
    assert res1["detected_artist"] == "Courteney Cox"
    assert res1["detected_studio"] == "Mr Skin"

    # Attached token (Jovovich6 -> Milla Jovovich)
    res2 = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\From Movies\45 Jovovich6 Hi [H264].mp4",
        filename="45 Jovovich6 Hi [H264].mp4",
        directory=r"F:\Aloha\Celebrities\From Movies",
        media_type="video",
    )
    assert res2["detected_artist"] == "Milla Jovovich"

    # Attached token (Kidman Hd -> Nicole Kidman)
    res3 = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Updates\Update1\Deadcalm Kidman Hd 01 Hi [H264].mp4",
        filename="Deadcalm Kidman Hd 01 Hi [H264].mp4",
        directory=r"F:\Aloha\Celebrities\Updates\Update1",
        media_type="video",
    )
    assert res3["detected_artist"] == "Nicole Kidman"


def test_legacy_misattribution_correction():
    """Verifies that invalid studio names in existing_artist are cleared and real artist extracted."""
    res = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Old\[Halle Berry Nude Birthday Vid] Mrskin Com - Aug 14, 2013 [H264].MP4",
        filename="[Halle Berry Nude Birthday Vid] Mrskin Com - Aug 14, 2013 [H264].MP4",
        directory=r"F:\Aloha\Celebrities\Old",
        media_type="video",
        existing_artist="Mrskin Com",
    )
    assert res["detected_artist"] == "Halle Berry"
    assert res["detected_studio"] == "Mr Skin"
    assert res["detected_date"] == "2013-08-14"


def test_thematic_compilation_classification():
    """Verifies that thematic compilations receive clean titles and Mr Skin studio attribution."""
    res = parse_celebrity_asset(
        file_path=r"F:\Aloha\Celebrities\Updates\Update1\The L Word Every Nude Scene Playlist 11 [H264].MP4",
        filename="The L Word Every Nude Scene Playlist 11 [H264].MP4",
        directory=r"F:\Aloha\Celebrities\Updates\Update1",
        media_type="video",
    )
    assert res["detected_studio"] == "Mr Skin"
    assert "The L Word" in res["detected_title"]


def test_database_synchronization(tmp_path):
    """Verifies updating media_inventory.db records with parsed metadata."""
    db_file = tmp_path / "test_inventory.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            existing_artist TEXT,
            existing_title TEXT,
            studio TEXT,
            existing_date TEXT,
            confidence_score REAL,
            needs_review INTEGER
        )
    """)
    conn.execute("""
        INSERT INTO media_files (id, file_path, existing_artist, existing_title, studio, existing_date, confidence_score, needs_review)
        VALUES (1, 'F:\\Aloha\\Celebrities\\Sasha Grey\\vid1.mp4', NULL, NULL, NULL, NULL, 0.0, 1)
    """)
    conn.commit()
    conn.close()

    mock_results = [
        {
            "id": 1,
            "detected_artist": "Sasha Grey",
            "detected_title": "vid1",
            "detected_studio": "Mr Skin",
            "detected_date": "2020-01-01",
            "confidence": 0.98,
        }
    ]

    updated_rec, updated_art = sync_to_database(str(db_file), mock_results)
    assert updated_rec == 1
    assert updated_art == 1

    conn = sqlite3.connect(str(db_file))
    row = conn.execute("SELECT existing_artist, existing_title, studio, existing_date, confidence_score, needs_review FROM media_files WHERE id = 1").fetchone()
    conn.close()

    assert row[0] == "Sasha Grey"
    assert row[1] == "vid1"
    assert row[2] == "Mr Skin"
    assert row[3] == "2020-01-01"
    assert row[4] == 0.98
    assert row[5] == 0
