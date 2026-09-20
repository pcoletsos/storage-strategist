"""
test_tag_movies_media.py

Unit tests for scripts/tag_movies_media.py verifying performer entity recognition,
studio attribution, film title normalization, database synchronization, and timestamp preservation.
"""

import os
import sys
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from tag_movies_media import (
    clean_movie_title,
    parse_movie_media,
    sync_to_database,
    _tag_single_mp4,
)


def test_clean_movie_title():
    """Verifies stripping resolution tags, codec marks, scrapers, and site noise."""
    assert clean_movie_title("[www Porn 18 Net] Dpg Teachrs Cd1 [AV1].mkv") == "Dpg Teachrs Cd1"
    assert clean_movie_title("Stoya in Love and Other Mishaps [hd720p] [720p AV1].mkv") == "Stoya in Love and Other Mishaps"
    assert clean_movie_title("[2011] Babysitters 2 2011 Digital Playground [720p H264].mp4") == "[2011] Babysitters 2 2011 Digital Playground"
    assert clean_movie_title("The Smiths Bluray Dpxxxhd [720p H264].mp4") == "The Smiths"


def test_digital_playground_dpg_releases():
    """Verifies Digital Playground abbreviation mapping and Jesse Jane recognition."""
    res1 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\New folder\\[www Porn 18 Net] Dpg Teachrs Cd1 [AV1].mkv",
        filename="[www Porn 18 Net] Dpg Teachrs Cd1 [AV1].mkv",
        directory="F:\\Aloha\\Movies\\New folder",
        media_type="video",
    )
    assert res1["detected_studio"] == "Digital Playground"
    assert res1["detected_title"] == "Teachers CD1"

    res2 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\New folder\\[www Porn 18 Net] Dpg Jjatmictease [AV1].mkv",
        filename="[www Porn 18 Net] Dpg Jjatmictease [AV1].mkv",
        directory="F:\\Aloha\\Movies\\New folder",
        media_type="video",
    )
    assert res2["detected_studio"] == "Digital Playground"
    assert res2["detected_artist"] == "Jesse Jane"
    assert res2["detected_title"] == "Jesse Jane: Atomic Tease"


def test_pirates_franchise():
    """Verifies Pirates 1 and Pirates II franchise parsing."""
    res1 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Pirates\\Pirates Cd1 [AV1].mkv",
        filename="Pirates Cd1 [AV1].mkv",
        directory="F:\\Aloha\\Movies\\Pirates",
        media_type="video",
    )
    assert res1["detected_studio"] == "Digital Playground"
    assert res1["detected_title"] == "Pirates (2005) CD1"
    assert res1["detected_date"] == "2005"
    assert "Jesse Jane" in res1["detected_artist"]

    res2 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Pirates\\Pirates2 [720p H264].mp4",
        filename="Pirates2 [720p H264].mp4",
        directory="F:\\Aloha\\Movies\\Pirates",
        media_type="video",
    )
    assert res2["detected_studio"] == "Digital Playground"
    assert res2["detected_title"] == "Pirates II: Stagnetti's Revenge (2008)"
    assert res2["detected_date"] == "2008"
    assert "Jesse Jane" in res2["detected_artist"]
    assert "Stoya" in res2["detected_artist"]


def test_stoya_releases():
    """Verifies Stoya Video Nasty and Love and Other Mishaps."""
    res1 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Stoya Video Nasty 2008\\Video Ts\\Vts 01 1 [480p AV1].mkv",
        filename="Vts 01 1 [480p AV1].mkv",
        directory="F:\\Aloha\\Movies\\Stoya Video Nasty 2008\\Video Ts",
        media_type="video",
    )
    assert res1["detected_artist"] == "Stoya"
    assert res1["detected_studio"] == "Digital Playground"
    assert res1["detected_date"] == "2008"
    assert "Stoya: Video Nasty (2008)" in res1["detected_title"]

    res2 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Stoya in Love and Other Mishaps [hd720p] [720p AV1].mkv",
        filename="Stoya in Love and Other Mishaps [hd720p] [720p AV1].mkv",
        directory="F:\\Aloha\\Movies",
        media_type="video",
    )
    assert res2["detected_artist"] == "Stoya"
    assert res2["detected_studio"] == "Digital Playground"
    assert res2["detected_title"] == "Love and Other Mishaps"


def test_wicked_peter_pan_xxx():
    """Verifies Wicked Pictures Peter Pan scene numbers and star extraction."""
    res = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\[wicked Fairy Tales] Peter Pan Keira Nicole, Riley Steele, Aiden Ashley, Mia Malkova & Vicki Chase [disney]\\[[Wicked Fairy Tales] Peter Pan XXX] Keira Nicole [disney] #1 [480p AV1].mkv",
        filename="[[Wicked Fairy Tales] Peter Pan XXX] Keira Nicole [disney] #1 [480p AV1].mkv",
        directory="F:\\Aloha\\Movies\\[wicked Fairy Tales] Peter Pan Keira Nicole, Riley Steele, Aiden Ashley, Mia Malkova & Vicki Chase [disney]",
        media_type="video",
    )
    assert res["detected_studio"] == "Wicked Pictures"
    assert "Keira Nicole" in res["detected_artist"]
    assert res["detected_title"] == "Wicked Fairy Tales: Peter Pan XXX Scene 1"


def test_parodies():
    """Verifies Vivid and New Sensations porn parodies."""
    res1 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Parodies\\Vivid the Avengers a Porn Parody [720p AV1].mkv",
        filename="Vivid the Avengers a Porn Parody [720p AV1].mkv",
        directory="F:\\Aloha\\Movies\\Parodies",
        media_type="video",
    )
    assert res1["detected_studio"] == "Vivid Entertainment"
    assert res1["detected_title"] == "The Avengers: A XXX Porn Parody Part 1"

    res2 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Parodies\\Friends a Porn Parody Cd2 [AV1].mkv",
        filename="Friends a Porn Parody Cd2 [AV1].mkv",
        directory="F:\\Aloha\\Movies\\Parodies",
        media_type="video",
    )
    assert res2["detected_studio"] == "New Sensations"
    assert res2["detected_title"] == "Friends: A XXX Porn Parody CD2"


def test_greek_sirina_movies():
    """Verifies Sirina Productions Greek movie titles and Julia Alexandratou parsing."""
    res1 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Greek Videos\\Show Bitch [480p AV1].mkv",
        filename="Show Bitch [480p AV1].mkv",
        directory="F:\\Aloha\\Movies\\Greek Videos",
        media_type="video",
    )
    assert res1["detected_studio"] == "Sirina Productions"
    assert res1["detected_title"] == "Show Bitch"

    res2 = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Greek\\Tzoulia\\Tzoulia 1 [AV1].mkv",
        filename="Tzoulia 1 [AV1].mkv",
        directory="F:\\Aloha\\Movies\\Greek\\Tzoulia",
        media_type="video",
    )
    assert res2["detected_artist"] == "Julia Alexandratou"
    assert res2["detected_studio"] == "Sirina Productions"
    assert res2["detected_title"] == "Tzoulia Alexandratou Full Movie"


def test_classic_deep_throat():
    """Verifies Deep Throat Linda Lovelace attribution and 1972 release date."""
    res = parse_movie_media(
        file_path="F:\\Aloha\\Movies\\Deep Throat\\Deep Throat [AV1].mkv",
        filename="Deep Throat [AV1].mkv",
        directory="F:\\Aloha\\Movies\\Deep Throat",
        media_type="video",
    )
    assert res["detected_artist"] == "Linda Lovelace"
    assert res["detected_studio"] == "Bryanston Distributing"
    assert res["detected_title"] == "Deep Throat (1972)"
    assert res["detected_date"] == "1972"


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
        VALUES (1, 'F:\\Aloha\\Movies\\Pirates\\Pirates2 [720p H264].mp4', NULL, NULL, NULL, NULL, 0.0, 1)
    """)
    conn.commit()
    conn.close()

    mock_results = [
        {
            "id": 1,
            "detected_artist": "Jesse Jane, Belladonna, Stoya",
            "detected_title": "Pirates II: Stagnetti's Revenge (2008)",
            "detected_studio": "Digital Playground",
            "detected_date": "2008",
            "confidence": 0.98,
        }
    ]

    updated_rec, updated_art, updated_std = sync_to_database(str(db_file), mock_results)
    assert updated_rec == 1
    assert updated_art == 1
    assert updated_std == 1

    conn = sqlite3.connect(str(db_file))
    row = conn.execute("SELECT existing_artist, studio, existing_title, existing_date, needs_review FROM media_files WHERE id = 1").fetchone()
    conn.close()

    assert "Jesse Jane" in row[0]
    assert row[1] == "Digital Playground"
    assert row[2] == "Pirates II: Stagnetti's Revenge (2008)"
    assert row[3] == "2008"
    assert row[4] == 0


def test_container_tagging_preserves_mtime():
    """Verifies that MP4 container tagging invokes os.utime to preserve timestamps."""
    item = {
        "file_path": "F:\\Aloha\\Movies\\Pirates\\Pirates2 [720p H264].mp4",
        "detected_artist": "Jesse Jane, Belladonna, Stoya",
        "detected_title": "Pirates II: Stagnetti's Revenge (2008)",
        "detected_studio": "Digital Playground",
        "detected_date": "2008",
    }

    mock_stat = MagicMock()
    mock_stat.st_atime = 1680000000.0
    mock_stat.st_mtime = 1680000000.0

    mock_mp4 = MagicMock()
    mock_mp4.tags = {}

    with patch("os.path.exists", return_value=True), \
         patch("os.stat", return_value=mock_stat), \
         patch("tag_movies_media.MP4", return_value=mock_mp4), \
         patch("os.utime") as mock_utime:
        result = _tag_single_mp4(item)
        assert result is True
        mock_mp4.save.assert_called_once()
        mock_utime.assert_called_once_with(
            "F:\\Aloha\\Movies\\Pirates\\Pirates2 [720p H264].mp4",
            (1680000000.0, 1680000000.0)
        )
