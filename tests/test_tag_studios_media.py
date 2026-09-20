"""
test_tag_studios_media.py

Unit tests for scripts/tag_studios_media.py verifying performer entity recognition,
studio attribution correction, title normalization, and database synchronization.
"""

import os
import sys
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from tag_studios_media import (
    clean_scene_title,
    parse_studio_media,
    sync_to_database,
    _tag_single_mp4,
)


def test_clean_scene_title():
    """Verifies stripping resolution tags, codec tags, and noise from titles."""
    assert clean_scene_title("X Art Carlie Misty Morning Hd [1080p H264].mp4") == "Carlie Misty Morning"
    assert clean_scene_title("Bigwai@18p2p X Art - Caprice Hot Bath.jpg") == "Caprice Hot Bath"
    assert clean_scene_title("[Bangbus] Episode 6889 [720p H264].mp4") == "Episode 6889"
    assert clean_scene_title("[Brazzers Exxtra] [2021-11-13] Billie Star and Tina Fire Big Tits Hit the Gym [480p H264].mp4") == "Billie Star and Tina Fire Big Tits Hit the Gym"


def test_xart_video_parsing():
    """Verifies single performer and duo extraction for X-Art videos."""
    # Single performer video
    res1 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\X-Art\\X Art Carlie Misty Morning Hd [1080p H264].mp4",
        filename="X Art Carlie Misty Morning Hd [1080p H264].mp4",
        directory="F:\\Aloha\\Studios\\X-Art",
        media_type="video",
        existing_artist=None,
        existing_title=None,
        existing_studio=None,
        existing_date=None,
    )
    assert res1["detected_artist"] == "Carlie"
    assert res1["detected_studio"] == "X-Art"
    assert res1["detected_title"] == "Misty Morning"
    assert res1["confidence"] >= 0.90

    # Duo performer video
    res2 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\X-Art\\X Art Francesca Capri Malibu Daze Hd [1080p H264].mp4",
        filename="X Art Francesca Capri Malibu Daze Hd [1080p H264].mp4",
        directory="F:\\Aloha\\Studios\\X-Art",
        media_type="video",
        existing_artist=None,
        existing_title=None,
        existing_studio=None,
        existing_date=None,
    )
    assert res2["detected_artist"] == "Francesca, Capri"
    assert res2["detected_studio"] == "X-Art"
    assert res2["detected_title"] == "Malibu Daze"


def test_xart_photo_parsing():
    """Verifies performer extraction from X-Art photo sets."""
    res = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\X-Art\\Bigwai@18p2p X Art - Caprice Hot Bath.jpg",
        filename="Bigwai@18p2p X Art - Caprice Hot Bath.jpg",
        directory="F:\\Aloha\\Studios\\X-Art",
        media_type="image",
        existing_artist=None,
        existing_title=None,
        existing_studio=None,
        existing_date=None,
    )
    assert res["detected_artist"] == "Caprice"
    assert res["detected_studio"] == "X-Art"
    assert res["detected_title"] == "Hot Bath"


def test_brcc_parsing():
    """Verifies Backroom Casting Couch auditions and episode extraction."""
    # Standard audition
    res1 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Backroom Casting Couch\\Allaura Brcc [AV1].mkv",
        filename="Allaura Brcc [AV1].mkv",
        directory="F:\\Aloha\\Studios\\Backroom Casting Couch",
        media_type="video",
        existing_artist=None,
        existing_title=None,
        existing_studio=None,
        existing_date=None,
    )
    assert res1["detected_artist"] == "Allaura"
    assert res1["detected_studio"] == "Backroom Casting Couch"
    assert res1["detected_title"] == "Casting: Allaura"

    # Multi-performer numbered episode
    res2 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Backroom Casting Couch\\[Backroom Casting Couch] Ktr Bcc E183 Melanie and Natalee [AV1].mkv",
        filename="[Backroom Casting Couch] Ktr Bcc E183 Melanie and Natalee [AV1].mkv",
        directory="F:\\Aloha\\Studios\\Backroom Casting Couch",
        media_type="video",
        existing_artist=None,
        existing_title=None,
        existing_studio=None,
        existing_date=None,
    )
    assert res2["detected_artist"] == "Melanie, Natalee"
    assert res2["detected_studio"] == "Backroom Casting Couch"
    assert res2["detected_title"] == "Episode 183: Melanie, Natalee"


def test_tonights_girlfriend_reattribution():
    """Verifies overriding legacy Brazzers studio attribution for Tonights Girlfriend."""
    # Video with legacy Brazzers tag
    res1 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Tonights Girlfriend\\[Tonights Girlfriend] Asarocco1 [1080p H264].mp4",
        filename="[Tonights Girlfriend] Asarocco1 [1080p H264].mp4",
        directory="F:\\Aloha\\Studios\\Tonights Girlfriend",
        media_type="video",
        existing_artist="Asa Akira, Rocco Reed",
        existing_title="Asa Akira / Rocco Reed",
        existing_studio="Brazzers",
        existing_date=None,
    )
    assert res1["detected_studio"] == "Tonights Girlfriend"
    assert res1["detected_artist"] == "Asa Akira, Rocco Reed"

    # Screen image token map
    res2 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Tonights Girlfriend\\Screens\\[Tonights Girlfriend] Screens - Tngfalannahbrandon.jpg",
        filename="[Tonights Girlfriend] Screens - Tngfalannahbrandon.jpg",
        directory="F:\\Aloha\\Studios\\Tonights Girlfriend\\Screens",
        media_type="image",
        existing_artist=None,
        existing_title=None,
        existing_studio=None,
        existing_date=None,
    )
    assert res2["detected_studio"] == "Tonights Girlfriend"
    assert res2["detected_artist"] == "Alanah Rae, Brandon Fox"
    assert "Tonights Girlfriend Screen" in res2["detected_title"]


def test_bangbus_and_bangbros():
    """Verifies episode normalization for Bangbus and Bangbros."""
    res1 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Bangbus\\[Bangbus] Episode 6889 [720p H264].mp4",
        filename="[Bangbus] Episode 6889 [720p H264].mp4",
        directory="F:\\Aloha\\Studios\\Bangbus",
        media_type="video",
        existing_artist=None,
        existing_title="Bangbus",
        existing_studio="Bangbros",
        existing_date=None,
    )
    assert res1["detected_studio"] == "Bangbus"
    assert res1["detected_title"] == "Episode 6889"

    res2 = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Bangbros\\Di11131 3000 [720p H264].mp4",
        filename="Di11131 3000 [720p H264].mp4",
        directory="F:\\Aloha\\Studios\\Bangbros",
        media_type="video",
        existing_artist=None,
        existing_title="Dorm Invasion",
        existing_studio="Bangbros",
        existing_date=None,
    )
    assert res2["detected_studio"] == "Bangbros"
    assert res2["detected_title"] == "Dorm Invasion: Episode 11131"


def test_brazzers_multi_performer():
    """Verifies date and performer parsing for Brazzers Exxtra releases."""
    res = parse_studio_media(
        file_path="F:\\Aloha\\Studios\\Brazzers\\[Brazzers Exxtra] [2021-11-13] Billie Star and Tina Fire Big Tits Hit the Gym [480p H264].mp4",
        filename="[Brazzers Exxtra] [2021-11-13] Billie Star and Tina Fire Big Tits Hit the Gym [480p H264].mp4",
        directory="F:\\Aloha\\Studios\\Brazzers",
        media_type="video",
        existing_artist=None,
        existing_title="Billie Star and Tina Fire Big Tits Hit the Gym",
        existing_studio="Brazzers",
        existing_date=None,
    )
    assert res["detected_studio"] == "Brazzers"
    assert res["detected_date"] == "2021-11-13"
    assert "Billie Star" in res["detected_artist"]
    assert "Tina Fire" in res["detected_artist"]


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
        VALUES (1, 'F:\\Aloha\\Studios\\X-Art\\vid1.mp4', NULL, NULL, NULL, NULL, 0.0, 1)
    """)
    conn.commit()
    conn.close()

    mock_results = [
        {
            "id": 1,
            "detected_artist": "Caprice",
            "detected_title": "Hot Bath",
            "detected_studio": "X-Art",
            "detected_date": "2020-01-01",
            "confidence": 0.95,
        }
    ]

    updated_rec, updated_art, updated_std = sync_to_database(str(db_file), mock_results)
    assert updated_rec == 1
    assert updated_art == 1
    assert updated_std == 1

    conn = sqlite3.connect(str(db_file))
    row = conn.execute("SELECT existing_artist, studio, existing_title, needs_review FROM media_files WHERE id = 1").fetchone()
    conn.close()

    assert row[0] == "Caprice"
    assert row[1] == "X-Art"
    assert row[2] == "Hot Bath"
    assert row[3] == 0


def test_container_tagging_preserves_mtime():
    """Verifies that MP4 container tagging invokes os.utime to preserve timestamps."""
    item = {
        "file_path": "F:\\Aloha\\Studios\\X-Art\\test.mp4",
        "detected_artist": "Carlie",
        "detected_title": "Misty Morning",
        "detected_studio": "X-Art",
        "detected_date": "2021",
    }

    mock_stat = MagicMock()
    mock_stat.st_atime = 1600000000.0
    mock_stat.st_mtime = 1600000000.0

    mock_mp4 = MagicMock()
    mock_mp4.tags = {}

    with patch("os.path.exists", return_value=True), \
         patch("os.stat", return_value=mock_stat), \
         patch("tag_studios_media.MP4", return_value=mock_mp4), \
         patch("os.utime") as mock_utime:
        result = _tag_single_mp4(item)
        assert result is True
        mock_mp4.save.assert_called_once()
        mock_utime.assert_called_once_with(
            "F:\\Aloha\\Studios\\X-Art\\test.mp4",
            (1600000000.0, 1600000000.0)
        )
