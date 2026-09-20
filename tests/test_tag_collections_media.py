"""
test_tag_collections_media.py

Unit tests for scripts/tag_collections_media.py verifying performer entity recognition,
siterip normalization, title cleaning, database synchronization, and timestamp preservation.
"""

import os
import sys
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from tag_collections_media import (
    clean_scene_title,
    parse_collections_media,
    sync_to_database,
    _tag_single_mp4,
)


def test_clean_scene_title():
    """Verifies stripping resolution tags, codec marks, scrapers, and site noise."""
    assert clean_scene_title("Igotporn Org Porntwins Chantel&chloe Stevenstwins Twinbritishmilfs Cd1 716mb [AV1].mkv") == "Porntwins Chantel&chloe Stevenstwins Twinbritishmilfs Cd1"
    assert clean_scene_title("[2_Ddfprod] Anetta Keys (1by Day) - Fuck [AV1].mkv") == "Anetta Keys (1by Day) - Fuck"
    assert clean_scene_title("Wckedforums Com Porntwins Lacey&lyndsey Love Twins Twindom 715mb [AV1].mkv") == "Porntwins Lacey&lyndsey Love Twins Twindom"
    assert clean_scene_title("Girls Gone Wild Ultimate Rush 2006 [AV1].mkv") == "Girls Gone Wild Ultimate Rush 2006"


def test_izzy_green_video_and_screen():
    """Verifies performer attribution, studio, and clean title for Izzy Green videos and screens."""
    # Video
    res_vid = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Onf Izzygreen 105 [480p AV1].mkv",
        filename="Onf Izzygreen 105 [480p AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack",
        media_type="video",
    )
    assert res_vid["detected_artist"] == "Izzy Green"
    assert res_vid["detected_studio"] == "OnlyFans"
    assert res_vid["detected_title"] == "Izzy Green Clip 105"
    assert res_vid["confidence"] >= 0.95

    # Screencap image
    res_scr = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Scr\\Scr - Onf Izzygreen 105 Mp4.jpg",
        filename="Scr - Onf Izzygreen 105 Mp4.jpg",
        directory="F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Scr",
        media_type="image",
    )
    assert res_scr["detected_artist"] == "Izzy Green"
    assert res_scr["detected_studio"] == "OnlyFans"
    assert res_scr["detected_title"] == "Screens: Izzy Green Clip 105"


def test_onlyfans_mix_models():
    """Verifies model extraction and clean titles across OnlyFans Mix releases."""
    res1 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\OnlyFans Mix\\Onlyfans Com Brittanya Razavi Aka Seebrittanya 53 [1080p H264].mp4",
        filename="Onlyfans Com Brittanya Razavi Aka Seebrittanya 53 [1080p H264].mp4",
        directory="F:\\Aloha\\Collections & Siterips\\OnlyFans Mix",
        media_type="video",
    )
    assert res1["detected_artist"] == "Brittanya Razavi"
    assert res1["detected_studio"] == "OnlyFans"

    res2 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\OnlyFans Mix\\Luna Okko Onlyfans Com Hotel Quickie [1080p H264].mp4",
        filename="Luna Okko Onlyfans Com Hotel Quickie [1080p H264].mp4",
        directory="F:\\Aloha\\Collections & Siterips\\OnlyFans Mix",
        media_type="video",
    )
    assert res2["detected_artist"] == "Luna Okko"
    assert res2["detected_studio"] == "OnlyFans"
    assert res2["detected_title"] == "Hotel Quickie"


def test_porn_twins():
    """Verifies duo performer extraction and clean title normalization for Porn Twins."""
    res = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Twins\\[Porn Twins] Lacey & Lyndsay - Love Twins Two Hot [AV1].mkv",
        filename="[Porn Twins] Lacey & Lyndsay - Love Twins Two Hot [AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Twins",
        media_type="video",
    )
    assert res["detected_artist"] == "Lacey & Lyndsay"
    assert res["detected_studio"] == "Porn Twins"
    assert res["detected_title"] == "Love Twins: Two Hot"


def test_girls_gone_wild():
    """Verifies series title normalization and studio attribution for Girls Gone Wild."""
    res = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Girls Gone Wild\\Girls Gone Wild Ultimate Rush 2006 [AV1].mkv",
        filename="Girls Gone Wild Ultimate Rush 2006 [AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Girls Gone Wild",
        media_type="video",
    )
    assert res["detected_studio"] == "Girls Gone Wild"
    assert res["detected_title"] == "Girls Gone Wild: Ultimate Rush 2006"


def test_alice():
    """Verifies Miss Alice 18 clip number and date parsing."""
    res1 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Alice\\Missalice 18 (4) [H264].mp4",
        filename="Missalice 18 (4) [H264].mp4",
        directory="F:\\Aloha\\Collections & Siterips\\Alice",
        media_type="video",
    )
    assert res1["detected_artist"] == "Miss Alice 18"
    assert res1["detected_studio"] == "Miss Alice 18"
    assert res1["detected_title"] == "Miss Alice Clip 4"

    res2 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Alice\\Missalice 18 2012 05 10 [AV1].mkv",
        filename="Missalice 18 2012 05 10 [AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Alice",
        media_type="video",
    )
    assert res2["detected_artist"] == "Miss Alice 18"
    assert res2["detected_studio"] == "Miss Alice 18"
    assert res2["detected_title"] == "Miss Alice 2012-05-10"


def test_anime_and_night_shift_nurses():
    """Verifies Vanilla and Anime studio tags and episode titles."""
    res = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Night Shift Nurses Karte Ep01 10 Extras [eng Sub] [uncen]\\Night Shift Nurses Karte Ep10 [eng Subs] [cen] [480p AV1].mkv",
        filename="Night Shift Nurses Karte Ep10 [eng Subs] [cen] [480p AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Night Shift Nurses Karte Ep01 10 Extras [eng Sub] [uncen]",
        media_type="video",
    )
    assert res["detected_studio"] == "Vanilla"
    assert res["detected_title"] == "Night Shift Nurses: Episode 10"


def test_thematic_hard_teasers_pov():
    """Verifies performer extraction from thematic collections."""
    # Hard
    res1 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Hard\\[2_Ddfprod] Anetta Keys (1by Day) - Fuck [AV1].mkv",
        filename="[2_Ddfprod] Anetta Keys (1by Day) - Fuck [AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Hard",
        media_type="video",
    )
    assert res1["detected_artist"] == "Anetta Keys"
    assert res1["detected_studio"] == "DDF Network"

    # Teasers
    res2 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Teasers\\Bikini Babe Heather Vandeven [480p AV1].mkv",
        filename="Bikini Babe Heather Vandeven [480p AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Teasers",
        media_type="video",
    )
    assert res2["detected_artist"] == "Heather Vandeven"
    assert res2["detected_studio"] == "Teasers"

    # POV
    res3 = parse_collections_media(
        file_path="F:\\Aloha\\Collections & Siterips\\Pov\\[Natasha Nice] Pov [480p AV1].mkv",
        filename="[Natasha Nice] Pov [480p AV1].mkv",
        directory="F:\\Aloha\\Collections & Siterips\\Pov",
        media_type="video",
    )
    assert res3["detected_artist"] == "Natasha Nice"
    assert res3["detected_studio"] == "POV"


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
        VALUES (1, 'F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Onf Izzygreen 105 [480p AV1].mkv', NULL, NULL, NULL, NULL, 0.0, 1)
    """)
    conn.commit()
    conn.close()

    mock_results = [
        {
            "id": 1,
            "detected_artist": "Izzy Green",
            "detected_title": "Izzy Green Clip 105",
            "detected_studio": "OnlyFans",
            "detected_date": None,
            "confidence": 0.98,
        }
    ]

    updated_rec, updated_art, updated_std = sync_to_database(str(db_file), mock_results)
    assert updated_rec == 1
    assert updated_art == 1
    assert updated_std == 1

    conn = sqlite3.connect(str(db_file))
    row = conn.execute("SELECT existing_artist, studio, existing_title, needs_review FROM media_files WHERE id = 1").fetchone()
    conn.close()

    assert row[0] == "Izzy Green"
    assert row[1] == "OnlyFans"
    assert row[2] == "Izzy Green Clip 105"
    assert row[3] == 0


def test_container_tagging_preserves_mtime():
    """Verifies that MP4 container tagging invokes os.utime to preserve timestamps."""
    item = {
        "file_path": "F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\test.mp4",
        "detected_artist": "Izzy Green",
        "detected_title": "Izzy Green Clip 1",
        "detected_studio": "OnlyFans",
        "detected_date": None,
    }

    mock_stat = MagicMock()
    mock_stat.st_atime = 1650000000.0
    mock_stat.st_mtime = 1650000000.0

    mock_mp4 = MagicMock()
    mock_mp4.tags = {}

    with patch("os.path.exists", return_value=True), \
         patch("os.stat", return_value=mock_stat), \
         patch("tag_collections_media.MP4", return_value=mock_mp4), \
         patch("os.utime") as mock_utime:
        result = _tag_single_mp4(item)
        assert result is True
        mock_mp4.save.assert_called_once()
        mock_utime.assert_called_once_with(
            "F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\test.mp4",
            (1650000000.0, 1650000000.0)
        )
