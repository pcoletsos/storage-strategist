import os
import sys
import sqlite3
import tempfile
import pytest
from unittest.mock import patch, MagicMock

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from triage_celebrities_media import (
    normalize_title,
    parse_celebrity_record,
    tag_mp4_container,
    run_triage
)



def test_normalize_title():
    raw1 = "[Barbara Niven Lesbian Sex Scene From A Perfect Ending] Xvideos Com [H264].mp4"
    assert normalize_title(raw1) == "Barbara Niven Lesbian Sex Scene From A Perfect Ending"

    raw2 = "Wolfofwallstreetthe Robbie W 01 Hi [H264].mp4"
    assert "Wolfofwallstreetthe Robbie" in normalize_title(raw2)

    raw3 = "Forced Celebrity Strip Searches Playlist 10 [H264].mp4"
    assert normalize_title(raw3) == "Forced Celebrity Strip Searches Playlist 10"


def test_playlist_compilation_parsing():
    rec1 = parse_celebrity_record("80s Teen Sex Comedies Playlist 2 [H264].mp4", "From Movies", None, None)
    assert rec1['artist'] == "Compilation"
    assert rec1['studio'] == "Mr Skin"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("Summer Shocker the 69 Most Outrageous Celeb Nude Scenes of All Time [H264].MP4", "Old", None, None)
    assert rec2['artist'] == "Compilation"
    assert rec2['studio'] == "Mr Skin"
    assert rec2['needs_review'] == 0


def test_mrskin_daily_bulletins():
    rec1 = parse_celebrity_record("[Back to the Boardwalk SKINpire] Sep 10, 2013 [H264].MP4", "New Folder", None, None)
    assert rec1['artist'] == "Compilation"
    assert rec1['studio'] == "Mr Skin"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("[Thanks for Sharing, Gwyneth!] Mrskin Com - Jun 28, 2013 [720p H264].MP4", "New Folder", None, None)
    assert rec2['artist'] == "Gwyneth Paltrow"
    assert rec2['studio'] == "Mr Skin"
    assert rec2['needs_review'] == 0

    rec3 = parse_celebrity_record("[The Doctor is Skin for Nurse 3D] Mrskin Com - Feb 7, 2014 [H264].mp4", "New Folder", None, None)
    assert rec3['artist'] == "Paz de la Huerta"
    assert rec3['needs_review'] == 0


def test_playboy_tv_and_hollywood_xposed():
    rec1 = parse_celebrity_record("[PlayboyTV- Swing] Rub a Dub, Extended Cut [H264].MP4", "Updates\\Update2", None, None)
    assert rec1['artist'] == "Compilation"
    assert rec1['studio'] == "Playboy TV"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("[Hollywood Xposed- 11_25_2013] Nov 25, 2013 [H264].MP4", "Updates\\Update2", None, None)
    assert rec2['artist'] == "Compilation"
    assert rec2['studio'] == "Mr Skin"
    assert rec2['needs_review'] == 0


def test_greek_celebrities():
    rec1 = parse_celebrity_record("Asiki Vina Bikini Peraste Filiste Teleiosate [480p AV1].mkv", "Celeb", None, None)
    assert rec1['artist'] == "Vina Asiki"
    assert rec1['studio'] == "Greek Cinema"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("Mastrokosta Xenodoxeion Paradeisos Greek Celebrity [AV1].mkv", "Celeb", None, None)
    assert rec2['artist'] == "Gogo Mastrokosta"
    assert rec2['needs_review'] == 0

    rec3 = parse_celebrity_record("Tzeni Theona1 [AV1].mkv", "Celeb", None, None)
    assert rec3['artist'] == "Tzeni Theona"
    assert rec3['needs_review'] == 0


def test_bracket_stars():
    rec1 = parse_celebrity_record("[Blake Lively Hot Sex Scene From Savages] Xvideos Com [H264].mp4", "New Folder", None, None)
    assert rec1['artist'] == "Blake Lively"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("[Barbara Niven and Jessica Clark Nude Lesbian Sex From A Perfect Ending] Xvideos Com [H264].mp4", "New Folder", None, None)
    assert rec2['artist'] == "Barbara Niven, Jessica Clark"
    assert rec2['needs_review'] == 0

    rec3 = parse_celebrity_record("[Gemma Arterton] The Disappearance of Alice Creed Hd [720p AV1].mkv", "Ga Tdoac7p", None, None)
    assert rec3['artist'] == "Gemma Arterton"
    assert rec3['needs_review'] == 0


def test_mrskin_abbreviated_clips():
    rec1 = parse_celebrity_record("Wolfofwallstreetthe Robbie W 01 Hi [H264].mp4", "Updates\\Update8", None, None)
    assert rec1['artist'] == "Margot Robbie"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("Showgirls Berkley Hd 01 Hi [H264].mp4", "Updates\\Update8", None, None)
    assert rec2['artist'] == "Elizabeth Berkley"
    assert rec2['needs_review'] == 0

    rec3 = parse_celebrity_record("10inch Harris 1 Hi [H264].mp4", "From Movies", None, None)
    assert rec3['artist'] == "Danneel Harris"
    assert rec3['needs_review'] == 0

    rec4 = parse_celebrity_record("Boulevard Wuher1 Hi [H264].mp4", "Updates\\Update4,5,6,7", None, None)
    assert rec4['artist'] == "Kari Wuhrer"
    assert rec4['needs_review'] == 0


def test_q_desire_feature():
    rec1 = parse_celebrity_record("Leticia Belliccini Q (desire) [1080p H264].mp4", "2349", None, None)
    assert rec1['artist'] == "Leticia Belliccini"
    assert rec1['needs_review'] == 0

    rec2 = parse_celebrity_record("Deborah Revy Q (desire) [1080p H264].mp4", "2349", None, None)
    assert rec2['artist'] == "Deborah Revy"
    assert rec2['needs_review'] == 0


def test_numeric_stubs_retained():
    rec1 = parse_celebrity_record("00014369 [H264].mp4", "New Folder", None, None)
    assert rec1['artist'] is None
    assert rec1['needs_review'] == 1

    rec2 = parse_celebrity_record("178960 Hi [H264].mp4", "Updates\\Update4,5,6,7", None, None)
    assert rec2['artist'] is None
    assert rec2['needs_review'] == 1


def test_mp4_tagging_timestamp_preservation():
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as f:
        dummy_path = f.name

    try:
        test_mtime = 1420000000.0  # Jan 2015
        os.utime(dummy_path, (test_mtime, test_mtime))

        with patch("triage_celebrities_media.MP4") as mock_mp4_cls:
            mock_inst = MagicMock()

            mock_inst.tags = {}
            mock_mp4_cls.return_value = mock_inst

            success = tag_mp4_container(dummy_path, "Margot Robbie", "Wolf of Wall Street", "Mr Skin")
            assert success is True
            assert mock_inst.tags['\xa9ART'] == ["Margot Robbie"]
            assert mock_inst.tags['\xa9nam'] == ["Wolf of Wall Street"]
            assert mock_inst.tags['\xa9cmt'] == ["Studio: Mr Skin"]
            mock_inst.save.assert_called_once()

            # Verify timestamp restoration
            cur_mtime = os.path.getmtime(dummy_path)
            assert abs(cur_mtime - test_mtime) < 1.0
    finally:
        if os.path.exists(dummy_path):
            os.remove(dummy_path)


def test_run_triage_flow():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as db_f, \
         tempfile.NamedTemporaryFile(suffix=".json", delete=False) as json_f:
        db_path = db_f.name
        json_path = json_f.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE media_files (
                id INTEGER PRIMARY KEY,
                file_path TEXT,
                filename TEXT,
                extension TEXT,
                file_size INTEGER,
                existing_artist TEXT,
                studio TEXT,
                existing_title TEXT,
                confidence_score REAL,
                needs_review INTEGER
            )
        """)
        conn.execute("""
            INSERT INTO media_files VALUES (
                1,
                'F:\\Aloha\\Celebrities\\Updates\\Update8\\Wolfofwallstreetthe Robbie W 01 Hi [H264].mp4',
                'Wolfofwallstreetthe Robbie W 01 Hi [H264].mp4',
                '.mp4',
                1000000,
                NULL,
                'Mr Skin',
                NULL,
                0.5,
                1
            )
        """)
        conn.execute("""
            INSERT INTO media_files VALUES (
                2,
                'F:\\Aloha\\Celebrities\\New Folder\\00014369 [H264].mp4',
                '00014369 [H264].mp4',
                '.mp4',
                500000,
                NULL,
                NULL,
                NULL,
                0.5,
                1
            )
        """)
        conn.commit()
        conn.close()

        summary = run_triage(db_path, json_path, apply_changes=True, skip_tagging=True)
        assert summary['total'] == 2
        assert summary['resolved'] == 1
        assert summary['retained'] == 1

        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT existing_artist, studio, needs_review FROM media_files WHERE id = 1")
        row1 = c.fetchone()
        assert row1[0] == "Margot Robbie"
        assert row1[1] == "Mr Skin"
        assert row1[2] == 0

        c.execute("SELECT existing_artist, needs_review FROM media_files WHERE id = 2")
        row2 = c.fetchone()
        assert row2[0] is None
        assert row2[1] == 1
        conn.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
        if os.path.exists(json_path):
            os.remove(json_path)
