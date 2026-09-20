import os
import sys
import time
import sqlite3
import pytest
import tempfile
import shutil
from unittest.mock import patch, MagicMock

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from quarantine_corrupted_media import (
    is_game_path,
    init_ledger,
    probe_file,
    execute_quarantine,
    execute_rollback,
    find_corrupted_candidates,
)


def test_is_game_path():
    assert is_game_path(r"F:\Aloha\Games\RPGGame\movie.mp4") is True
    assert is_game_path(r"F:\Aloha\Games") is True
    assert is_game_path("E:/Games/Intro.mp4") is True
    assert is_game_path(r"F:\Aloha\Studios\Scene.mp4") is False
    assert is_game_path(r"F:\Aloha\Collections & Siterips\Video.mp4") is False


def test_init_ledger():
    with tempfile.TemporaryDirectory() as tmp_dir:
        ledger_path = os.path.join(tmp_dir, "test_ledger.db")
        conn = init_ledger(ledger_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='corrupted_files'")
        assert cur.fetchone() is not None
        cur.execute("PRAGMA journal_mode;")
        assert cur.fetchone()[0].lower() == "wal"
        conn.close()


def test_probe_file_missing():
    is_valid, err_class, err_detail = probe_file("C:\\nonexistent\\missing_file.mp4", "ffprobe")
    assert is_valid is False
    assert err_class == "file_missing"


def test_probe_file_error_patterns():
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tf:
        tf.write(b"dummy corrupted video bytes")
        dummy_path = tf.name

    try:
        # Test moov atom not found
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="[mov,mp4 @ 0x123] moov atom not found\nInvalid data found when processing input",
                stdout="{}"
            )
            is_valid, err_class, _ = probe_file(dummy_path, "ffprobe")
            assert is_valid is False
            assert err_class == "truncated_mp4_missing_moov"

        # Test EBML header failure
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="[matroska @ 0x123] EBML header parsing failed\nInvalid data found",
                stdout="{}"
            )
            is_valid, err_class, _ = probe_file(dummy_path, "ffprobe")
            assert is_valid is False
            assert err_class == "corrupted_ebml_header"

        # Test Invalid data found
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr="Invalid data found when processing input",
                stdout="{}"
            )
            is_valid, err_class, _ = probe_file(dummy_path, "ffprobe")
            assert is_valid is False
            assert err_class == "invalid_container_data"

        # Test valid container
        with patch("subprocess.run") as mock_run:
            valid_json = '{"streams": [{"codec_type": "video", "duration": "120.0"}], "format": {"duration": "120.0"}}'
            mock_run.return_value = MagicMock(
                returncode=0,
                stderr="",
                stdout=valid_json
            )
            is_valid, err_class, _ = probe_file(dummy_path, "ffprobe")
            assert is_valid is True
            assert err_class == "valid"
    finally:
        if os.path.exists(dummy_path):
            os.remove(dummy_path)


def test_quarantine_and_rollback_roundtrip():
    with tempfile.TemporaryDirectory() as tmp_dir:
        orig_folder = os.path.join(tmp_dir, "media", "subfolder")
        os.makedirs(orig_folder, exist_ok=True)
        orig_file = os.path.join(orig_folder, "broken_video.mp4")
        payload = b"test corrupted payload 12345"
        with open(orig_file, "wb") as f:
            f.write(payload)

        test_mtime = time.time() - 3600
        os.utime(orig_file, (test_mtime, test_mtime))

        ledger_path = os.path.join(tmp_dir, "test_ledger.db")
        quarantine_dir = os.path.join(tmp_dir, ".quarantine_corrupted")
        ledger_conn = init_ledger(ledger_path)

        try:
            candidates = [{
                "file_path": orig_file,
                "file_size": len(payload),
                "mtime": test_mtime,
                "error_class": "truncated_mp4_missing_moov",
                "error_detail": "moov atom not found",
            }]

            # Test dry-run
            dry_moved = execute_quarantine(candidates, ledger_conn, quarantine_base=quarantine_dir, dry_run=True)
            assert dry_moved == 1
            assert os.path.exists(orig_file)
            assert not os.path.exists(quarantine_dir)

            # Test live quarantine
            moved = execute_quarantine(candidates, ledger_conn, quarantine_base=quarantine_dir, dry_run=False)
            assert moved == 1
            assert not os.path.exists(orig_file)
            assert os.path.exists(quarantine_dir)

            cur = ledger_conn.cursor()
            cur.execute("SELECT status, original_path, quarantine_path FROM corrupted_files")
            row = cur.fetchone()
            assert row[0] == "quarantined"
            assert row[1] == orig_file
            quar_path = row[2]
            assert os.path.exists(quar_path)
            with open(quar_path, "rb") as f:
                assert f.read() == payload

            # Test live rollback
            restored = execute_rollback(ledger_conn, dry_run=False)
            assert restored == 1
            assert os.path.exists(orig_file)
            assert not os.path.exists(quar_path)
            with open(orig_file, "rb") as f:
                assert f.read() == payload

            cur.execute("SELECT status FROM corrupted_files")
            assert cur.fetchone()[0] == "restored"
        finally:
            ledger_conn.close()


def test_quarantine_skips_game_path():
    with tempfile.TemporaryDirectory() as tmp_dir:
        game_folder = os.path.join(tmp_dir, "Aloha", "Games", "MyGame")
        os.makedirs(game_folder, exist_ok=True)
        game_file = os.path.join(game_folder, "cutscene.mp4")
        with open(game_file, "wb") as f:
            f.write(b"game cutscene bytes")

        ledger_path = os.path.join(tmp_dir, "test_ledger.db")
        quarantine_dir = os.path.join(tmp_dir, ".quarantine_corrupted")
        ledger_conn = init_ledger(ledger_path)
        try:
            candidates = [{
                "file_path": game_file,
                "file_size": 19,
                "mtime": time.time(),
                "error_class": "truncated_mp4_missing_moov",
                "error_detail": "moov atom not found",
            }]

            moved = execute_quarantine(candidates, ledger_conn, quarantine_base=quarantine_dir, dry_run=False)
            assert moved == 0
            assert os.path.exists(game_file)
        finally:
            ledger_conn.close()
