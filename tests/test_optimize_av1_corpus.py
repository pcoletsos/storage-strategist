import os
import sys
import sqlite3
import pytest
import tempfile
import shutil

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from optimize_av1_corpus import (
    classify_tier,
    build_ffmpeg_command,
    calculate_target_cq,
    init_ledger,
    record_transaction,
    verify_transcode,
    sync_inventory_db,
    query_candidates
)

def test_classify_tier():
    assert classify_tier(r"F:\Aloha\Studios\Brazzers\clip.mp4") == "Tier A"
    assert classify_tier(r"F:\Aloha\Movies\feature.mp4") == "Tier B"
    assert classify_tier(r"F:\Aloha\Collections & Siterips\scene.mp4") == "Tier C"
    assert classify_tier(r"F:\Aloha\Celebrities\star.mp4") == "Tier D"
    assert classify_tier(r"F:\Aloha\Games\asset.mp4") == "Games"
    assert classify_tier(r"F:\Aloha\Other\sample.mp4") == "Other"

def test_build_ffmpeg_command():
    ffmpeg = "ffmpeg.exe"
    src = "input.mp4"
    dst = "output.mp4"

    # With audio
    cmd = build_ffmpeg_command(ffmpeg, src, dst, cq=28, has_audio=True)
    assert "av1_nvenc" in cmd
    assert "-pix_fmt" in cmd
    assert "yuv420p" in cmd
    assert "-rc:v" in cmd
    assert "vbr" in cmd
    assert "-cq:v" in cmd
    assert "28" in cmd
    assert "-preset" in cmd
    assert "p6" in cmd
    assert "-tune" in cmd
    assert "hq" in cmd
    assert "-c:a" in cmd
    assert "copy" in cmd
    assert "+faststart" in cmd

    # Without audio
    cmd_no_audio = build_ffmpeg_command(ffmpeg, src, dst, cq=26, has_audio=False)
    assert "-an" in cmd_no_audio
    assert "copy" not in cmd_no_audio
    assert "26" in cmd_no_audio

def test_calculate_target_cq():
    # Non-adaptive returns default CQ
    cand_4k = {"width": 3840, "height": 2160, "bitrate": 15000000}
    assert calculate_target_cq(cand_4k, default_cq=28, adaptive=False) == 28

    # Adaptive CQ tests
    # 4K / UHD
    assert calculate_target_cq(cand_4k, default_cq=28, adaptive=True) == 26

    # 1080p high bitrate
    cand_1080_high = {"width": 1920, "height": 1080, "bitrate": 8000000}
    assert calculate_target_cq(cand_1080_high, default_cq=28, adaptive=True) == 28

    # 1080p moderate bitrate
    cand_1080_mod = {"width": 1920, "height": 1080, "bitrate": 3500000}
    assert calculate_target_cq(cand_1080_mod, default_cq=28, adaptive=True) == 30

    # 720p moderate bitrate
    cand_720 = {"width": 1280, "height": 720, "bitrate": 3000000}
    assert calculate_target_cq(cand_720, default_cq=28, adaptive=True) == 30

def test_init_ledger_and_records():
    temp_dir = tempfile.mkdtemp()
    ledger_path = os.path.join(temp_dir, "test_ledger.db")

    conn = init_ledger(ledger_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'")
    assert cur.fetchone() is not None

    record_transaction(
        conn,
        file_path="sample.mp4",
        original_size=1000,
        av1_size=600,
        saved_bytes=400,
        compression_ratio=0.6,
        duration=60.0,
        vmaf_score=95.5,
        transcode_time_sec=10.2,
        status="completed"
    )

    cur.execute("SELECT status, saved_bytes, compression_ratio FROM transactions WHERE file_path = 'sample.mp4'")
    row = cur.fetchone()
    assert row[0] == "completed"
    assert row[1] == 400
    assert row[2] == 0.6

    conn.close()
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_negative_delta_guardrail(monkeypatch):
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, "temp.mp4")
    with open(temp_file, "wb") as f:
        f.write(b"0" * 1500)

    orig_file = os.path.join(temp_dir, "orig.mp4")
    with open(orig_file, "wb") as f:
        f.write(b"0" * 1000)

    # Monkeypatch probe_stream to return simulated metrics where transcode size > original size
    def mock_probe(path, ffprobe_bin):
        return {
            "v_codec": "av1",
            "a_codec": "aac",
            "duration": 60.0,
            "size": 1500,
            "bitrate": 200000
        }

    monkeypatch.setattr("optimize_av1_corpus.probe_stream", mock_probe)

    orig_info = {"file_size": 1000, "duration": 60.0, "a_codec": "aac"}
    valid, msg, info = verify_transcode(temp_file, orig_file, orig_info, "ffprobe.exe")
    assert not valid
    assert "Negative delta guardrail" in msg

    shutil.rmtree(temp_dir, ignore_errors=True)

def test_verification_pass_and_failure_modes(monkeypatch):
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, "temp.mp4")
    with open(temp_file, "wb") as f:
        f.write(b"0" * 600)

    orig_file = os.path.join(temp_dir, "orig.mp4")
    with open(orig_file, "wb") as f:
        f.write(b"0" * 1000)

    orig_info = {"file_size": 1000, "duration": 60.0, "a_codec": "aac"}

    # Success case
    monkeypatch.setattr("optimize_av1_corpus.probe_stream", lambda p, b: {
        "v_codec": "av1", "a_codec": "aac", "duration": 60.0, "size": 600, "bitrate": 80000
    })
    valid, msg, _ = verify_transcode(temp_file, orig_file, orig_info, "ffprobe.exe")
    assert valid
    assert "Verification successful" in msg

    # Codec mismatch (e.g. h264 instead of av1)
    monkeypatch.setattr("optimize_av1_corpus.probe_stream", lambda p, b: {
        "v_codec": "h264", "a_codec": "aac", "duration": 60.0, "size": 600, "bitrate": 80000
    })
    valid, msg, _ = verify_transcode(temp_file, orig_file, orig_info, "ffprobe.exe")
    assert not valid
    assert "Unexpected video codec" in msg

    # Duration mismatch (> 2.0s delta)
    monkeypatch.setattr("optimize_av1_corpus.probe_stream", lambda p, b: {
        "v_codec": "av1", "a_codec": "aac", "duration": 50.0, "size": 600, "bitrate": 80000
    })
    valid, msg, _ = verify_transcode(temp_file, orig_file, orig_info, "ffprobe.exe")
    assert not valid
    assert "Duration divergence" in msg

    shutil.rmtree(temp_dir, ignore_errors=True)

def test_sync_inventory_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_inv.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            filename TEXT,
            extension TEXT,
            v_codec TEXT,
            file_size INTEGER,
            bitrate INTEGER
        )
    """)
    conn.execute(
        """
        INSERT INTO media_files (file_path, filename, extension, v_codec, file_size, bitrate)
        VALUES ('F:\\Aloha\\Studios\\test.mp4', 'test.mp4', '.mp4', 'h264', 1000, 200000)
        """
    )
    conn.commit()
    conn.close()

    ok = sync_inventory_db(db_path, "F:\\Aloha\\Studios\\test.mp4", "F:\\Aloha\\Studios\\test.mp4", 600, 120000)
    assert ok

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT v_codec, file_size, bitrate FROM media_files WHERE file_path = 'F:\\Aloha\\Studios\\test.mp4'")
    row = cur.fetchone()
    assert row[0] == "av1"
    assert row[1] == 600
    assert row[2] == 120000
    conn.close()

    shutil.rmtree(temp_dir, ignore_errors=True)

def test_query_candidates_filtering():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_query.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            file_size INTEGER,
            v_codec TEXT,
            a_codec TEXT,
            width INTEGER,
            height INTEGER,
            duration REAL,
            bitrate INTEGER,
            existing_title TEXT,
            existing_artist TEXT,
            existing_date TEXT,
            existing_comment TEXT,
            studio TEXT
        )
    """)
    conn.execute(
        """
        INSERT INTO media_files (file_path, file_size, v_codec, a_codec, width, height, duration, bitrate)
        VALUES 
        ('F:\\Aloha\\Studios\\valid.mp4', 5000, 'h264', 'aac', 1920, 1080, 60.0, 100000),
        ('F:\\Aloha\\Movies\\valid_movie.mp4', 8000, 'h264', 'aac', 1920, 1080, 120.0, 150000),
        ('F:\\Aloha\\Games\\ignored_game.mp4', 2000, 'h264', 'aac', 1280, 720, 30.0, 80000),
        ('F:\\Aloha\\Studios\\protected.vhdx', 10000, 'h264', 'aac', 1920, 1080, 60.0, 100000),
        ('F:\\Aloha\\Studios\\already_av1.mp4', 3000, 'av1', 'aac', 1920, 1080, 60.0, 60000)
        """
    )
    conn.commit()
    conn.close()

    cands_tier_a = query_candidates(db_path, tier="A")
    assert len(cands_tier_a) == 1
    assert cands_tier_a[0]["file_path"] == "F:\\Aloha\\Studios\\valid.mp4"

    cands_all = query_candidates(db_path, tier="all")
    assert len(cands_all) == 2
    paths = [c["file_path"] for c in cands_all]
    assert "F:\\Aloha\\Studios\\valid.mp4" in paths
    assert "F:\\Aloha\\Movies\\valid_movie.mp4" in paths
    assert "F:\\Aloha\\Games\\ignored_game.mp4" not in paths
    assert "F:\\Aloha\\Studios\\protected.vhdx" not in paths

    shutil.rmtree(temp_dir, ignore_errors=True)
