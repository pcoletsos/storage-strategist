import os
import sys
import sqlite3
import pytest
import tempfile
import shutil

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from modernize_legacy_containers import (
    classify_candidate_tier,
    build_ffmpeg_command,
    init_ledger,
    plan_modernization,
    sync_modernized_db
)

def test_classify_candidate_tier():
    # Tier 1: H.264 with AAC
    t1, d1 = classify_candidate_tier("h264", "aac")
    assert t1 == "tier1_remux"

    # Tier 1: H.264 with no audio
    t1_no_audio, _ = classify_candidate_tier("h264", None)
    assert t1_no_audio == "tier1_remux"

    # Tier 2: H.264 with PCM audio
    t2, d2 = classify_candidate_tier("h264", "pcm_s16le")
    assert t2 == "tier2_audio_transcode"

    # Tier 2: H.264 with MP3 audio
    t2_mp3, _ = classify_candidate_tier("h264", "mp3")
    assert t2_mp3 == "tier2_audio_transcode"

    # Tier 3: Legacy video codec (mpeg4, mpeg1, divx)
    t3, d3 = classify_candidate_tier("mpeg4", "mp3")
    assert t3 == "tier3_full_transcode"

    t3_mpg, _ = classify_candidate_tier("mpeg2video", "mp2")
    assert t3_mpg == "tier3_full_transcode"

def test_build_ffmpeg_command():
    ffmpeg = "ffmpeg.exe"
    src = "sample.mov"
    out = "sample.mp4"

    # Tier 1: Lossless copy
    cmd1 = build_ffmpeg_command(ffmpeg, src, out, "tier1_remux")
    assert "-c" in cmd1
    assert "copy" in cmd1
    assert "+faststart" in cmd1

    # Tier 2: Video copy, audio aac
    cmd2 = build_ffmpeg_command(ffmpeg, src, out, "tier2_audio_transcode")
    assert "-c:v" in cmd2
    assert "-c:a" in cmd2
    assert "aac" in cmd2
    assert "+faststart" in cmd2

    # Tier 3: Video encode, audio aac
    cmd3 = build_ffmpeg_command(ffmpeg, src, out, "tier3_full_transcode")
    assert "h264_nvenc" in cmd3
    assert "aac" in cmd3
    assert "+faststart" in cmd3

def test_init_ledger_and_records():
    temp_dir = tempfile.mkdtemp()
    ledger_path = os.path.join(temp_dir, "test_ledger.db")

    conn = init_ledger(ledger_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'")
    assert cur.fetchone() is not None

    conn.execute(
        """
        INSERT INTO transactions (
            original_path, modernized_path, tier, original_size, modernized_size, original_mtime, executed_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("old.mov", "new.mp4", "tier1_remux", 1000, 950, 12345.0, "2026-09-16 12:00:00", "completed")
    )
    conn.commit()

    cur.execute("SELECT status, tier FROM transactions WHERE id = 1")
    row = cur.fetchone()
    assert row[0] == "completed"
    assert row[1] == "tier1_remux"

    conn.close()
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_plan_modernization():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "media_inventory.db")

    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            extension TEXT,
            file_size INTEGER,
            mtime REAL,
            v_codec TEXT,
            a_codec TEXT,
            duration REAL,
            existing_title TEXT,
            existing_artist TEXT,
            existing_date TEXT,
            studio TEXT
        )
    """)
    conn.execute(
        """
        INSERT INTO media_files (file_path, extension, file_size, mtime, v_codec, a_codec, duration, existing_title)
        VALUES 
        ('F:\\Aloha\\Studios\\Brazzers\\clip.mov', '.mov', 5000000, 1000.0, 'h264', 'aac', 60.0, 'Clip Title'),
        ('F:\\Aloha\\Movies\\film.avi', '.avi', 10000000, 2000.0, 'mpeg4', 'mp3', 120.0, 'Film Title'),
        ('F:\\Aloha\\Studios\\Bangbus\\stay.mp4', '.mp4', 15000000, 3000.0, 'h264', 'aac', 180.0, 'Already MP4')
        """
    )
    conn.commit()
    conn.close()

    candidates = plan_modernization(db_path)
    assert len(candidates) == 2  # .mov and .avi, ignoring .mp4

    c1 = next(c for c in candidates if c["extension"] == ".mov")
    assert c1["dest_path"] == "F:\\Aloha\\Studios\\Brazzers\\clip.mp4"
    assert c1["tier"] == "tier1_remux"
    assert c1["metadata"]["title"] == "Clip Title"

    c2 = next(c for c in candidates if c["extension"] == ".avi")
    assert c2["dest_path"] == "F:\\Aloha\\Movies\\film.mp4"
    assert c2["tier"] == "tier3_full_transcode"

    shutil.rmtree(temp_dir, ignore_errors=True)
