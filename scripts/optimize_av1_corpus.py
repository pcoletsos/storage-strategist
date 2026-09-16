#!/usr/bin/env python3
"""Hardware-accelerated AV1 space-optimization pipeline for Aloha.

Optimizes high-capacity H.264 video corpus on F:\\Aloha using av1_nvenc on
NVIDIA RTX 5070 Ti hardware encoder. Implements strict negative delta
guardrails, same-volume atomic staging, metadata and timestamp preservation,
transactional SQLite ledger tracking, and live media inventory synchronization.
"""

import os
import re
import sys
import stat
import time
import json
import shutil
import sqlite3
import argparse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

# Reconfigure console output for Windows UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path

FFPROBE_DEFAULT = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe"
FFMPEG_DEFAULT = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffmpeg.exe"
DEFAULT_DB_PATH = os.path.join(os.path.dirname(SCRIPTS_DIR), "media_inventory.db")
DEFAULT_LEDGER_PATH = os.path.join(os.path.dirname(SCRIPTS_DIR), "av1_transcode_ledger.db")

FILE_ATTRIBUTE_NORMAL = 0x80

def clear_readonly(file_path: str) -> None:
    """Clears read-only file attributes using Windows kernel32 and os.chmod."""
    try:
        norm = to_extended_path(file_path)
        if os.path.exists(norm):
            os.chmod(norm, stat.S_IWRITE | stat.S_IREAD)
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(norm, FILE_ATTRIBUTE_NORMAL)
    except Exception:
        pass

def get_tool_paths() -> Tuple[str, str]:
    """Resolves absolute paths to ffmpeg and ffprobe binaries."""
    ffmpeg_bin = FFMPEG_DEFAULT if os.path.exists(FFMPEG_DEFAULT) else shutil.which("ffmpeg")
    ffprobe_bin = FFPROBE_DEFAULT if os.path.exists(FFPROBE_DEFAULT) else shutil.which("ffprobe")
    if not ffmpeg_bin or not os.path.exists(ffmpeg_bin):
        raise FileNotFoundError(f"ffmpeg binary not found at '{ffmpeg_bin}'")
    if not ffprobe_bin or not os.path.exists(ffprobe_bin):
        raise FileNotFoundError(f"ffprobe binary not found at '{ffprobe_bin}'")
    return ffmpeg_bin, ffprobe_bin

def init_ledger(ledger_path: str) -> sqlite3.Connection:
    """Initializes the transactional SQLite ledger with WAL mode."""
    conn = sqlite3.connect(ledger_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL UNIQUE,
                original_size INTEGER NOT NULL,
                av1_size INTEGER NOT NULL,
                saved_bytes INTEGER NOT NULL,
                compression_ratio REAL NOT NULL,
                duration REAL,
                vmaf_score REAL,
                transcode_time_sec REAL,
                executed_at TEXT NOT NULL,
                status TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_status ON transactions(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_file_path ON transactions(file_path);")
    return conn

def classify_tier(file_path: str) -> str:
    """Classifies file into Pareto tier based on canonical folder structure."""
    norm = file_path.replace("/", "\\")
    if "\\Aloha\\Studios\\" in norm:
        return "Tier A"
    elif "\\Aloha\\Movies\\" in norm:
        return "Tier B"
    elif "\\Aloha\\Collections & Siterips\\" in norm:
        return "Tier C"
    elif "\\Aloha\\Celebrities\\" in norm:
        return "Tier D"
    elif "\\Aloha\\Games\\" in norm:
        return "Games"
    return "Other"

def query_candidates(
    db_path: str,
    tier: str = "all",
    target_file: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Queries candidate H.264 video files from media_inventory.db."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Inventory database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if target_file:
        norm_target = os.path.abspath(target_file)
        cur.execute(
            """
            SELECT file_path, file_size, v_codec, a_codec, width, height, duration, bitrate,
                   existing_title, existing_artist, existing_date, existing_comment, studio
            FROM media_files
            WHERE file_path = ?
            """,
            (norm_target,)
        )
        rows = cur.fetchall()
        conn.close()
        candidates = [dict(r) for r in rows]
        for c in candidates:
            c["tier"] = classify_tier(c["file_path"])
        return candidates

    tier_upper = tier.upper()
    tier_conditions = []
    if tier_upper in ("A", "TIER A"):
        tier_conditions.append("file_path LIKE '%\\Aloha\\Studios\\%'")
    elif tier_upper in ("B", "TIER B"):
        tier_conditions.append("file_path LIKE '%\\Aloha\\Movies\\%'")
    elif tier_upper in ("C", "TIER C"):
        tier_conditions.append("file_path LIKE '%\\Aloha\\Collections & Siterips\\%'")
    elif tier_upper in ("D", "TIER D"):
        tier_conditions.append("file_path LIKE '%\\Aloha\\Celebrities\\%'")
    elif tier_upper == "ALL":
        tier_conditions.append(
            "(file_path LIKE '%\\Aloha\\Studios\\%' OR "
            "file_path LIKE '%\\Aloha\\Movies\\%' OR "
            "file_path LIKE '%\\Aloha\\Collections & Siterips\\%')"
        )
    else:
        tier_conditions.append("1=1")

    query = f"""
        SELECT file_path, file_size, v_codec, a_codec, width, height, duration, bitrate,
               existing_title, existing_artist, existing_date, existing_comment, studio
        FROM media_files
        WHERE v_codec = 'h264'
          AND file_path NOT LIKE '%\\Aloha\\Games\\%'
          AND file_path NOT LIKE '%.vhdx'
          AND file_path NOT LIKE '%HANDOFF_%'
          AND ({' AND '.join(tier_conditions)})
        ORDER BY file_size DESC
    """
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()

    candidates = []
    for r in rows:
        d = dict(r)
        d["tier"] = classify_tier(d["file_path"])
        candidates.append(d)
    return candidates

def calculate_target_cq(candidate: Dict[str, Any], default_cq: int = 28, adaptive: bool = False) -> int:
    """Determines target constant quality (CQ) value."""
    if not adaptive:
        return default_cq

    width = candidate.get("width") or 0
    height = candidate.get("height") or 0
    bitrate = candidate.get("bitrate") or 0

    # 4K / UHD: High detail benefits from lower CQ (higher bitrate allocation)
    if width >= 3840 or height >= 2160:
        return 26
    # 1080p: Use CQ 28 for high bitrate, CQ 30 for medium bitrate
    elif width >= 1920 or height >= 1080:
        if bitrate > 6_000_000:
            return 28
        return 30
    # 720p and below
    else:
        if bitrate > 4_000_000:
            return 28
        return 30

def build_ffmpeg_command(
    ffmpeg_bin: str,
    source_path: str,
    temp_output_path: str,
    cq: int,
    has_audio: bool = True
) -> List[str]:
    """Constructs the hardware-accelerated av1_nvenc transcode command."""
    audio_args = ["-c:a", "copy"] if has_audio else ["-an"]
    return [
        ffmpeg_bin,
        "-y",
        "-v", "error",
        "-stats",
        "-i", source_path,
        "-c:v", "av1_nvenc",
        "-pix_fmt", "yuv420p",
        "-rc:v", "vbr",
        "-cq:v", str(cq),
        "-b:v", "0",
        "-preset", "p6",
        "-tune", "hq",
        *audio_args,
        "-movflags", "+faststart",
        temp_output_path
    ]

def probe_stream(file_path: str, ffprobe_bin: str) -> Optional[Dict[str, Any]]:
    """Probes video and audio streams using ffprobe."""
    cmd = [
        ffprobe_bin,
        "-v", "error",
        "-show_entries", "stream=index,codec_name,codec_type,width,height,duration,channels:format=duration,size,bit_rate",
        "-of", "json",
        file_path
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return None
        data = json.loads(res.stdout)
        streams = data.get("streams", [])
        fmt = data.get("format", {})

        v_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
        a_stream = next((s for s in streams if s.get("codec_type") == "audio"), None)

        if not v_stream:
            return None

        v_codec = v_stream.get("codec_name", "").lower()
        a_codec = a_stream.get("codec_name", "").lower() if a_stream else None
        a_channels = int(a_stream.get("channels") or 0) if a_stream else None

        duration = 0.0
        if "duration" in fmt and fmt["duration"] not in (None, "N/A"):
            try:
                duration = float(fmt["duration"])
            except ValueError:
                pass
        if duration <= 0.0 and "duration" in v_stream and v_stream["duration"] not in (None, "N/A"):
            try:
                duration = float(v_stream["duration"])
            except ValueError:
                pass

        size = 0
        if "size" in fmt and fmt["size"] not in (None, "N/A"):
            try:
                size = int(fmt["size"])
            except ValueError:
                pass
        if size <= 0:
            try:
                size = os.path.getsize(file_path)
            except Exception:
                pass

        bitrate = 0
        if "bit_rate" in fmt and fmt["bit_rate"] not in (None, "N/A"):
            try:
                bitrate = int(fmt["bit_rate"])
            except ValueError:
                pass
        if bitrate <= 0 and duration > 0 and size > 0:
            bitrate = int((size * 8) / duration)

        return {
            "v_codec": v_codec,
            "a_codec": a_codec,
            "a_channels": a_channels,
            "width": int(v_stream.get("width") or 0),
            "height": int(v_stream.get("height") or 0),
            "duration": duration,
            "size": size,
            "bitrate": bitrate
        }
    except Exception:
        return None

def verify_transcode(
    temp_path: str,
    orig_path: str,
    orig_info: Dict[str, Any],
    ffprobe_bin: str,
    duration_tolerance: float = 2.0
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Validates modernized transcode against source file metrics."""
    if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
        return False, "Output file is missing or zero bytes", None

    temp_info = probe_stream(temp_path, ffprobe_bin)
    if not temp_info:
        return False, "Failed to probe transcode output with ffprobe", None

    # Check 1: Video codec must be AV1
    if temp_info["v_codec"] != "av1":
        return False, f"Unexpected video codec: {temp_info['v_codec']} (expected av1)", temp_info

    # Check 2: Audio stream parity
    orig_has_audio = orig_info.get("a_codec") not in (None, "", "none", "null")
    temp_has_audio = temp_info.get("a_codec") not in (None, "", "none", "null")
    if orig_has_audio != temp_has_audio:
        return False, f"Audio stream mismatch: source_audio={orig_has_audio}, transcode_audio={temp_has_audio}", temp_info

    # Check 3: Duration tolerance
    orig_dur = float(orig_info.get("duration") or 0.0)
    temp_dur = float(temp_info.get("duration") or 0.0)
    if orig_dur > 5.0 and temp_dur > 0.0:
        delta = abs(temp_dur - orig_dur)
        if delta > duration_tolerance:
            return False, f"Duration divergence {delta:.2f}s exceeds tolerance {duration_tolerance}s", temp_info

    # Check 4: Negative delta guardrail
    orig_size = int(orig_info.get("file_size") or orig_info.get("size") or 0)
    if orig_size <= 0 and os.path.exists(orig_path):
        orig_size = os.path.getsize(orig_path)
    temp_size = temp_info["size"]

    if temp_size >= orig_size:
        return False, f"Negative delta guardrail: transcode size ({temp_size:,}) >= original ({orig_size:,})", temp_info

    return True, "Verification successful", temp_info

def transfer_metadata(
    orig_path: str,
    temp_path: str,
    candidate: Dict[str, Any]
) -> bool:
    """Transfers MP4 tags via Mutagen and synchronizes filesystem timestamps."""
    tags_applied = False
    try:
        from mutagen.mp4 import MP4
        dst = MP4(temp_path)

        # First attempt extracting atoms directly from source MP4
        if orig_path.lower().endswith((".mp4", ".m4v")) and os.path.exists(orig_path):
            try:
                src = MP4(orig_path)
                for atom in ["\xa9nam", "\xa9ART", "\xa9day", "\xa9cmt", "\xa9alb", "covr", "desc"]:
                    if atom in src:
                        dst[atom] = src[atom]
                        tags_applied = True
            except Exception:
                pass

        # Fallback to database metadata if atoms are absent
        if "\xa9nam" not in dst and candidate.get("existing_title"):
            dst["\xa9nam"] = [str(candidate["existing_title"])]
            tags_applied = True
        if "\xa9ART" not in dst and candidate.get("existing_artist"):
            dst["\xa9ART"] = [str(candidate["existing_artist"])]
            tags_applied = True
        if "\xa9day" not in dst and candidate.get("existing_date"):
            dst["\xa9day"] = [str(candidate["existing_date"])]
            tags_applied = True
        if "\xa9cmt" not in dst:
            cmt = candidate.get("studio") or candidate.get("existing_comment")
            if cmt:
                dst["\xa9cmt"] = [str(cmt)]
                tags_applied = True

        if tags_applied:
            dst.save()
    except Exception as e:
        print(f"[!] Warning: Mutagen metadata transfer error: {e}")

    # Restore modification and access timestamps
    try:
        if os.path.exists(orig_path):
            st = os.stat(orig_path)
            os.utime(temp_path, (st.st_atime, st.st_mtime))
    except Exception as e:
        print(f"[!] Warning: Timestamp restoration error: {e}")

    return tags_applied

def record_transaction(
    conn: sqlite3.Connection,
    file_path: str,
    original_size: int,
    av1_size: int,
    saved_bytes: int,
    compression_ratio: float,
    duration: float,
    vmaf_score: Optional[float],
    transcode_time_sec: float,
    status: str
) -> None:
    """Records atomic transcode attempt to SQLite ledger."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with conn:
        conn.execute(
            """
            INSERT INTO transactions (
                file_path, original_size, av1_size, saved_bytes, compression_ratio,
                duration, vmaf_score, transcode_time_sec, executed_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                original_size = excluded.original_size,
                av1_size = excluded.av1_size,
                saved_bytes = excluded.saved_bytes,
                compression_ratio = excluded.compression_ratio,
                duration = excluded.duration,
                vmaf_score = excluded.vmaf_score,
                transcode_time_sec = excluded.transcode_time_sec,
                executed_at = excluded.executed_at,
                status = excluded.status
            """,
            (
                file_path, original_size, av1_size, saved_bytes, compression_ratio,
                duration, vmaf_score, transcode_time_sec, now_str, status
            )
        )

def sync_inventory_db(
    db_path: str,
    old_file_path: str,
    new_file_path: str,
    new_size: int,
    new_bitrate: int
) -> bool:
    """Updates media_inventory.db with modernized AV1 metrics."""
    if not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        with conn:
            new_ext = os.path.splitext(new_file_path)[1].lower()
            new_filename = os.path.basename(new_file_path)
            conn.execute(
                """
                UPDATE media_files
                SET file_path = ?,
                    filename = ?,
                    extension = ?,
                    v_codec = 'av1',
                    file_size = ?,
                    bitrate = ?
                WHERE file_path = ?
                """,
                (new_file_path, new_filename, new_ext, new_size, new_bitrate, old_file_path)
            )
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Warning: Inventory DB update error for {old_file_path}: {e}")
        return False

def optimize_single_file(
    candidate: Dict[str, Any],
    ffmpeg_bin: str,
    ffprobe_bin: str,
    ledger_conn: sqlite3.Connection,
    inventory_db: str,
    cq: int,
    backup_dir: Optional[str] = None
) -> Dict[str, Any]:
    """Executes full optimization workflow on a single video file."""
    orig_path = candidate["file_path"]
    if not os.path.exists(orig_path):
        record_transaction(
            ledger_conn, orig_path, 0, 0, 0, 0.0, 0.0, None, 0.0, "failed_missing_source"
        )
        return {"status": "failed", "reason": "Source file does not exist", "path": orig_path}

    parent_dir = os.path.dirname(orig_path)
    file_stem, ext = os.path.splitext(os.path.basename(orig_path))
    timestamp = int(time.time() * 1000)
    temp_output_path = os.path.join(parent_dir, f"._tmp_av1_{file_stem}_{timestamp}.mp4")

    has_audio = candidate.get("a_codec") not in (None, "", "none", "null")
    cmd = build_ffmpeg_command(ffmpeg_bin, orig_path, temp_output_path, cq, has_audio)

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        transcode_time = time.time() - t0

        if proc.returncode != 0:
            if os.path.exists(temp_output_path):
                clear_readonly(temp_output_path)
                os.remove(temp_output_path)
            record_transaction(
                ledger_conn, orig_path, candidate.get("file_size", 0), 0, 0, 0.0,
                candidate.get("duration", 0.0), None, transcode_time, "failed_ffmpeg_error"
            )
            return {"status": "failed", "reason": f"FFmpeg error: {proc.stderr.strip()}", "path": orig_path}

        valid, msg, temp_info = verify_transcode(temp_output_path, orig_path, candidate, ffprobe_bin)
        if not valid:
            temp_size = temp_info["size"] if temp_info else 0
            if os.path.exists(temp_output_path):
                clear_readonly(temp_output_path)
                os.remove(temp_output_path)

            status_tag = "skipped_negative_delta" if "Negative delta" in msg else "failed_verification"
            record_transaction(
                ledger_conn, orig_path, candidate.get("file_size", 0), temp_size, 0,
                (temp_size / candidate.get("file_size", 1)) if candidate.get("file_size") else 1.0,
                candidate.get("duration", 0.0), None, transcode_time, status_tag
            )
            return {"status": status_tag, "reason": msg, "path": orig_path}

        # Transfer metadata and timestamps
        transfer_metadata(orig_path, temp_output_path, candidate)

        # Optional backup
        if backup_dir:
            os.makedirs(backup_dir, exist_ok=True)
            shutil.copy2(orig_path, os.path.join(backup_dir, os.path.basename(orig_path)))

        # Target destination path (always .mp4)
        dest_path = os.path.join(parent_dir, f"{file_stem}.mp4")

        # Atomic replacement
        clear_readonly(dest_path)
        clear_readonly(temp_output_path)
        os.replace(temp_output_path, dest_path)

        # Restore timestamps on destination
        try:
            st = os.stat(dest_path)
            orig_stat = os.stat(orig_path) if os.path.exists(orig_path) and orig_path != dest_path else st
            os.utime(dest_path, (orig_stat.st_atime, orig_stat.st_mtime))
        except Exception:
            pass

        # If source was not .mp4 (e.g. .mkv), remove original
        if orig_path != dest_path and os.path.exists(orig_path):
            clear_readonly(orig_path)
            os.remove(orig_path)

        orig_size = candidate.get("file_size") or 0
        new_size = temp_info["size"]
        saved_bytes = orig_size - new_size
        comp_ratio = (new_size / orig_size) if orig_size > 0 else 1.0
        new_bitrate = temp_info["bitrate"]

        # Record to ledger
        record_transaction(
            ledger_conn, orig_path, orig_size, new_size, saved_bytes, comp_ratio,
            temp_info["duration"], None, transcode_time, "completed"
        )

        # Live sync to media_inventory.db
        sync_inventory_db(inventory_db, orig_path, dest_path, new_size, new_bitrate)

        return {
            "status": "completed",
            "path": dest_path,
            "orig_size": orig_size,
            "new_size": new_size,
            "saved_bytes": saved_bytes,
            "compression_ratio": comp_ratio,
            "transcode_time": transcode_time
        }

    except Exception as e:
        if os.path.exists(temp_output_path):
            try:
                clear_readonly(temp_output_path)
                os.remove(temp_output_path)
            except Exception:
                pass
        record_transaction(
            ledger_conn, orig_path, candidate.get("file_size", 0), 0, 0, 0.0,
            candidate.get("duration", 0.0), None, 0.0, f"failed_exception_{type(e).__name__}"
        )
        return {"status": "failed", "reason": str(e), "path": orig_path}

def print_summary(ledger_path: str) -> None:
    """Prints aggregate execution metrics from the transactional ledger."""
    if not os.path.exists(ledger_path):
        print(f"No ledger database found at '{ledger_path}'.")
        return

    conn = sqlite3.connect(ledger_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT status, COUNT(*), SUM(original_size), SUM(av1_size), SUM(saved_bytes)
        FROM transactions
        GROUP BY status
    """)
    rows = cur.fetchall()
    conn.close()

    print("\n" + "=" * 65)
    print("AV1 SPACE OPTIMIZATION LEDGER SUMMARY")
    print("=" * 65)
    total_saved = 0
    total_completed = 0
    for status, count, orig_s, av1_s, saved in rows:
        orig_mb = (orig_s or 0) / (1024 * 1024)
        saved_mb = (saved or 0) / (1024 * 1024)
        saved_gb = saved_mb / 1024
        print(f"Status: {status:<24} Count: {count:<6} Saved: {saved_mb:10.1f} MB ({saved_gb:6.2f} GB)")
        if status == "completed":
            total_saved += (saved or 0)
            total_completed += count
    print("-" * 65)
    total_gb = total_saved / (1024 * 1024 * 1024)
    print(f"Total Completed: {total_completed} files | Total Space Reclaimed: {total_gb:.2f} GB")
    print("=" * 65 + "\n")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hardware-accelerated AV1 space-optimization pipeline for Aloha"
    )
    parser.add_argument("--tier", default="all", choices=["A", "B", "C", "D", "all"],
                        help="Pareto tier to optimize (A: Studios, B: Movies, C: Collections, all: A+B+C)")
    parser.add_argument("--file", default=None, help="Target specific single file for transcode")
    parser.add_argument("--dry-run", action="store_true", help="Catalog candidates and show projections without changes")
    parser.add_argument("--cq", type=int, default=28, help="Constant quality target (default: 28)")
    parser.add_argument("--adaptive-cq", action="store_true", help="Adaptively adjust CQ based on resolution and bitrate")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent encoding jobs (default: 1)")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of candidates to process")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to media_inventory.db")
    parser.add_argument("--ledger", default=DEFAULT_LEDGER_PATH, help="Path to av1_transcode_ledger.db")
    parser.add_argument("--backup-dir", default=None, help="Directory to preserve original files before swap")
    parser.add_argument("--summary", action="store_true", help="Print ledger summary and exit")
    args = parser.parse_args()

    if args.summary:
        print_summary(args.ledger)
        return

    ffmpeg_bin, ffprobe_bin = get_tool_paths()
    ledger_conn = init_ledger(args.ledger)

    candidates = query_candidates(args.db, tier=args.tier, target_file=args.file)
    if args.limit and args.limit > 0:
        candidates = candidates[:args.limit]

    # Filter out candidates already successfully completed in ledger
    cur = ledger_conn.cursor()
    cur.execute("SELECT file_path FROM transactions WHERE status = 'completed'")
    completed_paths = {row[0] for row in cur.fetchall()}
    active_candidates = [c for c in candidates if c["file_path"] not in completed_paths]

    total_count = len(candidates)
    active_count = len(active_candidates)
    total_bytes = sum(c.get("file_size") or 0 for c in candidates)
    active_bytes = sum(c.get("file_size") or 0 for c in active_candidates)

    print(f"Target Scope: Tier={args.tier} | Total Found={total_count} ({total_bytes / (1024**3):.2f} GB)")
    print(f"Active Candidates: {active_count} ({active_bytes / (1024**3):.2f} GB) | Completed={total_count - active_count}")

    if args.dry_run:
        print("\n[DRY RUN] Candidate sample:")
        for idx, c in enumerate(active_candidates[:15], 1):
            target_cq = calculate_target_cq(c, args.cq, args.adaptive_cq)
            size_mb = (c.get("file_size") or 0) / (1024 * 1024)
            print(f"  {idx:2d}. [{c['tier']}] CQ {target_cq:2d} | {size_mb:8.1f} MB | {os.path.basename(c['file_path'])}")
        if active_count > 15:
            print(f"  ... and {active_count - 15} more candidates.")
        est_min_gb = (active_bytes * 0.30) / (1024**3)
        est_max_gb = (active_bytes * 0.50) / (1024**3)
        print(f"\nProjected Space Reclamation: {est_min_gb:.2f} GB to {est_max_gb:.2f} GB")
        ledger_conn.close()
        return

    print("\nStarting AV1 hardware-accelerated transcode pipeline...")
    completed_count = 0
    skipped_count = 0
    failed_count = 0
    reclaimed_bytes = 0

    t_start = time.time()
    for idx, c in enumerate(active_candidates, 1):
        target_cq = calculate_target_cq(c, args.cq, args.adaptive_cq)
        file_name = os.path.basename(c["file_path"])
        size_mb = (c.get("file_size") or 0) / (1024 * 1024)
        print(f"\n[{idx}/{active_count}] [{c['tier']}] Processing: {file_name} ({size_mb:.1f} MB, CQ {target_cq})...")

        res = optimize_single_file(
            c, ffmpeg_bin, ffprobe_bin, ledger_conn, args.db, target_cq, args.backup_dir
        )

        status = res["status"]
        if status == "completed":
            saved_mb = res["saved_bytes"] / (1024 * 1024)
            saved_pct = (1.0 - res["compression_ratio"]) * 100.0
            reclaimed_bytes += res["saved_bytes"]
            completed_count += 1
            print(f"  -> COMPLETED in {res['transcode_time']:.1f}s | Saved: {saved_mb:.1f} MB ({saved_pct:.1f}%)")
        elif status == "skipped_negative_delta":
            skipped_count += 1
            print(f"  -> SKIPPED (Negative Delta): {res['reason']}")
        else:
            failed_count += 1
            print(f"  -> FAILED: {res.get('reason', 'Unknown error')}")

    total_time = time.time() - t_start
    total_reclaimed_gb = reclaimed_bytes / (1024**3)
    print("\n" + "=" * 65)
    print("EXECUTION RUN COMPLETE")
    print(f"Processed: {active_count} | Completed: {completed_count} | Skipped: {skipped_count} | Failed: {failed_count}")
    print(f"Total Space Reclaimed This Run: {total_reclaimed_gb:.2f} GB")
    print(f"Total Elapsed Time: {total_time / 60:.1f} minutes")
    print("=" * 65)

    ledger_conn.close()

if __name__ == "__main__":
    main()
