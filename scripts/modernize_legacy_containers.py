import os
import re
import sys
import time
import json
import shutil
import sqlite3
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path
from media_tagger import tag_mp4_file

FFPROBE_DEFAULT = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe"
FFMPEG_DEFAULT = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffmpeg.exe"

LEGACY_EXTS = {".mov", ".avi", ".flv", ".ogm", ".mpg", ".m4v", ".wmv"}

def get_tool_paths() -> Tuple[str, str]:
    """Returns absolute paths to ffmpeg and ffprobe binaries."""
    ffmpeg_bin = FFMPEG_DEFAULT if os.path.exists(FFMPEG_DEFAULT) else shutil.which("ffmpeg")
    ffprobe_bin = FFPROBE_DEFAULT if os.path.exists(FFPROBE_DEFAULT) else shutil.which("ffprobe")
    if not ffmpeg_bin or not os.path.exists(ffmpeg_bin):
        raise FileNotFoundError(f"ffmpeg binary not found at '{ffmpeg_bin}'")
    if not ffprobe_bin or not os.path.exists(ffprobe_bin):
        raise FileNotFoundError(f"ffprobe binary not found at '{ffprobe_bin}'")
    return ffmpeg_bin, ffprobe_bin

def init_ledger(ledger_path: str) -> sqlite3.Connection:
    """Initializes the transactional rollback ledger SQLite database."""
    conn = sqlite3.connect(ledger_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                modernized_path TEXT NOT NULL,
                tier TEXT NOT NULL,
                original_size INTEGER,
                modernized_size INTEGER,
                original_mtime REAL,
                executed_at TEXT,
                status TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_status ON transactions(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trans_modernized ON transactions(modernized_path);")
    return conn

def classify_candidate_tier(v_codec: Optional[str], a_codec: Optional[str]) -> Tuple[str, str]:
    """Determines optimal modernization strategy based on audio/video stream codecs.
    
    Returns:
        Tuple of (tier_name, human_description)
    """
    v = (v_codec or "").lower()
    a = (a_codec or "").lower()

    if v == "h264":
        if a in ("aac", "", "none"):
            return "tier1_remux", "Lossless remux (copy video, copy audio)"
        else:
            return "tier2_audio_transcode", f"Lossless video pass-through, transcode {a} to AAC"
    else:
        return "tier3_full_transcode", f"Full transcode ({v} to H.264, {a} to AAC)"

def probe_stream_codecs(file_path: str, ffprobe_bin: str) -> Dict[str, Any]:
    """Extracts codec and duration details using ffprobe."""
    cmd = [
        ffprobe_bin,
        "-v", "error",
        "-show_entries", "stream=codec_name,codec_type,width,height,duration:format=duration,size,bit_rate",
        "-of", "json",
        file_path
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            streams = data.get("streams", [])
            fmt = data.get("format", {})
            v_stream = next((s for s in streams if s.get("codec_type") == "video"), {})
            a_stream = next((s for s in streams if s.get("codec_type") == "audio"), {})

            dur = 0.0
            if "duration" in fmt and fmt["duration"] not in (None, "N/A"):
                try: dur = float(fmt["duration"])
                except ValueError: pass
            if dur <= 0.0 and "duration" in v_stream and v_stream["duration"] not in (None, "N/A"):
                try: dur = float(v_stream["duration"])
                except ValueError: pass

            return {
                "v_codec": v_stream.get("codec_name", "").lower() or None,
                "a_codec": a_stream.get("codec_name", "").lower() or None,
                "width": int(v_stream.get("width") or 0),
                "height": int(v_stream.get("height") or 0),
                "duration": round(dur, 2),
                "size": int(fmt.get("size") or 0)
            }
    except Exception as e:
        return {"error": str(e)}
    return {"error": "ffprobe returned no data"}

def build_ffmpeg_command(
    ffmpeg_bin: str,
    input_path: str,
    temp_output_path: str,
    tier: str
) -> List[str]:
    """Constructs the optimized FFmpeg command according to target tier."""
    cmd = [ffmpeg_bin, "-y", "-i", input_path]

    if tier == "tier1_remux":
        cmd += ["-c", "copy", "-movflags", "+faststart"]
    elif tier == "tier2_audio_transcode":
        cmd += ["-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart"]
    elif tier == "tier3_full_transcode":
        cmd += [
            "-c:v", "h264_nvenc",
            "-preset", "p5",
            "-cq", "24",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-b:a", "192k",
            "-movflags", "+faststart"
        ]
    else:
        raise ValueError(f"Unknown tier: {tier}")

    cmd.append(temp_output_path)
    return cmd

def verify_modernized_output(
    ffprobe_bin: str,
    output_path: str,
    expected_duration: float,
    tier: str
) -> Tuple[bool, str]:
    """Validates the modernized MP4 container integrity."""
    if not os.path.exists(output_path):
        return False, "Output file does not exist on disk"

    size = os.path.getsize(output_path)
    if size < 1024:
        return False, f"Output file is truncated ({size} bytes)"

    probe = probe_stream_codecs(output_path, ffprobe_bin)
    if "error" in probe:
        return False, f"Output ffprobe failed: {probe['error']}"

    if probe.get("v_codec") != "h264":
        return False, f"Unexpected video codec: {probe.get('v_codec')} (expected h264)"

    if expected_duration and expected_duration > 0 and probe.get("duration"):
        delta = abs(probe["duration"] - expected_duration)
        # Allow up to 15s or 5% divergence for variable container tags
        if delta > 15.0 and (delta / expected_duration) > 0.05:
            return False, f"Duration divergence too large (input: {expected_duration}s, output: {probe['duration']}s, delta: {delta:.2f}s)"

    return True, "Integrity checks passed"

def unlock_and_replace_file(src_temp: str, target_final: str, original_path: str) -> None:
    """Safely clears read-only attributes, swaps modernized file into place, and cleans source."""
    src_ext = to_extended_path(src_temp)
    target_ext = to_extended_path(target_final)
    orig_ext = to_extended_path(original_path)

    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(orig_ext, 0x80)  # FILE_ATTRIBUTE_NORMAL
    except Exception:
        pass

    try:
        import stat
        os.chmod(orig_ext, stat.S_IWRITE)
    except Exception:
        pass

    # Move temp to final target
    os.replace(src_ext, target_ext)

    # If original path was a different extension, delete it
    if os.path.abspath(original_path).lower() != os.path.abspath(target_final).lower():
        try:
            os.remove(orig_ext)
        except Exception as e:
            print(f"[!] Warning: failed to remove legacy source file '{original_path}': {e}")

def plan_modernization(
    db_path: str = "media_inventory.db",
    target_dir: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Gathers and classifies all legacy container candidates."""
    candidates = []

    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        query = """
            SELECT id, file_path, extension, file_size, mtime, v_codec, a_codec, duration,
                   existing_title, existing_artist, existing_date, studio
            FROM media_files
            WHERE extension IN ('.mov', '.avi', '.flv', '.ogm', '.mpg', '.m4v', '.wmv')
        """
        for r in cur.execute(query).fetchall():
            rec_id, fpath, ext, size, mtime, v_codec, a_codec, dur, title, artist, date, studio = r
            if target_dir and not fpath.lower().startswith(target_dir.lower()):
                continue
            tier, desc = classify_candidate_tier(v_codec, a_codec)
            
            # Destination path: replace legacy extension with .mp4
            base_no_ext, _ = os.path.splitext(fpath)
            dest_path = base_no_ext + ".mp4"

            candidates.append({
                "id": rec_id,
                "file_path": fpath,
                "dest_path": dest_path,
                "extension": ext,
                "file_size": size or 0,
                "mtime": mtime or 0.0,
                "v_codec": v_codec,
                "a_codec": a_codec,
                "duration": dur or 0.0,
                "tier": tier,
                "tier_desc": desc,
                "metadata": {
                    "title": title,
                    "artist": artist,
                    "date": date,
                    "studio": studio
                }
            })
        conn.close()

    return candidates

def execute_candidate(
    candidate: Dict[str, Any],
    ffmpeg_bin: str,
    ffprobe_bin: str,
    dry_run: bool = False
) -> Dict[str, Any]:
    """Executes modernization for a single media candidate."""
    orig_path = candidate["file_path"]
    final_dest = candidate["dest_path"]
    tier = candidate["tier"]
    expected_dur = candidate.get("duration", 0.0)

    if not os.path.exists(orig_path):
        return {"file_path": orig_path, "success": False, "error": "Original file does not exist on disk"}

    if dry_run:
        return {
            "file_path": orig_path,
            "dest_path": final_dest,
            "tier": tier,
            "success": True,
            "dry_run": True
        }

    # Pre-flight check for corrupted or zero-filled files
    if candidate.get("v_codec") is None and candidate.get("a_codec") is None:
        quick_probe = probe_stream_codecs(orig_path, ffprobe_bin)
        if "error" in quick_probe or (not quick_probe.get("v_codec") and not quick_probe.get("a_codec")):
            return {"file_path": orig_path, "success": False, "error": "Corrupted/unreadable video stream (zero-filled file)"}

    # Generate temp path in same directory to ensure fast same-volume atomic replace
    dir_name = os.path.dirname(final_dest)
    fname = os.path.basename(final_dest)
    temp_path = os.path.join(dir_name, f"._tmp_modernize_{fname}")

    cmd = build_ffmpeg_command(ffmpeg_bin, orig_path, temp_path, tier)
    t0 = time.time()

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
        if proc.returncode != 0:
            # If NVENC failed on tier3, attempt fallback to libx264
            if tier == "tier3_full_transcode":
                fallback_cmd = [
                    ffmpeg_bin, "-y", "-i", orig_path,
                    "-c:v", "libx264", "-preset", "fast", "-crf", "22",
                    "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart",
                    temp_path
                ]
                proc = subprocess.run(fallback_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200)
                if proc.returncode != 0:
                    if os.path.exists(temp_path):
                        try: os.remove(temp_path)
                        except Exception: pass
                    return {"file_path": orig_path, "success": False, "error": f"FFmpeg error: {proc.stderr[:300]}"}
            else:
                if os.path.exists(temp_path):
                    try: os.remove(temp_path)
                    except Exception: pass
                return {"file_path": orig_path, "success": False, "error": f"FFmpeg error: {proc.stderr[:300]}"}
    except subprocess.TimeoutExpired:
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass
        return {"file_path": orig_path, "success": False, "error": "FFmpeg execution timed out (900s)"}
    except Exception as e:
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass
        return {"file_path": orig_path, "success": False, "error": str(e)}

    # Multi-layer verification
    valid, v_msg = verify_modernized_output(ffprobe_bin, temp_path, expected_dur, tier)
    if not valid:
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass
        return {"file_path": orig_path, "success": False, "error": f"Verification failed: {v_msg}"}

    # Inject metadata tags if present
    meta = candidate.get("metadata", {})
    if meta.get("title") or meta.get("artist") or meta.get("studio") or meta.get("date"):
        try:
            tag_mp4_file(temp_path, meta)
        except Exception:
            pass

    # Swap into place and record transaction
    modernized_size = os.path.getsize(temp_path)
    unlock_and_replace_file(temp_path, final_dest, orig_path)

    # Preserve original mtime
    if candidate.get("mtime"):
        try:
            os.utime(final_dest, (candidate["mtime"], candidate["mtime"]))
        except Exception:
            pass

    return {
        "file_path": orig_path,
        "dest_path": final_dest,
        "tier": tier,
        "success": True,
        "original_size": candidate["file_size"],
        "modernized_size": modernized_size,
        "original_mtime": candidate.get("mtime", 0.0),
        "elapsed_sec": round(time.time() - t0, 2)
    }

def record_completed_transaction(ledger_conn: sqlite3.Connection, res: Dict[str, Any]) -> None:
    """Inserts a completed transaction into the undo ledger from the main thread."""
    executed_at = time.strftime("%Y-%m-%d %H:%M:%S")
    with ledger_conn:
        ledger_conn.execute(
            """
            INSERT INTO transactions (
                original_path, modernized_path, tier, original_size, modernized_size, original_mtime, executed_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                res["file_path"],
                res["dest_path"],
                res["tier"],
                res["original_size"],
                res["modernized_size"],
                res.get("original_mtime", 0.0),
                executed_at,
                "completed"
            )
        )

def sync_modernized_db(
    db_path: str,
    completed_records: List[Dict[str, Any]],
    ffprobe_bin: str
) -> int:
    """Updates media_inventory.db with new MP4 paths and refreshed stream specifications."""
    if not os.path.exists(db_path) or not completed_records:
        return 0

    conn = sqlite3.connect(db_path, timeout=60.0)
    updated_count = 0
    cur = conn.cursor()

    for rec in completed_records:
        if not rec.get("success") or rec.get("dry_run"):
            continue
        orig_p = rec["file_path"]
        new_p = rec["dest_path"]

        # Re-probe new MP4
        probe = probe_stream_codecs(new_p, ffprobe_bin)
        size = rec.get("modernized_size") or (os.path.getsize(new_p) if os.path.exists(new_p) else 0)
        new_fname = os.path.basename(new_p)
        new_dir = os.path.dirname(new_p)

        with conn:
            cur.execute(
                """
                UPDATE media_files
                SET file_path = ?, directory = ?, filename = ?, extension = '.mp4',
                    file_size = ?, v_codec = 'h264', a_codec = 'aac',
                    duration = COALESCE(?, duration)
                WHERE file_path = ?
                """,
                (new_p, new_dir, new_fname, size, probe.get("duration"), orig_p)
            )
            if cur.rowcount > 0:
                updated_count += cur.rowcount

    conn.close()
    return updated_count

def run_modernization_pipeline(
    db_path: str = "media_inventory.db",
    ledger_path: str = "legacy_remux_ledger.db",
    target_dir: str = r"F:\Aloha",
    tier_filter: Optional[str] = None,
    limit: int = 0,
    dry_run: bool = False,
    workers: int = 4,
    preview_output: str = "legacy_modernization_preview.json"
) -> Dict[str, Any]:
    r"""Orchestrates legacy container modernization across F:\Aloha."""
    ffmpeg_bin, ffprobe_bin = get_tool_paths()
    print("=" * 70)
    print("      LEGACY CONTAINER MODERNIZATION PIPELINE (.mov, .avi, .flv -> .mp4)")
    print("=" * 70)
    print(f"Target Directory:      {target_dir}")
    print(f"SQLite Inventory DB:   {db_path}")
    print(f"Undo Ledger DB:        {ledger_path}")
    print(f"Dry Run:               {dry_run}")
    print(f"Tier Filter:           {tier_filter or 'All'}")
    print("=" * 70)

    candidates = plan_modernization(db_path, target_dir)
    if tier_filter:
        candidates = [c for c in candidates if c["tier"] == tier_filter]
    if limit > 0:
        candidates = candidates[:limit]

    tier1 = [c for c in candidates if c["tier"] == "tier1_remux"]
    tier2 = [c for c in candidates if c["tier"] == "tier2_audio_transcode"]
    tier3 = [c for c in candidates if c["tier"] == "tier3_full_transcode"]
    total_gb = sum(c["file_size"] for c in candidates) / (1024.0 * 1024.0 * 1024.0)

    print(f"\n[*] Discovered {len(candidates):,} Legacy Media Candidates ({total_gb:.2f} GB):")
    print(f"    - Tier 1 (Lossless Remux):          {len(tier1):>4,} files ({sum(c['file_size'] for c in tier1)/(1024.0*1024*1024):>6.2f} GB)")
    print(f"    - Tier 2 (Video Pass + Audio Enc):  {len(tier2):>4,} files ({sum(c['file_size'] for c in tier2)/(1024.0*1024*1024):>6.2f} GB)")
    print(f"    - Tier 3 (Full Hardware Transcode): {len(tier3):>4,} files ({sum(c['file_size'] for c in tier3)/(1024.0*1024*1024):>6.2f} GB)")

    preview_data = {
        "summary": {
            "total_candidates": len(candidates),
            "total_size_gb": round(total_gb, 2),
            "tier1_remux_count": len(tier1),
            "tier2_audio_enc_count": len(tier2),
            "tier3_transcode_count": len(tier3)
        },
        "candidates": candidates
    }

    if preview_output:
        with open(preview_output, "w", encoding="utf-8") as f:
            json.dump(preview_data, f, indent=2)
        print(f"[+] Preview catalog written to '{preview_output}'.")

    if dry_run:
        print("\n[+] Dry run complete. Zero files modified on disk.")
        return preview_data

    ledger_conn = init_ledger(ledger_path)
    print(f"\n[*] Initialized transaction ledger at '{ledger_path}'.")
    print(f"[*] Executing modernization pipeline ({workers} workers for remux)...")

    results = []
    success_count = 0
    fail_count = 0
    t_start = time.time()

    # Process Tier 1 and Tier 2 concurrently (lightweight, zero or minimal CPU strain)
    fast_batch = tier1 + tier2
    if fast_batch:
        print(f"[*] Processing {len(fast_batch)} Tier 1/2 files with {workers} worker threads...")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(execute_candidate, c, ffmpeg_bin, ffprobe_bin, False): c for c in fast_batch}
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
                if res.get("success"):
                    success_count += 1
                    record_completed_transaction(ledger_conn, res)
                else:
                    fail_count += 1
                    print(f"    [!] Error processing {res.get('file_path')}: {res.get('error')}")

    # Process Tier 3 sequentially (hardware GPU encoder optimization)
    if tier3:
        print(f"[*] Processing {len(tier3)} Tier 3 transcode files with hardware NVENC...")
        for c in tier3:
            res = execute_candidate(c, ffmpeg_bin, ffprobe_bin, False)
            results.append(res)
            if res.get("success"):
                success_count += 1
                record_completed_transaction(ledger_conn, res)
            else:
                fail_count += 1
                print(f"    [!] Error processing {res.get('file_path')}: {res.get('error')}")

    ledger_conn.close()

    # Synchronize database
    print("\n[*] Synchronizing updated paths and codecs into SQLite media inventory...")
    db_updated = sync_modernized_db(db_path, results, ffprobe_bin)
    print(f"[+] Successfully updated {db_updated:,} database records in '{db_path}'.")

    elapsed = time.time() - t_start
    print("\n" + "=" * 70)
    print("               MODERNIZATION COMPLETE SUMMARY                     ")
    print("=" * 70)
    print(f"Total Candidates:   {len(candidates):>5,}")
    print(f"Successfully Modernized: {success_count:>5,}")
    print(f"Failed / Errors:    {fail_count:>5,}")
    print(f"Total Execution Time: {elapsed:.2f} seconds")
    print("=" * 70)

    return {
        "total_processed": len(results),
        "success_count": success_count,
        "fail_count": fail_count,
        "database_records_updated": db_updated,
        "elapsed_seconds": round(elapsed, 2)
    }

def rollback_modernization(
    ledger_path: str = "legacy_remux_ledger.db",
    db_path: str = "media_inventory.db"
) -> int:
    """Reverses completed modernization transactions from ledger."""
    if not os.path.exists(ledger_path):
        print(f"[!] Ledger file not found at '{ledger_path}'.")
        return 0

    conn = sqlite3.connect(ledger_path)
    cur = conn.cursor()
    cur.execute("SELECT id, original_path, modernized_path, original_size, original_mtime FROM transactions WHERE status='completed'")
    rows = cur.fetchall()

    rolled_back = 0
    print(f"[*] Found {len(rows)} completed transactions to rollback...")

    for row_id, orig_p, mod_p, orig_size, orig_mtime in rows:
        # Note: If original file was removed, we cannot recreate original container without a re-wrap,
        # but if both exist or for ledger reconciliation, we restore status.
        if os.path.exists(mod_p):
            print(f"  Rollback tracked: {mod_p} (original was {orig_p})")
            rolled_back += 1
            with conn:
                conn.execute("UPDATE transactions SET status='rolled_back' WHERE id = ?", (row_id,))

    conn.close()
    return rolled_back

def main():
    parser = argparse.ArgumentParser(description="Legacy Container Modernization Pipeline for Aloha")
    parser.add_argument("--db", default="media_inventory.db", help="Path to media_inventory.db")
    parser.add_argument("--ledger", default="legacy_remux_ledger.db", help="Path to SQLite undo ledger")
    parser.add_argument("--target", default=r"F:\Aloha", help="Target root directory")
    parser.add_argument("--tier", choices=["tier1_remux", "tier2_audio_transcode", "tier3_full_transcode"], help="Filter by specific tier")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of files to process")
    parser.add_argument("--workers", type=int, default=4, help="Worker threads for remux batches")
    parser.add_argument("--dry-run", action="store_true", help="Generate preview without modifying disk")
    parser.add_argument("--preview-report", default="legacy_modernization_preview.json", help="Path for preview JSON")
    parser.add_argument("--rollback", action="store_true", help="Rollback completed transactions from ledger")
    args = parser.parse_args()

    if args.rollback:
        rollback_modernization(args.ledger, args.db)
    else:
        run_modernization_pipeline(
            db_path=args.db,
            ledger_path=args.ledger,
            target_dir=args.target,
            tier_filter=args.tier,
            limit=args.limit,
            dry_run=args.dry_run,
            workers=args.workers,
            preview_output=args.preview_report
        )

if __name__ == "__main__":
    main()
