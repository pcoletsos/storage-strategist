import os
import sys
import time
import json
import sqlite3
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FFPROBE_DEFAULT = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe"

VIDEO_EXTS = {".mp4", ".mkv", ".mov", ".avi", ".flv", ".webm", ".ogm", ".mpg", ".m4v", ".wmv", ".ts"}
IMAGE_EXTS = {".jpg", ".jpeg", ".webp", ".png", ".gif", ".bmp", ".rpgmvp"}

def get_ffprobe_path() -> Optional[str]:
    if os.path.exists(FFPROBE_DEFAULT):
        return FFPROBE_DEFAULT
    import shutil
    return shutil.which("ffprobe")

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS media_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                directory TEXT,
                filename TEXT,
                extension TEXT,
                media_type TEXT,
                file_size INTEGER,
                mtime REAL,
                v_codec TEXT,
                a_codec TEXT,
                width INTEGER,
                height INTEGER,
                duration REAL,
                bitrate INTEGER,
                resolution_tier TEXT,
                existing_title TEXT,
                existing_artist TEXT,
                existing_date TEXT,
                existing_comment TEXT,
                exif_datetime TEXT,
                exif_artist TEXT,
                scanned_at TEXT,
                error TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_media_type ON media_files(media_type);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_extension ON media_files(extension);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_directory ON media_files(directory);")
    return conn

def classify_resolution(width: int, height: int) -> str:
    if width <= 0 and height <= 0:
        return "Unknown"
    max_dim = max(width, height)
    min_dim = min(width, height)
    if min_dim >= 2160 or max_dim >= 3840:
        return "2160p/4K"
    elif min_dim >= 1080 or max_dim >= 1920:
        return "1080p"
    elif min_dim >= 720 or max_dim >= 1280:
        return "720p"
    elif min_dim >= 480 or max_dim >= 854:
        return "480p"
    else:
        return "SD"

def probe_video(file_path: str, ffprobe_bin: Optional[str]) -> Dict[str, Any]:
    stat = None
    try:
        stat = os.stat(file_path)
    except Exception as e:
        return {"error": f"Stat error: {e}"}

    record = {
        "file_path": file_path,
        "directory": os.path.dirname(file_path),
        "filename": os.path.basename(file_path),
        "extension": os.path.splitext(file_path)[1].lower(),
        "media_type": "video",
        "file_size": stat.st_size if stat else 0,
        "mtime": stat.st_mtime if stat else 0.0,
        "v_codec": None,
        "a_codec": None,
        "width": 0,
        "height": 0,
        "duration": 0.0,
        "bitrate": 0,
        "resolution_tier": "Unknown",
        "existing_title": None,
        "existing_artist": None,
        "existing_date": None,
        "existing_comment": None,
        "exif_datetime": None,
        "exif_artist": None,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "error": None
    }

    # First attempt reading with mutagen if MP4 / M4V
    if record["extension"] in (".mp4", ".m4v"):
        try:
            from mutagen.mp4 import MP4
            tags = MP4(file_path)
            if tags:
                record["existing_title"] = tags.get("\xa9nam", [None])[0]
                record["existing_artist"] = tags.get("\xa9ART", [None])[0]
                record["existing_date"] = tags.get("\xa9day", [None])[0]
                record["existing_comment"] = tags.get("\xa9cmt", [None])[0]
        except Exception:
            pass

    # Use ffprobe if available
    if ffprobe_bin and os.path.exists(ffprobe_bin):
        cmd = [
            ffprobe_bin,
            "-v", "error",
            "-show_entries", "stream=index,codec_name,codec_type,width,height,duration:format=duration,size,bit_rate:format_tags=title,artist,date,comment",
            "-of", "json",
            file_path
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                streams = data.get("streams", [])
                fmt = data.get("format", {})
                fmt_tags = fmt.get("tags", {})
                
                if not record["existing_title"] and fmt_tags.get("title"):
                    record["existing_title"] = str(fmt_tags.get("title"))
                if not record["existing_artist"] and fmt_tags.get("artist"):
                    record["existing_artist"] = str(fmt_tags.get("artist"))
                if not record["existing_date"] and fmt_tags.get("date"):
                    record["existing_date"] = str(fmt_tags.get("date"))
                if not record["existing_comment"] and fmt_tags.get("comment"):
                    record["existing_comment"] = str(fmt_tags.get("comment"))

                v_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
                a_stream = next((s for s in streams if s.get("codec_type") == "audio"), None)

                if v_stream:
                    record["v_codec"] = v_stream.get("codec_name", "").lower()
                    record["width"] = int(v_stream.get("width") or 0)
                    record["height"] = int(v_stream.get("height") or 0)
                    record["resolution_tier"] = classify_resolution(record["width"], record["height"])
                
                if a_stream:
                    record["a_codec"] = a_stream.get("codec_name", "").lower()

                # Duration
                dur = 0.0
                if "duration" in fmt and fmt["duration"] not in (None, "N/A"):
                    try:
                        dur = float(fmt["duration"])
                    except ValueError:
                        pass
                if dur <= 0.0 and v_stream and "duration" in v_stream and v_stream["duration"] not in (None, "N/A"):
                    try:
                        dur = float(v_stream["duration"])
                    except ValueError:
                        pass
                record["duration"] = round(dur, 2)

                # Bitrate
                br = 0
                if "bit_rate" in fmt and fmt["bit_rate"] not in (None, "N/A"):
                    try:
                        br = int(fmt["bit_rate"])
                    except ValueError:
                        pass
                if br <= 0 and dur > 0 and record["file_size"] > 0:
                    br = int((record["file_size"] * 8) / dur)
                record["bitrate"] = br
                return record
        except subprocess.TimeoutExpired:
            record["error"] = "ffprobe timeout (25s)"
            return record
        except Exception as e:
            record["error"] = f"ffprobe error: {e}"

    # Fallback to pymediainfo if ffprobe failed or was missing
    try:
        from pymediainfo import MediaInfo
        mi = MediaInfo.parse(file_path)
        for track in mi.tracks:
            if track.track_type == "Video" and not record["v_codec"]:
                record["v_codec"] = (track.format or "").lower()
                record["width"] = int(track.width or 0)
                record["height"] = int(track.height or 0)
                record["resolution_tier"] = classify_resolution(record["width"], record["height"])
            elif track.track_type == "Audio" and not record["a_codec"]:
                record["a_codec"] = (track.format or "").lower()
            elif track.track_type == "General":
                if not record["duration"] and track.duration:
                    record["duration"] = round(float(track.duration) / 1000.0, 2)
                if not record["existing_title"] and track.title:
                    record["existing_title"] = track.title
    except Exception as e:
        if not record["error"]:
            record["error"] = f"pymediainfo error: {e}"

    return record

def probe_image(file_path: str) -> Dict[str, Any]:
    stat = None
    try:
        stat = os.stat(file_path)
    except Exception as e:
        return {"error": f"Stat error: {e}"}

    record = {
        "file_path": file_path,
        "directory": os.path.dirname(file_path),
        "filename": os.path.basename(file_path),
        "extension": os.path.splitext(file_path)[1].lower(),
        "media_type": "image",
        "file_size": stat.st_size if stat else 0,
        "mtime": stat.st_mtime if stat else 0.0,
        "v_codec": None,
        "a_codec": None,
        "width": 0,
        "height": 0,
        "duration": 0.0,
        "bitrate": 0,
        "resolution_tier": "Unknown",
        "existing_title": None,
        "existing_artist": None,
        "existing_date": None,
        "existing_comment": None,
        "exif_datetime": None,
        "exif_artist": None,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "error": None
    }

    ext = record["extension"]
    if ext == ".rpgmvp":
        # Encrypted RPG Maker image asset
        record["v_codec"] = "rpgmvp"
        record["resolution_tier"] = "RPG-Asset"
        return record

    try:
        from PIL import Image
        with Image.open(file_path) as img:
            record["width"], record["height"] = img.size
            record["v_codec"] = (img.format or "").lower()
            record["resolution_tier"] = classify_resolution(record["width"], record["height"])

            # Extract EXIF if present
            exif = img.getexif()
            if exif:
                # 306 = DateTime, 36867 = DateTimeOriginal, 315 = Artist, 270 = ImageDescription
                dt = exif.get(36867) or exif.get(306)
                if dt:
                    record["exif_datetime"] = str(dt)
                art = exif.get(315)
                if art:
                    record["exif_artist"] = str(art)
                desc = exif.get(270)
                if desc:
                    record["existing_comment"] = str(desc)
    except Exception as e:
        record["error"] = f"PIL read error: {e}"

    return record

def scan_worker(file_path: str, ffprobe_bin: Optional[str]) -> Dict[str, Any]:
    ext = os.path.splitext(file_path)[1].lower()
    if ext in VIDEO_EXTS:
        return probe_video(file_path, ffprobe_bin)
    elif ext in IMAGE_EXTS:
        return probe_image(file_path)
    else:
        stat = os.stat(file_path)
        return {
            "file_path": file_path,
            "directory": os.path.dirname(file_path),
            "filename": os.path.basename(file_path),
            "extension": ext,
            "media_type": "other",
            "file_size": stat.st_size if stat else 0,
            "mtime": stat.st_mtime if stat else 0.0,
            "v_codec": None,
            "a_codec": None,
            "width": 0,
            "height": 0,
            "duration": 0.0,
            "bitrate": 0,
            "resolution_tier": "Other",
            "existing_title": None,
            "existing_artist": None,
            "existing_date": None,
            "existing_comment": None,
            "exif_datetime": None,
            "exif_artist": None,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": None
        }

def scan_target(target_dir: str, db_path: str, max_workers: int = 24, incremental: bool = True):
    print(f"[*] Initializing SQLite Media Inventory at '{db_path}'...")
    conn = init_db(db_path)
    ffprobe_bin = get_ffprobe_path()
    print(f"[*] Using ffprobe: {ffprobe_bin}")

    existing_paths = set()
    if incremental:
        cur = conn.cursor()
        for row in cur.execute("SELECT file_path FROM media_files"):
            existing_paths.add(row[0])
        print(f"[*] Found {len(existing_paths)} existing records in SQLite inventory.")

    print(f"[*] Walking filesystem at '{target_dir}'...")
    t0 = time.time()
    for root, dirs, files in os.walk(target_dir):
        # Exclude hidden directories and quarantine staging areas
        dirs[:] = [d for d in dirs if not d.startswith(".") and not d.startswith(".quarantine_")]
        if ".quarantine_" in root.replace("/", "\\"):
            continue

        for f in files:
            if f.startswith("._tmp_") or f == "Thumbs.db":
                continue
            full_path = os.path.join(root, f)
            if incremental and full_path in existing_paths:
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext in VIDEO_EXTS or ext in IMAGE_EXTS:
                all_files.append(full_path)

    total_files = len(all_files)
    print(f"[*] Discovered {total_files} files requiring inventorying in {time.time() - t0:.2f}s.")
    if total_files == 0:
        print("[+] Inventory is already up to date!")
        return

    batch = []
    BATCH_SIZE = 500
    completed = 0
    t_start = time.time()

    insert_sql = """
        INSERT OR REPLACE INTO media_files (
            file_path, directory, filename, extension, media_type,
            file_size, mtime, v_codec, a_codec, width, height,
            duration, bitrate, resolution_tier, existing_title,
            existing_artist, existing_date, existing_comment,
            exif_datetime, exif_artist, scanned_at, error
        ) VALUES (
            :file_path, :directory, :filename, :extension, :media_type,
            :file_size, :mtime, :v_codec, :a_codec, :width, :height,
            :duration, :bitrate, :resolution_tier, :existing_title,
            :existing_artist, :existing_date, :existing_comment,
            :exif_datetime, :exif_artist, :scanned_at, :error
        )
    """

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(scan_worker, p, ffprobe_bin): p for p in all_files}
        for future in as_completed(future_to_file):
            completed += 1
            res = future.result()
            if res:
                batch.append(res)

            if len(batch) >= BATCH_SIZE:
                with conn:
                    conn.executemany(insert_sql, batch)
                batch.clear()

            if completed % 1000 == 0 or completed == total_files:
                elapsed = time.time() - t_start
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_files - completed) / rate if rate > 0 else 0
                print(f"    Scanned {completed}/{total_files} ({completed/total_files*100:.1f}%) | {rate:.1f} items/sec | ETA: {eta:.0f}s")

    if batch:
        with conn:
            conn.executemany(insert_sql, batch)
        batch.clear()

    conn.close()
    print(f"[+] Media Inventory complete in {time.time() - t_start:.2f}s! Stored in {db_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Media Inventory Scanner for F:\\Aloha")
    parser.add_argument("--target", default=r"F:\Aloha", help="Target root directory")
    parser.add_argument("--db", default=r"media_inventory.db", help="SQLite database output path")
    parser.add_argument("--workers", type=int, default=24, help="Worker threads")
    parser.add_argument("--full", action="store_true", help="Force full rescan")
    args = parser.parse_args()

    scan_target(args.target, args.db, max_workers=args.workers, incremental=not args.full)
