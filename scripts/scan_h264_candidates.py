import os
import sys
import json
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Reconfigure console output for Windows UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FFPROBE_PATH = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe"
TARGET_DIR = r"F:\Aloha"
OUTPUT_CANDIDATES = r"e:\repos\projects\storage-strategist\h264_candidates.json"
MAX_WORKERS = 24

def probe_file(file_path):
    cmd = [
        FFPROBE_PATH,
        "-v", "error",
        "-show_entries", "stream=index,codec_name,codec_type,width,height,duration,r_frame_rate:format=duration,size,bit_rate",
        "-of", "json",
        file_path
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return {"path": file_path, "error": f"ffprobe returncode {res.returncode}: {res.stderr.strip()}"}
        data = json.loads(res.stdout)
        
        streams = data.get("streams", [])
        fmt = data.get("format", {})
        
        v_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
        a_stream = next((s for s in streams if s.get("codec_type") == "audio"), None)
        
        if not v_stream:
            return {"path": file_path, "error": "No video stream found"}
            
        v_codec = v_stream.get("codec_name", "").lower()
        width = int(v_stream.get("width") or 0)
        height = int(v_stream.get("height") or 0)
        
        # Determine duration
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
                
        # File size
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

        # Bitrate
        bitrate = 0
        if "bit_rate" in fmt and fmt["bit_rate"] not in (None, "N/A"):
            try:
                bitrate = int(fmt["bit_rate"])
            except ValueError:
                pass
        if bitrate <= 0 and duration > 0 and size > 0:
            bitrate = int((size * 8) / duration)

        mb_per_min = (size / (1024 * 1024)) / (duration / 60.0) if duration > 0 else 0.0
        a_codec = a_stream.get("codec_name", "").lower() if a_stream else "none"

        return {
            "path": file_path,
            "v_codec": v_codec,
            "a_codec": a_codec,
            "width": width,
            "height": height,
            "duration": round(duration, 2),
            "size": size,
            "bitrate": bitrate,
            "mb_per_min": round(mb_per_min, 2),
            "error": None
        }
    except subprocess.TimeoutExpired:
        return {"path": file_path, "error": "Probe timeout"}
    except Exception as e:
        return {"path": file_path, "error": str(e)}

def categorize_and_filter(info):
    if info.get("error"):
        return False, None, "error"
        
    v_codec = info["v_codec"]
    # 1. Video Codec must be h264 / avc1
    if v_codec not in ("h264", "avc", "avc1"):
        return False, None, f"non_h264_{v_codec}"
        
    duration = info["duration"]
    size = info["size"]
    bitrate = info["bitrate"]
    mb_per_min = info["mb_per_min"]
    width = info["width"]
    height = info["height"]
    
    if duration < 2.0 or size < 1024 * 1024:
        return False, None, "too_short_or_small"

    # Resolution classification & CQ assignment
    # 1080p / 4K (height >= 1080 or width >= 1800): CQ 26
    # 720p (720 <= height < 1080 or 1200 <= width < 1800): CQ 28
    # 480p / SD / Sub-HD (< 720 and < 1200): CQ 32
    if height >= 1080 or width >= 1800:
        resolution_tier = "1080p+"
        cq = 26
        # Bitrate > 6.5 Mbps (6,500,000) or size > 50 MB/min
        is_candidate = (bitrate > 6_500_000) or (mb_per_min > 50.0)
    elif height >= 720 or width >= 1200:
        resolution_tier = "720p"
        cq = 28
        # Bitrate > 4.0 Mbps (4,000,000) or size > 30 MB/min
        is_candidate = (bitrate > 4_000_000) or (mb_per_min > 30.0)
    else:
        resolution_tier = "SD/480p"
        cq = 32
        # Bitrate > 2.0 Mbps (2,000,000) or size > 15 MB/min
        is_candidate = (bitrate > 2_000_000) or (mb_per_min > 15.0)

    if not is_candidate:
        return False, None, f"below_bitrate_threshold_{resolution_tier}"

    return True, {
        "path": info["path"],
        "resolution_tier": resolution_tier,
        "width": width,
        "height": height,
        "cq": cq,
        "v_codec": v_codec,
        "a_codec": info["a_codec"],
        "duration": duration,
        "size": size,
        "bitrate": bitrate,
        "mb_per_min": mb_per_min
    }, "candidate"

def main():
    print(f"[*] Discovering all .mp4 files in {TARGET_DIR}...")
    t0 = time.time()
    mp4_files = []
    for root, dirs, files in os.walk(TARGET_DIR):
        for f in files:
            if f.lower().endswith(".mp4") and not f.startswith("._tmp_"):
                mp4_files.append(os.path.join(root, f))
                
    total_found = len(mp4_files)
    print(f"[*] Discovered {total_found} MP4 files in {time.time() - t0:.2f}s. Starting parallel probe with {MAX_WORKERS} workers...")
    
    candidates = []
    reasons = {}
    codec_dist = {}
    total_scanned_bytes = 0
    candidate_bytes = 0
    
    t_probe_start = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(probe_file, f): f for f in mp4_files}
        
        completed_count = 0
        for future in as_completed(future_to_file):
            completed_count += 1
            info = future.result()
            
            if "size" in info:
                total_scanned_bytes += info["size"]
            v_codec = info.get("v_codec", "unknown")
            codec_dist[v_codec] = codec_dist.get(v_codec, 0) + 1
            
            is_cand, cand_data, reason = categorize_and_filter(info)
            reasons[reason] = reasons.get(reason, 0) + 1
            
            if is_cand and cand_data:
                candidates.append(cand_data)
                candidate_bytes += cand_data["size"]
                
            if completed_count % 1000 == 0 or completed_count == total_found:
                elapsed = time.time() - t_probe_start
                rate = completed_count / elapsed if elapsed > 0 else 0
                print(f"    Probed {completed_count}/{total_found} files ({completed_count/total_found*100:.1f}%) - {rate:.1f} files/s - Candidates: {len(candidates)} ({candidate_bytes / (1024**3):.2f} GB)")

    t_probe_end = time.time()
    print(f"\n[+] Probing completed in {t_probe_end - t_probe_start:.2f}s.")
    
    # Sort candidates by size descending so biggest storage wins happen first
    candidates.sort(key=lambda x: x["size"], reverse=True)
    
    manifest = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_dir": TARGET_DIR,
            "total_mp4_scanned": total_found,
            "total_scanned_gb": round(total_scanned_bytes / (1024**3), 2),
            "candidates_count": len(candidates),
            "candidates_total_gb": round(candidate_bytes / (1024**3), 2),
            "codec_distribution": codec_dist,
            "filtering_breakdown": reasons
        },
        "candidates": candidates
    }
    
    with open(OUTPUT_CANDIDATES, "w", encoding="utf-8") as out_f:
        json.dump(manifest, out_f, indent=2)
        
    print(f"[+] Candidate manifest saved to {OUTPUT_CANDIDATES}")
    print(f"==================================================")
    print(f"Total MP4 Scanned:     {total_found} ({total_scanned_bytes / (1024**3):.2f} GB)")
    print(f"Qualified Candidates:  {len(candidates)} ({candidate_bytes / (1024**3):.2f} GB)")
    print(f"Codec Distribution:    {codec_dist}")
    print(f"Filter Breakdown:      {reasons}")
    print(f"==================================================")

if __name__ == "__main__":
    main()
