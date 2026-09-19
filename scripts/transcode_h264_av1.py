import os
import sys
import time
import json
import stat
import ctypes
import subprocess

# Reconfigure console output for Windows UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

FFMPEG_PATH = "ffmpeg"
FFPROBE_PATH = r"C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe"
CANDIDATES_FILE = r"e:\repos\projects\storage-strategist\h264_candidates.json"
STATE_FILE = r"e:\repos\projects\storage-strategist\transcode_h264_state.json"

FILE_ATTRIBUTE_NORMAL = 0x80

def clear_readonly(file_path):
    try:
        if os.path.exists(file_path):
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_NORMAL)
    except Exception as e:
        pass

def probe_output(file_path):
    cmd = [
        FFPROBE_PATH,
        "-v", "error",
        "-show_entries", "stream=index,codec_name,codec_type,width,height,duration:format=duration,size",
        "-of", "json",
        file_path
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return None, f"ffprobe returncode {res.returncode}: {res.stderr.strip()}"
        data = json.loads(res.stdout)
        streams = data.get("streams", [])
        fmt = data.get("format", {})
        
        v_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
        if not v_stream:
            return None, "No video stream found in output"
            
        v_codec = v_stream.get("codec_name", "").lower()
        
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

        return {
            "v_codec": v_codec,
            "duration": duration,
            "size": size
        }, None
    except Exception as e:
        return None, str(e)

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_candidates": 0,
        "total_reclaimed_bytes": 0,
        "summary": {
            "completed": 0,
            "skipped_no_savings": 0,
            "skipped_existing": 0,
            "failed": 0
        },
        "completed": {},
        "skipped": {},
        "failed": {}
    }

def save_state(state):
    state["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    tmp_state = STATE_FILE + ".tmp"
    try:
        with open(tmp_state, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        clear_readonly(STATE_FILE)
        os.replace(tmp_state, STATE_FILE)
    except Exception as e:
        print(f"[!] Error saving state: {e}")

def transcode_candidate(candidate, state):
    orig_path = candidate["path"]
    cq = candidate["cq"]
    orig_duration = candidate["duration"]
    orig_size = candidate["size"]
    a_codec = candidate.get("a_codec", "").lower()
    res_tier = candidate.get("resolution_tier", "Unknown")
    
    parent_dir = os.path.dirname(orig_path)
    base_name = os.path.splitext(os.path.basename(orig_path))[0]
    final_mkv = os.path.join(parent_dir, base_name + ".mkv")
    
    # Check if original exists
    if not os.path.exists(orig_path):
        # If final MKV exists, maybe it was finished earlier
        if os.path.exists(final_mkv):
            return "skipped_existing", f"Original missing, {os.path.basename(final_mkv)} exists"
        return "failed", f"Source file does not exist: {orig_path}"
        
    # Check if final MKV already exists
    if os.path.exists(final_mkv):
        probe_info, err = probe_output(final_mkv)
        if probe_info and probe_info["v_codec"] == "av1" and abs(probe_info["duration"] - orig_duration) <= 4.0:
            # Valid existing MKV
            new_size = probe_info["size"]
            if new_size < orig_size:
                # Remove original safely
                clear_readonly(orig_path)
                try:
                    os.remove(orig_path)
                    reclaimed = orig_size - new_size
                    return "completed_existing", {
                        "path": final_mkv,
                        "orig_path": orig_path,
                        "orig_size": orig_size,
                        "new_size": new_size,
                        "reclaimed_bytes": reclaimed,
                        "duration": probe_info["duration"]
                    }
                except Exception as e:
                    return "failed", f"Could not remove original: {e}"
            else:
                return "skipped_no_savings", f"Existing MKV has no savings ({new_size}/{orig_size})"
        else:
            # Existing MKV is incomplete or invalid, remove it before proceeding
            try:
                clear_readonly(final_mkv)
                os.remove(final_mkv)
            except Exception:
                pass

    timestamp = int(time.time() * 1000)
    temp_mkv = os.path.join(parent_dir, f"._tmp_{base_name}_{timestamp}.mkv")
    
    # Audio parameters
    # Copy if already a standard web codec, otherwise transcode to AAC 128k
    if a_codec in ("aac", "opus", "mp3"):
        audio_args = ["-c:a", "copy"]
    elif a_codec in ("", "none", "null"):
        audio_args = ["-an"]
    else:
        audio_args = ["-c:a", "aac", "-b:a", "128k"]

    cmd = [
        FFMPEG_PATH,
        "-y",
        "-v", "error",
        "-stats",
        "-i", orig_path,
        "-c:v", "av1_nvenc",
        "-preset", "p6",
        "-cq", str(cq),
        "-pix_fmt", "yuv420p",
        *audio_args,
        "-f", "matroska",
        temp_mkv
    ]
    
    t0 = time.time()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        t_encode = time.time() - t0
        
        if res.returncode != 0:
            if os.path.exists(temp_mkv):
                clear_readonly(temp_mkv)
                os.remove(temp_mkv)
            return "failed", f"ffmpeg returncode {res.returncode}: {res.stderr.strip()}"
            
        if not os.path.exists(temp_mkv) or os.path.getsize(temp_mkv) == 0:
            if os.path.exists(temp_mkv):
                os.remove(temp_mkv)
            return "failed", "Output file is missing or 0 bytes"
            
        # Probe temp output
        probe_info, err = probe_output(temp_mkv)
        if err or not probe_info:
            if os.path.exists(temp_mkv):
                os.remove(temp_mkv)
            return "failed", f"Probe validation failed: {err}"
            
        new_v_codec = probe_info["v_codec"]
        new_duration = probe_info["duration"]
        new_size = probe_info["size"]
        
        if new_v_codec != "av1":
            os.remove(temp_mkv)
            return "failed", f"Unexpected codec {new_v_codec}"
            
        if orig_duration > 5.0 and abs(new_duration - orig_duration) > 4.0:
            os.remove(temp_mkv)
            return "failed", f"Duration mismatch: source {orig_duration}s vs transcode {new_duration}s"
            
        # Space savings check (Accept any positive reduction: savings_bytes > 0)
        savings_bytes = orig_size - new_size
        savings_pct = (savings_bytes / orig_size) * 100.0 if orig_size > 0 else 0.0
        
        if savings_bytes <= 0:
            clear_readonly(temp_mkv)
            os.remove(temp_mkv)
            return "skipped_no_savings", f"No savings: new size {new_size} >= orig {orig_size} ({savings_pct:.1f}%)"
            
        # Atomic Finalization
        clear_readonly(final_mkv)
        clear_readonly(temp_mkv)
        os.replace(temp_mkv, final_mkv)
        
        clear_readonly(orig_path)
        os.remove(orig_path)
        
        return "completed", {
            "path": final_mkv,
            "orig_path": orig_path,
            "orig_size": orig_size,
            "new_size": new_size,
            "reclaimed_bytes": savings_bytes,
            "savings_pct": round(savings_pct, 2),
            "duration": new_duration,
            "encode_time_s": round(t_encode, 2),
            "cq": cq,
            "resolution_tier": res_tier
        }
        
    except Exception as e:
        if os.path.exists(temp_mkv):
            try:
                clear_readonly(temp_mkv)
                os.remove(temp_mkv)
            except Exception:
                pass
        return "failed", str(e)

def main():
    if not os.path.exists(CANDIDATES_FILE):
        print(f"[!] Candidate manifest {CANDIDATES_FILE} not found. Please run scan_h264_candidates.py first.")
        sys.exit(1)
        
    with open(CANDIDATES_FILE, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    candidates = manifest.get("candidates", [])
    total_candidates = len(candidates)
    
    state = load_state()
    state["total_candidates"] = total_candidates
    
    print(f"[*] Loaded {total_candidates} candidates from manifest.")
    print(f"[*] Starting/Resuming batch transcode on RTX 5070 Ti (av1_nvenc)...")
    print(f"================================================================================")
    
    idx = 0
    for cand in candidates:
        idx += 1
        path = cand["path"]
        
        # Check if already completed/skipped in state
        if path in state["completed"]:
            continue
        if path in state["skipped"]:
            continue
            
        base_name = os.path.basename(path)
        res_tier = cand.get("resolution_tier", "Unknown")
        cq = cand.get("cq", 28)
        orig_mb = cand["size"] / (1024 * 1024)
        
        t_start = time.time()
        status, result = transcode_candidate(cand, state)
        elapsed = time.time() - t_start
        
        if status in ("completed", "completed_existing"):
            data = result
            state["completed"][path] = data
            state["total_reclaimed_bytes"] += data["reclaimed_bytes"]
            state["summary"]["completed"] += 1
            
            reclaimed_mb = data["reclaimed_bytes"] / (1024 * 1024)
            new_mb = data["new_size"] / (1024 * 1024)
            pct = (data["reclaimed_bytes"] / data["orig_size"]) * 100.0
            total_gb = state["total_reclaimed_bytes"] / (1024 ** 3)
            speed_mult = data["duration"] / data["encode_time_s"] if "encode_time_s" in data and data["encode_time_s"] > 0 else 0
            
            print(f"[{idx}/{total_candidates}] ({idx/total_candidates*100:.1f}%) [OK] {res_tier} CQ{cq} | {base_name[:35]:<35} | {orig_mb:.1f}MB -> {new_mb:.1f}MB (-{pct:.1f}%) | -{reclaimed_mb:.1f}MB | {speed_mult:.1f}x | Total Reclaimed: {total_gb:.2f} GB", flush=True)
            
        elif status == "skipped_no_savings":
            state["skipped"][path] = {"reason": result}
            state["summary"]["skipped_no_savings"] += 1
            total_gb = state["total_reclaimed_bytes"] / (1024 ** 3)
            print(f"[{idx}/{total_candidates}] ({idx/total_candidates*100:.1f}%) [SKIP] {base_name[:35]:<35} | No savings (kept original) | Total Reclaimed: {total_gb:.2f} GB", flush=True)
            
        elif status == "skipped_existing":
            state["skipped"][path] = {"reason": result}
            state["summary"]["skipped_existing"] += 1
            total_gb = state["total_reclaimed_bytes"] / (1024 ** 3)
            print(f"[{idx}/{total_candidates}] ({idx/total_candidates*100:.1f}%) [SKIP] {base_name[:35]:<35} | Already exists | Total Reclaimed: {total_gb:.2f} GB", flush=True)
            
        else: # failed
            state["failed"][path] = {"error": str(result)}
            state["summary"]["failed"] += 1
            print(f"[{idx}/{total_candidates}] ({idx/total_candidates*100:.1f}%) [FAIL] {base_name[:35]:<35} | Error: {result}", flush=True)
            
        # Save state every item
        save_state(state)
        
    print(f"\n================================================================================", flush=True)
    print(f"[+] Transcode run completed!", flush=True)
    print(f"    Completed:          {state['summary']['completed']}", flush=True)
    print(f"    Skipped No Savings: {state['summary']['skipped_no_savings']}", flush=True)
    print(f"    Skipped Existing:   {state['summary']['skipped_existing']}", flush=True)
    print(f"    Failed:             {state['summary']['failed']}", flush=True)
    print(f"    Total Space Saved:  {state['total_reclaimed_bytes'] / (1024**3):.2f} GB", flush=True)
    print(f"================================================================================", flush=True)

if __name__ == "__main__":
    main()
