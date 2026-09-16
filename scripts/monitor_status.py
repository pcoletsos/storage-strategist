import os
import sys
import json
import shutil

# Reconfigure console output for Windows UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

STATE_FILE = r"e:\repos\projects\storage-strategist\transcode_h264_state.json"
CANDIDATES_FILE = r"e:\repos\projects\storage-strategist\h264_candidates.json"

def main():
    total, used, free = shutil.disk_usage(r"F:\\")
    print(f"Drive F: Total: {total/(1024**3):.2f} GB | Used: {used/(1024**3):.2f} GB | Free: {free/(1024**3):.2f} GB")

    # Check active temp files in F:\Aloha
    temp_files = []
    for root, dirs, files in os.walk(r"F:\Aloha"):
        for f in files:
            if f.startswith("._tmp_"):
                p = os.path.join(root, f)
                try:
                    sz = os.path.getsize(p)
                    temp_files.append((f, sz, p))
                except Exception:
                    pass
    print(f"Active temporary MKV files: {len(temp_files)}")
    for f, sz, p in temp_files[:5]:
        print(f"  {f}: {sz / (1024*1024):.2f} MB")

    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"State Summary: {data.get('summary')}")
            reclaimed_gb = data.get('total_reclaimed_bytes', 0) / (1024**3)
            print(f"Total Reclaimed: {reclaimed_gb:.2f} GB")
            completed = list(data.get("completed", {}).values())
            if completed:
                print(f"Last completed ({len(completed)} total):")
                for c in completed[-5:]:
                    orig_mb = c.get("orig_size", 0) / (1024*1024)
                    new_mb = c.get("new_size", 0) / (1024*1024)
                    saved_mb = c.get("reclaimed_bytes", 0) / (1024*1024)
                    print(f"  {os.path.basename(c.get('path', ''))}: {orig_mb:.1f}MB -> {new_mb:.1f}MB (-{saved_mb:.1f}MB)")
        except Exception as e:
            print(f"Error reading state: {e}")
    else:
        print("transcode_h264_state.json not yet written (first video encoding in progress).")

if __name__ == "__main__":
    main()
