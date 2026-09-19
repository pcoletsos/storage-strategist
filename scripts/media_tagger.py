import os
import sys
import time
from typing import Dict, Any, Optional

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def tag_mp4_file(file_path: str, tags: Dict[str, Any]) -> bool:
    """Losslessly writes MP4 tags using mutagen without remuxing stream payloads, preserving timestamps."""
    try:
        from mutagen.mp4 import MP4
        stat = os.stat(file_path)
        orig_atime, orig_mtime = stat.st_atime, stat.st_mtime

        mp4 = MP4(file_path)
        
        if tags.get("title"):
            mp4["\xa9nam"] = [str(tags["title"])]
        if tags.get("artist") or tags.get("performers"):
            perf = tags.get("performers")
            if isinstance(perf, list):
                art = ", ".join(perf)
            else:
                art = str(tags.get("artist") or perf)
            if art:
                mp4["\xa9ART"] = [art]
        if tags.get("date"):
            mp4["\xa9day"] = [str(tags["date"])]
        if tags.get("studio") or tags.get("comment"):
            cmt = tags.get("studio") or tags.get("comment")
            if cmt:
                mp4["\xa9cmt"] = [str(cmt)]
                
        mp4.save()
        os.utime(file_path, (orig_atime, orig_mtime))
        return True
    except Exception as e:
        print(f"[!] Warning: mutagen tag failed for {file_path}: {e}")
        return False

def sync_image_timestamp(file_path: str, date_str: Optional[str]) -> bool:
    """Synchronizes file filesystem modification time (os.utime) with target date string."""
    if not date_str:
        return False
    try:
        # Parse date_str e.g. YYYY-MM-DD or YYYY
        if len(date_str) == 10 and date_str.count("-") == 2:
            t = time.strptime(date_str, "%Y-%m-%d")
            epoch = time.mktime(t)
            os.utime(file_path, (epoch, epoch))
            return True
        elif len(date_str) == 4 and date_str.isdigit():
            t = time.strptime(f"{date_str}-01-01", "%Y-%m-%d")
            epoch = time.mktime(t)
            os.utime(file_path, (epoch, epoch))
            return True
    except Exception as e:
        print(f"[!] Warning: utime sync failed for {file_path}: {e}")
        return False
    return False

def tag_media_file(file_path: str, parsed_info: Dict[str, Any]) -> Dict[str, Any]:
    """Applies lossless metadata tagging appropriate for file type."""
    ext = os.path.splitext(file_path)[1].lower()
    success = False
    
    if ext in (".mp4", ".m4v"):
        success = tag_mp4_file(file_path, parsed_info)
    elif ext in (".jpg", ".jpeg", ".png", ".webp"):
        date = parsed_info.get("date")
        if date:
            success = sync_image_timestamp(file_path, date)
    else:
        success = True # No writeback required for unsupported formats

    return {"file_path": file_path, "tagged": success}
