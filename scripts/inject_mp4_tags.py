import os
import re
import sys
import json
import time
import sqlite3
import argparse
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import (
    STUDIO_MAP,
    clean_title_case,
    sanitize_win_filename,
    normalize_date
)
from media_tagger import tag_mp4_file

KNOWN_PERFORMERS = [
    "Lexi Belle", "Amy Brooke", "August Ames", "Ava Addams", "Riley Steele",
    "Jesse Jane", "Sasha Grey", "Tori Black", "Jenna Jameson", "Savannah Sixx",
    "Penny Pax", "Emily Willis", "Ellie Eilish", "Gabbie Carter", "Kyler Quinn",
    "Mia Malkova", "Dillion Harper", "Audrey Bitoni", "Rocco Reed", "AnnMarie Rios",
    "Alec Knight", "Allaura", "Alli", "Amber", "Ami", "Amy", "Angelina", "Ashlee",
    "Ashley", "Bella", "Boxxy", "Brianna", "Brittany", "Izzy Green", "Katerina Stikoudi",
    "Olga Farmaki", "Christina Koletsa", "Nikoleta Ralli", "Megan Fox", "Olivia Wilde",
    "Kendra Lust", "Angela White", "Nicole Aniston", "Alina Lopez", "Abella Danger"
]

BRACKET_REGEX = re.compile(r"^\[(?P<studio>[^\]]+)\]\s*(?:\[(?P<date>\d{4}-\d{2}-\d{2})\]\s*)?(?P<rest>.*)$")
TECH_TAG_REGEX = re.compile(r"\s*\[(2160p|1080p|720p|480p|360p|4k|av1|h264|hevc)[\s\w\-]*\]", re.IGNORECASE)

def load_visual_cache(cache_path: str) -> Dict[str, Dict[str, Any]]:
    """Loads visually extracted metadata from SQLite cache."""
    cache = {}
    if not os.path.exists(cache_path):
        return cache
    try:
        conn = sqlite3.connect(cache_path)
        cur = conn.cursor()
        rows = cur.execute("""
            SELECT file_path, detected_studio, detected_performers, detected_title, detected_date, confidence
            FROM visual_enrichment_cache
        """).fetchall()
        for fpath, studio, perfs, title, date, conf in rows:
            cache[os.path.normpath(fpath).lower()] = {
                "studio": studio,
                "performers": json.loads(perfs) if perfs else [],
                "title": title,
                "date": date,
                "confidence": conf
            }
    except Exception as e:
        print(f"[!] Warning: could not load visual cache: {e}")
    return cache

def load_inventory_db(db_path: str, undo_ledger_path: str) -> Dict[str, Dict[str, Any]]:
    """Loads existing artist, title, date, and studio from media_inventory.db."""
    inv = {}
    if not os.path.exists(db_path):
        return inv
    try:
        # Load undo ledger reverse mapping if available
        reverse_map = {}
        if os.path.exists(undo_ledger_path):
            uconn = sqlite3.connect(undo_ledger_path)
            for orig, target in uconn.execute("SELECT original_path, target_path FROM transactions").fetchall():
                reverse_map[orig.lower()] = target

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cols = [c[1] for c in cur.execute("PRAGMA table_info(media_files)").fetchall()]
        has_studio = "studio" in cols

        query = f"""
            SELECT file_path, existing_title, existing_artist, existing_date {', studio' if has_studio else ''}
            FROM media_files
            WHERE extension IN ('.mp4', '.m4v')
        """
        for row in cur.execute(query).fetchall():
            fpath = row[0]
            title = row[1]
            artist = row[2]
            date = row[3]
            studio = row[4] if has_studio else None

            entry = {"title": title, "artist": artist, "date": date, "studio": studio}
            inv[os.path.normpath(fpath).lower()] = entry
            # Also register under current disk path if tracked in undo ledger
            if fpath.lower() in reverse_map:
                inv[os.path.normpath(reverse_map[fpath.lower()]).lower()] = entry
    except Exception as e:
        print(f"[!] Warning: could not load inventory DB: {e}")
    return inv

def infer_tags_for_file(
    file_path: str,
    visual_cache: Dict[str, Dict[str, Any]],
    inventory_db: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Combines visual cache, inventory DB, and filename heuristics into canonical tag set."""
    norm_path = os.path.normpath(file_path).lower()
    fname = os.path.basename(file_path)
    base, ext = os.path.splitext(fname)

    # Clean base name (strip technical resolution tags e.g. [480p H264])
    clean_base = TECH_TAG_REGEX.sub("", base).strip()

    studio = None
    date = None
    performers = []
    title = clean_base

    # 1. First Priority: Visual Cache (verified via OCR / compliance statements)
    v_data = visual_cache.get(norm_path)
    if v_data:
        if v_data.get("studio"):
            studio = v_data["studio"]
        if v_data.get("performers"):
            performers = list(v_data["performers"])
        if v_data.get("title"):
            title = v_data["title"]
        if v_data.get("date"):
            date = v_data["date"]

    # 2. Second Priority: Bracketed Filename Components e.g. [Studio] [Date] Performer - Title
    m = BRACKET_REGEX.match(clean_base)
    if m:
        b_studio = m.group("studio").strip()
        b_date = m.group("date")
        rest = m.group("rest").strip()

        if not studio and b_studio:
            studio = b_studio
        if not date and b_date:
            date = b_date

        if " - " in rest:
            parts = rest.split(" - ")
            p_cand = parts[0].strip()
            t_cand = " - ".join(parts[1:]).strip()
            if not performers and p_cand:
                performers = [p_cand]
            if t_cand:
                title = t_cand
        elif rest:
            title = rest

    # 3. Third Priority: Inventory DB values
    inv_data = inventory_db.get(norm_path)
    if inv_data:
        if not studio and inv_data.get("studio"):
            studio = inv_data["studio"]
        if not date and inv_data.get("date"):
            date = inv_data["date"]
        if not performers and inv_data.get("artist"):
            performers = [a.strip() for a in inv_data["artist"].split(",") if a.strip()]
        if (not title or title == clean_base) and inv_data.get("title"):
            title = inv_data["title"]

    # 4. Fourth Priority: Folder Path & Pattern Heuristics
    dir_lower = file_path.lower()
    if not studio:
        if "bangbus" in dir_lower:
            studio = "Bangbus"
        elif "dorm invasion" in dir_lower or re.search(r"\bdi\d{4,6}\b", fname.lower()):
            studio = "Bangbros"
            if not title or title == clean_base:
                title = f"Dorm Invasion {clean_base}"
        elif "backroom casting couch" in dir_lower or "brcc" in fname.lower():
            studio = "Backroom Casting Couch"
        elif "brazzers" in dir_lower:
            studio = "Brazzers"
        elif "digitalplayground" in dir_lower or "digital playground" in dir_lower:
            studio = "Digital Playground"
        elif "vixen" in dir_lower:
            studio = "Vixen"
        elif "fuckedhard18" in dir_lower or "fh18" in fname.lower() or "fh 18" in fname.lower():
            studio = "FuckedHard18"
        elif "tonights.girlfriend" in dir_lower or "tonights girlfriend" in dir_lower:
            studio = "Tonights Girlfriend"

    # Year inference from folder name e.g. "Bangbus ALL 2010 videos 720p"
    if not date:
        m_year = re.search(r"\b(19\d\d|20\d\d)\b", file_path)
        if m_year:
            date = m_year.group(1)

    # Performer name recognition in title or filename
    if not performers:
        combined_text = f"{fname} {title}".lower()
        for perf in KNOWN_PERFORMERS:
            pattern = r"\b" + re.escape(perf.lower()) + r"\b"
            if re.search(pattern, combined_text):
                performers.append(perf)

    # Clean and standardize title
    title = clean_title_case(title)
    if studio and title.lower().startswith(f"[{studio.lower()}]"):
        title = title[len(studio) + 2:].strip()

    return {
        "file_path": file_path,
        "filename": fname,
        "title": title or clean_base,
        "performers": performers,
        "studio": studio,
        "date": date
    }

def process_file_tagging(file_info: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    """Injects tags into a single MP4 file."""
    fpath = file_info["file_path"]
    tag_dict = {
        "title": file_info.get("title"),
        "performers": file_info.get("performers"),
        "studio": file_info.get("studio"),
        "date": file_info.get("date")
    }

    if dry_run:
        return {"file_path": fpath, "success": True, "dry_run": True, "tags": tag_dict}

    success = tag_mp4_file(fpath, tag_dict)
    return {"file_path": fpath, "success": success, "dry_run": False, "tags": tag_dict}

def main():
    parser = argparse.ArgumentParser(description="Lossless MP4 Metadata Container Tag Injector")
    parser.add_argument("--root", default=r"F:\Aloha", help="Target root directory (default F:\\Aloha)")
    parser.add_argument("--visual-cache", default="visual_enrichment_cache.db", help="Path to visual enrichment SQLite cache")
    parser.add_argument("--inventory-db", default="media_inventory.db", help="Path to media_inventory.db")
    parser.add_argument("--undo-ledger", default="undo_ledger.db", help="Path to undo_ledger.db")
    parser.add_argument("--dry-run", action="store_true", help="Preview tags without writing to disk")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of files to tag (0 = all)")
    parser.add_argument("--workers", type=int, default=8, help="Number of concurrent worker threads")
    parser.add_argument("--output-report", default="mp4_tagging_report.json", help="Path for output JSON report")
    args = parser.parse_args()

    print(f"[*] Scanning for MP4/M4V files in '{args.root}'...")
    all_mp4_files = []
    for dirpath, _, filenames in os.walk(args.root):
        for f in filenames:
            if f.lower().endswith((".mp4", ".m4v")):
                all_mp4_files.append(os.path.join(dirpath, f))

    print(f"[*] Found {len(all_mp4_files):,} MP4 containers on '{args.root}'.")

    # Load metadata sources
    visual_cache = load_visual_cache(args.visual_cache)
    print(f"[*] Loaded {len(visual_cache):,} visual enrichment cache entries.")

    inventory_db = load_inventory_db(args.inventory_db, args.undo_ledger)
    print(f"[*] Loaded {len(inventory_db):,} inventory DB entries.")

    # Infer tags for all files
    print("[*] Resolving canonical metadata for MP4 assets...")
    candidates = []
    for fpath in all_mp4_files:
        tags = infer_tags_for_file(fpath, visual_cache, inventory_db)
        # Keep candidates that have at least studio, performer, or title
        if tags.get("studio") or tags.get("performers") or (tags.get("title") and len(tags["title"]) > 2):
            candidates.append(tags)

    if args.limit > 0:
        candidates = candidates[:args.limit]

    print(f"[*] Ready to tag {len(candidates):,} candidate MP4 files.")
    if args.dry_run:
        print("[*] DRY-RUN MODE: Previewing first 10 tagging operations:")
        for c in candidates[:10]:
            print(f"  File:   {c['filename']}")
            print(f"    Title:      {c['title']}")
            print(f"    Studio:     {c['studio']}")
            print(f"    Performers: {c['performers']}")
            print(f"    Date:       {c['date']}")
        print(f"\n[+] Dry-run preview complete for {len(candidates):,} files. Zero disk changes made.")
        return

    # Execute multi-threaded tagging
    print(f"[*] Executing lossless container tagging ({args.workers} threads)...")
    results = []
    success_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_file_tagging, c, False): c for c in candidates}
        pbar = tqdm(total=len(candidates), desc="Injecting MP4 Tags", unit="file")

        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            if res.get("success"):
                success_count += 1
            else:
                fail_count += 1
            pbar.update(1)

        pbar.close()

    print("\n" + "=" * 60)
    print("           MP4 CONTAINER TAGGING COMPLETE SUMMARY          ")
    print("=" * 60)
    print(f"Total Processed:    {len(results):,}")
    print(f"Successfully Tagged:{success_count:>6,} files")
    print(f"Failed Tagging:     {fail_count:>6,} files")
    print("=" * 60)

    # Write output report
    with open(args.output_report, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "total_processed": len(results),
                "success_count": success_count,
                "fail_count": fail_count
            },
            "sample_tags": results[:200]
        }, f, indent=2)
    print(f"[+] Output report written to '{args.output_report}'.")

if __name__ == "__main__":
    main()
