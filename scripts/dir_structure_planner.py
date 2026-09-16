import os
import re
import sys
import csv
import json
import sqlite3
import argparse
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add scripts dir to sys.path for sibling imports
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import (
    STUDIO_MAP,
    SCENE_BLOAT_PATTERNS,
    FORBIDDEN_WIN_CHARS,
    sanitize_win_filename,
    clean_title_case,
    to_extended_path
)

# Canonical 7-Root Categories
CANONICAL_ROOTS = [
    "Studios",
    "Movies",
    "Celebrities",
    "Collections & Siterips",
    "Photos & Sets",
    "Games",
    "Magazines & Docs"
]

# Additional Studio Mappings - unified under major studio brands
EXTENDED_STUDIO_MAP = {
    **STUDIO_MAP,
    "brazzersexxtra": "Brazzers",
    "brazzers": "Brazzers",
    "bangbros": "Bangbros",
    "x-art": "X-Art",
    "xart": "X-Art",
    "private": "Private",
    "youporn": "YouPorn",
    "mrskin": "Mr Skin",
    "mr skin": "Mr Skin",
}

# Known Studio prefixes in brackets e.g. "[Bangbus]", "[Vixen]"
STUDIO_BRACKET_REGEX = re.compile(r"^\[([a-zA-Z0-9\s\.\-_']+)\]")

# Strip redundant bloat from folder names
FOLDER_BLOAT_PATTERNS = [
    re.compile(r"[-._\s]+XXX[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+XXXClub\.to[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+rarbg[-._\s]*", re.IGNORECASE),
    re.compile(r"\[rarbg\]", re.IGNORECASE),
    re.compile(r"\[XC\]", re.IGNORECASE),
    re.compile(r"\[eztv\]", re.IGNORECASE),
    re.compile(r"[-._\s]+MP4[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+MKV[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+MP4-[A-Z0-9]+(\[[^\]]*\])?", re.IGNORECASE),
    re.compile(r"[-._\s]+MKV-[A-Z0-9]+(\[[^\]]*\])?", re.IGNORECASE),
    re.compile(r"[-._\s]+BDRip[-._\s]*[A-Z0-9]*", re.IGNORECASE),
    re.compile(r"[-._\s]+DVDRip[-._\s]*[A-Z0-9]*", re.IGNORECASE),
    re.compile(r"[-._\s]+WEB-DL[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+WEBRip[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+HDTV[-._\s]*", re.IGNORECASE),
    re.compile(r"\[720p\s*HD\]", re.IGNORECASE),
    re.compile(r"\[1080p\s*HD\]", re.IGNORECASE),
    re.compile(r"[-._\s]+(2160p|1080p|720p|480p|360p|4k|540p|1080|720|480)[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+(h264|h265|hevc|x264|x265|avc|av1|vp9|aac|mp3|dts|ac3)[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+ALL\s+\d{4}\s+videos\s+\w+", re.IGNORECASE),
    re.compile(r"[-._\s]+SiteRip[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+SITERIP[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+--_fitgirl-repacks\.site[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+_MinQ$", re.IGNORECASE),
]

def clean_folder_name(name: str) -> str:
    cleaned = name
    for pat in FOLDER_BLOAT_PATTERNS:
        cleaned = pat.sub(" ", cleaned)
    cleaned = re.sub(r"[\._\s]+", " ", cleaned).strip(" .-_")
    cleaned = clean_title_case(cleaned)
    cleaned = sanitize_win_filename(cleaned)
    return cleaned or name

def detect_studio_from_path_or_name(rel_path: str, filename: str) -> Optional[str]:
    # 1. Check bracket prefix in filename e.g. [Bangbus]
    m = STUDIO_BRACKET_REGEX.match(filename)
    if m:
        token = m.group(1).strip()
        key = token.lower().replace(" ", "").replace(".", "").replace("-", "")
        if key in EXTENDED_STUDIO_MAP:
            return EXTENDED_STUDIO_MAP[key]
        for k, v in EXTENDED_STUDIO_MAP.items():
            if k == token.lower() or k == key:
                return v

    # 2. Check path segments
    segments = rel_path.replace("/", "\\").split("\\")
    for seg in segments:
        seg_lower = seg.lower().replace(" ", "").replace(".", "").replace("-", "")
        for k, v in EXTENDED_STUDIO_MAP.items():
            if k in seg_lower:
                return v
    return None

def load_visual_enrichment_cache(cache_path: str = "visual_enrichment_cache.db") -> Dict[str, Dict[str, Any]]:
    cache = {}
    if not os.path.exists(cache_path):
        return cache
    try:
        conn = sqlite3.connect(cache_path)
        cur = conn.cursor()
        rows = cur.execute("""
            SELECT file_path, detected_studio, detected_performers, confidence, method 
            FROM visual_enrichment_cache
            WHERE confidence >= 0.80
        """).fetchall()
        for fpath, studio, perfs, conf, method in rows:
            norm_key = os.path.normpath(fpath).lower()
            cache[norm_key] = {
                "studio": studio,
                "performers": json.loads(perfs) if perfs else [],
                "confidence": conf,
                "method": method
            }
    except Exception as e:
        print(f"[!] Warning: failed to load visual cache: {e}")
    return cache

def plan_directory_restructure(root_dir: str, cache_db: str = "visual_enrichment_cache.db") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    root_dir = os.path.abspath(root_dir)
    print(f"[*] Scanning and planning directory restructure for '{root_dir}'...")
    visual_cache = load_visual_enrichment_cache(cache_db)
    if visual_cache:
        print(f"[*] Loaded {len(visual_cache)} verified visual enrichment entries from '{cache_db}'.")

    relocations = []
    target_registry = {}  # lower(target_path) -> count
    stats = {
        "total_scanned_files": 0,
        "files_to_relocate": 0,
        "files_unchanged": 0,
        "collisions_resolved": 0,
        "root_category_counts": defaultdict(int),
        "folders_to_prune": set(),
        "preserved_root_files": 0,
        "skipped_caches": 0
    }

    # Map directories
    dir_files = defaultdict(list)
    dir_subdirs = defaultdict(list)
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        rel = os.path.relpath(dirpath, root_dir)
        dir_files[rel] = filenames
        dir_subdirs[rel] = dirnames

    print(f"[*] Indexed {len(dir_files)} directories on '{root_dir}'.")

    # Analyze single-video leaf folders to identify candidate folders for flattening
    flattenable_dirs = set()
    for rel, fnames in dir_files.items():
        if rel == ".":
            continue
        subdirs = dir_subdirs[rel]
        if not subdirs:
            media_files = [f for f in fnames if f.lower().endswith((".mp4", ".mkv", ".avi", ".mov", ".flv", ".webm", ".m4v"))]
            if len(media_files) == 1 and len(fnames) <= 4:
                flattenable_dirs.add(rel)

    # Walk all files and resolve canonical target paths
    for dirpath, dirnames, filenames in os.walk(root_dir):
        rel_dir = os.path.relpath(dirpath, root_dir)
        parts = rel_dir.split(os.sep) if rel_dir != "." else []
        top_folder = parts[0] if parts else ""

        for fname in filenames:
            stats["total_scanned_files"] += 1
            src_full = os.path.join(dirpath, fname)
            fname_lower = fname.lower()
            _, ext = os.path.splitext(fname_lower)

            # 1. System caches / Thumbs.db
            if fname_lower in ("thumbs.db", "desktop.ini"):
                stats["skipped_caches"] += 1
                continue

            # 2. Root preservation: VHDX, .md files at root of Aloha
            if rel_dir == "." and (ext in (".vhdx", ".md") or "vhdx" in fname_lower):
                stats["preserved_root_files"] += 1
                stats["files_unchanged"] += 1
                continue

            # Determine canonical destination category and relative target path
            target_category = ""
            target_subpath = ""
            norm_src = os.path.normpath(src_full).lower()
            visual_entry = visual_cache.get(norm_src)

            # --- CASE A: GAMES ---
            if top_folder == "Games":
                # STRICT NON-INTERFERENCE: Keep internal game trees intact!
                target_category = "Games"
                sub_rel = os.path.relpath(dirpath, os.path.join(root_dir, "Games"))
                if sub_rel == ".":
                    target_subpath = fname
                else:
                    target_subpath = os.path.join(sub_rel, fname)

            elif top_folder == "Torrents" and any(k in fname_lower or (len(parts) > 1 and k in parts[1].lower()) for k in ("treasure of nadia", "home together")):
                target_category = "Games"
                if len(parts) > 1:
                    sub_rel = os.path.relpath(dirpath, os.path.join(root_dir, "Torrents"))
                    target_subpath = os.path.join(sub_rel, fname)
                else:
                    target_subpath = fname

            # --- CASE B: MAGAZINES & DOCS ---
            elif (
                (top_folder == "girls" and (ext == ".pdf" or "periodika" in rel_dir.lower()))
                or (rel_dir == "." and ext in (".rar", ".zip", ".pdf") and ("magazine" in fname_lower or "pdf" in fname_lower))
                or (rel_dir == "." and fname_lower.endswith(".txt") and "hentai" in fname_lower)
            ):
                target_category = "Magazines & Docs"
                if "greek periodika" in rel_dir.lower() and ext == ".pdf":
                    target_subpath = os.path.join("Greek Periodika", fname)
                elif "rar" in rel_dir.lower() or ext in (".rar", ".zip"):
                    target_subpath = os.path.join("Archives", fname)
                else:
                    target_subpath = fname

            # --- CASE C: PHOTOS & SETS ---
            elif (
                top_folder == "GIF"
                or (top_folder == "DigitalPlayground" and "imageset" in rel_dir.lower())
                or (top_folder == "girls" and any(k in rel_dir.lower() for k in ("katerina stikoudi", "olga farmaki", "maxjune", "sexy_avatars", "my love", "κολετσα", "women")))
                or (top_folder == "girls" and ext in (".jpg", ".jpeg", ".png", ".webp"))
                or (top_folder == "Vixen" and ext in (".jpg", ".png", ".webp") and "vixen -" in rel_dir.lower())
                or (rel_dir == "." and ext in (".jpg", ".jpeg", ".png", ".webp"))
            ):
                target_category = "Photos & Sets"
                if top_folder == "GIF":
                    target_subpath = os.path.join("GIFs", fname)
                elif "imageset" in rel_dir.lower():
                    target_subpath = os.path.join("Stella Cox - Force Awakens", fname)
                elif "katerina stikoudi" in rel_dir.lower():
                    target_subpath = os.path.join("Greek Models", "Katerina Stikoudi - Nitro", fname)
                elif "olga farmaki" in rel_dir.lower():
                    target_subpath = os.path.join("Greek Models", "Olga Farmaki - Playboy", fname)
                elif "maxjune" in rel_dir.lower():
                    target_subpath = os.path.join("Greek Models", "Nikoleta Ralli - Max June 2010", fname)
                elif "sexy_avatars" in rel_dir.lower():
                    target_subpath = os.path.join("Sexy Avatars", fname)
                elif "my love" in rel_dir.lower():
                    target_subpath = os.path.join("My Love", fname)
                elif "κολετσα" in rel_dir.lower():
                    target_subpath = os.path.join("Greek Models", "Christina Koletsa", fname)
                elif top_folder == "girls" and len(parts) == 1:
                    target_subpath = os.path.join("Loose Photos", fname)
                elif top_folder == "Vixen":
                    set_name = clean_folder_name(parts[-1])
                    target_subpath = os.path.join("Vixen Sets", set_name, fname)
                elif rel_dir == ".":
                    target_subpath = fname
                else:
                    target_subpath = os.path.join(clean_folder_name(parts[-1]), fname)

            # --- CASE D: STUDIOS ---
            elif (
                (visual_entry and visual_entry.get("studio"))
                or top_folder in ("Bangbus ALL 2010 videos 720p", "Brazzers", "DigitalPlayground", "FuckedHard18", "Vixen")
                or top_folder.startswith("Tonights.Girlfriend")
                or (top_folder == "siterips" and any(k in rel_dir.lower() for k in ("backroom", "bangbros", "x-art")))
                or (top_folder == "VIDEOS" and any(k in rel_dir.lower() for k in ("backroom casting couch", "brazzers", "digitalplayground", "x-art")))
                or (top_folder == "Torrents" and "freeze" in rel_dir.lower())
                or (top_folder == "temp" and any(k in fname_lower or k in rel_dir.lower() for k in ("brattysis", "pure taboo", "vixen")))
            ):
                target_category = "Studios"
                if visual_entry and visual_entry.get("studio"):
                    detected_studio = visual_entry["studio"]
                else:
                    detected_studio = detect_studio_from_path_or_name(rel_dir, fname)

                if not detected_studio:
                    if "bangbus" in rel_dir.lower():
                        detected_studio = "Bangbus"
                    elif "brazzers" in rel_dir.lower():
                        detected_studio = "Brazzers"
                    elif "digitalplayground" in rel_dir.lower():
                        detected_studio = "Digital Playground"
                    elif "fuckedhard18" in rel_dir.lower() or "fh18" in rel_dir.lower():
                        detected_studio = "FuckedHard18"
                    elif "vixen" in rel_dir.lower():
                        detected_studio = "Vixen"
                    elif "tonights" in rel_dir.lower():
                        detected_studio = "Tonights Girlfriend"
                    elif "backroom" in rel_dir.lower():
                        detected_studio = "Backroom Casting Couch"
                    elif "bangbros" in rel_dir.lower():
                        detected_studio = "Bangbros"
                    elif "x-art" in rel_dir.lower():
                        detected_studio = "X-Art"
                    elif "freeze" in rel_dir.lower():
                        detected_studio = "Freeze"
                    elif "pure taboo" in fname_lower or "pure taboo" in rel_dir.lower():
                        detected_studio = "Pure Taboo"
                    elif "brattysis" in fname_lower or "brattysis" in rel_dir.lower():
                        detected_studio = "Brattysis"
                    else:
                        detected_studio = "Other Studios"

                # Check if file is in screens subfolder (e.g. Tonights Girlfriend Screens)
                if "screens" in rel_dir.lower() and ext in (".jpg", ".png", ".webp"):
                    target_subpath = os.path.join(detected_studio, "Screens", fname)
                # Check if it is a single-release folder being flattened
                elif rel_dir in flattenable_dirs or len(parts) > 1:
                    target_subpath = os.path.join(detected_studio, fname)
                    stats["folders_to_prune"].add(dirpath)
                else:
                    target_subpath = os.path.join(detected_studio, fname)

            # --- CASE E: CELEBRITIES ---
            elif (
                top_folder == "Celeb"
                or (top_folder == "VIDEOS" and any(k in rel_dir.lower() for k in ("celeb", "mr skin", "jesse jane", "sasha grey", "from movies")))
                or (top_folder == "L & S" and "megan fox" in fname_lower)
                or (rel_dir == "." and "mr skins" in fname_lower)
                or (visual_entry and visual_entry.get("performers") and not visual_entry.get("studio"))
                or any(k in fname_lower for k in ("lexi belle", "amy brooke", "tori black", "sasha grey", "jesse jane", "riley steele", "jenna jameson"))
            ):
                target_category = "Celebrities"
                if "megan fox" in rel_dir.lower() or "megan fox" in fname_lower:
                    target_subpath = os.path.join("Megan Fox", fname)
                elif "mr skin" in rel_dir.lower() or "mr skins" in fname_lower:
                    target_subpath = os.path.join("Mr Skin", fname)
                elif "sasha grey" in rel_dir.lower() or "sasha grey" in fname_lower:
                    target_subpath = os.path.join("Sasha Grey", fname)
                elif "jesse jane" in rel_dir.lower() or "jesse jane" in fname_lower:
                    target_subpath = os.path.join("Jesse Jane", fname)
                elif "lexi belle" in fname_lower or "lexi belle" in rel_dir.lower():
                    target_subpath = os.path.join("Lexi Belle", fname)
                elif "amy brooke" in fname_lower or "amy brooke" in rel_dir.lower():
                    target_subpath = os.path.join("Amy Brooke", fname)
                elif "tori black" in fname_lower or "tori black" in rel_dir.lower():
                    target_subpath = os.path.join("Tori Black", fname)
                elif "riley steele" in fname_lower or "riley steele" in rel_dir.lower():
                    target_subpath = os.path.join("Riley Steele", fname)
                elif "jenna jameson" in fname_lower or "jenna jameson" in rel_dir.lower():
                    target_subpath = os.path.join("Jenna Jameson", fname)
                elif visual_entry and visual_entry.get("performers"):
                    primary_perf = visual_entry["performers"][0]
                    target_subpath = os.path.join(primary_perf, fname)
                elif "top 300" in rel_dir.lower():
                    target_subpath = os.path.join("Top 300 Celebrity Nude Scenes", fname)
                elif "olivia" in rel_dir.lower():
                    target_subpath = os.path.join("Olivia Wilde", fname)
                elif "from movies" in rel_dir.lower():
                    target_subpath = os.path.join("From Movies", fname)
                elif "update" in rel_dir.lower():
                    folder_name = clean_folder_name(parts[-1])
                    target_subpath = os.path.join("Updates", folder_name, fname)
                elif top_folder == "Celeb" and len(parts) == 1:
                    target_subpath = fname
                elif rel_dir == ".":
                    target_subpath = fname
                else:
                    target_subpath = os.path.join(clean_folder_name(parts[-1]), fname)

            # --- CASE F: MOVIES ---
            elif (
                top_folder == "MOVIES"
                or (top_folder == "Torrents" and "night shift nurses" in rel_dir.lower())
                or (top_folder == "VIDEOS" and any(k in rel_dir.lower() for k in ("friends.xxx", "parody", "greek videos")))
                or (top_folder == "temp" and "young fantasies" in rel_dir.lower())
            ):
                target_category = "Movies"
                if "night shift nurses" in rel_dir.lower():
                    sub_part = parts[-1] if len(parts) > 2 else "Series"
                    target_subpath = os.path.join("Night Shift Nurses", clean_folder_name(sub_part), fname)
                elif "friends.xxx" in rel_dir.lower() or "parody" in rel_dir.lower():
                    target_subpath = os.path.join("Parodies", clean_folder_name(parts[-1]), fname)
                elif "young fantasies" in rel_dir.lower():
                    target_subpath = os.path.join("Young Fantasies 5", fname)
                elif top_folder == "MOVIES":
                    if len(parts) > 1:
                        clean_movie_parts = [clean_folder_name(p) for p in parts[1:]]
                        target_subpath = os.path.join(*clean_movie_parts, fname)
                    else:
                        target_subpath = fname
                else:
                    target_subpath = os.path.join(clean_folder_name(parts[-1]), fname)

            # --- CASE G: COLLECTIONS & SITERIPS ---
            else:
                target_category = "Collections & Siterips"
                if "izzy green" in rel_dir.lower():
                    clean_izzy = [clean_folder_name(p) for p in parts[2:]] if len(parts) > 2 else []
                    target_subpath = os.path.join("Izzy Green (OnlyFans)", *clean_izzy, fname) if clean_izzy else os.path.join("Izzy Green (OnlyFans)", fname)
                elif "onlyfans mix" in rel_dir.lower():
                    target_subpath = os.path.join("OnlyFans Mix", fname)
                elif top_folder == "L & S":
                    target_subpath = os.path.join("L & S Erotica", fname)
                elif top_folder == "VIDEOS":
                    clean_vid_parts = [clean_folder_name(p) for p in parts[1:]] if len(parts) > 1 else ["Clips"]
                    target_subpath = os.path.join(*clean_vid_parts, fname)
                elif rel_dir == ".":
                    target_subpath = fname
                else:
                    target_subpath = os.path.join(clean_folder_name(parts[-1]), fname)

            # Build absolute target path
            canonical_dest_dir = os.path.join(root_dir, target_category)
            proposed_target_path = os.path.join(canonical_dest_dir, target_subpath)

            # Handle collision resolution
            target_key = proposed_target_path.lower()
            if target_key in target_registry:
                target_registry[target_key] += 1
                idx = target_registry[target_key]
                stats["collisions_resolved"] += 1
                
                # Suffix disambiguation
                t_dir = os.path.dirname(proposed_target_path)
                t_base, t_ext = os.path.splitext(os.path.basename(proposed_target_path))
                disambiguated_name = f"{t_base} ({idx}){t_ext}"
                final_target_path = os.path.join(t_dir, disambiguated_name)
            else:
                target_registry[target_key] = 1
                final_target_path = proposed_target_path

            # Is file moving?
            norm_src = os.path.normpath(src_full).lower()
            norm_dest = os.path.normpath(final_target_path).lower()
            is_moved = (norm_src != norm_dest)

            if is_moved:
                stats["files_to_relocate"] += 1
            else:
                stats["files_unchanged"] += 1

            stats["root_category_counts"][target_category] += 1

            relocations.append({
                "source_path": src_full,
                "target_path": final_target_path,
                "relative_source": os.path.relpath(src_full, root_dir),
                "relative_target": os.path.relpath(final_target_path, root_dir),
                "category": target_category,
                "is_moved": is_moved,
                "file_size": os.path.getsize(src_full) if os.path.exists(src_full) else 0,
                "mtime": os.path.getmtime(src_full) if os.path.exists(src_full) else 0.0
            })

    stats["folders_to_prune_count"] = len(stats["folders_to_prune"])
    return relocations, stats

def export_dry_run_reports(relocations: List[Dict[str, Any]], stats: Dict[str, Any], csv_path: str, json_path: str):
    print(f"[*] Exporting Dry-Run Preview to '{csv_path}' and '{json_path}'...")
    
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Category", "Is Moved", "Source Filename", "Target Filename",
            "File Size Bytes", "Relative Source Path", "Relative Target Path",
            "Absolute Source Path", "Absolute Target Path"
        ])
        for r in relocations:
            writer.writerow([
                r["category"],
                "YES" if r["is_moved"] else "NO",
                os.path.basename(r["source_path"]),
                os.path.basename(r["target_path"]),
                r["file_size"],
                r["relative_source"],
                r["relative_target"],
                r["source_path"],
                r["target_path"]
            ])

    json_stats = dict(stats)
    json_stats["root_category_counts"] = dict(stats["root_category_counts"])
    json_stats["folders_to_prune"] = sorted(list(stats["folders_to_prune"]))

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "summary": json_stats,
            "sample_relocations": relocations[:500],
            "total_records": len(relocations)
        }, f, indent=2)

    print(f"[+] Dry-Run Preview export completed successfully.")

def print_summary_dashboard(stats: Dict[str, Any]):
    print("\n=======================================================")
    print("      ALOHA DIRECTORY RESTRUCTURE DRY-RUN REPORT       ")
    print("=======================================================")
    print(f"Total Scanned Files:      {stats['total_scanned_files']:,}")
    print(f"Files To Relocate:        {stats['files_to_relocate']:,}")
    print(f"Files Unchanged:          {stats['files_unchanged']:,}")
    print(f"Collisions Resolved:      {stats['collisions_resolved']:,}")
    print(f"Preserved Root Files:     {stats['preserved_root_files']:,}")
    print(f"Skipped System Caches:    {stats['skipped_caches']:,}")
    print(f"Empty/Wrapper Dirs Prune: {stats['folders_to_prune_count']:,}")
    print("\nCanonical Root Allocations:")
    for cat, count in sorted(stats["root_category_counts"].items(), key=lambda x: x[1], reverse=True):
        print(f"  - {cat:<25}: {count:>6,} files")
    print("=======================================================\n")

def main():
    parser = argparse.ArgumentParser(description="Directory Hierarchy Analysis & Restructure Planner for F:\\Aloha")
    parser.add_argument("--root", default=r"F:\Aloha", help="Target root directory (default F:\\Aloha)")
    parser.add_argument("--preview-csv", default="folder_restructure_preview.csv", help="Output path for CSV preview")
    parser.add_argument("--preview-json", default="folder_restructure_preview.json", help="Output path for JSON preview")
    args = parser.parse_args()

    relocations, stats = plan_directory_restructure(args.root)
    print_summary_dashboard(stats)
    export_dry_run_reports(relocations, stats, args.preview_csv, args.preview_json)

if __name__ == "__main__":
    main()
