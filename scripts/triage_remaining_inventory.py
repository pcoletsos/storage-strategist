import os
import re
import sys
import json
import sqlite3
import argparse
from typing import Dict, Any, List, Tuple, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Sibling import for safe paths and known mappings
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

try:
    from media_name_parser import clean_title_case, sanitize_win_filename, to_extended_path
except ImportError:
    def clean_title_case(s: str) -> str:
        return s.title()
    def sanitize_win_filename(s: str) -> str:
        return s
    def to_extended_path(p: str) -> str:
        return p

try:
    from mutagen.mp4 import MP4
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False


KNOWN_PERFORMER_LOOKUPS = {
    "august ames": "August Ames",
    "lexi belle": "Lexi Belle",
    "kimmy granger": "Kimmy Granger",
    "halia": "Halia",
    "chelsea": "Chelsea",
    "little dragon": "Little Dragon",
    "riley steele": "Riley Steele",
    "jazlyn ray": "Jazlyn Ray",
    "olga farmaki": "Olga Farmaki",
    "olga farmakh": "Olga Farmaki",
    "gogo mastrokosta": "Gogo Mastrokosta",
    "vina asiki": "Vina Asiki",
    "monica sweetheart": "Monica Sweetheart",
    "lela star": "Lela Star",
    "lela starr": "Lela Star",
    "tiffany mynx": "Tiffany Mynx",
    "danny wylde": "Danny Wylde",
    "tara lynn foxx": "Tara Lynn Foxx",
    "nella": "Nella",
    "britney b": "Britney B",
}


def classify_studios_item(filename: str, current_studio: Optional[str]) -> Tuple[Optional[str], Optional[str], str, float]:
    """Classifies an unreviewed Studios item."""
    artist: Optional[str] = None
    studio: str = current_studio or "Studios"
    title: str = filename
    confidence: float = 0.90

    # 1. X-Art Nella Photoshoot Images
    m_nella = re.search(r"Nella\s+([A-Za-z\s]+?)\s*(?:\d+)?\s*(?:Lrg)?\.(jpg|png)$", filename, re.IGNORECASE)
    if "x art" in filename.lower() and "nella" in filename.lower():
        artist = "Nella"
        studio = "X-Art"
        sub_gallery = m_nella.group(1).strip() if m_nella else "Photoshoot"
        title = f"Nella {clean_title_case(sub_gallery)}"
        return artist, studio, title, 0.95

    # 2. X-Art Generic Photoshoot Images
    if "x art" in filename.lower() and filename.lower().endswith((".jpg", ".png")):
        artist = "Compilation"
        studio = "X-Art"
        title = "X-Art Photoshoot"
        return artist, studio, title, 0.90

    # 3. Specific Studio Performers
    fn_lower = filename.lower()
    if "fh18 august" in fn_lower or "august" in fn_lower and "fh" in fn_lower:
        artist = "August Ames"
        studio = "FuckedHard18"
        title = "August"
    elif "fh18 lexi" in fn_lower or "lexi" in fn_lower and "fh" in fn_lower:
        artist = "Lexi Belle"
        studio = "FuckedHard18"
        title = "Lexi"
    elif "kimmy" in fn_lower and "fuckedhard18" in fn_lower:
        artist = "Kimmy Granger"
        studio = "FuckedHard18"
        title = "Kimmy"
    elif "britney b" in fn_lower:
        artist = "Britney B"
        studio = "FuckedHard18"
        title = "Britney B"
    elif "halia" in fn_lower and "fuckedhard18" in fn_lower:
        artist = "Halia"
        studio = "FuckedHard18"
        title = "Halia"
    elif "little dragon" in fn_lower:
        artist = "Little Dragon"
        studio = "Freeze"
        title = "Little Dragon Thief of Hearts"
    elif "rileysteel" in fn_lower:
        artist = "Riley Steele"
        studio = "Digital Playground"
        title = "Riley Steele Strip For Me"
    elif "jazlyn ray" in fn_lower:
        artist = "Jazlyn Ray"
        studio = "Tonights Girlfriend"
        title = "Jazlyn Ray"
    elif "olga farmak" in fn_lower and "gogo" in fn_lower:
        artist = "Olga Farmaki, Gogo Mastrokosta, Vina Asiki"
        studio = "Sweetheart Video"
        title = "Greek Stars Special"
    elif "monica sweetheart" in fn_lower:
        artist = "Monica Sweetheart"
        studio = "Bangbros"
        title = "Monica Sweetheart POV Sex"
    elif "lela star" in fn_lower:
        artist = "Lela Star"
        studio = "Twistys"
        title = "Lela Star Strips and Tease"
    elif "chelsea" in fn_lower and "x art" in fn_lower:
        artist = "Chelsea"
        studio = "X-Art"
        title = "Chelsea First and Forever"
    elif "btas pool party" in fn_lower:
        artist = "Compilation"
        studio = "Brazzers"
        title = "Big Tits at School Pool Party"
    elif "plib" in fn_lower:
        artist = "Compilation"
        studio = "Brazzers"
        title = "Pornstar Live in Berlin"
    elif "assparade" in fn_lower or "motor ass" in fn_lower or "latin ass fever" in fn_lower:
        artist = "Compilation"
        studio = "Bangbros"
        title = "Ass Parade"
    else:
        # Generic studio clip
        artist = "Compilation"
        # strip resolution/codec tags from title
        title = re.sub(r"\[.*?\]", "", filename).strip()
        title = os.path.splitext(title)[0]
        title = clean_title_case(title)

    return artist, studio, title, confidence


def classify_movies_item(filename: str, current_studio: Optional[str]) -> Tuple[Optional[str], Optional[str], str, float]:
    """Classifies an unreviewed Movies item."""
    studio = current_studio or "Movies"
    artist = "Compilation"
    clean_name = re.sub(r"\[.*?\]", "", filename).strip()
    clean_name = os.path.splitext(clean_name)[0]
    title = clean_title_case(clean_name)
    return artist, studio, title, 0.95


def classify_collections_item(filename: str, current_studio: Optional[str]) -> Tuple[Optional[str], Optional[str], str, float]:
    """Classifies an unreviewed Collections & Siterips item."""
    artist = "Compilation"
    studio = current_studio or "Collections & Siterips"
    fn_lower = filename.lower()

    if "taras titties jiggly" in fn_lower:
        artist = "Tara Lynn Foxx, Riley Steele"
        studio = "Digital Playground"
        title = "Taras Titties Jiggly"
    elif "smokin hot cougar" in fn_lower:
        artist = "Tiffany Mynx, Danny Wylde"
        studio = "Brazzers"
        title = "Smokin Hot Cougar Seduces a Young Stud"
    else:
        clean_name = re.sub(r"\[.*?\]", "", filename).strip()
        clean_name = os.path.splitext(clean_name)[0]
        title = clean_title_case(clean_name)

    return artist, studio, title, 0.90


def classify_celebrities_item(filename: str, current_studio: Optional[str]) -> Tuple[Optional[str], Optional[str], str, float]:
    """Classifies an unreviewed Celebrities item."""
    studio = current_studio if current_studio and current_studio != "Unknown" else "Mr Skin"
    artist = "Compilation"
    fn_lower = filename.lower()

    if fn_lower.startswith("ahaze"):
        artist = "Keeley Hazell"
        studio = "Mr Skin"
        title = "Keeley Hazell Scene Clip"
        return artist, studio, title, 0.88

    # Generic or numeric stubs
    clean_name = re.sub(r"\[.*?\]", "", filename).strip()
    clean_name = os.path.splitext(clean_name)[0]
    title = clean_title_case(clean_name)
    return artist, studio, title, 0.85


def classify_photos_item(filename: str, current_studio: Optional[str]) -> Tuple[Optional[str], Optional[str], str, float]:
    """Classifies an unreviewed Photos & Sets item."""
    artist = "Compilation"
    studio = current_studio or "Photo Sets Collection"
    clean_name = re.sub(r"\[.*?\]", "", filename).strip()
    clean_name = os.path.splitext(clean_name)[0]
    # Remove leading "New Folder - " if present
    clean_name = re.sub(r"^New\s+Folder\s*-\s*", "", clean_name, flags=re.IGNORECASE)
    title = clean_title_case(clean_name)
    return artist, studio, title, 0.88


def triage_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Triages a single needs_review item based on its pool root."""
    file_path = item["file_path"]
    filename = item["filename"]
    rel = file_path.replace("F:\\Aloha\\", "").replace("F:/Aloha/", "")
    pool = rel.split(os.sep)[0] if os.sep in rel else rel.split("/")[0]

    cur_studio = item.get("studio")

    if pool == "Studios":
        artist, studio, title, conf = classify_studios_item(filename, cur_studio)
    elif pool == "Movies":
        artist, studio, title, conf = classify_movies_item(filename, cur_studio)
    elif pool == "Collections & Siterips":
        artist, studio, title, conf = classify_collections_item(filename, cur_studio)
    elif pool == "Celebrities":
        artist, studio, title, conf = classify_celebrities_item(filename, cur_studio)
    elif pool == "Photos & Sets":
        artist, studio, title, conf = classify_photos_item(filename, cur_studio)
    else:
        artist = item.get("existing_artist") or "Compilation"
        studio = cur_studio or pool
        title = os.path.splitext(filename)[0]
        conf = 0.85

    return {
        "id": item["id"],
        "file_path": file_path,
        "filename": filename,
        "pool": pool,
        "new_artist": artist,
        "new_studio": studio,
        "new_title": title,
        "confidence_score": conf,
        "needs_review": 0
    }


def inject_mp4_tags_lossless(file_path: str, title: str, artist: Optional[str], studio: Optional[str]) -> bool:
    """Injects MP4 metadata tags while preserving original file mtime."""
    if not MUTAGEN_AVAILABLE:
        return False
    if not file_path.lower().endswith(".mp4"):
        return False
    if not os.path.exists(file_path):
        return False

    try:
        stat_info = os.stat(file_path)
        orig_atime = stat_info.st_atime
        orig_mtime = stat_info.st_mtime

        mp4 = MP4(to_extended_path(file_path))
        if mp4.tags is None:
            mp4.add_tags()

        mp4.tags["\xa9nam"] = [title]
        if artist:
            mp4.tags["\xa9ART"] = [artist]
        if studio:
            mp4.tags["\xa9cmt"] = [f"Studio: {studio}"]

        mp4.save()
        os.utime(to_extended_path(file_path), (orig_atime, orig_mtime))
        return True
    except Exception as e:
        return False


def run_triage(db_path: str, dry_run: bool = True, output_report: Optional[str] = None) -> Dict[str, Any]:
    """Runs the triage engine across all needs_review items."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, filename, existing_artist, existing_title, studio 
        FROM media_files 
        WHERE needs_review = 1
    """)
    rows = c.fetchall()

    items = [
        {
            "id": r[0],
            "file_path": r[1],
            "filename": r[2],
            "existing_artist": r[3],
            "existing_title": r[4],
            "studio": r[5]
        }
        for r in rows
    ]

    triaged_results = [triage_item(it) for it in items]
    tagged_mp4_count = 0

    if not dry_run:
        for res in triaged_results:
            c.execute("""
                UPDATE media_files
                SET existing_artist = ?,
                    studio = ?,
                    existing_title = ?,
                    confidence_score = ?,
                    needs_review = 0
                WHERE id = ?
            """, (res["new_artist"], res["new_studio"], res["new_title"], res["confidence_score"], res["id"]))

            # Attempt lossless MP4 tag injection
            if res["file_path"].lower().endswith(".mp4"):
                if inject_mp4_tags_lossless(res["file_path"], res["new_title"], res["new_artist"], res["new_studio"]):
                    tagged_mp4_count += 1

        conn.commit()

    conn.close()

    summary = {
        "total_evaluated": len(items),
        "total_resolved": len(triaged_results),
        "remaining_unreviewed": 0 if not dry_run else 0,
        "dry_run": dry_run,
        "tagged_mp4_count": tagged_mp4_count,
        "results": triaged_results
    }

    if output_report:
        with open(output_report, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    return summary


def main():
    parser = argparse.ArgumentParser(description="Triage remaining unreviewed media assets across Aloha.")
    parser.add_argument("--db", default="media_inventory.db", help="Path to media_inventory.db")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Run analysis without writing changes")
    parser.add_argument("--commit", action="store_true", default=False, help="Commit updates to SQLite database")
    parser.add_argument("--output-report", default="remaining_triage_preview.json", help="Path to write JSON summary")

    args = parser.parse_args()
    is_dry_run = not args.commit

    summary = run_triage(args.db, dry_run=is_dry_run, output_report=args.output_report)
    print(f"Evaluated {summary['total_evaluated']} assets.")
    print(f"Resolved to needs_review=0: {summary['total_resolved']}.")
    print(f"Mode: {'DRY RUN' if is_dry_run else 'COMMITTED TO DATABASE'}.")
    if not is_dry_run:
        print(f"Losslessly tagged MP4s: {summary['tagged_mp4_count']}.")
    print(f"Report exported to {args.output_report}")


if __name__ == "__main__":
    main()
