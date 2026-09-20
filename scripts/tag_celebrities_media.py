#!/usr/bin/env python3
"""Performer entity recognition and metadata tagging for Celebrities pool on Aloha.

Extracts canonical celebrity performer entities, scene titles, and studio attributions
from directory taxonomy, Top 300 compilation brackets, celebrity registries, and
clip tokens. Corrects legacy studio misattributions, losslessly injects QuickTime
tags (©ART, ©nam, ©cmt, ©day) into MP4 containers with timestamp preservation,
and synchronizes media_inventory.db.
"""

import os
import re
import sys
import json
import time
import sqlite3
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Tuple, Set

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path
from media_tagger import tag_media_file

DEFAULT_TARGET_DIR = r"F:\Aloha\Celebrities"
DEFAULT_DB_PATH = os.path.join(REPO_ROOT, "media_inventory.db")
DEFAULT_OUTPUT_REPORT = os.path.join(REPO_ROOT, "celebrities_tagging_preview.json")

# Subfolder-to-performer direct mapping
FOLDER_PERFORMERS: Dict[str, str] = {
    "Sasha Grey": "Sasha Grey",
    "Jesse Jane": "Jesse Jane",
    "Vana Barba": "Vana Barba",
    "Olga Farmaki": "Olga Farmaki",
    "Jenna Jameson": "Jenna Jameson",
    "Riley Steele": "Riley Steele",
    "Olivia Wilde": "Olivia Wilde",
    "Megan Fox": "Megan Fox",
    "Tori Black": "Tori Black",
    "Lexi Belle": "Lexi Belle",
    "Amy Brooke": "Amy Brooke",
    "Julia Alexandratou Dvd": "Julia Alexandratou",
}

# Recognized celebrity actresses and mainstream performers
KNOWN_CELEBS: List[str] = [
    "Abbie Cornish", "Addison Timlin", "Aditi Rao", "Alexis Dziena", "Ali Larter", "Ali Zafar",
    "Alyssa Milano", "Amanda Peet", "Amanda Seyfried", "Amber Heard", "Amy Adams", "Amy Brooke",
    "Angelina Jolie", "Anna Chlumsky", "Anne Hathaway", "Asia Argento", "Ashley Hinshaw", "Ashley Judd",
    "Cameron Diaz", "Carla Gugino", "Charlize Theron", "Charlotte Gainsbourg", "Chloe Sevigny",
    "Christina Ricci", "Claudine Digard", "Courteney Cox", "Dana Delany", "Debra Cole",
    "Demi Moore", "Diane Farr", "Diane Kruger", "Diane Lane", "Elisha Cuthbert", "Eliza Dushku",
    "Emily Browning", "Emmanuelle Beart", "Emmanuelle Vaugier", "Eva Green", "Eva Mendes",
    "Gretchen Mol", "Gwyneth Paltrow", "Halle Berry", "Heather Graham", "Helen Mirren", "Ivana Milicevic",
    "Jaime Pressly", "Jamie Lee Curtis", "Jana Kaderabkova", "January Jones", "Jenna Jameson",
    "Jennifer Connelly", "Jennifer Tilly", "Jesse Jane", "Jessica Alba", "Jessica Biel",
    "Julia Alexandratou", "Julianna Guill", "Julie Benz", "Kate Hudson", "Kate Winslet",
    "Katie Holmes", "Kelly Preston", "Kim Basinger", "Kim Cattrall", "Kirsten Dunst",
    "Kristen Bell", "Kristen Stewart", "Laura Prepon", "Lena Headey", "Lexi Belle", "Lexi Love",
    "Lindsay Lohan", "Liv Tyler", "Lizzy Caplan", "Ludivine Sagnier", "Maggie Gyllenhaal", "Maitland Ward",
    "Malin Akerman", "Maria Bello", "Marion Cotillard", "Marisa Tomei", "Marketa Barnfield",
    "Mary Louise Parker", "Megan Fox", "Michelle Pfeiffer", "Michelle Trachtenberg",
    "Mila Kunis", "Milla Jovovich", "Monica Bellucci", "Naomi Watts", "Natasha Henstridge",
    "Natalie Portman", "Nicole Kidman", "Olga Farmaki", "Olivia Wilde", "Pamela Anderson",
    "Penelope Cruz", "Phoebe Cates", "Rachel Miner", "Rachel Weisz", "Reese Witherspoon",
    "Rhona Mitra", "Riki Lindhome", "Riley Steele", "Rinko Kikuchi", "Rose McGowan", "Salma Hayek",
    "Sarah Michelle Gellar", "Sasha Grey", "Scarlett Johansson", "Shannon Elizabeth",
    "Sharon Stone", "Sherilyn Fenn", "Sienna Miller", "Sophie Marceau", "Stephanie Niznik",
    "Susan Sarandon", "Tara Reid", "Tori Black", "Uma Thurman", "Vana Barba",
    "Veronica Wasko", "Virginie Ledoyen", "Winona Ryder"
]

# Surnames and clip tokens for shorthand resolution
SURNAME_MAP: Dict[str, str] = {
    "gwyneth": "Gwyneth Paltrow",
    "gyllenhaal": "Maggie Gyllenhaal",
    "lindhome": "Riki Lindhome",
    "jovovich": "Milla Jovovich",
    "kidman": "Nicole Kidman",
    "theron": "Charlize Theron",
    "gainsbourg": "Charlotte Gainsbourg",
    "benz": "Julie Benz",
    "prepon": "Laura Prepon",
    "kikuchi": "Rinko Kikuchi",
    "milicevic": "Ivana Milicevic",
    "cotillard": "Marion Cotillard",
    "bellucci": "Monica Bellucci",
    "jolie": "Angelina Jolie",
    "portman": "Natalie Portman",
    "hayek": "Salma Hayek",
    "headey": "Lena Headey",
    "seyfried": "Amanda Seyfried",
    "judd": "Ashley Judd",
    "ricci": "Christina Ricci",
    "connelly": "Jennifer Connelly",
    "basinger": "Kim Basinger",
    "pfeiffer": "Michelle Pfeiffer",
    "sagnier": "Ludivine Sagnier",
    "tomei": "Marisa Tomei",
    "thurman": "Uma Thurman",
    "witherspoon": "Reese Witherspoon",
    "berry": "Halle Berry",
    "holmes": "Katie Holmes",
    "cates": "Phoebe Cates",
    "graham": "Heather Graham",
    "pressly": "Jaime Pressly",
    "henstridge": "Natasha Henstridge",
    "curtis": "Jamie Lee Curtis",
    "green": "Eva Green",
    "mendes": "Eva Mendes",
    "lane": "Diane Lane",
    "cox": "Courteney Cox",
    "larter": "Ali Larter",
    "milano": "Alyssa Milano",
    "miner": "Rachel Miner",
    "fenn": "Sherilyn Fenn",
    "peet": "Amanda Peet",
    "marceau": "Sophie Marceau",
    "mol": "Gretchen Mol",
    "dziena": "Alexis Dziena",
    "wilde": "Olivia Wilde",
    "fox": "Megan Fox",
    "grey": "Sasha Grey",
    "jane": "Jesse Jane",
    "jameson": "Jenna Jameson",
    "steele": "Riley Steele",
    "black": "Tori Black",
    "belle": "Lexi Belle",
    "brooke": "Amy Brooke",
    "barba": "Vana Barba",
    "farmaki": "Olga Farmaki",
    "alexandratou": "Julia Alexandratou",
    "wasko": "Veronica Wasko",
    "vaugier": "Emmanuelle Vaugier",
    "vaugler": "Emmanuelle Vaugier",
    "hinshaw": "Ashley Hinshaw",
    "caplan": "Lizzy Caplan",
    "tilly": "Jennifer Tilly",
    "sarandon": "Susan Sarandon",
    "cattrall": "Kim Cattrall",
    "anderson": "Pamela Anderson",
    "biel": "Jessica Biel",
    "alba": "Jessica Alba",
    "kunis": "Mila Kunis",
    "trachtenberg": "Michelle Trachtenberg",
    "hathaway": "Anne Hathaway",
    "stone": "Sharon Stone",
    "elizabeth": "Shannon Elizabeth",
    "diaz": "Cameron Diaz",
    "watts": "Naomi Watts",
    "gugino": "Carla Gugino",
    "dunst": "Kirsten Dunst",
    "stewart": "Kristen Stewart",
    "lohan": "Lindsay Lohan",
    "mcgowan": "Rose McGowan",
    "tyler": "Liv Tyler",
    "moore": "Demi Moore",
    "parker": "Mary Louise Parker",
    "chlumsky": "Anna Chlumsky",
    "heard": "Amber Heard",
    "sevigny": "Chloe Sevigny",
    "mitra": "Rhona Mitra",
    "akerman": "Malin Akerman",
    "browning": "Emily Browning",
    "guill": "Julianna Guill",
    "weisz": "Rachel Weisz",
    "delany": "Dana Delany",
    "kaderabkova": "Jana Kaderabkova",
    "barnfield": "Marketa Barnfield",
    "bell": "Kristen Bell",
    "dushku": "Eliza Dushku",
    "johansson": "Scarlett Johansson",
    "cuthbert": "Elisha Cuthbert",
    "timlin": "Addison Timlin",
}

# Strings mistakenly recorded as artists in previous passes
INVALID_ARTIST_STRINGS: Set[str] = {
    "mrskin com", "mrskin", "mr skin", "all nude scenes", "video dailymotion",
    "katzbabes", "blogspot com", "pornhub com", "youtube"
}


def parse_date_from_string(text: str) -> Optional[str]:
    """Parses date expressions such as 'Oct 18, 2013' or 'Jan 14, 2014' into ISO format."""
    patterns = [
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}",
        r"\d{4}-\d{2}-\d{2}",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            raw = m.group(0)
            for fmt in ("%b %d, %Y", "%B %d, %Y", "%b %d %Y", "%B %d %Y", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(raw.replace(",", " ").strip(), fmt.replace(",", " "))
                    return dt.strftime("%Y-%m-%d")
                except Exception:
                    pass
    return None


def clean_scene_title(raw_title: str) -> str:
    """Removes technical resolution tags, codec tags, and trailing punctuation from title."""
    t = re.sub(r"\[(?:480p|720p|1080p|2160p|4K|H264|H\.264|AV1|HEVC|MP4|MKV)[^\]]*\]", "", raw_title, flags=re.IGNORECASE)
    t = re.sub(r"\[\d+p\s+[^\]]+\]", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\.\w{2,4}$", "", t)
    t = re.sub(r"\s+", " ", t).strip(" -_")
    return t


def parse_celebrity_asset(
    file_path: str,
    filename: str,
    directory: str,
    media_type: str,
    existing_artist: Optional[str] = None,
    existing_title: Optional[str] = None,
    existing_studio: Optional[str] = None,
) -> Dict[str, Any]:
    """Extracts performer entity, clean title, studio, and date from asset metadata."""
    folder = directory.replace("/", "\\").rstrip("\\").split("\\")[-1]
    artist = None
    title = None
    studio = existing_studio
    date = parse_date_from_string(filename)
    confidence = 0.0
    method = "none"

    # Fix legacy invalid artist strings
    if existing_artist and existing_artist.strip().lower() in INVALID_ARTIST_STRINGS:
        if "mrskin" in existing_artist.lower() or "mr skin" in existing_artist.lower():
            studio = "Mr Skin"
        existing_artist = None

    # Rule A: Subfolder direct match
    if folder in FOLDER_PERFORMERS:
        artist = FOLDER_PERFORMERS[folder]
        confidence = 0.98
        method = "subfolder"

    # Rule B: Top 300 bracket [### Performer Name] <Title>
    if not artist:
        m = re.search(r"\[\d+\s+([^\]]+)\]\s*(.*)", filename)
        if m:
            candidate_artist = m.group(1).strip()
            raw_title = m.group(2).strip()
            # Multi-performer normalization (e.g. Dana Delany & Stephanie Niznik)
            if " & " in candidate_artist:
                perfs = [p.strip() for p in candidate_artist.split("&") if p.strip()]
                artist = ", ".join(perfs)
            else:
                artist = candidate_artist
            title = clean_scene_title(raw_title) if raw_title else clean_scene_title(filename)
            confidence = 0.95
            method = "top300_bracket"
        else:
            # Rule B2: Top 300 prefix ### Performer Name <Title>
            m2 = re.match(r"^\d+\s+(.*)", filename)
            if m2:
                rest = m2.group(1).strip()
                matched_celeb = False
                for celeb in KNOWN_CELEBS:
                    if rest.lower().startswith(celeb.lower()):
                        artist = celeb
                        title_rem = rest[len(celeb):].strip()
                        title = clean_scene_title(title_rem) if title_rem else clean_scene_title(filename)
                        confidence = 0.95
                        method = "top300_prefix"
                        matched_celeb = True
                        break
                if not matched_celeb:
                    m_name = re.match(r"^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s+(.*)", rest)
                    if m_name and not any(w in m_name.group(1).lower() for w in ["playlist", "video", "scenes", "the", "best"]):
                        artist = m_name.group(1).strip()
                        title = clean_scene_title(m_name.group(2))
                        confidence = 0.95
                        method = "top300_prefix"

    # Rule C: Known Celebrity Full Name in filename
    if not artist:
        for celeb in KNOWN_CELEBS:
            pattern = r"(" + re.escape(celeb) + r"|" + re.escape(celeb.replace(" ", "")) + r")"
            if re.search(pattern, filename, re.IGNORECASE):
                artist = celeb
                confidence = 0.95
                method = "known_celeb_full"
                break

    # Rule D: Surname clip token resolver
    if not artist:
        clean_tokens = re.sub(r"[_\-\.\[\]\(\)\&]", " ", filename)
        for token in clean_tokens.split():
            base_token = re.sub(r"\d+$", "", token).lower()
            if base_token in SURNAME_MAP:
                artist = SURNAME_MAP[base_token]
                confidence = 0.90
                method = "surname_token"
                break

    # Rule E: Fallback to existing valid artist if present
    if not artist and existing_artist and existing_artist.strip().lower() not in INVALID_ARTIST_STRINGS:
        artist = existing_artist.strip()
        confidence = 0.85
        method = "existing_artist"

    # Rule F: Studio and Platform Attribution
    fname_lower = filename.lower()
    dpath_lower = directory.lower()
    if any(k in fname_lower for k in ["mrskin", "mr skin", "playlist", "top 5", "top 10"]) or "top 300" in dpath_lower:
        studio = "Mr Skin"
    elif "pornhub" in fname_lower:
        studio = "Pornhub"
    elif "youtube" in fname_lower:
        studio = "YouTube"
    elif "dailymotion" in fname_lower:
        studio = "Dailymotion"

    # Rule G: Clean title generation
    if not title:
        title = clean_scene_title(filename)

    return {
        "file_path": file_path,
        "filename": filename,
        "directory": directory,
        "media_type": media_type,
        "detected_artist": artist,
        "detected_title": title,
        "detected_studio": studio,
        "detected_date": date,
        "confidence": confidence,
        "method": method,
    }


def analyze_celebrities_pool(
    db_path: str,
    target_dir: str = DEFAULT_TARGET_DIR,
) -> List[Dict[str, Any]]:
    """Analyzes all media records in Celebrities root and extracts enriched metadata."""
    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found at {db_path}")
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, file_path, filename, directory, media_type,
               existing_artist, existing_title, studio, existing_date, confidence_score
        FROM media_files
        WHERE file_path LIKE ?
        ORDER BY directory ASC, filename ASC
    """, (f"{target_dir}\\%",))

    rows = cursor.fetchall()
    conn.close()

    print(f"[INFO] Evaluating {len(rows)} media assets in '{target_dir}'...")
    results = []

    for row in rows:
        parsed = parse_celebrity_asset(
            file_path=row["file_path"],
            filename=row["filename"],
            directory=row["directory"],
            media_type=row["media_type"],
            existing_artist=row["existing_artist"],
            existing_title=row["existing_title"],
            existing_studio=row["studio"],
        )
        parsed["id"] = row["id"]
        parsed["prior_artist"] = row["existing_artist"]
        parsed["prior_title"] = row["existing_title"]
        parsed["prior_studio"] = row["studio"]
        results.append(parsed)

    return results


def sync_to_database(db_path: str, results: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Updates media_files in SQLite database with recognized performers, titles, and studios."""
    conn = sqlite3.connect(db_path, timeout=60.0)
    updated_artists = 0
    updated_records = 0

    with conn:
        for r in results:
            artist = r.get("detected_artist")
            title = r.get("detected_title")
            studio = r.get("detected_studio")
            date = r.get("detected_date")
            conf = r.get("confidence", 0.0)
            rec_id = r["id"]
            prior_artist = (r.get("prior_artist") or "").strip().lower()

            needs_review = 0 if conf >= 0.85 else 1

            # If artist is recognized, update it. If prior artist was an invalid string (e.g. Mrskin Com), explicitly clear it.
            if artist:
                cur = conn.execute("""
                    UPDATE media_files
                    SET existing_artist = ?,
                        existing_title = COALESCE(?, existing_title),
                        studio = COALESCE(?, studio),
                        existing_date = COALESCE(?, existing_date),
                        confidence_score = MAX(COALESCE(confidence_score, 0.0), ?),
                        needs_review = ?
                    WHERE id = ?
                """, (artist, title, studio, date, conf, needs_review, rec_id))
            elif prior_artist in INVALID_ARTIST_STRINGS:
                cur = conn.execute("""
                    UPDATE media_files
                    SET existing_artist = NULL,
                        existing_title = COALESCE(?, existing_title),
                        studio = COALESCE(?, studio),
                        existing_date = COALESCE(?, existing_date),
                        confidence_score = MAX(COALESCE(confidence_score, 0.0), ?),
                        needs_review = ?
                    WHERE id = ?
                """, (title, studio, date, conf, needs_review, rec_id))
            else:
                cur = conn.execute("""
                    UPDATE media_files
                    SET existing_title = COALESCE(?, existing_title),
                        studio = COALESCE(?, studio),
                        existing_date = COALESCE(?, existing_date),
                        confidence_score = MAX(COALESCE(confidence_score, 0.0), ?),
                        needs_review = ?
                    WHERE id = ?
                """, (title, studio, date, conf, needs_review, rec_id))

            if cur.rowcount > 0:
                updated_records += 1
                if artist:
                    updated_artists += 1

    conn.close()
    return updated_records, updated_artists


def tag_mp4_containers(
    results: List[Dict[str, Any]],
    workers: int = 4,
    min_confidence: float = 0.85,
) -> int:
    """Losslessly injects QuickTime tags into MP4 files using mutagen with timestamp preservation."""
    mp4_targets = []
    for r in results:
        if r.get("media_type") != "video":
            continue
        ext = os.path.splitext(r["file_path"])[1].lower()
        if ext not in (".mp4", ".m4v"):
            continue
        if r.get("confidence", 0.0) < min_confidence and not r.get("detected_studio"):
            continue
        mp4_targets.append(r)

    print(f"[INFO] Ingesting tags into {len(mp4_targets)} eligible MP4 containers (workers={workers})...")
    tagged_count = 0

    def _worker(item: Dict[str, Any]) -> bool:
        fpath = item["file_path"]
        norm = to_extended_path(fpath)
        if not os.path.exists(norm):
            return False

        tag_dict = {
            "title": item.get("detected_title"),
            "artist": item.get("detected_artist"),
            "studio": item.get("detected_studio"),
            "date": item.get("detected_date"),
        }
        res = tag_media_file(norm, tag_dict)
        return res.get("tagged", False)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for idx, ok in enumerate(executor.map(_worker, mp4_targets), 1):
            if ok:
                tagged_count += 1
            if idx % 100 == 0 or idx == len(mp4_targets):
                print(f"[PROGRESS] Tagged {idx}/{len(mp4_targets)} MP4 files ({idx * 100.0 / len(mp4_targets):.1f}%)")

    return tagged_count


def print_summary_dashboard(results: List[Dict[str, Any]]) -> None:
    total = len(results) if results else 1
    with_artist = sum(1 for r in results if r.get("detected_artist"))
    with_studio = sum(1 for r in results if r.get("detected_studio"))
    with_title = sum(1 for r in results if r.get("detected_title"))
    high_conf = sum(1 for r in results if r.get("confidence", 0.0) >= 0.85)

    method_counts: Dict[str, int] = {}
    for r in results:
        m = r.get("method", "none")
        method_counts[m] = method_counts.get(m, 0) + 1

    artist_counts: Dict[str, int] = {}
    for r in results:
        a = r.get("detected_artist")
        if a:
            artist_counts[a] = artist_counts.get(a, 0) + 1

    print("\n" + "=" * 70)
    print("         CELEBRITIES PERFORMER & METADATA TAGGING SUMMARY")
    print("=" * 70)
    print(f"Total Evaluated Assets:       {len(results):,}")
    print(f"Performers Recognized:        {with_artist:,} ({with_artist * 100.0 / total:.1f}%)")
    print(f"Studios Recognized:           {with_studio:,} ({with_studio * 100.0 / total:.1f}%)")
    print(f"Titles Cleaned:               {with_title:,} ({with_title * 100.0 / total:.1f}%)")
    print(f"High Confidence (>=0.85):     {high_conf:,} ({high_conf * 100.0 / total:.1f}%)")
    print("-" * 70)
    print("Entity Recognition Breakdown by Method:")
    for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {method:<24}: {count:>4,} assets")
    print("-" * 70)
    print("Top Recognized Performers:")
    for artist, count in sorted(artist_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"  - {artist:<24}: {count:>4,} assets")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Performer Entity Recognition & Metadata Tagging for Celebrities Pool"
    )
    parser.add_argument(
        "--target-dir",
        default=DEFAULT_TARGET_DIR,
        help=f"Target directory for Celebrities pool (default: {DEFAULT_TARGET_DIR})",
    )
    parser.add_argument(
        "--db-path",
        default=DEFAULT_DB_PATH,
        help=f"Path to media_inventory.db (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_REPORT,
        help=f"Path for output JSON preview report (default: {DEFAULT_OUTPUT_REPORT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate metadata recognition without modifying database or files",
    )
    parser.add_argument(
        "--sync-db",
        action="store_true",
        help="Synchronize recognized performers, titles, and studios into media_inventory.db",
    )
    parser.add_argument(
        "--tag-containers",
        action="store_true",
        help="Losslessly inject QuickTime tags into MP4 video containers with timestamp preservation",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Worker thread concurrency for container tagging (default: 4)",
    )

    args = parser.parse_args()

    results = analyze_celebrities_pool(args.db_path, args.target_dir)
    print_summary_dashboard(results)

    # Export preview report
    report_payload = {
        "generated_at": datetime.now().isoformat(),
        "target_dir": args.target_dir,
        "database_path": args.db_path,
        "summary": {
            "total_assets": len(results),
            "performers_recognized": sum(1 for r in results if r.get("detected_artist")),
            "studios_recognized": sum(1 for r in results if r.get("detected_studio")),
            "titles_cleaned": sum(1 for r in results if r.get("detected_title")),
            "high_confidence_count": sum(1 for r in results if r.get("confidence", 0.0) >= 0.85),
        },
        "records": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)
    print(f"[REPORT] Written preview audit report to '{args.output}'.")

    if args.dry_run:
        print("[INFO] Dry-run active: Database synchronization and container tagging skipped.")
        return

    if args.sync_db:
        print(f"\n[SYNC] Synchronizing metadata into '{args.db_path}'...")
        updated_records, updated_artists = sync_to_database(args.db_path, results)
        print(f"[COMPLETE] Updated {updated_records} records in media_inventory.db ({updated_artists} with performers).")

    if args.tag_containers:
        print(f"\n[TAG] Injecting container tags into MP4 files...")
        tagged = tag_mp4_containers(results, workers=args.workers)
        print(f"[COMPLETE] Losslessly tagged {tagged} MP4 video containers.")


if __name__ == "__main__":
    main()
