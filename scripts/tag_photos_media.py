#!/usr/bin/env python3
"""Performer entity recognition, thematic classification, and deduplication for Photos & Sets on Aloha.

Attributes celebrity stars and models, classifies thematic image galleries, verifies
perceptual duplicate integrity, synchronizes media_inventory.db, and preserves original
filesystem modification timestamps (mtime).
"""

import os
import re
import sys
import json
import time
import shutil
import sqlite3
import argparse
from datetime import datetime
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

DEFAULT_TARGET_DIR = r"F:\Aloha\Photos & Sets"
DEFAULT_DB_PATH = os.path.join(REPO_ROOT, "media_inventory.db")
DEFAULT_OUTPUT_REPORT = os.path.join(REPO_ROOT, "photos_tagging_preview.json")
DEFAULT_DEDUP_REPORT = os.path.join(REPO_ROOT, "photos_deduplication_audit.json")

# Dedicated performer / set folder direct mappings
FOLDER_DIRECT_MAP: Dict[str, Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]] = {
    # folder_key: (artist, studio, title, date)
    "Stella Cox - Force Awakens": (
        "Stella Cox",
        "Digital Playground",
        "Star Wars: The Force Awakens A Parody - Image Set",
        "2016-04-18",
    ),
    "Kate Beckinsale": ("Kate Beckinsale", None, None, None),
    "Keira Knightley": ("Keira Knightley", None, None, None),
    "Keira": ("Keira Knightley", None, None, None),
    "Elisha Cuthbert": ("Elisha Cuthbert", None, None, None),
    "Krista Allen (emannuelle)": ("Krista Allen", None, "Emmanuelle Photo Gallery", None),
    "Adriana Lima]": ("Adriana Lima", None, None, None),
    "Jessica Biel": ("Jessica Biel", None, None, None),
    "Asia Argento": ("Asia Argento", None, None, None),
    "Lina Sakka": ("Lina Sakka", None, None, None),
    "Brook Burke": ("Brooke Burke", None, None, None),
    "Kristin Kreyk": ("Kristin Kreuk", None, None, None),
    "Eva Longoria": ("Eva Longoria", None, None, None),
    "Tawnee Stone": ("Tawnee Stone", None, None, None),
    "Britney": ("Britney Spears", None, None, None),
    "Eva Mendes": ("Eva Mendes", None, None, None),
    "Cameron Diaz": ("Cameron Diaz", None, None, None),
    "Lindsey": ("Lindsay Lohan", None, None, None),
    "Zhang Ziyi": ("Zhang Ziyi", None, None, None),
    "Greek Models": ("Christina Koletsa", None, "Christina Koletsa Photo Set", None),
}

# Subfolder specific studio / set mappings
SUBFOLDER_SETS: Dict[str, Tuple[str, str, str]] = {
    # subfolder_key: (artist, studio, title)
    "Vixen Ellie Eilish Treat Me Right": ("Ellie Eilish", "Vixen", "Treat Me Right - Photo Set"),
    "Vixen Gabbie Carter Take a Chance": ("Gabbie Carter", "Vixen", "Take a Chance - Photo Set"),
}

# Thematic gallery folders mapping to structured compilations
THEMATIC_GALLERIES: Dict[str, Tuple[str, str]] = {
    # folder_name: (studio, default_category)
    "Sexy Avatars": ("Sexy Avatars", "Avatars & Wallpapers"),
    "Kocicky Babes": ("Kocicky Babes", "Erotic Babes Gallery"),
    "Exotic": ("Exotic Gallery", "Exotic Models"),
    "Nude(ipod Ready)": ("Nude iPod Ready", "Mobile Wallpapers"),
    "GIFs": ("GIFs Gallery", "Animated Media"),
    "My Love": ("My Love Gallery", "Glamour & Erotica"),
    "Best": ("Best Compilations", "Curated Highlights"),
    "Np": ("Np Art Gallery", "Fine Art Photography"),
    "Ass Amateur": ("Amateur Collections", "Amateur Photography"),
    "Amateur": ("Amateur Collections", "Amateur Photography"),
    "Lesbians": ("Lesbian Collections", "Lesbian Erotica"),
    "Strip Poker": ("Strip Poker Sets", "Strip Poker Photography"),
    "Play": ("Play Gallery", "Playboy & Glamour"),
    "Play2": ("Play Gallery", "Playboy & Glamour"),
    "Play Various": ("Play Gallery", "Playboy & Glamour"),
    "Models Pornstars": ("Models & Pornstars", "Adult Models & Stars"),
}

# Explicit entity extraction patterns from filenames
ENTITY_PATTERNS: List[Tuple[str, str, Optional[str]]] = [
    # (regex_pattern, canonical_performer, studio)
    (r"Angelina\s*Jolie", "Angelina Jolie", None),
    (r"Alyssa\s*Milano", "Alyssa Milano", None),
    (r"Ashley\s*Judd", "Ashley Judd", None),
    (r"Salma\s*Hayek", "Salma Hayek", None),
    (r"Catherine\s*Bell", "Catherine Bell", None),
    (r"Catherine\s*Zeta\s*Jones", "Catherine Zeta-Jones", None),
    (r"Charisma\s*Carpenter", "Charisma Carpenter", None),
    (r"Mary\s*Kate\s*(?:and|&)\s*Ashley\s*Olsen", "Mary-Kate Olsen, Ashley Olsen", None),
    (r"Alizee", "Aliz\u00e9e", None),
    (r"Gwen\s*Stefani", "Gwen Stefani", None),
    (r"Christina\s*Aguilera|Cristina\s*Aguilera", "Christina Aguilera", None),
    (r"Danii\s*Minogue|Dannii\s*Minogue", "Dannii Minogue", None),
    (r"Kylie\s*Minogue", "Kylie Minogue", None),
    (r"Avril\s*Lavigne", "Avril Lavigne", None),
    (r"Anna\s*Nicole\s*Smith", "Anna Nicole Smith", None),
    (r"Carmen\s*Electra", "Carmen Electra", None),
    (r"Tiffany\s*Taylor", "Tiffany Taylor", None),
    (r"Daniela\s*Pestova", "Daniela Pestova", None),
    (r"Elle\s*(?:mc\s*pherson|macpherson)", "Elle Macpherson", None),
    (r"Estella\s*Warren", "Estella Warren", None),
    (r"Heidi\s*Klum", "Heidi Klum", None),
    (r"Gisele\s*B[u\u00fc]ndchen", "Gisele B\u00fcndchen", None),
    (r"Tyra\s*Banks", "Tyra Banks", None),
    (r"Cindy\s*Crawford", "Cindy Crawford", None),
    (r"Alison\s*Doody|Alisondoody", "Alison Doody", None),
    (r"Angie\s*Chong|Angiechong", "Angie Cheung", None),
    (r"Barbara\s*Gehring|Barbaragehring", "Barbara Gehring", None),
    (r"Beth\s*Hyatt|Bethhyatt", "Beth Hyatt", None),
    (r"Lindsay\s*Lohan", "Lindsay Lohan", None),
    (r"Jodi\s*Albert", "Jodi Albert", None),
    (r"Claudia\s*Romani", "Claudia Romani", "IGN"),
    (r"Ellie\s*Eilish", "Ellie Eilish", "Vixen"),
    (r"Gabbie\s*Carter", "Gabbie Carter", "Vixen"),
    (r"Dimitra\s*Matsouka|Dimitramatsouka", "Dimitra Matsouka", None),
    (r"Aleka\s*Kamila|Alekakamila", "Aleka Kamila", None),
    (r"Elina\s*Kantza|Elinakantza", "Elina Kantza", None),
    (r"Giagkousi", "Litsa Giagkousi", None),
    (r"Vana\s*Barba|Vanabarba", "Vana Barba", None),
    (r"Katerina\s*Stikoudi", "Katerina Stikoudi", None),
    (r"Olga\s*Farmaki", "Olga Farmaki", None),
    (r"Julia\s*Alexandratou", "Julia Alexandratou", None),
    (r"Anna\s*Kournikova", "Anna Kournikova", None),
    (r"Paris\s*Hilton", "Paris Hilton", None),
    (r"Kate\s*Moss", "Kate Moss", None),
    (r"Scarlett?\s*Johansson", "Scarlett Johansson", None),
    (r"Charlize\s*Theron", "Charlize Theron", None),
    (r"Jennifer\s*Aniston", "Jennifer Aniston", None),
    (r"Jennifer\s*Lopez", "Jennifer Lopez", None),
    (r"Jessica\s*Alba", "Jessica Alba", None),
    (r"Monica\s*Bellucci", "Monica Bellucci", None),
    (r"Penelope\s*Cruz", "Pen\u00e9lope Cruz", None),
    (r"Halle\s*Berry", "Halle Berry", None),
    (r"Beyonce", "Beyonc\u00e9", None),
    (r"Shakira", "Shakira", None),
    (r"Pamela\s*Anderson", "Pamela Anderson", None),
    (r"Denise\s*Richards", "Denise Richards", None),
    (r"Hilary\s*Duff", "Hilary Duff", None),
    (r"Mila\s*Kunis", "Mila Kunis", None),
    (r"Megan\s*Fox", "Megan Fox", None),
    (r"Natalie\s*Portman", "Natalie Portman", None),
    (r"Tara\s*Reid", "Tara Reid", None),
    (r"Kelly\s*Brook", "Kelly Brook", None),
    (r"Keeley\s*Hazell", "Keeley Hazell", None),
    (r"Gemma\s*Atkinson", "Gemma Atkinson", None),
    (r"Lucy\s*Pinder", "Lucy Pinder", None),
    (r"Christina\s*Koletsa|\u03a7\u03c1\u03b9\u03c3\u03c4\u03b9\u03bd\u03b1\s*\u039a\u03bf\u03bb\u03b5\u03c4\u03c3\u03b1", "Christina Koletsa", None),
]


def clean_photo_title(raw_filename: str) -> str:
    """Normalizes raw photo filename into clean, readable asset title."""
    stem = os.path.splitext(raw_filename)[0]

    # Decode URL percent-encodings
    stem = stem.replace("%5b", "[").replace("%5d", "]").replace("%20", " ")

    # Strip bracketed dates e.g. [2016-04-18] or [2008-09-02]
    stem = re.sub(r"^\[\d{4}-\d{2}-\d{2}\]\s*", "", stem)

    # Strip bracketed studio markers at start
    stem = re.sub(r"^\[(?:Digital Playground|Vixen)\]\s*", "", stem, flags=re.IGNORECASE)

    # Strip common redundant folder prefixes like "Sexy Avatars - "
    stem = re.sub(r"^(?:Sexy Avatars|Kocicky Babes|Exotic|Nude\(ipod Ready\)|Guns|Actors|Singers|Top Models|Greek Stars|Scarlet|Lindsey|Amateur|Ass Amateur|Np|Best|Play2|Play Various|Play)\s*-\s*", "", stem, flags=re.IGNORECASE)

    # Strip duplicate number markers like (1), (2)
    stem = re.sub(r"\s*\(\d+\)", "", stem)

    # Strip technical image size / camera noise
    stem = re.sub(r"\b\d+x\d+\s*Wallpaper\b", "Wallpaper", stem, flags=re.IGNORECASE)

    # Clean multi-space
    stem = re.sub(r"\s+", " ", stem).strip()
    return stem if stem else raw_filename


def parse_photo_asset(
    file_path: str,
    filename: str,
    directory: str,
    media_type: str = "image",
    existing_artist: Optional[str] = None,
    existing_title: Optional[str] = None,
    existing_studio: Optional[str] = None,
) -> Dict[str, Any]:
    """Applies hierarchical deterministic rules to classify photo asset."""
    norm_path = file_path.replace("/", "\\")
    norm_dir = directory.replace("/", "\\")
    dir_parts = [p for p in norm_dir.split("\\") if p]

    # Identify top folder within Photos & Sets
    top_folder = ""
    for idx, part in enumerate(dir_parts):
        if part.lower() == "photos & sets" and idx + 1 < len(dir_parts):
            top_folder = dir_parts[idx + 1]
            break

    detected_artist = existing_artist
    detected_studio = existing_studio
    detected_title = clean_photo_title(filename)
    detected_date: Optional[str] = None
    confidence = 0.50
    method = "unrecognized"

    # Extract date from bracket if present
    date_match = re.search(r"\[(\d{4}-\d{2}-\d{2})\]", filename)
    if date_match:
        detected_date = date_match.group(1)

    # Rule 1: Subfolder set mappings (e.g. Vixen Sets)
    for sub_key, (s_artist, s_studio, s_title) in SUBFOLDER_SETS.items():
        if sub_key.lower() in norm_path.lower():
            detected_artist = s_artist
            detected_studio = s_studio
            detected_title = s_title
            confidence = 0.98
            method = "subfolder_vixen_set"
            break

    # Rule 2: Dedicated star / model folders
    if method == "unrecognized" and top_folder:
        for f_key, (f_artist, f_studio, f_title, f_date) in FOLDER_DIRECT_MAP.items():
            if f_key.lower() == top_folder.lower():
                if f_artist:
                    detected_artist = f_artist
                if f_studio:
                    detected_studio = f_studio
                if f_title and not detected_title:
                    detected_title = f_title
                if f_date and not detected_date:
                    detected_date = f_date
                confidence = 0.98
                method = "folder_direct_performer"
                break

    # Rule 3: Entity detection from filename (for multi-performer galleries)
    if not detected_artist or method == "unrecognized":
        for pat, ent_name, ent_studio in ENTITY_PATTERNS:
            if re.search(pat, filename, re.IGNORECASE):
                detected_artist = ent_name
                if ent_studio and not detected_studio:
                    detected_studio = ent_studio
                confidence = 0.95
                method = "filename_entity_match"
                break

    # Rule 4: Dedicated Greek Stars gallery resolution
    if method == "unrecognized" and top_folder.lower() == "greek stars":
        if not detected_artist:
            detected_artist = "Compilation"
            detected_studio = "Greek Stars"
            confidence = 0.88
            method = "thematic_greek_stars_compilation"

    # Rule 5: IGN gallery resolution
    if method == "unrecognized" and top_folder.lower() == "ign":
        if not detected_artist:
            detected_artist = "Compilation"
        detected_studio = "IGN"
        confidence = 0.88
        method = "thematic_ign_compilation"

    # Rule 6: Guns gallery resolution
    if method == "unrecognized" and top_folder.lower() == "guns":
        if not detected_artist:
            detected_artist = "Compilation"
        detected_studio = "Guns Gallery"
        confidence = 0.88
        method = "thematic_guns_compilation"

    # Rule 7: Actors, Singers, Top Models, Scarlet, Famous fallback compilations
    if method == "unrecognized" and top_folder.lower() in ("actors", "singers", "top models", "scarlet", "famous"):
        if not detected_artist:
            detected_artist = "Compilation"
        detected_studio = f"{top_folder.title()} Gallery"
        confidence = 0.88
        method = f"thematic_{top_folder.lower().replace(' ', '_')}_compilation"

    # Rule 8: Thematic albums and curated compilations
    if method == "unrecognized" and top_folder:
        for t_folder, (t_studio, t_desc) in THEMATIC_GALLERIES.items():
            if t_folder.lower() == top_folder.lower():
                if not detected_artist:
                    detected_artist = "Compilation"
                if not detected_studio:
                    detected_studio = t_studio
                confidence = 0.90
                method = "thematic_gallery_compilation"
                break

    # Rule 9: New Folder variants and loose root photos
    if method == "unrecognized" and ("new folder" in top_folder.lower() or top_folder in ("", ".", "Loose Photos", "photos & sets")):
        if detected_artist:
            confidence = 0.90
            method = "residual_entity_attributed"
        else:
            detected_artist = "Compilation"
            detected_studio = "Loose Photos" if not top_folder else "Miscellaneous Sets"
            confidence = 0.60
            method = "residual_unattributed"

    # Fallback review flag
    needs_review = 0 if confidence >= 0.85 else 1

    return {
        "file_path": file_path,
        "filename": filename,
        "directory": directory,
        "media_type": media_type,
        "detected_artist": detected_artist,
        "detected_title": detected_title,
        "detected_studio": detected_studio,
        "detected_date": detected_date,
        "confidence": confidence,
        "needs_review": needs_review,
        "method": method,
    }


def analyze_photos_pool(db_path: str, target_dir: str = DEFAULT_TARGET_DIR) -> List[Dict[str, Any]]:
    """Loads all Photos & Sets assets from SQLite and executes entity recognition."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found at '{db_path}'")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, file_path, directory, filename, media_type, file_size,
               existing_artist, existing_title, studio, confidence_score, needs_review
        FROM media_files
        WHERE file_path LIKE '%Photos & Sets%'
        ORDER BY id ASC
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    results: List[Dict[str, Any]] = []
    for row in rows:
        parsed = parse_photo_asset(
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
    # Pre-flight safety snapshot
    backup_path = db_path.replace(".db", "_pre_photos_tagging.bak")
    if not os.path.exists(backup_path):
        shutil.copy2(db_path, backup_path)
        print(f"[SAFETY] Created atomic pre-tagging backup at '{backup_path}'.")

    conn = sqlite3.connect(db_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    updated_records = 0
    updated_artists = 0

    with conn:
        for r in results:
            artist = r.get("detected_artist")
            title = r.get("detected_title")
            studio = r.get("detected_studio")
            date = r.get("detected_date")
            conf = r.get("confidence", 0.0)
            rec_id = r["id"]
            needs_review = r.get("needs_review", 0)

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

            if cur.rowcount > 0:
                updated_records += 1
                if artist:
                    updated_artists += 1

    conn.close()
    return updated_records, updated_artists


def run_dedup_audit(
    db_path: str,
    target_dir: str = DEFAULT_TARGET_DIR,
    output_path: str = DEFAULT_DEDUP_REPORT,
) -> Dict[str, Any]:
    """Runs SHA-256 byte scan and perceptual hash check to certify 0 duplicates in pool."""
    print("[DEDUP AUDIT] Scanning Photos & Sets for byte-level and perceptual duplicates...")
    import hashlib
    from PIL import Image
    import imagehash

    records: List[Tuple[int, str]] = []
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, file_path FROM media_files WHERE file_path LIKE '%Photos & Sets%'")
    rows = cursor.fetchall()
    conn.close()

    exact_hashes: Dict[str, List[str]] = {}
    phashes: Dict[str, List[str]] = {}
    total_scanned = 0

    for rec_id, fpath in rows:
        norm = to_extended_path(fpath)
        if not os.path.exists(norm):
            continue
        total_scanned += 1

        # Fast SHA-256
        try:
            with open(norm, "rb") as fh:
                shash = hashlib.sha256(fh.read()).hexdigest()
            if shash not in exact_hashes:
                exact_hashes[shash] = []
            exact_hashes[shash].append(fpath)
        except OSError:
            pass

        # Perceptual hash for images
        ext = os.path.splitext(fpath)[1].lower()
        if ext in (".jpg", ".jpeg", ".png", ".bmp"):
            try:
                with Image.open(norm) as img:
                    ph = str(imagehash.phash(img))
                if ph not in phashes:
                    phashes[ph] = []
                phashes[ph].append(fpath)
            except Exception:
                pass

    exact_dups = {k: v for k, v in exact_hashes.items() if len(v) > 1}
    phash_dups = {k: v for k, v in phashes.items() if len(v) > 1}

    audit_result = {
        "audit_timestamp": datetime.now().isoformat(),
        "target_pool": "Photos & Sets",
        "target_dir": target_dir,
        "total_assets_scanned": total_scanned,
        "unique_sha256_digests": len(exact_hashes),
        "exact_duplicate_clusters": len(exact_dups),
        "perceptual_hash_clusters": len(phash_dups),
        "status": "CERTIFIED_CLEAN" if len(exact_dups) == 0 and len(phash_dups) == 0 else "ACTION_REQUIRED",
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(audit_result, f, indent=2)

    print(f"[DEDUP AUDIT] Completed: {audit_result['total_assets_scanned']} assets evaluated.")
    print(f"[DEDUP AUDIT] Exact duplicate clusters: {audit_result['exact_duplicate_clusters']}")
    print(f"[DEDUP AUDIT] Perceptual hash clusters: {audit_result['perceptual_hash_clusters']}")
    print(f"[DEDUP AUDIT] Audit status: {audit_result['status']} -> exported to '{output_path}'")
    return audit_result


def print_summary_dashboard(results: List[Dict[str, Any]]) -> None:
    total = len(results) if results else 1
    with_artist = sum(1 for r in results if r.get("detected_artist"))
    with_studio = sum(1 for r in results if r.get("detected_studio"))
    with_title = sum(1 for r in results if r.get("detected_title"))
    high_conf = sum(1 for r in results if r.get("confidence", 0.0) >= 0.85)
    needs_review = sum(1 for r in results if r.get("needs_review") == 1)

    method_counts: Dict[str, int] = {}
    for r in results:
        m = r.get("method", "none")
        method_counts[m] = method_counts.get(m, 0) + 1

    artist_counts: Dict[str, int] = {}
    for r in results:
        a = r.get("detected_artist")
        if a:
            artist_counts[a] = artist_counts.get(a, 0) + 1

    studio_counts: Dict[str, int] = {}
    for r in results:
        s = r.get("detected_studio")
        if s:
            studio_counts[s] = studio_counts.get(s, 0) + 1

    print("\n" + "=" * 70)
    print("         PHOTOS & SETS PERFORMER & METADATA TAGGING SUMMARY")
    print("=" * 70)
    print(f"Total Evaluated Assets:       {len(results):,}")
    print(f"Performers Recognized:        {with_artist:,} ({with_artist * 100.0 / total:.1f}%)")
    print(f"Studios Recognized:           {with_studio:,} ({with_studio * 100.0 / total:.1f}%)")
    print(f"Titles Cleaned:               {with_title:,} ({with_title * 100.0 / total:.1f}%)")
    print(f"High Confidence (>=0.85):     {high_conf:,} ({high_conf * 100.0 / total:.1f}%)")
    print(f"Needs Review Flag:            {needs_review:,} ({needs_review * 100.0 / total:.1f}%)")
    print("-" * 70)
    print("Entity Recognition Breakdown by Method:")
    for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {method:<35}: {count:>4,} assets")
    print("-" * 70)
    print("Top Recognized Performers / Categories:")
    for artist, count in sorted(artist_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"  - {artist:<35}: {count:>4,} assets")
    print("-" * 70)
    print("Top Recognized Studios / Galleries:")
    for studio, count in sorted(studio_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"  - {studio:<35}: {count:>4,} assets")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Performer Entity Recognition & Perceptual Deduplication for Photos & Sets"
    )
    parser.add_argument(
        "--target-dir",
        default=DEFAULT_TARGET_DIR,
        help=f"Target directory for Photos & Sets pool (default: {DEFAULT_TARGET_DIR})",
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
        "--dedup-report",
        default=DEFAULT_DEDUP_REPORT,
        help=f"Path for output deduplication audit report (default: {DEFAULT_DEDUP_REPORT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate metadata recognition without modifying database",
    )
    parser.add_argument(
        "--sync-db",
        action="store_true",
        help="Synchronize recognized performers, titles, and studios into media_inventory.db",
    )
    parser.add_argument(
        "--audit-dedup",
        action="store_true",
        help="Execute deduplication audit certifying duplicate cleanliness",
    )

    args = parser.parse_args()

    # Run deduplication audit if requested
    if args.audit_dedup:
        run_dedup_audit(args.db_path, args.target_dir, args.dedup_report)

    results = analyze_photos_pool(args.db_path, args.target_dir)
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
            "needs_review_count": sum(1 for r in results if r.get("needs_review") == 1),
        },
        "records": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)
    print(f"[REPORT] Written preview audit report to '{args.output}'.")

    if args.dry_run:
        print("[INFO] Dry-run active: Database synchronization skipped.")
        return

    if args.sync_db:
        print(f"\n[SYNC] Synchronizing metadata into '{args.db_path}'...")
        updated_records, updated_artists = sync_to_database(args.db_path, results)
        print(f"[COMPLETE] Updated {updated_records} records in media_inventory.db ({updated_artists} with performers).")


if __name__ == "__main__":
    main()
