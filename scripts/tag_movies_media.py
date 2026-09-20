#!/usr/bin/env python3
"""
tag_movies_media.py

Deterministic performer entity recognition, studio attribution, title
normalization, and lossless MP4 container tagging across the Movies media pool
on F:\\Aloha.

Synchronizes metadata into media_inventory.db and losslessly injects QuickTime
iTunes atoms (©ART, ©nam, ©cmt, ©day) into compatible MP4 media assets while
strictly preserving original file modification timestamps (mtime).
"""

import os
import sys
import re
import stat
import time
import json
import sqlite3
import argparse
from typing import Dict, Any, List, Optional, Tuple

try:
    from mutagen.mp4 import MP4
except ImportError:
    MP4 = None

from visual_metadata_extractor import KNOWN_PERFORMERS

DEFAULT_DB_PATH = r"E:\repos\projects\storage-strategist\media_inventory.db"
DEFAULT_TARGET_DIR = r"F:\Aloha\Movies"

# DPG Release Code to Title & Performer Map
DPG_CODE_MAP = {
    "teachrs": ("Teachers", "Digital Playground", None),
    "jjatmictease": ("Jesse Jane: Atomic Tease", "Digital Playground", "Jesse Jane"),
    "nrses": ("Nurses", "Digital Playground", None),
    "flygrls": ("Fly Girls", "Digital Playground", None),
    "cheerleadrs": ("Cheerleaders", "Digital Playground", None),
    "babysttrs": ("Babysitters", "Digital Playground", None),
    "jjplyful": ("Jesse Jane: Playful", "Digital Playground", "Jesse Jane"),
    "intoxicatd": ("Intoxicated", "Digital Playground", None),
    "jjhomewrk": ("Jesse Jane: Homework", "Digital Playground", "Jesse Jane"),
}

# Greek Movie Title Normalization Map
GREEK_TITLE_MAP = {
    "show bitch": ("Show Bitch", "Sirina Productions", None),
    "sirina agrotisa": ("Sirina: Agrotisa", "Sirina Productions", None),
    "gatakia parte to": ("Gatakia Parte To", "Sirina Productions", None),
    "το παλαμάρι του βαρκάρη": ("Το Παλαμάρι Του Βαρκάρη", "Greek Erotica", None),
    "classic greek kayto sex stin ammo": ("Καυτό Σεξ Στην Άμμο", "Greek Erotica", None),
    "tzoulia": ("Tzoulia Alexandratou Full Movie", "Sirina Productions", "Julia Alexandratou"),
    "sirina next porn model 2 greek gousgounis": ("Sirina Next Porn Model 2", "Sirina Productions", None),
    "sex in the city of athens dvd": ("Sex in the City of Athens", "Sirina Productions", None),
    "this is mykonos greece 2009 homevideo hdxt": ("This Is Mykonos Greece 2009", "Greek Erotica", None),
}


def clean_movie_title(raw_title: str) -> str:
    """Strips technical resolutions, codecs, scene noise, and extensions from movie titles."""
    title = os.path.splitext(raw_title)[0]

    # Remove leading release tags and sites
    title = re.sub(r"^(?:\[www\s*porn\s*18\s*net\]|www\s*porn\s*18\s*net)\s*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"^(?:dnz|xnetporn\s*com)\s*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"^\[(?:orgasms\.xxx|living sex toy delivery|wicked fairy tales\]\s*peter pan xxx)\]\s*", "", title, flags=re.IGNORECASE)

    # Remove trailing bracketed codec / resolution info
    title = re.sub(r"\s*\[(?:1080p|720p|480p|540p|360p|2160p|4k|hd|sd)?\s*(?:h264|x264|av1|hevc|x265|mpeg4|mpeg2video|mpeg1video)?\]", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s*\[(?:hd720p|hd1080p)\]", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s*\[(?:eng\s*subs?|eng\s*dub|cen|uncen|disney)\]", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s*\[(?:av1|h264|hevc)\]", "", title, flags=re.IGNORECASE)

    # Remove file size indicators like 716mb, 762mb
    title = re.sub(r"\b\d{3,4}mb\b", "", title, flags=re.IGNORECASE)

    # Remove release group tags
    title = re.sub(r"\b(?:xvid|dvdrip|bluray|dpxxxhd|pornolation|sweet6rus)\b", "", title, flags=re.IGNORECASE)

    # Normalize underscores and hyphens
    title = title.replace("_", " ")
    title = re.sub(r"\s*-\s*", " - ", title)
    title = re.sub(r"\s+", " ", title).strip()

    if title.islower():
        title = title.title()

    return title


def parse_movie_media(
    file_path: str,
    filename: str,
    directory: str,
    media_type: str,
    existing_artist: Optional[str] = None,
    existing_title: Optional[str] = None,
    existing_studio: Optional[str] = None,
    existing_date: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parses performer entity, canonical studio, clean movie title, and release date
    from file attributes within the Movies pool.
    """
    detected_artist = existing_artist
    detected_studio = existing_studio
    detected_title = existing_title
    detected_date = existing_date
    confidence = 0.50

    rel_dir = directory.replace("F:\\Aloha\\Movies", "").replace("F:/Aloha/Movies", "")
    if rel_dir.startswith("\\") or rel_dir.startswith("/"):
        rel_dir = rel_dir[1:]
    top_sub = rel_dir.split("\\")[0].split("/")[0].lower() if rel_dir else ""
    filename_lower = filename.lower()

    # Rule A: Digital Playground DPG Releases in New folder
    if "new folder" in top_sub or "dpg" in filename_lower:
        detected_studio = "Digital Playground"
        confidence = 0.95

        # Check CD part
        m_cd = re.search(r"cd\s*(\d+)", filename_lower)
        cd_str = f" CD{m_cd.group(1)}" if m_cd else ""

        matched = False
        for code, (clean_name, studio_name, star_name) in DPG_CODE_MAP.items():
            if code in filename_lower:
                detected_title = f"{clean_name}{cd_str}"
                if star_name:
                    detected_artist = star_name
                matched = True
                break

        if not matched:
            detected_title = f"{clean_movie_title(filename)}{cd_str}"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule B: Pirates Franchise (Digital Playground)
    if "pirates" in top_sub or "pirates" in filename_lower:
        detected_studio = "Digital Playground"
        confidence = 0.98

        if "pirates2" in filename_lower or "pirates 2" in filename_lower or "stagnettisrevenge" in filename_lower:
            detected_title = "Pirates II: Stagnetti's Revenge (2008)"
            detected_artist = "Jesse Jane, Belladonna, Stoya"
            detected_date = "2008"
        elif "vts" in filename_lower:
            m_vts = re.search(r"vts\s*01\s*(\d+)", filename_lower)
            part_num = m_vts.group(1) if m_vts else "1"
            detected_title = f"Pirates (2005) DVD Part {part_num}"
            detected_artist = "Jesse Jane, Carmen Luvana, Janine Lindemulder"
            detected_date = "2005"
        else:
            m_cd = re.search(r"cd\s*(\d+)", filename_lower)
            cd_str = f" CD{m_cd.group(1)}" if m_cd else ""
            detected_title = f"Pirates (2005){cd_str}"
            detected_artist = "Jesse Jane, Carmen Luvana, Janine Lindemulder"
            detected_date = "2005"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule C: Stoya Releases (Video Nasty & Love and Other Mishaps)
    if "stoya video nasty" in top_sub or "video nasty" in filename_lower:
        detected_artist = "Stoya"
        detected_studio = "Digital Playground"
        detected_date = "2008"
        confidence = 0.98

        m_vts = re.search(r"vts\s*(\d+)\s*(\d+)", filename_lower)
        if m_vts:
            detected_title = f"Stoya: Video Nasty (2008) Title {m_vts.group(1)} Part {m_vts.group(2)}"
        else:
            clean = clean_movie_title(filename)
            detected_title = f"Stoya: Video Nasty (2008) - {clean}"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    if "love and other mishaps" in filename_lower:
        detected_artist = "Stoya"
        detected_studio = "Digital Playground"
        detected_title = "Love and Other Mishaps"
        confidence = 0.95
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule D: Other Digital Playground feature films
    if "babysitters 2" in filename_lower:
        detected_studio = "Digital Playground"
        detected_artist = "Riley Steele, Jesse Jane"
        detected_title = "Babysitters 2 (2011)"
        detected_date = "2011"
        confidence = 0.98
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    if "the smiths" in filename_lower:
        detected_studio = "Digital Playground"
        detected_title = "The Smiths"
        confidence = 0.95
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    if "milflicious" in filename_lower:
        detected_studio = "Digital Playground"
        detected_title = "MILFlicious"
        confidence = 0.95
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule E: Wicked Fairy Tales Peter Pan XXX
    if "peter pan" in filename_lower or "wicked fairy tales" in top_sub:
        detected_studio = "Wicked Pictures"
        confidence = 0.95

        # Check featured stars in filename
        stars = []
        for s in ["Keira Nicole", "Riley Steele", "Aiden Ashley", "Mia Malkova", "Vicki Chase"]:
            if s.lower() in filename_lower:
                stars.append(s)

        if stars:
            detected_artist = ", ".join(stars)

        m_num = re.search(r"#\s*(\d+)", filename)
        scene_str = f" Scene {m_num.group(1)}" if m_num else ""
        detected_title = f"Wicked Fairy Tales: Peter Pan XXX{scene_str}"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule F: Parodies
    if "parodies" in top_sub or "a porn parody" in filename_lower:
        confidence = 0.95
        if "avengers" in filename_lower:
            detected_studio = "Vivid Entertainment"
            m_num = re.search(r"parody\s*(\d+)", filename_lower)
            part_str = f" Part {m_num.group(1)}" if m_num else " Part 1"
            detected_title = f"The Avengers: A XXX Porn Parody{part_str}"
        elif "friends" in filename_lower:
            detected_studio = "New Sensations"
            m_cd = re.search(r"cd\s*(\d+)", filename_lower)
            cd_str = f" CD{m_cd.group(1)}" if m_cd else ""
            detected_title = f"Friends: A XXX Porn Parody{cd_str}"
        else:
            detected_title = clean_movie_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule G: Private Features
    if "private" in top_sub or "[private]" in filename_lower:
        detected_studio = "Private"
        confidence = 0.95

        if "sexth element" in filename_lower:
            m_cd = re.search(r"cd\s*(\d+)", filename_lower)
            cd_str = f" CD{m_cd.group(1)}" if m_cd else ""
            detected_title = f"The Sexth Element (2008){cd_str}"
            detected_date = "2008"
        elif "italian milfs" in filename_lower or "swe6" in filename_lower:
            m_pt = re.search(r"imilfs([ab])", filename_lower)
            pt_str = f" Part {m_pt.group(1).upper()}" if m_pt else ""
            detected_title = f"Private Specials 34: Italian Milfs Mama Mia{pt_str}"
        else:
            detected_title = clean_movie_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule H: Deep Throat Classic Cinema
    if "deep throat" in top_sub or "deep throat" in filename_lower:
        detected_artist = "Linda Lovelace"
        detected_studio = "Bryanston Distributing"
        detected_date = "1972"
        confidence = 0.98

        if media_type == "image":
            clean = clean_movie_title(filename)
            detected_title = f"Deep Throat (1972) Screen - {clean}"
        else:
            detected_title = "Deep Throat (1972)"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule I: Greek Movies & Sirina Productions
    if any(k in top_sub for k in ["greek", "ελληνικο", "tzoulia", "ammo", "barkarh"]):
        confidence = 0.90
        detected_studio = "Sirina Productions"

        clean_lower = clean_movie_title(filename).lower()

        for g_pat, (g_title, g_studio, g_artist) in GREEK_TITLE_MAP.items():
            if g_pat in filename_lower or g_pat in clean_lower:
                detected_title = g_title
                detected_studio = g_studio
                if g_artist:
                    detected_artist = g_artist
                break

        if not detected_title:
            if "tzoulia" in filename_lower:
                detected_artist = "Julia Alexandratou"
                detected_title = "Tzoulia Alexandratou Full Movie"
            elif "katerina & eirini" in filename_lower:
                detected_artist = "Katerina, Eirini"
                detected_title = "Katerina & Eirini"
            elif "laoura" in filename_lower:
                detected_artist = "Laoura, Aris"
                detected_title = "Laoura Does Loutraki"
            else:
                detected_title = clean_movie_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule J: Night Shift Nurses & Anime
    if "night shift nurses" in top_sub or "night shift nurses" in filename_lower or "yakin byoutou" in filename_lower:
        detected_studio = "Vanilla"
        confidence = 0.92

        m_vol = re.search(r"vol\s*(\d+)", filename_lower)
        m_krk = re.search(r"kranke\s*(\d+)", filename_lower)
        if m_vol:
            detected_title = f"Night Shift Nurses 2: Vol {m_vol.group(1)}"
        elif m_krk:
            detected_title = f"Night Shift Nurses: Kranke {m_krk.group(1)}"
        else:
            detected_title = clean_movie_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule K: Pg 65 Sex Ang
    if "pg 65 sex ang" in top_sub:
        detected_studio = "Private"
        confidence = 0.90
        m_vts = re.search(r"vts\s*(\d+)\s*(\d+)", filename_lower)
        if m_vts:
            detected_title = f"Sex Angels DVD Title {m_vts.group(1)} Part {m_vts.group(2)}"
        else:
            detected_title = "Sex Angels DVD"
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule L: Performers of the Year
    if "performers of the year" in top_sub or "performers of the year" in filename_lower:
        detected_studio = "Pornolation"
        detected_date = "2010"
        confidence = 0.90
        m_disc = re.search(r"disc\s*(\d+)", filename_lower)
        m_cd = re.search(r"cd\s*(\d+)", filename_lower)
        disc_str = f" Disc {m_disc.group(1)}" if m_disc else ""
        cd_str = f" CD{m_cd.group(1)}" if m_cd else ""
        detected_title = f"Performers of the Year 2010{disc_str}{cd_str}"
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule M: Jiggly
    if "jiggly" in filename_lower or "fighters" in top_sub:
        detected_studio = "Jiggly"
        confidence = 0.92
        if "codeofhonor" in filename_lower or "code of honor" in filename_lower:
            detected_title = "Code of Honor"
        elif "fighters" in filename_lower or "fighters" in top_sub:
            m_cd = re.search(r"cd\s*(\d+)", filename_lower)
            cd_str = f" CD{m_cd.group(1)}" if m_cd else ""
            detected_title = f"Fighters{cd_str}"
        else:
            detected_title = clean_movie_title(filename)
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule N: Generic Star Extraction from KNOWN_PERFORMERS
    if not detected_artist:
        name_lower = filename.lower()
        matched_stars = []
        for star in KNOWN_PERFORMERS:
            pattern = r"(?<![a-zA-Z0-9])" + re.escape(star.lower()) + r"(?![a-zA-Z0-9])"
            if re.search(pattern, name_lower):
                matched_stars.append(star)

        if matched_stars:
            matched_stars.sort(key=len, reverse=True)
            primary = matched_stars[0]
            non_overlapping = [primary]
            for s in matched_stars[1:]:
                if not any(s in existing for existing in non_overlapping):
                    non_overlapping.append(s)
            detected_artist = ", ".join(non_overlapping[:2])
            confidence = 0.90

    # Fallback title and studio
    if not detected_title:
        detected_title = clean_movie_title(filename)

    if not detected_studio:
        detected_studio = "Feature Cinema"
        if confidence < 0.80:
            confidence = 0.80

    return {
        "detected_artist": detected_artist,
        "detected_studio": detected_studio,
        "detected_title": detected_title,
        "detected_date": detected_date,
        "confidence": confidence,
    }


def _tag_single_mp4(item: Dict[str, Any]) -> bool:
    """Losslessly injects QuickTime iTunes atoms into MP4 file preserving mtime."""
    if MP4 is None:
        return False

    file_path = item["file_path"]
    if not os.path.exists(file_path):
        return False

    try:
        stat_info = os.stat(file_path)
        orig_atime = stat_info.st_atime
        orig_mtime = stat_info.st_mtime

        mp4 = MP4(file_path)
        if mp4.tags is None:
            mp4.add_tags()

        changed = False

        artist_val = item.get("detected_artist")
        if artist_val:
            if mp4.tags.get("\xa9ART") != [artist_val]:
                mp4.tags["\xa9ART"] = [artist_val]
                changed = True

        title_val = item.get("detected_title")
        if title_val:
            if mp4.tags.get("\xa9nam") != [title_val]:
                mp4.tags["\xa9nam"] = [title_val]
                changed = True

        studio_val = item.get("detected_studio")
        if studio_val:
            if mp4.tags.get("\xa9cmt") != [studio_val]:
                mp4.tags["\xa9cmt"] = [studio_val]
                changed = True

        date_val = item.get("detected_date")
        if date_val:
            if mp4.tags.get("\xa9day") != [str(date_val)]:
                mp4.tags["\xa9day"] = [str(date_val)]
                changed = True

        if changed:
            mp4.save()
            os.utime(file_path, (orig_atime, orig_mtime))
            return True

        return False
    except Exception as err:
        print(f"[WARN] Failed to tag {file_path}: {err}", file=sys.stderr)
        return False


def sync_to_database(db_path: str, results: List[Dict[str, Any]]) -> Tuple[int, int, int]:
    """Updates media_files records in SQLite database."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    updated_records = 0
    updated_artists = 0
    updated_studios = 0

    for item in results:
        rec_id = item["id"]
        artist = item.get("detected_artist")
        studio = item.get("detected_studio")
        title = item.get("detected_title")
        date_val = item.get("detected_date")
        conf = item.get("confidence", 0.85)
        needs_review = 0 if conf >= 0.80 else 1

        c.execute("""
            UPDATE media_files
            SET existing_artist = ?,
                studio = ?,
                existing_title = ?,
                existing_date = COALESCE(?, existing_date),
                confidence_score = ?,
                needs_review = ?
            WHERE id = ?
        """, (artist, studio, title, date_val, conf, needs_review, rec_id))

        if c.rowcount > 0:
            updated_records += 1
            if artist:
                updated_artists += 1
            if studio:
                updated_studios += 1

    conn.commit()
    conn.close()
    return updated_records, updated_artists, updated_studios


def main():
    parser = argparse.ArgumentParser(description="Tag performer, studio, and movie title metadata across Movies.")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="Path to media_inventory.db")
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR, help="Target directory for Movies pool")
    parser.add_argument("--dry-run", action="store_true", help="Preview tags without writing to disk or database")
    parser.add_argument("--sync-db", action="store_true", help="Update database records with parsed metadata")
    parser.add_argument("--tag-containers", action="store_true", help="Losslessly write MP4 container metadata")
    parser.add_argument("--report", default="movies_tagging_preview.json", help="Path for JSON audit report")
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print(f"[ERROR] Database not found at {args.db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(args.db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT id, file_path, directory, filename, extension, media_type, file_size,
               existing_artist, existing_title, studio, existing_date, confidence_score, needs_review
        FROM media_files
        WHERE file_path LIKE ?
        ORDER BY file_path ASC
    """, (f"{args.target_dir}%",))

    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    print(f"Loaded {len(rows)} assets from {args.target_dir}")

    results = []
    tagged_performers = 0
    tagged_studios = 0

    for r in rows:
        parsed = parse_movie_media(
            file_path=r["file_path"],
            filename=r["filename"],
            directory=r["directory"],
            media_type=r["media_type"],
            existing_artist=r["existing_artist"],
            existing_title=r["existing_title"],
            existing_studio=r["studio"],
            existing_date=r["existing_date"],
        )

        item = {
            "id": r["id"],
            "file_path": r["file_path"],
            "filename": r["filename"],
            "directory": r["directory"],
            "media_type": r["media_type"],
            "extension": r["extension"],
            "file_size": r["file_size"],
            "orig_artist": r["existing_artist"],
            "orig_studio": r["studio"],
            "orig_title": r["existing_title"],
            "orig_date": r["existing_date"],
            **parsed,
        }

        results.append(item)
        if item.get("detected_artist"):
            tagged_performers += 1
        if item.get("detected_studio"):
            tagged_studios += 1

    print("\n" + "=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Total Evaluated Assets:     {len(results)}")
    print(f"Performer Attributions:     {tagged_performers} ({tagged_performers / len(results) * 100:.1f}%)")
    print(f"Studio Attributions:        {tagged_studios} ({tagged_studios / len(results) * 100:.1f}%)")
    print("=" * 60)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Audit preview report written to {args.report}")

    if args.sync_db:
        print("\nSynchronizing metadata to database...")
        up_rec, up_art, up_std = sync_to_database(args.db_path, results)
        print(f"Database sync complete: {up_rec} records updated ({up_art} artists, {up_std} studios).")

    if args.tag_containers:
        print("\nStarting lossless MP4 container tagging...")
        mp4_items = [item for item in results if item["extension"].lower() == ".mp4" and item["media_type"] == "video"]
        print(f"Found {len(mp4_items)} eligible MP4 video files.")

        tagged_count = 0
        skipped_count = 0

        for item in mp4_items:
            changed = _tag_single_mp4(item)
            if changed:
                tagged_count += 1
            else:
                skipped_count += 1

        print(f"MP4 Tagging complete: {tagged_count} tagged losslessly, {skipped_count} unchanged.")


if __name__ == "__main__":
    main()
