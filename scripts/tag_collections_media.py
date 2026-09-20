#!/usr/bin/env python3
"""
tag_collections_media.py

Deterministic performer entity recognition, studio/siterip attribution, scene
title normalization, and lossless MP4 container tagging across the Collections
& Siterips media pool on F:\\Aloha.

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
DEFAULT_TARGET_DIR = r"F:\Aloha\Collections & Siterips"

# Siterip and Studio Map for Collections
SITERIP_STUDIO_MAP = {
    "onlyfans": "OnlyFans",
    "onf": "OnlyFans",
    "girls gone wild": "Girls Gone Wild",
    "ggw": "Girls Gone Wild",
    "porn twins": "Porn Twins",
    "porntwins": "Porn Twins",
    "the lovers' guide": "The Lovers' Guide",
    "the lovers guide": "The Lovers' Guide",
    "l & s erotica": "L & S Erotica",
    "miss alice 18": "Miss Alice 18",
    "missalice 18": "Miss Alice 18",
    "missalice": "Miss Alice 18",
    "ddfprod": "DDF Network",
    "ddf": "DDF Network",
    "drunksexorgy": "Drunk Sex Orgy",
    "privatamateure": "Private Amateure",
    "pound the round": "Pound the Round",
    "squirting orgasms": "Squirting Orgasms",
    "vanilla": "Vanilla",
    "night shift nurses": "Vanilla",
}

# Subdirectory to default studio/category mapping
SUBDIR_STUDIO_DEFAULTS = {
    "izzy green (onlyfans)": "OnlyFans",
    "onlyfans mix": "OnlyFans",
    "girls gone wild": "Girls Gone Wild",
    "twins": "Porn Twins",
    "alice": "Miss Alice 18",
    "anime": "Anime",
    "night shift nurses karte ep01 10 extras [eng sub] [uncen]": "Vanilla",
    "l & s erotica": "L & S Erotica",
    "pound the round avi": "Pound the Round",
    "educative": "Squirting Orgasms",
    "strip": "Strip",
    "hard": "Hard Erotica",
    "teasers": "Teasers",
    "girl on girl action": "Girl on Girl",
    "pov": "POV",
    "extreme & kinky & stories": "Extreme & Kinky",
    "amateur": "Amateur",
    "squirts": "Squirts",
    "clips": "Clips",
    "blowjob": "Blowjob",
}

# Specific model extractions for OnlyFans Mix
ONLYFANS_MIX_MODELS = [
    (r"brittanya\s*razavi|seebrittanya", "Brittanya Razavi", "Brittanya Razavi Clip"),
    (r"ashley\s*adams", "Ashley Adams", "Ashley Adams Clip"),
    (r"mouchette(?:4bbc)?", "Mouchette", "Tangie Dream"),
    (r"amouranth|kaytlin\s*siragusa", "Amouranth", "Amouranth Clip"),
    (r"@miniblondie|bellasboobies|mbbella", "Mini Blondie", "Mini Blondie Clip"),
    (r"indica\s*flower|@indicaflower", "Indica Flower", "Indica Flower Clip"),
    (r"luna\s*okko", "Luna Okko", "Hotel Quickie"),
    (r"oliviayoung(?:188)?", "Olivia Young", "Olivia Young Clip"),
    (r"turn\s*up\s*monster|@turnupmonsters", "Turn Up Monster", "Turn Up Monster Clip"),
]

# Specific model pairs for Porn Twins
PORN_TWINS_MODELS = [
    (r"chantel\s*&\s*chloe|stevenstwins", "Chantel & Chloe Stevens", "Twin British Milfs"),
    (r"lacey\s*&\s*lyndsay|lacey\s*&\s*lyndsey", "Lacey & Lyndsay", None),
    (r"annamichelle\s*&\s*katja", "Anna Michelle & Katja", "Geile Zwillinge"),
    (r"cherish\s*&\s*cali|miltontwins", "Cherish & Cali Milton", "Fearsome Foursome"),
    (r"marika\s*&\s*dominica", "Marika & Dominica", "Up and Cummers"),
]


def clean_scene_title(raw_title: str) -> str:
    """Strips technical resolutions, codecs, scene noise, and extensions from title."""
    title = os.path.splitext(raw_title)[0]

    # Remove leading web scrapers and site marks
    title = re.sub(r"^(?:igotporn\s*(?:org|\.org)?|wckedforums\s*(?:com|\.com)?|cysforum\s*(?:com|\.com)?)\s*", "", title, flags=re.IGNORECASE)
    title = re.sub(r"^(?:bigwai@18p2p\s*)?", "", title, flags=re.IGNORECASE)
    title = re.sub(r"^\[(?:2_ddfprod|ddfprod|drunksexorgy|privatamateure|the lovers\' guide|the lovers guide|squirting orgasms)\]\s*", "", title, flags=re.IGNORECASE)

    # Remove trailing bracketed codec / resolution info
    title = re.sub(r"\s*\[(?:1080p|720p|480p|540p|360p|2160p|4k|hd|sd)?\s*(?:h264|x264|av1|hevc|x265|mpeg4|mpeg2video)?\]", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s*\[(?:eng\s*subs?|cen|uncen)\]", "", title, flags=re.IGNORECASE)
    title = re.sub(r"\s*\[(?:av1|h264|hevc)\]", "", title, flags=re.IGNORECASE)

    # Remove file size indicators like 716mb, 762mb, etc.
    title = re.sub(r"\b\d{3,4}mb\b", "", title, flags=re.IGNORECASE)

    # Normalize underscores and hyphens
    title = title.replace("_", " ")
    title = re.sub(r"\s*-\s*", " - ", title)
    title = re.sub(r"\s+", " ", title).strip()

    # Capitalize cleanly if all lowercase
    if title.islower():
        title = title.title()

    return title


def parse_collections_media(
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
    Parses performer entity, canonical studio, clean title, and release date
    from file attributes within Collections & Siterips.
    """
    detected_artist = existing_artist
    detected_studio = existing_studio
    detected_title = existing_title
    detected_date = existing_date
    confidence = 0.50

    rel_dir = directory.replace("F:\\Aloha\\Collections & Siterips", "").replace("F:/Aloha/Collections & Siterips", "")
    if rel_dir.startswith("\\") or rel_dir.startswith("/"):
        rel_dir = rel_dir[1:]
    top_sub = rel_dir.split("\\")[0].split("/")[0].lower() if rel_dir else ""

    # Rule A: Izzy Green (OnlyFans) Pack
    if "izzy green" in top_sub:
        detected_artist = "Izzy Green"
        detected_studio = "OnlyFans"
        confidence = 0.98

        # Check for episode/clip number in filename
        # Pattern: Onf Izzygreen <NUM> or Scr - Onf Izzygreen <NUM> Mp4.jpg
        m_num = re.search(r"izzygreen\s*(\d+)", filename, re.IGNORECASE)
        clip_num = m_num.group(1) if m_num else ""

        if media_type == "image" or "scr" in filename.lower():
            if clip_num:
                detected_title = f"Screens: Izzy Green Clip {clip_num}"
            else:
                clean_name = clean_scene_title(filename)
                detected_title = f"Screens: {clean_name}"
        else:
            if clip_num:
                detected_title = f"Izzy Green Clip {clip_num}"
            else:
                detected_title = clean_scene_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule B: OnlyFans Mix
    if "onlyfans mix" in top_sub:
        detected_studio = "OnlyFans"
        confidence = 0.90
        model_found = False

        for pat, name, default_title in ONLYFANS_MIX_MODELS:
            if re.search(pat, filename, re.IGNORECASE):
                detected_artist = name
                model_found = True
                if default_title:
                    detected_title = default_title
                else:
                    detected_title = f"{name} Clip"
                break

        if not model_found:
            detected_title = clean_scene_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule C: Porn Twins / Twins
    if "twins" in top_sub:
        detected_studio = "Porn Twins"
        confidence = 0.92

        # Check models
        for pat, names, default_title in PORN_TWINS_MODELS:
            if re.search(pat, filename, re.IGNORECASE):
                detected_artist = names
                if default_title and not detected_title:
                    detected_title = default_title
                break

        # Check specific release titles
        clean = clean_scene_title(filename)
        clean = re.sub(r"^(?:porntwins|porn twins)\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^(?:chantel&chloe|lacey\s*&\s*lyndsay|lacey\s*&\s*lyndsey|annamichelle&katja|cherish&cali|marika&dominica)\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^(?:stevenstwins|miltontwins)\s*", "", clean, flags=re.IGNORECASE)

        if "love twins two hot" in filename.lower():
            detected_title = "Love Twins: Two Hot"
        elif "my evil twin" in filename.lower():
            detected_title = "Love Twins: My Evil Twin"
        elif "twindom" in filename.lower():
            detected_title = "Love Twins: Twindom"
        elif "joinedatthehip" in filename.lower():
            detected_title = "Love Twins: Joined at the Hip"
        elif "truehollywoodtwins" in filename.lower():
            detected_title = "Love Twins: True Hollywood Twins"
        elif clean:
            detected_title = clean

        if not detected_artist and "lacey" in filename.lower():
            detected_artist = "Lacey & Lyndsay"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title or clean_scene_title(filename),
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule D: Girls Gone Wild
    if "girls gone wild" in top_sub:
        detected_studio = "Girls Gone Wild"
        confidence = 0.95

        clean = clean_scene_title(filename)
        clean = re.sub(r"^girls\s*gone\s*wild\s*", "", clean, flags=re.IGNORECASE)
        if "ggwsuv2" in filename.lower():
            detected_title = "Girls Gone Wild: SUV Vol 2"
        elif clean:
            detected_title = f"Girls Gone Wild: {clean}"
        else:
            detected_title = "Girls Gone Wild"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date or ("2006" if "2006" in filename else None),
            "confidence": confidence,
        }

    # Rule E: Alice / Miss Alice 18
    if "alice" in top_sub:
        detected_artist = "Miss Alice 18"
        detected_studio = "Miss Alice 18"
        confidence = 0.95

        m_date = re.search(r"(\d{4})[_\s-](\d{2})[_\s-](\d{2})", filename)
        m_num = re.search(r"\((\d+)\)", filename)

        if m_date:
            detected_title = f"Miss Alice {m_date.group(1)}-{m_date.group(2)}-{m_date.group(3)}"
            detected_date = f"{m_date.group(1)}-{m_date.group(2)}-{m_date.group(3)}"
        elif m_num:
            detected_title = f"Miss Alice Clip {m_num.group(1)}"
        else:
            detected_title = "Miss Alice Clip"

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule F: Anime & Night Shift Nurses
    if "anime" in top_sub or "night shift nurses" in top_sub:
        confidence = 0.90
        if "night shift nurses" in filename.lower() or "nightshiftnurses" in filename.lower() or "night shift nurses" in top_sub:
            detected_studio = "Vanilla"
            m_ep = re.search(r"(?:ep|karte\s*ep|nurses\s*)(\d+)", filename, re.IGNORECASE)
            if m_ep:
                detected_title = f"Night Shift Nurses: Episode {m_ep.group(1)}"
            else:
                detected_title = clean_scene_title(filename)
        else:
            detected_studio = "Anime"
            detected_title = clean_scene_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule G: L & S Erotica
    if "l & s erotica" in top_sub:
        confidence = 0.90
        if "the lovers' guide" in filename.lower() or "the lovers guide" in filename.lower():
            detected_studio = "The Lovers' Guide"
            clean = clean_scene_title(filename)
            detected_title = f"The Lovers' Guide: {clean}"
        else:
            detected_studio = "L & S Erotica"
            detected_title = clean_scene_title(filename)

        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule H: Specific collections (Pound the Round, Educative, Strip)
    if "pound the round" in top_sub:
        detected_studio = "Pound the Round"
        confidence = 0.95
        if "cd1" in filename.lower():
            detected_title = "Pound the Round: CD1"
        elif "cd2" in filename.lower():
            detected_title = "Pound the Round: CD2"
        else:
            detected_title = "Pound the Round"
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    if "educative" in top_sub:
        detected_studio = "Squirting Orgasms"
        detected_title = "How to Squirt"
        confidence = 0.90
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    if "strip" in top_sub:
        detected_studio = "Strip"
        confidence = 0.85
        if "veronika zemanova" in filename.lower():
            detected_artist = "Veronika Zemanova"
            detected_title = "Hot Strip"
            confidence = 0.95
        else:
            detected_title = clean_scene_title(filename)
        return {
            "detected_artist": detected_artist,
            "detected_studio": detected_studio,
            "detected_title": detected_title,
            "detected_date": detected_date,
            "confidence": confidence,
        }

    # Rule I: Thematic directories (Hard, Teasers, Pov, Girl on Girl, Extreme, Amateur, Squirts, Clips, Blowjob)
    # 1. Check bracketed studio marks
    m_brack = re.search(r"^\[([a-zA-Z0-9_\s']+)\]", filename)
    if m_brack:
        token = m_brack.group(1).lower().strip()
        norm_token = re.sub(r"^\d+_", "", token)
        if token in SITERIP_STUDIO_MAP:
            detected_studio = SITERIP_STUDIO_MAP[token]
        elif norm_token in SITERIP_STUDIO_MAP:
            detected_studio = SITERIP_STUDIO_MAP[norm_token]
        else:
            # Could be performer in bracket: e.g. [Bambi] or [Natasha Nice] or [Elena Grimaldi]
            for star in KNOWN_PERFORMERS:
                if star.lower() == token or token.startswith(star.lower()):
                    detected_artist = star
                    confidence = 0.90
                    break

    # 2. Check performer names in filename
    if not detected_artist:
        name_lower = filename.lower()
        matched_stars = []
        for star in KNOWN_PERFORMERS:
            # Match word boundary
            pattern = r"(?<![a-zA-Z0-9])" + re.escape(star.lower()) + r"(?![a-zA-Z0-9])"
            if re.search(pattern, name_lower):
                matched_stars.append(star)

        if matched_stars:
            # Sort by length descending to pick most specific name
            matched_stars.sort(key=len, reverse=True)
            primary = matched_stars[0]
            # Check for multi-performer combinations
            non_overlapping = [primary]
            for s in matched_stars[1:]:
                if not any(s in existing for existing in non_overlapping):
                    non_overlapping.append(s)
            detected_artist = ", ".join(non_overlapping[:2])
            confidence = 0.90

    # 3. If studio still None, assign default from directory taxonomy
    if not detected_studio:
        detected_studio = SUBDIR_STUDIO_DEFAULTS.get(top_sub, "Collections & Siterips")
        if confidence < 0.80:
            confidence = 0.80

    # Clean title
    detected_title = clean_scene_title(filename)

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
    parser = argparse.ArgumentParser(description="Tag performer and studio metadata across Collections & Siterips.")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="Path to media_inventory.db")
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR, help="Target directory for Collections & Siterips")
    parser.add_argument("--dry-run", action="store_true", help="Preview tags without writing to disk or database")
    parser.add_argument("--sync-db", action="store_true", help="Update database records with parsed metadata")
    parser.add_argument("--tag-containers", action="store_true", help="Losslessly write MP4 container metadata")
    parser.add_argument("--report", default="collections_tagging_preview.json", help="Path for JSON audit report")
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
        parsed = parse_collections_media(
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
