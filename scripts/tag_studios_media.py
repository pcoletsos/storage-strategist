#!/usr/bin/env python3
r"""
tag_studios_media.py

Deterministic performer entity recognition, studio attribution correction,
scene title normalization, and lossless MP4 container tagging for the
Studios media pool on F:\Aloha.

Attributes performers across:
- X-Art (photos and videos)
- Backroom Casting Couch (episodes and auditions)
- Tonights Girlfriend (videos and screens)
- Bangbus and Bangbros (episodes and series)
- Brazzers, Digital Playground, Vixen, FuckedHard18, Twistys, etc.

Reconciles metadata in media_inventory.db and losslessly injects QuickTime atoms
(©ART, ©nam, ©cmt, ©day) into compatible MP4 media assets, strictly preserving original
filesystem modification timestamps (mtime).
"""

import argparse
import concurrent.futures
import json
import os
import re
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from mutagen.mp4 import MP4
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False

DEFAULT_TARGET_DIR = r"F:\Aloha\Studios"
DEFAULT_DB_PATH = r"e:\repos\projects\storage-strategist\media_inventory.db"
DEFAULT_BACKUP_PATH = r"e:\repos\projects\storage-strategist\media_inventory_pre_studios_tagging.bak"

# ---------------------------------------------------------------------------
# Registry of Known Studio Performers for Entity Matching
# ---------------------------------------------------------------------------
KNOWN_STUDIO_PERFORMERS = [
    # Full Names
    "Alanah Rae", "Alessandra Jane", "Alexis Texas", "Allaura", "Amia Miley",
    "Angela White", "AnnMarie Rios", "Apolonia Lapiedra", "April O'Neil",
    "Ariana Marie", "Ariella Ferrera", "Asa Akira", "Audrey Bitoni",
    "August Ames", "Autumn Falls", "Ava Addams", "Billie Star", "Bobbi Starr",
    "Brandon Fox", "Breanne Benson", "Briana Blair", "Capri Anderson",
    "Capri Cavanni", "Carmella Bing", "Cassidy Banks", "Cathy Heaven",
    "Celeste Star", "Coco Lovelock", "Courtney Cummz", "Crystal Jane",
    "Dana Dearmond", "Diana Doll", "Ellie Eilish", "Emily Willis",
    "Emma Starr", "Esperanza Gomez", "Eva Lovia", "Gabbie Carter",
    "Gianna Michaels", "Gracie Glam", "Honey Gold", "India Summer",
    "Izabella Carr", "Janice Griffith", "Jayden Jaymes", "Jesse Jane",
    "John Strong", "Johnny Rocket", "Johnny Sins", "Jordi El Nino Polla",
    "Juelz Ventura", "Julia Ann", "Justin Magnum", "Kagney Linn Karter",
    "Kayden Kross", "Kenzie Madison", "Kimmy Granger", "Kortney Kane",
    "Kris Slater", "Krissy Lynn", "Kyler Quinn", "Lela Star", "Levi Cash",
    "Lexi Belle", "Lexie Fux", "Little Caprice", "Malena Morgan", "Mark Wood",
    "Mia Malkova", "Mia Melano", "Naomi Swann", "Nia Nacci", "Nikki Benz",
    "Olga Farmaki", "Pauly Harker", "Penny Pax", "Priya Rai", "Quinn Wilde",
    "Rachel Roxxx", "Remy LaCroix", "Riley Reid", "Riley Steele", "Rocco Reed",
    "Ryan Mclane", "Savannah Sixx", "Scarlit Scandal", "Shyla Stylez",
    "Stacy Cruz", "Stoya", "Sunny Leone", "Talia Mint", "Tanna Marie",
    "Taylor Wane", "Teagan Presley", "Tina Fire", "Tori Black",
    # X-Art Single Names and Duos
    "Caprice", "Capri", "Carla", "Carlie", "Emma", "Eniko", "Eufrat",
    "Francesca", "Georgia", "Kat", "Katka", "Kristen", "Leila", "Lilly",
    "Megan", "Mina", "Monique", "Nella", "Ophelia", "Regina", "Reina",
    "Ruby", "Silvie", "Star", "Stevie", "Susie", "Vicky", "Christian",
    # Backroom Casting Couch Names
    "Alli", "Amber", "Ami", "Amy", "Angelina", "Ashlee", "Ashley", "Bella",
    "Boxxy", "Brianna", "Brittany", "Carleigh", "Chanel", "Chastity", "Colby",
    "Courtney", "Danica", "Danielle", "Danni", "Devon", "Dina", "Elizabeth",
    "Evangeline", "Evie", "Gina", "Haley", "Hannah", "Heather", "Jaylynn",
    "Jenna", "Jenny", "Jesse", "Jordan", "Julia", "Kacey", "Kaedyn", "Kali",
    "Kara", "Katie", "Kendra", "Kim", "Kyle", "Lacy", "Leanne", "Lena",
    "Madison", "Melissa", "Mia", "Misha", "Morgan", "Rebecca", "Riley",
    "Serena", "Shantel", "Stacy", "Stephanie", "Sterling", "Talia", "Tamber",
    "Tatiana", "Toni", "Kassey", "Kayla", "Kenzie", "Nicole Rey", "Dani",
    "Desirae", "Ellie", "Kendall", "Kristy", "Melanie", "Natalee", "Sabrina",
    "Sierra", "Dara", "Winter", "Sarah", "Lindsey", "Hanna", "Violet",
    "Lyla", "Haili", "Cami", "Raine", "Rose", "Lauren", "Erica", "Brittney"
]

# Tonights Girlfriend Screencap Token Mapping to Normalized Performers
TG_SCREEN_TOKEN_MAP = {
    "alannahbrandon": ("Alanah Rae, Brandon Fox", "Tonights Girlfriend Screen: Alanah Rae & Brandon Fox"),
    "alexisjohnny": ("Alexis Texas, Johnny Rocket", "Tonights Girlfriend Screen: Alexis Texas & Johnny Rocket"),
    "anmariejack": ("AnnMarie Rios, Jack Venice", "Tonights Girlfriend Screen: AnnMarie Rios & Jack Venice"),
    "apriljohn": ("April O'Neil, John Strong", "Tonights Girlfriend Screen: April O'Neil & John Strong"),
    "ariellajohny2": ("Ariella Ferrera, Johnny Sins", "Tonights Girlfriend Screen: Ariella Ferrera & Johnny Sins"),
    "asarocco1": ("Asa Akira, Rocco Reed", "Tonights Girlfriend Screen: Asa Akira & Rocco Reed"),
    "bobbiroco": ("Bobbi Starr, Rocco Reed", "Tonights Girlfriend Screen: Bobbi Starr & Rocco Reed"),
    "breannelevi": ("Breanne Benson, Levi Cash", "Tonights Girlfriend Screen: Breanne Benson & Levi Cash"),
    "brianamark": ("Briana Blair, Mark Wood", "Tonights Girlfriend Screen: Briana Blair & Mark Wood"),
    "capribil": ("Capri Anderson, Bill Bailey", "Tonights Girlfriend Screen: Capri Anderson & Bill Bailey"),
    "courtneybill": ("Courtney Cummz, Bill Bailey", "Tonights Girlfriend Screen: Courtney Cummz & Bill Bailey"),
    "dianakris5": ("Diana Doll, Kris Slater", "Tonights Girlfriend Screen: Diana Doll & Kris Slater"),
    "emmajustin": ("Emma Starr, Justin Magnum", "Tonights Girlfriend Screen: Emma Starr & Justin Magnum"),
    "esperanzamark": ("Esperanza Gomez, Mark Wood", "Tonights Girlfriend Screen: Esperanza Gomez & Mark Wood"),
    "graciekagneypauly": ("Gracie Glam, Kagney Linn Karter, Pauly Harker", "Tonights Girlfriend Screen: Gracie Glam, Kagney Linn Karter & Pauly Harker"),
    "indiajohn": ("India Summer, John Strong", "Tonights Girlfriend Screen: India Summer & John Strong"),
    "jaydenlevi": ("Jayden Jaymes, Levi Cash", "Tonights Girlfriend Screen: Jayden Jaymes & Levi Cash"),
    "jennijustin": ("Jenni Lee, Justin Magnum", "Tonights Girlfriend Screen: Jenni Lee & Justin Magnum"),
    "juelzmark": ("Juelz Ventura, Mark Wood", "Tonights Girlfriend Screen: Juelz Ventura & Mark Wood"),
    "juliajohnn": ("Julia Ann, John Strong", "Tonights Girlfriend Screen: Julia Ann & John Strong"),
    "kortneyalec": ("Kortney Kane, Alec Knight", "Tonights Girlfriend Screen: Kortney Kane & Alec Knight"),
    "krissybill": ("Krissy Lynn, Bill Bailey", "Tonights Girlfriend Screen: Krissy Lynn & Bill Bailey"),
    "lexiryan": ("Lexi Belle, Ryan Mclane", "Tonights Girlfriend Screen: Lexi Belle & Ryan Mclane"),
    "madelynchris": ("Madelyn Marie, Chris Strokes", "Tonights Girlfriend Screen: Madelyn Marie & Chris Strokes"),
    "phoenixbary": ("Phoenix Marie, Barry Scott", "Tonights Girlfriend Screen: Phoenix Marie & Barry Scott"),
    "racheljustin": ("Rachel Roxxx, Justin Magnum", "Tonights Girlfriend Screen: Rachel Roxxx & Justin Magnum"),
    "sashamark": ("Sasha Grey, Mark Wood", "Tonights Girlfriend Screen: Sasha Grey & Mark Wood"),
    "sunnyjohon": ("Sunny Leone, John Strong", "Tonights Girlfriend Screen: Sunny Leone & John Strong"),
    "sunnyjohn": ("Sunny Leone, John Strong", "Tonights Girlfriend Screen: Sunny Leone & John Strong"),
    "tannabill": ("Tanna Marie, Bill Bailey", "Tonights Girlfriend Screen: Tanna Marie & Bill Bailey"),
    "tanyajohny": ("Tanya James, Johnny Sins", "Tonights Girlfriend Screen: Tanya James & Johnny Sins"),
    "tashamark": ("Tasha Reign, Mark Wood", "Tonights Girlfriend Screen: Tasha Reign & Mark Wood"),
    "taylorjohn": ("Taylor Wane, John Strong", "Tonights Girlfriend Screen: Taylor Wane & John Strong"),
    "teaganbill": ("Teagan Presley, Bill Bailey", "Tonights Girlfriend Screen: Teagan Presley & Bill Bailey"),
    "torigregg": ("Tori Black, Gregg Stone", "Tonights Girlfriend Screen: Tori Black & Gregg Stone"),
    "torijohn": ("Tori Black, John Strong", "Tonights Girlfriend Screen: Tori Black & John Strong"),
    "veronicakris": ("Veronica Avluv, Kris Slater", "Tonights Girlfriend Screen: Veronica Avluv & Kris Slater"),
}

# X-Art Known Name Duos and Single Tokens
XART_PERFORMERS = [
    "Izabella Carr", "Sarah K", "Sasha D", "Shyla Stylez", "Lexi Belle", "Mia Malkova",
    "Apolonia Lapiedra", "Caprice", "Capri", "Carla", "Carlie", "Emma", "Eniko", "Eufrat",
    "Francesca", "Georgia", "Katka", "Kat", "Kristen", "Leila", "Lilly", "Megan", "Minas",
    "Mina", "Monique", "Nella", "Ophelia", "Regina", "Reina", "Ruby", "Shyla", "Silvie",
    "Star", "Stevie", "Susie", "Tori", "Vicky", "Christian", "Jennifer", "Patsy", "Jeff"
]

BRCC_PERFORMERS = [
    "Allaura", "Alli", "Amber", "Ami", "Amy", "Angelina", "Ashlee", "Ashley", "Bella",
    "Boxxy", "Brianna", "Brittany", "Carleigh", "Chanel", "Chastity", "Colby", "Courtney",
    "Crystal Jane", "Danica", "Danielle", "Danni", "Devon", "Dina", "Elizabeth", "Evangeline",
    "Evie", "Gina", "Haley", "Hannah", "Heather", "Jaylynn", "Jenna", "Jenny", "Jesse",
    "Jordan", "Julia", "Kacey", "Kaedyn", "Kali", "Kara", "Katie", "Kendra", "Kim", "Klementine",
    "Kyle", "Lacy", "Leanne", "Lena", "Madison", "Melissa", "Mia", "Mikela", "Misha", "Morgan",
    "Rebecca", "Riley", "Serena", "Shantel", "Stacy", "Stephanie", "Sterling", "Talia", "Tamber",
    "Tatiana", "Toni", "Vicky", "Kassey", "Kayla", "Kenzie", "Nicole Rey", "Dani", "Desirae",
    "Ellie", "Kendall", "Kristy", "Melanie", "Natalee", "Sabrina", "Sierra", "Dara", "Winter",
    "Sarah", "Lindsey", "Hanna", "Violet", "Lyla", "Haili", "Cami", "Raine", "Rose", "Lauren",
    "Erica", "Brittney", "Amia Miley"
]


def clean_scene_title(raw_title: str) -> str:
    """Strips release tags, resolution flags, codec markers, and file extensions."""
    title = re.sub(r'\.[a-zA-Z0-9]{2,4}$', '', raw_title)
    # Remove resolution tags
    title = re.sub(r'\[(1080p|720p|480p|2160p|4K|DVD|HD|SD)[^\]]*\]', '', title, flags=re.IGNORECASE)
    # Remove codec markers
    title = re.sub(r'\[(H264|AV1|HEVC|XVID)[^\]]*\]', '', title, flags=re.IGNORECASE)
    # Remove trailing quality tags
    title = re.sub(r'\b(1080p|720p|480p|2160p|4k|1920x1080|1280x720|hd|sd|av1|h264|xvid|dvdrip|bluray)\b', '', title, flags=re.IGNORECASE)
    # Remove site watermarks and prefixes
    title = re.sub(r'^(?:Bigwai@18p2p\s*)?X\s*Art\s*[-\u2013]?\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'Bigwai@18p2p\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[YouPorn\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[YouTube\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Bangbus\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Brazzers(?:\s+Exxtra)?\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Digital\s+Playground\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Vixen\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[FuckedHard18\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Tonights\s+Girlfriend\]\s*(?:Screens\s*-\s*)?', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Freeze\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Pure\s+Taboo\]\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\[Brattysis\]\s*', '', title, flags=re.IGNORECASE)
    # Strip dates in brackets [YYYY-MM-DD]
    title = re.sub(r'\[\d{4}-\d{2}-\d{2}\]', '', title)
    title = re.sub(r'\[\d{4}\]', '', title)
    # Strip duplicate duplicate suffix (2)
    title = re.sub(r'\(\d+\)', '', title)
    # Clean up whitespace and punctuation
    title = re.sub(r'[-\u2013_]+', ' ', title)
    title = re.sub(r'\s+', ' ', title).strip()
    return title


def parse_studio_media(
    file_path: str,
    filename: str,
    directory: str,
    media_type: str,
    existing_artist: Optional[str],
    existing_title: Optional[str],
    existing_studio: Optional[str],
    existing_date: Optional[str],
) -> Dict[str, Any]:
    """Applies deterministic extraction rules across Studios directory assets."""
    artist = existing_artist
    title = existing_title
    studio = existing_studio
    date = existing_date
    confidence = 0.50
    method = "existing"

    fname_lower = filename.lower()
    dpath_lower = directory.lower()

    # Rule 1: Determine Canonical Studio from Directory Path
    if "x-art" in dpath_lower:
        studio = "X-Art"
    elif "backroom casting couch" in dpath_lower:
        studio = "Backroom Casting Couch"
    elif "bangbus" in dpath_lower:
        studio = "Bangbus"
    elif "bangbros" in dpath_lower:
        studio = "Bangbros"
    elif "tonights girlfriend" in dpath_lower:
        # Explicitly override legacy Brazzers tag
        studio = "Tonights Girlfriend"
    elif "brazzers" in dpath_lower:
        studio = "Brazzers"
    elif "digital playground" in dpath_lower:
        studio = "Digital Playground"
    elif "vixen" in dpath_lower:
        studio = "Vixen"
    elif "fuckedhard18" in dpath_lower:
        studio = "FuckedHard18"
    elif "twistys" in dpath_lower:
        studio = "Twistys"
    elif "brattysis" in dpath_lower:
        studio = "Brattysis"
    elif "freeze" in dpath_lower:
        studio = "Freeze"
    elif "naughty america" in dpath_lower:
        studio = "Naughty America"
    elif "pure taboo" in dpath_lower:
        studio = "Pure Taboo"
    elif "stolen porn videos" in dpath_lower:
        studio = "Stolen Porn Videos"
    elif "sweetheart video" in dpath_lower:
        studio = "Sweetheart Video"

    # Rule 2: Extract Release Date if present in brackets [YYYY-MM-DD] or [YYYY]
    date_match = re.search(r'\[(20\d\d-\d\d-\d\d)\]', filename)
    if date_match:
        date = date_match.group(1)
    else:
        year_match = re.search(r'\[(19\d\d|20\d\d)\]', filename)
        if year_match and not date:
            date = year_match.group(1)

    # -----------------------------------------------------------------------
    # Rule A: Tonights Girlfriend Screencaps
    # -----------------------------------------------------------------------
    if "tonights girlfriend" in dpath_lower and "screens" in dpath_lower:
        studio = "Tonights Girlfriend"
        tg_match = re.search(r'tngf([a-z0-9]+)', fname_lower)
        if tg_match:
            token = tg_match.group(1)
            if token in TG_SCREEN_TOKEN_MAP:
                artist, title = TG_SCREEN_TOKEN_MAP[token]
                confidence = 0.98
                method = "tg_screen_token_map"
        if not title:
            title = clean_scene_title(filename)

    # -----------------------------------------------------------------------
    # Rule B: Tonights Girlfriend Videos
    # -----------------------------------------------------------------------
    elif "tonights girlfriend" in dpath_lower:
        studio = "Tonights Girlfriend"
        # If artist is already set, retain it and clean title
        if existing_artist and existing_artist != "None":
            artist = existing_artist
            confidence = 0.95
            method = "tg_video_artist_retained"
        else:
            # Check for token in filename
            tg_match = re.search(r'\[tonights girlfriend\]\s*([a-z0-9]+)', fname_lower)
            if tg_match:
                token = tg_match.group(1)
                if token in TG_SCREEN_TOKEN_MAP:
                    artist, mapped_title = TG_SCREEN_TOKEN_MAP[token]
                    title = mapped_title.replace("Tonights Girlfriend Screen: ", "")
                    confidence = 0.95
                    method = "tg_video_token_map"

        if not title or title.upper() == "TONIGHTS GIRLFRIEND":
            if artist:
                title = f"{artist} Scene"
            else:
                title = clean_scene_title(filename)

    # -----------------------------------------------------------------------
    # Rule C: X-Art (Photos and Videos)
    # -----------------------------------------------------------------------
    elif "x-art" in dpath_lower:
        studio = "X-Art"
        # Clean prefix variations: "Bigwai@18p2p X Art - ", "X Art "
        cleaned_name = re.sub(r'^(?:Bigwai@18p2p\s*)?X\s*Art\s*[-–]?\s*', '', filename, flags=re.IGNORECASE)
        cleaned_name = clean_scene_title(cleaned_name)

        # Match known X-Art models at start of cleaned string
        detected_performers = []
        remainder = cleaned_name

        # Check for multi-word or single-word performers
        for p in XART_PERFORMERS:
            pattern = rf'^{re.escape(p)}\b'
            if re.search(pattern, remainder, re.IGNORECASE):
                detected_performers.append(p)
                remainder = re.sub(pattern, '', remainder, flags=re.IGNORECASE).strip()
                # Check for second performer in duos (e.g. "Capri Malibu Daze" after Francesca)
                for p2 in XART_PERFORMERS:
                    pattern2 = rf'^{re.escape(p2)}\b'
                    if re.search(pattern2, remainder, re.IGNORECASE) and p2 != p:
                        detected_performers.append(p2)
                        remainder = re.sub(pattern2, '', remainder, flags=re.IGNORECASE).strip()
                        break
                break

        # Check special cases like "Truth or Dare - Lexi Belle, Mia Malkova"
        if not detected_performers:
            special_m = re.search(r'-\s*([A-Za-z\s,]+)$', clean_scene_title(filename))
            if special_m:
                cand = [c.strip() for c in special_m.group(1).split(',')]
                cand_perf = [c for c in cand if c in KNOWN_STUDIO_PERFORMERS]
                if cand_perf:
                    detected_performers = cand_perf
                    remainder = clean_scene_title(filename).split('-')[0].strip()

        if detected_performers:
            artist = ", ".join(detected_performers)
            title = remainder if remainder else clean_scene_title(filename)
            confidence = 0.95
            method = "xart_performer_extraction"
        else:
            if not title:
                title = clean_scene_title(filename)

    # -----------------------------------------------------------------------
    # Rule D: Backroom Casting Couch
    # -----------------------------------------------------------------------
    elif "backroom casting couch" in dpath_lower:
        studio = "Backroom Casting Couch"

        # Pattern D1: "[Backroom Casting Couch] Ktr Bcc E### Performer1 and Performer2"
        ktr_m = re.search(r'ktr\s+bcc\s+e(\d+)\s+([a-zA-Z]+(?:\s+and\s+[a-zA-Z]+)?)', fname_lower)
        if ktr_m:
            ep_num = ktr_m.group(1)
            raw_perf = ktr_m.group(2)
            perfs = [p.strip().title() for p in raw_perf.split('and')]
            artist = ", ".join(perfs)
            title = f"Episode {ep_num}: {artist}"
            confidence = 0.95
            method = "brcc_ktr_episode"

        # Pattern D2: "[Performer] Brcc" or "[Performer]2 Brcc" or "Brcchaley2"
        elif not artist or existing_title == "BACKROOM CASTING COUCH" or existing_title == "BACKROOMCASTINGCOUCH.COM":
            brcc_m = re.search(r'^(?:brcc)?([a-zA-Z]+(?:\s+[a-zA-Z]+)?)2?\s*(?:brcc)?\b', filename, re.IGNORECASE)
            # Match directly against known BRCC list
            found_brcc_artist = None
            for p in sorted(BRCC_PERFORMERS, key=len, reverse=True):
                # Look for performer at start or before Brcc
                if re.search(rf'\b{re.escape(p)}2?\b', filename, re.IGNORECASE):
                    found_brcc_artist = p
                    break

            if found_brcc_artist:
                artist = found_brcc_artist
                title = f"Casting: {artist}"
                confidence = 0.95
                method = "brcc_named_audition"
            else:
                title = clean_scene_title(filename)
                confidence = 0.85
                method = "brcc_general"

    # -----------------------------------------------------------------------
    # Rule E: Bangbus & Bangbros
    # -----------------------------------------------------------------------
    elif "bangbus" in dpath_lower:
        studio = "Bangbus"
        ep_m = re.search(r'episode\s+(\d+)', fname_lower)
        if ep_m:
            title = f"Episode {ep_m.group(1)}"
            confidence = 0.95
            method = "bangbus_episode"
        else:
            title = clean_scene_title(filename)

    elif "bangbros" in dpath_lower:
        studio = "Bangbros"
        di_m = re.search(r'di(\d+)', fname_lower)
        if di_m:
            title = f"Dorm Invasion: Episode {di_m.group(1)}"
            confidence = 0.95
            method = "bangbros_dorm_invasion"
        else:
            title = clean_scene_title(filename)

    # -----------------------------------------------------------------------
    # Rule F: Brazzers
    # -----------------------------------------------------------------------
    elif "brazzers" in dpath_lower:
        studio = "Brazzers"

        # Check for Performer1 and Performer2 Title in clean scene title
        clean_title = clean_scene_title(filename)
        if " and " in clean_title.lower():
            and_parts = re.split(r'\s+and\s+', clean_title, maxsplit=1, flags=re.IGNORECASE)
            p1_cand = and_parts[0].strip().title()
            rest = and_parts[1].strip()
            matched_p2 = None
            for kp in sorted(KNOWN_STUDIO_PERFORMERS, key=len, reverse=True):
                if re.search(rf'^{re.escape(kp)}\b', rest, re.IGNORECASE):
                    matched_p2 = kp
                    rest = re.sub(rf'^{re.escape(kp)}\s*', '', rest, flags=re.IGNORECASE).strip()
                    break
            if matched_p2:
                artist = f"{p1_cand}, {matched_p2}"
                title = rest if rest else f"{p1_cand} and {matched_p2}"
                confidence = 0.95
                method = "brazzers_exxtra_duo"

        # Check specific Brazzers series and duo tokens
        if not artist or artist == "None":
            if "jayden nikki" in fname_lower:
                artist = "Jayden Jaymes, Nikki Benz"
                confidence = 0.95
                method = "brazzers_duo_token"
            elif "august ava" in fname_lower:
                artist = "August Ames, Ava Addams"
                confidence = 0.95
                method = "brazzers_duo_token"
            elif "shyla carmella gianna" in fname_lower:
                artist = "Shyla Stylez, Carmella Bing, Gianna Michaels"
                confidence = 0.95
                method = "brazzers_trio_token"
            elif "mrslynn" in fname_lower:
                artist = "Krissy Lynn"
                confidence = 0.95
                method = "brazzers_token"
            elif "rachel roxxx" in fname_lower:
                artist = "Rachel Roxxx"
                confidence = 0.95
                method = "brazzers_token"
            elif "lisa ann" in fname_lower:
                artist = "Lisa Ann"
                confidence = 0.95
                method = "brazzers_token"
            elif "priya rai" in fname_lower:
                artist = "Priya Rai"
                confidence = 0.95
                method = "brazzers_token"
            else:
                matched_perf = []
                for kp in KNOWN_STUDIO_PERFORMERS:
                    if re.search(rf'\b{re.escape(kp)}\b', filename, re.IGNORECASE):
                        matched_perf.append(kp)
                if matched_perf:
                    artist = ", ".join(matched_perf)
                    confidence = 0.92
                    method = "brazzers_known_performer"

        if not title:
            title = clean_scene_title(filename)

    # -----------------------------------------------------------------------
    # Rule G: Digital Playground, Vixen, FuckedHard18, Twistys
    # -----------------------------------------------------------------------
    else:
        # Check for known performers across filename
        matched = []
        for kp in sorted(KNOWN_STUDIO_PERFORMERS, key=len, reverse=True):
            if re.search(rf'\b{re.escape(kp)}\b', filename, re.IGNORECASE):
                if kp not in matched:
                    matched.append(kp)

        if matched:
            artist = ", ".join(matched)
            confidence = 0.95
            method = "studio_known_performer"

        if not title:
            title = clean_scene_title(filename)

    if artist and confidence < 0.90:
        confidence = 0.92

    # Final cleanup on title
    if title:
        title = title.replace("  ", " ").strip()
        # Capitalize nicely if all uppercase or lowercase
        if title.isupper() or title.islower():
            title = title.title()

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
        "prior_artist": existing_artist,
        "prior_studio": existing_studio,
        "prior_title": existing_title,
    }


def analyze_studios_pool(
    db_path: str,
    target_dir: str = DEFAULT_TARGET_DIR,
) -> List[Dict[str, Any]]:
    """Analyzes all media records in Studios root and extracts enriched metadata."""
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

    results = []
    for r in rows:
        parsed = parse_studio_media(
            file_path=r["file_path"],
            filename=r["filename"],
            directory=r["directory"],
            media_type=r["media_type"],
            existing_artist=r["existing_artist"],
            existing_title=r["existing_title"],
            existing_studio=r["studio"],
            existing_date=r["existing_date"],
        )
        parsed["id"] = r["id"]
        results.append(parsed)

    return results


def sync_to_database(db_path: str, results: List[Dict[str, Any]]) -> Tuple[int, int, int]:
    """Applies parsed performer, studio, and title attributes to media_inventory.db."""
    conn = sqlite3.connect(db_path)
    updated_records = 0
    updated_artists = 0
    updated_studios = 0

    with conn:
        for r in results:
            artist = r.get("detected_artist")
            title = r.get("detected_title")
            studio = r.get("detected_studio")
            date = r.get("detected_date")
            conf = r.get("confidence", 0.0)
            rec_id = r["id"]

            needs_review = 0 if conf >= 0.85 else 1

            cur = conn.execute("""
                UPDATE media_files
                SET existing_artist = COALESCE(?, existing_artist),
                    existing_title = COALESCE(?, existing_title),
                    studio = ?,
                    existing_date = COALESCE(?, existing_date),
                    confidence_score = MAX(COALESCE(confidence_score, 0.0), ?),
                    needs_review = ?
                WHERE id = ?
            """, (artist, title, studio, date, conf, needs_review, rec_id))

            if cur.rowcount > 0:
                updated_records += 1
                if artist:
                    updated_artists += 1
                if studio:
                    updated_studios += 1

    conn.close()
    return updated_records, updated_artists, updated_studios


def _tag_single_mp4(item: Dict[str, Any]) -> bool:
    """Losslessly injects QuickTime atoms into an MP4 file with mtime preservation."""
    file_path = item["file_path"]
    artist = item.get("detected_artist")
    title = item.get("detected_title")
    studio = item.get("detected_studio")
    date = item.get("detected_date")

    if not os.path.exists(file_path):
        return False

    try:
        stat = os.stat(file_path)
        orig_atime = stat.st_atime
        orig_mtime = stat.st_mtime

        mp4 = MP4(file_path)
        if mp4.tags is None:
            mp4.add_tags()

        changed = False
        if artist and mp4.tags.get("\xa9ART") != [artist]:
            mp4.tags["\xa9ART"] = [artist]
            changed = True
        if title and mp4.tags.get("\xa9nam") != [title]:
            mp4.tags["\xa9nam"] = [title]
            changed = True
        if studio and mp4.tags.get("\xa9cmt") != [studio]:
            mp4.tags["\xa9cmt"] = [studio]
            changed = True
        if date and mp4.tags.get("\xa9day") != [str(date)]:
            mp4.tags["\xa9day"] = [str(date)]
            changed = True

        if changed:
            mp4.save()
            os.utime(file_path, (orig_atime, orig_mtime))
            return True
        return False
    except Exception as e:
        print(f"[WARN] Failed to tag {file_path}: {e}")
        return False


def tag_mp4_containers(
    results: List[Dict[str, Any]],
    workers: int = 4,
    min_confidence: float = 0.85,
) -> int:
    """Concurrent lossless MP4 container tagging with timestamp preservation."""
    if not MUTAGEN_AVAILABLE:
        print("[ERROR] mutagen library not installed. Cannot tag MP4 containers.")
        return 0

    mp4_candidates = [
        r for r in results
        if r["filename"].lower().endswith(".mp4")
        and r.get("confidence", 0.0) >= min_confidence
        and (r.get("detected_artist") or r.get("detected_title") or r.get("detected_studio"))
    ]

    total = len(mp4_candidates)
    print(f"[CONTAINER] Queued {total} MP4 video containers for lossless tagging.")
    tagged_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_tag_single_mp4, item): item for item in mp4_candidates}
        for future in concurrent.futures.as_completed(future_map):
            if future.result():
                tagged_count += 1

    print(f"[CONTAINER] Completed tagging {tagged_count}/{total} MP4 files with mtime preserved.")
    return tagged_count


def main():
    parser = argparse.ArgumentParser(description="Deterministic performer and studio metadata tagger for Studios pool on Aloha")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="Path to media_inventory.db")
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR, help="Target Studios root directory")
    parser.add_argument("--preview", action="store_true", help="Generate preview JSON without modifying files or DB")
    parser.add_argument("--apply-db", action="store_true", help="Synchronize parsed metadata into media_inventory.db")
    parser.add_argument("--apply-tags", action="store_true", help="Tag eligible MP4 containers on disk with mtime preserved")
    parser.add_argument("--workers", type=int, default=4, help="Worker threads for container tagging")
    args = parser.parse_args()

    print("=" * 70)
    print(" STUDIOS POOL: PERFORMER & STUDIO METADATA TAGGING PIPELINE")
    print(f" Target: {args.target_dir}")
    print(f" Database: {args.db_path}")
    print("=" * 70)

    start_t = time.time()
    results = analyze_studios_pool(args.db_path, args.target_dir)
    elapsed = time.time() - start_t

    if not results:
        print("[ERROR] No media records found for Studios pool.")
        sys.exit(1)

    total_assets = len(results)
    videos = [r for r in results if r["media_type"] == "video"]
    images = [r for r in results if r["media_type"] == "image"]
    with_artist = [r for r in results if r.get("detected_artist")]
    with_studio = [r for r in results if r.get("detected_studio")]
    with_title = [r for r in results if r.get("detected_title")]

    print(f"[ANALYSIS] Processed {total_assets} assets ({len(videos)} videos, {len(images)} images) in {elapsed:.2f}s.")
    print(f"  Performers Recognized: {len(with_artist)} / {total_assets} ({len(with_artist)/total_assets*100:.1f}%)")
    print(f"  Studios Attributed:    {len(with_studio)} / {total_assets} ({len(with_studio)/total_assets*100:.1f}%)")
    print(f"  Titles Normalized:     {len(with_title)} / {total_assets} ({len(with_title)/total_assets*100:.1f}%)")

    # Output preview file if requested or by default
    preview_file = "studios_tagging_preview.json"
    with open(preview_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[PREVIEW] Saved audit preview report to {preview_file}")

    if args.apply_db:
        print("[DATABASE] Synchronizing metadata records into media_inventory.db...")
        updated_rec, updated_art, updated_std = sync_to_database(args.db_path, results)
        print(f"[DATABASE] Synchronized: {updated_rec} records updated, {updated_art} with performers, {updated_std} with studios.")

    if args.apply_tags:
        print("[CONTAINER] Starting lossless MP4 container tagging...")
        tagged = tag_mp4_containers(results, workers=args.workers)
        print(f"[CONTAINER] Losslessly tagged {tagged} MP4 containers.")

    print("\n[COMPLETE] Studios pool tagging run finished successfully.")


if __name__ == "__main__":
    main()
