import os
import re
import sys
import json
import time
import struct
import sqlite3
import shutil
import argparse
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import cv2
from PIL import Image
import pytesseract
from rapidfuzz import fuzz
from tqdm import tqdm

# Sibling script imports
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPTS_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import (
    STUDIO_MAP,
    SCENE_BLOAT_PATTERNS,
    sanitize_win_filename,
    clean_title_case,
    to_extended_path,
    normalize_date
)
from media_tagger import tag_media_file

# Configure Tesseract
TESSERACT_DEFAULT = r"C:\Program Files\PDF24\tesseract\tesseract.exe"
if os.path.exists(TESSERACT_DEFAULT):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_DEFAULT

LOCAL_TESSDATA = os.path.join(REPO_ROOT, "tessdata")
if os.path.exists(LOCAL_TESSDATA) and "TESSDATA_PREFIX" not in os.environ:
    os.environ["TESSDATA_PREFIX"] = LOCAL_TESSDATA

# Canonical Roots Mapping for F:\Aloha
CANONICAL_ROOTS = {
    "studios": "Studios",
    "movies": "Movies",
    "celebrities": "Celebrities",
    "collections": "Collections & Siterips",
    "photos": "Photos & Sets",
    "magazines": "Magazines & Docs"
}

ALL_CANONICAL_POOLS = [
    "Studios",
    "Movies",
    "Celebrities",
    "Collections & Siterips",
    "Photos & Sets"
]

# Known Performer Registry for Entity Disambiguation
KNOWN_PERFORMERS = [
    "Abella Danger", "Abbie Cornish", "Addison Timlin", "Aditi Rao", "Adriana Chechik",
    "Alec Knight", "Alexis Dziena", "Alexis Texas", "Ali Larter", "Ali Zafar", "Alina Lopez",
    "Allaura", "Alli", "Alyssa Milano", "Amanda Peet", "Amanda Seyfried", "Amber", "Amber Heard",
    "Ami", "Amy", "Amy Adams", "Amy Brooke", "Angela White", "Angelina", "Angelina Jolie",
    "Anna Chlumsky", "Anne Hathaway", "AnnMarie Rios", "Ashlee", "Ashley", "Ashley Hinshaw",
    "Ashley Judd", "Asia Argento", "Audrey Bitoni", "August Ames", "Autumn Falls", "Ava Addams",
    "Backroom Casting Couch", "Bella", "Blake Blossom", "Boxxy", "Brandie Love", "Brandi Love",
    "Brianna", "Brittany", "Cameron Diaz", "Carla Gugino", "Charlize Theron", "Charlotte Gainsbourg",
    "Chloe Sevigny", "Christina Koletsa", "Christina Ricci", "Claudine Digard", "Cory Chase",
    "Courteney Cox", "Dana Delany", "Debra Cole", "Demi Moore", "Diane Farr", "Diane Kruger",
    "Diane Lane", "Dillion Harper", "Elisha Cuthbert", "Eliza Dushku", "Ellie Eilish",
    "Elsa Jean", "Emily Browning", "Emily Willis", "Emmanuelle Beart", "Emmanuelle Vaugier",
    "Eva Green", "Eva Lovia", "Eva Mendes", "Gabbie Carter", "Gia Paige", "Gianna Michaels",
    "Gretchen Mol", "Halle Berry", "Heather Graham", "Helen Mirren", "Ivana Milicevic",
    "Izzy Green", "Jaime Pressly", "Jamie Lee Curtis", "Jana Kaderabkova", "Janice Griffith",
    "January Jones", "Jenna Jameson", "Jennifer Connelly", "Jennifer Tilly", "Jesse Jane",
    "Jessica Alba", "Jessica Biel", "Julia Alexandratou", "Julianna Guill", "Jules Jordan",
    "Julie Benz", "Kagney Linn Karter", "Katerina Stikoudi", "Kate Hudson", "Kate Winslet",
    "Katie Holmes", "Kelly Preston", "Kenna James", "Kendra Lust", "Kim Basinger",
    "Kim Cattrall", "Kirsten Dunst", "Kristen Bell", "Kristen Stewart", "Kyler Quinn",
    "Lana Rhoades", "Laura Prepon", "Lena Headey", "Lena Paul", "Lexi Belle", "Lexi Love",
    "Lindsay Lohan", "Lisa Ann", "Liv Tyler", "Liya Silver", "Lizzy Caplan", "Ludivine Sagnier",
    "Maitland Ward", "Malin Akerman", "Maria Bello", "Marion Cotillard", "Marisa Tomei",
    "Marketa Barnfield", "Mary Louise Parker", "Megan Fox", "Mia Khalifa", "Mia Malkova",
    "Michelle Pfeiffer", "Michelle Trachtenberg", "Mila Kunis", "Milla Jovovich", "Monica Bellucci",
    "Naomi Watts", "Natasha Henstridge", "Natalie Portman", "Nicole Aniston", "Nicole Kidman",
    "Nikoleta Ralli", "Olga Farmaki", "Olivia Wilde", "Pamela Anderson", "Penelope Cruz",
    "Penny Pax", "Peta Jensen", "Phoebe Cates", "Phoenix Marie", "Rachel Miner", "Rachel Weisz",
    "Reese Witherspoon", "Rhona Mitra", "Riley Reid", "Riley Steele", "Rinko Kikuchi",
    "Rocco Reed", "Rose McGowan", "Salma Hayek", "Sarah Michelle Gellar", "Sasha Grey",
    "Savannah Sixx", "Scarlit Scandal", "Scarlett Johansson", "Shannon Elizabeth", "Sharon Stone",
    "Sherilyn Fenn", "Sienna Miller", "Sophie Marceau", "Stephanie Niznik", "Susan Sarandon",
    "Tara Reid", "Teanna Trump", "Tori Black", "Uma Thurman", "Vana Barba", "Veronica Wasko",
    "Vina Sky", "Virginie Ledoyen", "Winona Ryder"
]

# Extended Studio Registry with Keywords and Custodian Signatures
EXTENDED_STUDIOS = {
    "Brazzers": {
        "aliases": ["brazzers", "brazzersexxtra", "brazzers network", "bzz", "zz series", "rk and brazzers"],
        "custodians": ["625 broadway", "m. dickinson", "manwin", "mindgeek", "mg freemium", "mg content"],
        "sub_sites": [
            "big tits at school", "doctor adventures", "mommy got boobs", "milfs like it big",
            "baby got boobs", "jugfuckers", "pornstars like it big", "teens like it big",
            "real wife stories", "hot and mean", "dirty masons"
        ]
    },
    "Bangbros": {
        "aliases": ["bangbros", "bang bros", "bangbus", "dorm invasion", "monsters of cock", "ass parade", "milf hunter", "big mouthfuls"],
        "custodians": ["carol santiago", "6955 nw 52 street", "miami, fl 33166", "bangbros network", "bang bros network"],
        "sub_sites": ["bangbus", "dorm invasion", "tugjobs", "brown bunnies", "monsters of cock", "ass parade", "milf hunter"]
    },
    "Digital Playground": {
        "aliases": ["digital playground", "digitalplayground", "dpg"],
        "custodians": ["digital playground inc", "chatsworth, ca 91311", "samir savoy", "digital playground"]
    },
    "Naughty America": {
        "aliases": ["naughty america", "naughtyamerica", "naughty athletic", "naughty bookworms", "my first sex teacher", "i have a wife", "tonights girlfriend"],
        "custodians": ["naughty america", "625 broadway"]
    },
    "Reality Kings": {
        "aliases": ["reality kings", "realitykings", "rk", "team skeet", "teamskeet"],
        "custodians": ["reality kings", "625 broadway", "mg content"],
        "sub_sites": ["captain stabbin", "monster curves", "round and brown", "pure 18", "street blowjobs", "crazy college girlfriends"]
    },
    "Vixen": {
        "aliases": ["vixen", "vixen media", "vixen.com", "vixen group"],
        "custodians": ["vixen media group", "luxembourg", "greg lansky"]
    },
    "Blacked": {
        "aliases": ["blacked", "blackedraw", "blacked raw"],
        "custodians": ["blacked", "vixen media group"]
    },
    "Tushy": {
        "aliases": ["tushy", "tushyraw", "tushy raw"],
        "custodians": ["tushy", "vixen media group"]
    },
    "Deeper": {
        "aliases": ["deeper", "deeper.com"],
        "custodians": ["deeper", "vixen media group"]
    },
    "Pure Taboo": {
        "aliases": ["pure taboo", "puretaboo"],
        "custodians": ["pure taboo", "vixen media group"]
    },
    "Evil Angel": {
        "aliases": ["evil angel", "evilangel", "john stagliano", "evil angel video"],
        "custodians": ["evil angel", "john stagliano", "chatsworth"]
    },
    "Jules Jordan": {
        "aliases": ["jules jordan", "julesjordan", "jules jordan video"],
        "custodians": ["jules jordan", "van nuys", "jules jordan video inc"]
    },
    "FuckedHard18": {
        "aliases": ["fuckedhard18", "fucked hard 18", "fh18", "fh 18"],
        "custodians": ["fuckedhard18"]
    },
    "Backroom Casting Couch": {
        "aliases": ["backroom casting couch", "backroomcastingcouch", "brcc", "backroomcastingcouch.com"],
        "custodians": ["backroom casting couch"]
    },
    "X-Art": {
        "aliases": ["x-art", "xart", "x art"],
        "custodians": ["x-art", "colette"]
    },
    "Brattysis": {
        "aliases": ["brattysis", "bratty sis"],
        "custodians": ["brattysis"]
    },
    "Wicked Pictures": {
        "aliases": ["wicked pictures", "wicked", "wicked sensual"],
        "custodians": ["wicked pictures", "canoga park", "steve orenstein"]
    },
    "Hustler": {
        "aliases": ["hustler", "hustler video", "lfp"],
        "custodians": ["larry flynt", "lfp video", "beverly hills"]
    },
    "Elegant Angel": {
        "aliases": ["elegant angel", "elegant angel video"],
        "custodians": ["elegant angel", "chatsworth", "patrick collins"]
    },
    "Sweetheart Video": {
        "aliases": ["sweetheart video", "sweetheartvideo", "mile high media"],
        "custodians": ["sweetheart video", "mile high"]
    },
    "Twistys": {
        "aliases": ["twistys", "twistys.com"],
        "custodians": ["twistys", "625 broadway"]
    },
    "Stolen Porn Videos": {
        "aliases": ["stolenpornvideos.com", "stolenpornvideos", "stolen porn videos"],
        "custodians": ["stolenpornvideos"]
    }
}

def init_cache_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visual_enrichment_cache (
                file_path TEXT PRIMARY KEY,
                oshash TEXT,
                file_size INTEGER,
                duration REAL,
                detected_studio TEXT,
                detected_performers TEXT,
                detected_title TEXT,
                detected_date TEXT,
                confidence REAL,
                method TEXT,
                details_json TEXT,
                processed_at TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_oshash ON visual_enrichment_cache(oshash);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_studio ON visual_enrichment_cache(detected_studio);")
    return conn

def backup_inventory_db(db_path: str, backup_path: Optional[str] = None) -> str:
    """Creates a safety snapshot backup of media_inventory.db before modifications."""
    if not backup_path:
        backup_path = os.path.join(os.path.dirname(os.path.abspath(db_path)), "media_inventory_pre_enrichment.bak")
    if os.path.exists(db_path) and not os.path.exists(backup_path):
        shutil.copy2(db_path, backup_path)
        print(f"[+] Safety snapshot created: '{backup_path}'.")
    return backup_path

def parse_pool_argument(pool_arg: str) -> List[str]:
    """Parses user pool argument into a list of canonical root directory names."""
    if not pool_arg or pool_arg.lower() == "all":
        return list(ALL_CANONICAL_POOLS)
    
    parts = [p.strip().lower() for p in pool_arg.split(",") if p.strip()]
    selected = []
    for p in parts:
        if p in CANONICAL_ROOTS:
            selected.append(CANONICAL_ROOTS[p])
        else:
            matched = False
            for canon in ALL_CANONICAL_POOLS:
                if p == canon.lower():
                    selected.append(canon)
                    matched = True
                    break
            if not matched and "games" not in p:
                selected.append(p)
    return selected

def select_candidates_from_db(
    inventory_db_path: str,
    pool_roots: List[str],
    sample_batch: int = 0
) -> List[str]:
    """Selects video assets needing metadata enrichment directly from media_inventory.db."""
    if not os.path.exists(inventory_db_path):
        print(f"[!] Inventory database '{inventory_db_path}' not found.")
        return []

    conn = sqlite3.connect(inventory_db_path, timeout=60.0)
    cur = conn.cursor()

    where_clauses = [
        "media_type = 'video'",
        "file_path NOT LIKE '%\\Games\\%'",
        "file_path NOT LIKE '%/Games/%'",
        "(studio IS NULL OR studio = '' OR existing_artist IS NULL OR existing_artist = '')"
    ]

    root_conditions = []
    for r in pool_roots:
        root_conditions.append(f"file_path LIKE 'F:\\Aloha\\{r}\\%'")
        root_conditions.append(f"file_path LIKE '%\\Aloha\\{r}\\%'")
        root_conditions.append(f"file_path LIKE '%/Aloha/{r}/%'")
    if root_conditions:
        where_clauses.append(f"({' OR '.join(root_conditions)})")

    sql = f"SELECT file_path FROM media_files WHERE {' AND '.join(where_clauses)}"
    rows = cur.execute(sql).fetchall()
    conn.close()

    candidates = []
    for (fpath,) in rows:
        if os.path.exists(to_extended_path(fpath)):
            candidates.append(fpath)

    if sample_batch > 0:
        candidates = candidates[:sample_batch]

    return candidates

def discover_target_files(root: str, pool_roots: List[str], sample_batch: int = 0) -> List[str]:
    """Discovers candidate video files by walking canonical roots, strictly isolating Games."""
    all_target_files = []
    for p in pool_roots:
        p_dir = os.path.join(root, p)
        if not os.path.exists(p_dir):
            continue
        for r, _, files in os.walk(p_dir):
            r_lower = r.lower()
            if "\\games\\" in r_lower or "/games/" in r_lower or r_lower.endswith("\\games") or r_lower.endswith("/games"):
                continue
            for f in files:
                if f.lower().endswith((".mp4", ".mkv", ".flv", ".avi", ".mov", ".wmv", ".m4v")):
                    all_target_files.append(os.path.join(r, f))

    if sample_batch > 0:
        all_target_files = all_target_files[:sample_batch]

    return all_target_files

def compute_oshash(file_path: str) -> str:
    """Computes standard 64-bit OpenSubtitles hash in ~1-10ms."""
    try:
        filesize = os.path.getsize(file_path)
        if filesize < 65536 * 2:
            return ""
        hash_val = filesize & 0xFFFFFFFFFFFFFFFF
        with open(file_path, "rb") as f:
            chunk1 = f.read(65536)
            nums1 = struct.unpack(f"<{len(chunk1)//8}Q", chunk1[:(len(chunk1)//8)*8])
            for n in nums1:
                hash_val = (hash_val + n) & 0xFFFFFFFFFFFFFFFF

            f.seek(max(0, filesize - 65536), 0)
            chunk2 = f.read(65536)
            nums2 = struct.unpack(f"<{len(chunk2)//8}Q", chunk2[:(len(chunk2)//8)*8])
            for n in nums2:
                hash_val = (hash_val + n) & 0xFFFFFFFFFFFFFFFF
        return f"{hash_val:016x}"
    except Exception:
        return ""

def clean_ocr_text(text: str) -> str:
    clean = re.sub(r"[^\w\s\-\.,/:'\"()&]", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean

def parse_2257_statement(text: str) -> Dict[str, Any]:
    """Parses 18 U.S.C. 2257 statement blocks for production date, title, and custodian."""
    info = {}
    text_lower = text.lower()
    
    # 1. Date extraction
    m_date = re.search(r"(?:produced\s+on|date\s+of\s+production|filmed\s+on)\s*:\s*(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})", text, re.IGNORECASE)
    if not m_date:
        m_date = re.search(r"\b(\d{4}[-/\.]\d{1,2}[-/\.]\d{1,2})\b", text)
    if m_date:
        raw_date = m_date.group(1).replace("/", "-").replace(".", "-")
        parts = raw_date.split("-")
        if len(parts) == 3:
            if len(parts[0]) == 4:
                y, m, d = parts[0], parts[1], parts[2]
            else:
                m, d, y = parts[0], parts[1], parts[2]
            if len(y) == 2:
                y = f"20{y}" if int(y) < 70 else f"19{y}"
            if len(m) == 1:
                m = f"0{m}"
            if len(d) == 1:
                d = f"0{d}"
            info["date"] = f"{y}-{m}-{d}"

    # 2. Title extraction
    m_title = re.search(r"Title\s*:\s*([^;\n\r]{3,80})", text, re.IGNORECASE)
    if m_title:
        candidate_title = m_title.group(1).strip()
        for kw in ["records", "pursuant", "u.s.c", "custodian", "in compliance", "all models", "section"]:
            pos = candidate_title.lower().find(kw)
            if pos != -1:
                candidate_title = candidate_title[:pos].strip()
        candidate_title = candidate_title.strip(" -.,:/")
        if candidate_title:
            info["title"] = candidate_title
            performers = [p.strip() for p in re.split(r"[/,]|(\s+and\s+)", candidate_title) if p and p.strip() and p.strip().lower() != "and"]
            if performers and all(len(p.split()) in (1, 2, 3) for p in performers):
                info["performers"] = performers

    # 3. Custodian & Studio resolution
    for studio_name, meta in EXTENDED_STUDIOS.items():
        for cust in meta.get("custodians", []):
            if cust in text_lower:
                info["studio"] = studio_name
                info["custodian_match"] = cust
                break
        if "studio" in info:
            break

    return info

def resolve_studio_from_ocr_tokens(tokens_str: str) -> Optional[Tuple[str, float]]:
    """Fuzzy and exact token matching against extended studio registry."""
    tokens_lower = tokens_str.lower()
    
    # 1. Exact alias / keyword scan
    for studio_name, meta in EXTENDED_STUDIOS.items():
        for alias in meta["aliases"]:
            pattern = r"\b" + re.escape(alias) + r"\b"
            if re.search(pattern, tokens_lower):
                return studio_name, 0.95

    # 2. Sub-site scan
    for studio_name, meta in EXTENDED_STUDIOS.items():
        for sub in meta.get("sub_sites", []):
            pattern = r"\b" + re.escape(sub) + r"\b"
            if re.search(pattern, tokens_lower):
                return studio_name, 0.90

    # 3. High-confidence fuzzy match across words
    for studio_name, meta in EXTENDED_STUDIOS.items():
        for alias in meta["aliases"]:
            if len(alias) >= 5:
                ratio = fuzz.partial_ratio(alias, tokens_lower)
                if ratio >= 90:
                    return studio_name, 0.82

    return None

def detect_performers_from_text(text: str, filename: str) -> List[str]:
    """Detects recognized performer names from combined text and filename."""
    found = set()
    combined_lower = f"{text.lower()} {filename.lower()}"

    for perf in KNOWN_PERFORMERS:
        perf_lower = perf.lower()
        pattern = r"\b" + re.escape(perf_lower) + r"\b"
        if re.search(pattern, combined_lower):
            found.add(perf)

    return sorted(list(found))

def quick_signature_match(file_path: str) -> Optional[Dict[str, Any]]:
    """Fast Tier 1 heuristic matching using folder paths, release codes, and performer patterns."""
    fname = os.path.basename(file_path)
    fname_lower = fname.lower()
    rel_lower = file_path.lower()
    
    studio = None
    confidence = 0.0
    method = None
    title = None
    performers = detect_performers_from_text("", fname)

    # 1. Backroom Casting Couch
    if "backroom casting couch" in rel_lower or "backroom.casting.couch" in rel_lower or "brcc" in fname_lower:
        studio = "Backroom Casting Couch"
        confidence = 0.95
        method = "brcc_code"

    # 2. Bangbros
    elif re.search(r"\bdi\d{4,6}\b", fname_lower) or "dorm invasion" in rel_lower:
        studio = "Bangbros"
        title = "Dorm Invasion"
        confidence = 0.95
        method = "bangbros_di_code"
    elif re.search(r"\bbb\d{4,6}\b", fname_lower) or "bangbus" in rel_lower:
        studio = "Bangbros"
        title = "Bangbus"
        confidence = 0.95
        method = "bangbros_bb_code"
    elif "bangbros" in rel_lower or "bangbros" in fname_lower or "bang bros" in rel_lower:
        studio = "Bangbros"
        confidence = 0.95
        method = "bangbros_token"

    # 3. Brazzers
    elif "brazzers" in rel_lower or any(code in fname_lower for code in ("vl0", "kf0", "btas", "mgb ", "mlib ", "bgb ")):
        studio = "Brazzers"
        confidence = 0.95
        method = "brazzers_code"

    # 4. Reality Kings
    elif "reality kings" in rel_lower or "realitykings" in rel_lower or "captain stabbin" in rel_lower:
        studio = "Reality Kings"
        confidence = 0.95
        method = "realitykings_token"

    # 5. FuckedHard18
    elif "fuckedhard18" in rel_lower or "fh18" in fname_lower or "fh 18" in fname_lower:
        studio = "FuckedHard18"
        confidence = 0.95
        method = "fh18_code"

    # 6. X-Art
    elif "x-art" in rel_lower or "x art" in rel_lower:
        studio = "X-Art"
        confidence = 0.95
        method = "xart_code"

    # 7. Digital Playground
    elif "digitalplayground" in rel_lower or "digital playground" in rel_lower:
        studio = "Digital Playground"
        confidence = 0.95
        method = "dpg_token"

    # 8. Vixen
    elif "vixen" in rel_lower or "vixen" in fname_lower:
        studio = "Vixen"
        confidence = 0.95
        method = "vixen_token"

    # 9. Blacked
    elif "blacked" in rel_lower or "blackedraw" in rel_lower:
        studio = "Blacked"
        confidence = 0.95
        method = "blacked_token"

    # 10. Tushy
    elif "tushy" in rel_lower or "tushyraw" in rel_lower:
        studio = "Tushy"
        confidence = 0.95
        method = "tushy_token"

    # 11. Deeper
    elif "deeper" in rel_lower and ("deeper.com" in rel_lower or "deeper" in fname_lower):
        studio = "Deeper"
        confidence = 0.95
        method = "deeper_token"

    # 12. Evil Angel
    elif "evil angel" in rel_lower or "evilangel" in rel_lower:
        studio = "Evil Angel"
        confidence = 0.95
        method = "evilangel_token"

    # 13. Jules Jordan
    elif "jules jordan" in rel_lower or "julesjordan" in rel_lower:
        studio = "Jules Jordan"
        confidence = 0.95
        method = "julesjordan_token"

    # 14. Pure Taboo
    elif "pure taboo" in rel_lower or "puretaboo" in rel_lower:
        studio = "Pure Taboo"
        confidence = 0.95
        method = "puretaboo_token"

    # 15. Brattysis
    elif "brattysis" in rel_lower or "bratty sis" in rel_lower:
        studio = "Brattysis"
        confidence = 0.95
        method = "brattysis_token"

    # 16. Naughty America
    elif "naughty america" in rel_lower or "naughtyamerica" in rel_lower:
        studio = "Naughty America"
        confidence = 0.95
        method = "naughtyamerica_token"

    # 17. Stolen Porn Videos
    elif "stolenpornvideos" in rel_lower or "stolen porn vid" in fname_lower:
        studio = "Stolen Porn Videos"
        confidence = 0.90
        method = "stolenporn_token"

    if studio:
        return {
            "file_path": file_path,
            "filename": fname,
            "detected_studio": studio,
            "detected_performers": performers,
            "detected_title": title,
            "detected_date": None,
            "confidence": confidence,
            "method": method,
            "ocr_snippets": [],
            "raw_tokens": []
        }
    return None

def extract_visual_metadata_from_video(file_path: str) -> Dict[str, Any]:
    """Captures keyframes at intro (3s, 8s, 15s, 25s) and outro (final 30s) to extract OCR text and 2257 data."""
    fast_match = quick_signature_match(file_path)
    if fast_match and fast_match["confidence"] >= 0.90:
        return fast_match

    result = {
        "file_path": file_path,
        "filename": os.path.basename(file_path),
        "detected_studio": None,
        "detected_performers": [],
        "detected_title": None,
        "detected_date": None,
        "confidence": 0.0,
        "method": "none",
        "ocr_snippets": [],
        "raw_tokens": []
    }

    cap = cv2.VideoCapture(to_extended_path(file_path))
    if not cap.isOpened():
        result["error"] = "Failed to open video file"
        return result

    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0
    duration = frame_count / fps if fps > 0 else 0
    result["duration"] = duration

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    all_extracted_text = []

    def extract_from_frame(frame_img, label_prefix):
        h, w = frame_img.shape[:2]
        if h < 50 or w < 50:
            return []
        crops = [
            ("full", frame_img),
            ("lower", frame_img[int(h * 0.68):, :]),
            ("br", frame_img[int(h * 0.70):, int(w * 0.65):]),
            ("tl", frame_img[:int(h * 0.35), :int(w * 0.40)])
        ]
        snippets = []
        for zone_name, crop_img in crops:
            try:
                gray = cv2.cvtColor(crop_img, cv2.COLOR_BGR2GRAY)
                enhanced = clahe.apply(gray)
                raw_txt = pytesseract.image_to_string(enhanced, timeout=3)
                cleaned = clean_ocr_text(raw_txt)
                if len(cleaned) >= 3:
                    all_extracted_text.append((label_prefix, zone_name, cleaned))
                    snippets.append(cleaned)
                    result["ocr_snippets"].append(f"[{label_prefix} {zone_name}]: {cleaned}")
            except Exception:
                pass
        return snippets

    # Stage 2: Intro Title Card OCR (3s, 8s, 15s, 25s)
    intro_timestamps = [3, 8, 15, 25]
    for ts in intro_timestamps:
        if ts > duration and duration > 0:
            continue
        cap.set(cv2.CAP_PROP_POS_MSEC, ts * 1000)
        ret, frame = cap.read()
        if not ret or frame is None:
            continue

        snippets = extract_from_frame(frame, f"{ts:02d}s")
        combined_ts = " ".join(snippets)

        info_2257 = parse_2257_statement(combined_ts)
        if info_2257.get("studio"):
            result["detected_studio"] = info_2257["studio"]
            result["confidence"] = 0.98
            result["method"] = "2257_custodian"
            if info_2257.get("title"):
                result["detected_title"] = info_2257["title"]
            if info_2257.get("date"):
                result["detected_date"] = info_2257["date"]
            if info_2257.get("performers"):
                result["detected_performers"] = info_2257["performers"]
            break

        studio_match = resolve_studio_from_ocr_tokens(combined_ts)
        if studio_match:
            result["detected_studio"], conf = studio_match
            result["confidence"] = conf
            result["method"] = "intro_logo_ocr"
            break

    # Stage 3: Outro 2257 Custodian OCR (final 30 seconds)
    if (not result["detected_studio"] or result["confidence"] < 0.85) and duration > 35:
        outro_candidates = [
            max(duration - 25.0, 0.0),
            max(duration - 15.0, 0.0),
            max(duration - 6.0, 0.0),
            max(duration - 2.0, 0.0)
        ]
        outro_timestamps = sorted(list({round(t, 1) for t in outro_candidates if t > 25}))
        for ts in outro_timestamps:
            cap.set(cv2.CAP_PROP_POS_MSEC, int(ts * 1000))
            ret, frame = cap.read()
            if not ret or frame is None:
                continue

            snippets = extract_from_frame(frame, f"{int(ts):02d}s_outro")
            combined_ts = " ".join(snippets)

            info_2257 = parse_2257_statement(combined_ts)
            if info_2257.get("studio"):
                result["detected_studio"] = info_2257["studio"]
                result["confidence"] = 0.98
                result["method"] = "outro_2257_custodian"
                if info_2257.get("title"):
                    result["detected_title"] = info_2257["title"]
                if info_2257.get("date"):
                    result["detected_date"] = info_2257["date"]
                if info_2257.get("performers"):
                    result["detected_performers"] = info_2257["performers"]
                break

            studio_match = resolve_studio_from_ocr_tokens(combined_ts)
            if studio_match and (not result["detected_studio"] or studio_match[1] > result["confidence"]):
                result["detected_studio"], conf = studio_match
                result["confidence"] = conf
                result["method"] = "outro_logo_ocr"
                if conf >= 0.85:
                    break

    cap.release()

    combined_text = " ".join([txt for _, _, txt in all_extracted_text])
    result["raw_tokens"] = list(set(combined_text.split()))

    # Fallback to combined text
    if not result["detected_studio"]:
        info_2257 = parse_2257_statement(combined_text)
        if info_2257.get("studio"):
            result["detected_studio"] = info_2257["studio"]
            result["confidence"] = 0.98
            result["method"] = "2257_custodian"
            if info_2257.get("title"):
                result["detected_title"] = info_2257["title"]
            if info_2257.get("date"):
                result["detected_date"] = info_2257["date"]
            if info_2257.get("performers"):
                result["detected_performers"] = info_2257["performers"]
        else:
            studio_match = resolve_studio_from_ocr_tokens(combined_text)
            if studio_match:
                result["detected_studio"], conf = studio_match
                result["confidence"] = conf
                result["method"] = "intro_logo_ocr"

    # Performer detection fallback
    if not result["detected_performers"]:
        detected_perfs = detect_performers_from_text(combined_text, result["filename"])
        if detected_perfs:
            result["detected_performers"] = detected_perfs
            if not result["detected_studio"] and result["confidence"] < 0.75:
                result["confidence"] = 0.75
                result["method"] = "known_performer"

    return result

def sync_to_inventory_db(db_path: str, results: List[Dict[str, Any]], undo_ledger_path: str = "undo_ledger.db"):
    """Updates media_inventory.db with enriched metadata for current and ledger-tracked paths."""
    if not os.path.exists(db_path):
        print(f"[!] Warning: Inventory DB '{db_path}' not found.")
        return

    # Create safety backup snapshot before bulk update
    backup_inventory_db(db_path)

    conn = sqlite3.connect(db_path, timeout=60.0)
    with conn:
        cols = [c[1] for c in conn.execute("PRAGMA table_info(media_files)").fetchall()]
        if "studio" not in cols:
            conn.execute("ALTER TABLE media_files ADD COLUMN studio TEXT;")
        if "confidence_score" not in cols:
            conn.execute("ALTER TABLE media_files ADD COLUMN confidence_score REAL;")
        if "needs_review" not in cols:
            conn.execute("ALTER TABLE media_files ADD COLUMN needs_review INTEGER DEFAULT 0;")

    reverse_map = {}
    if os.path.exists(undo_ledger_path):
        uconn = sqlite3.connect(undo_ledger_path)
        for orig, target in uconn.execute("SELECT original_path, target_path FROM transactions").fetchall():
            reverse_map[target.lower()] = orig

    updated_count = 0
    with conn:
        for r in results:
            conf = r.get("confidence", 0.0)
            # Scores < 0.60 are kept unassigned to preserve database cleanliness
            if conf < 0.60:
                continue

            studio = r.get("detected_studio")
            title = r.get("detected_title")
            perfs = r.get("detected_performers", [])
            perf_str = ", ".join(perfs) if perfs else None
            date = r.get("detected_date")
            fpath = r.get("file_path", "")
            needs_review = 1 if conf < 0.85 else 0

            candidates = [fpath]
            if fpath.lower() in reverse_map:
                candidates.append(reverse_map[fpath.lower()])

            for p in candidates:
                cur = conn.execute("""
                    UPDATE media_files
                    SET studio = COALESCE(?, studio),
                        confidence_score = COALESCE(?, confidence_score),
                        existing_title = COALESCE(?, existing_title),
                        existing_artist = COALESCE(?, existing_artist),
                        existing_date = COALESCE(?, existing_date),
                        needs_review = ?
                    WHERE file_path = ?
                """, (studio, conf, title, perf_str, date, needs_review, p))
                if cur.rowcount > 0:
                    updated_count += cur.rowcount

    print(f"[+] Synchronized {updated_count} records in '{db_path}'.")

def tag_video_containers(results: List[Dict[str, Any]]):
    """Applies lossless metadata tagging to MP4 video container headers for high-confidence records."""
    tagged_count = 0
    for r in results:
        # Confidence threshold gating: only tag containers if confidence >= 0.85
        if r.get("confidence", 0.0) < 0.85:
            continue

        fpath = r.get("file_path", "")
        if not os.path.exists(fpath):
            continue
        ext = os.path.splitext(fpath)[1].lower()
        if ext not in (".mp4", ".m4v"):
            continue

        tag_dict = {
            "title": r.get("detected_title") or r.get("filename"),
            "performers": r.get("detected_performers"),
            "studio": r.get("detected_studio"),
            "date": r.get("detected_date")
        }
        res = tag_media_file(fpath, tag_dict)
        if res.get("tagged"):
            tagged_count += 1

    print(f"[+] Losslessly tagged {tagged_count} MP4 video containers (confidence >= 0.85).")

def process_single_asset(fpath: str, cached_data: Optional[Tuple], recheck_low_conf: bool = False) -> Dict[str, Any]:
    """Worker function for single asset inspection."""
    fname = os.path.basename(fpath)
    oshash = compute_oshash(fpath)
    fsize = os.path.getsize(fpath) if os.path.exists(fpath) else 0

    if cached_data:
        studio = cached_data[0]
        perfs = json.loads(cached_data[1]) if cached_data[1] else []
        title = cached_data[2]
        date = cached_data[3]
        conf = cached_data[4] or 0.0
        method = cached_data[5]
        
        # If cache has high confidence, reuse it directly
        if conf >= 0.85 or not recheck_low_conf:
            if not perfs:
                perfs = detect_performers_from_text("", fname)
            return {
                "file_path": fpath,
                "filename": fname,
                "oshash": oshash,
                "file_size": fsize,
                "detected_studio": studio,
                "detected_performers": perfs,
                "detected_title": title,
                "detected_date": date,
                "confidence": conf,
                "method": method,
                "is_cached": True
            }

    # Run visual and heuristic extractor
    meta = extract_visual_metadata_from_video(fpath)
    meta["oshash"] = oshash
    meta["file_size"] = fsize
    meta["is_cached"] = False
    return meta

def run_full_pool_evaluation(
    target_files: List[str],
    cache_conn: sqlite3.Connection,
    num_workers: int = 4,
    recheck_low_conf: bool = False
) -> List[Dict[str, Any]]:
    """Evaluates candidate files with multithreading and batched cache writes."""
    results = []
    print(f"[*] Starting Visual Extraction across {len(target_files)} video assets...")
    print(f"[*] Worker concurrency: {num_workers} threads.\n")

    cur = cache_conn.cursor()
    cached_map = {}
    for row in cur.execute("SELECT file_path, detected_studio, detected_performers, detected_title, detected_date, confidence, method FROM visual_enrichment_cache").fetchall():
        cached_map[os.path.normpath(row[0]).lower()] = row[1:]

    newly_processed = 0
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {
            executor.submit(
                process_single_asset,
                fpath,
                cached_map.get(os.path.normpath(fpath).lower()),
                recheck_low_conf
            ): fpath
            for fpath in target_files
        }

        pbar = tqdm(total=len(target_files), desc="Visual Extraction Progress", unit="file")
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            pbar.update(1)

            if not res.get("is_cached"):
                newly_processed += 1
                try:
                    with cache_conn:
                        cache_conn.execute("""
                            INSERT OR REPLACE INTO visual_enrichment_cache
                            (file_path, oshash, file_size, duration, detected_studio, detected_performers, detected_title, detected_date, confidence, method, details_json, processed_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                        """, (
                            res["file_path"],
                            res.get("oshash", ""),
                            res.get("file_size", 0),
                            res.get("duration", 0.0),
                            res.get("detected_studio"),
                            json.dumps(res.get("detected_performers", [])),
                            res.get("detected_title"),
                            res.get("detected_date"),
                            res.get("confidence", 0.0),
                            res.get("method", "none"),
                            json.dumps({"snippets": res.get("ocr_snippets", [])[:5]})
                        ))
                except Exception:
                    pass

        pbar.close()

    print(f"\n[+] Pool evaluation complete. Newly analyzed: {newly_processed}, Cache hits: {len(target_files) - newly_processed}")
    return results

def print_enrichment_dashboard(results: List[Dict[str, Any]]):
    print("\n" + "=" * 105)
    print("                      VISUAL EXTRACTION ENRICHMENT SUMMARY REPORT                      ")
    print("=" * 105)
    
    studio_counts = {}
    resolved_count = 0
    high_confidence_count = 0
    review_needed_count = 0
    low_confidence_count = 0

    for r in results:
        studio = r.get("detected_studio")
        conf = r.get("confidence", 0.0)

        if studio or r.get("detected_performers"):
            resolved_count += 1
        if conf >= 0.85:
            high_confidence_count += 1
        elif conf >= 0.60:
            review_needed_count += 1
        else:
            low_confidence_count += 1

        if studio:
            studio_counts[studio] = studio_counts.get(studio, 0) + 1

    total = len(results) if results else 1
    res_rate = (resolved_count / total) * 100
    high_conf_rate = (high_confidence_count / total) * 100
    review_rate = (review_needed_count / total) * 100
    low_conf_rate = (low_confidence_count / total) * 100

    print(f"Total Evaluated Assets:       {len(results):,}")
    print(f"Successfully Resolved:        {resolved_count:,} ({res_rate:.1f}%)")
    print(f"High Confidence (>=0.85):     {high_confidence_count:,} ({high_conf_rate:.1f}%) [Auto-Sync & Tag]")
    print(f"Needs Review (0.60 to 0.84):  {review_needed_count:,} ({review_rate:.1f}%) [Candidate Sync]")
    print(f"Unassigned (<0.60):           {low_confidence_count:,} ({low_conf_rate:.1f}%) [Skipped]")
    print("-" * 105)
    print("Top Identified Studios / Networks:")
    for studio, count in sorted(studio_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"  - {studio:<28}: {count:>4,} files")
    print("=" * 105 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Deep Visual Inspection & Community Metadata Extractor")
    parser.add_argument("--root", default=r"F:\Aloha", help="Root directory (default F:\\Aloha)")
    parser.add_argument("--pool", default="all", help="Target pool: all, studios, movies, celebrities, collections, photos, or comma-separated roots")
    parser.add_argument("--target-missing", action="store_true", help="Query media_inventory.db directly for missing studio/performer records")
    parser.add_argument("--sample-batch", type=int, default=0, help="Number of files to sample (0 = full pool)")
    parser.add_argument("--workers", type=int, default=4, help="Thread concurrency for inspection")
    parser.add_argument("--output-report", default="visual_enrichment_report.json", help="Path for output JSON report")
    parser.add_argument("--db-cache", default="visual_enrichment_cache.db", help="Path for SQLite cache DB")
    parser.add_argument("--sync-db", action="store_true", help="Synchronize detected metadata into media_inventory.db")
    parser.add_argument("--tag-containers", action="store_true", help="Inject lossless tags into MP4 container headers (confidence >= 0.85)")
    parser.add_argument("--recheck-low-conf", action="store_true", help="Re-evaluate cached items having confidence < 0.85")
    args = parser.parse_args()

    cache_conn = init_cache_db(args.db_cache)
    pool_roots = parse_pool_argument(args.pool)
    inventory_db_path = os.path.join(REPO_ROOT, "media_inventory.db")

    if args.target_missing:
        print(f"[*] Selecting candidate assets from database '{inventory_db_path}'...")
        all_target_files = select_candidates_from_db(inventory_db_path, pool_roots, args.sample_batch)
    else:
        print(f"[*] Discovering candidate assets from root '{args.root}' across pools: {pool_roots}...")
        all_target_files = discover_target_files(args.root, pool_roots, args.sample_batch)

    print(f"[*] Discovered {len(all_target_files)} candidate videos to evaluate.")
    results = run_full_pool_evaluation(
        all_target_files,
        cache_conn,
        num_workers=args.workers,
        recheck_low_conf=args.recheck_low_conf
    )
    print_enrichment_dashboard(results)

    # Save output report
    with open(args.output_report, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "total_files": len(results),
                "resolved_count": sum(1 for r in results if r.get("detected_studio") or r.get("detected_performers")),
                "high_confidence_count": sum(1 for r in results if r.get("confidence", 0) >= 0.85),
                "review_needed_count": sum(1 for r in results if 0.60 <= r.get("confidence", 0) < 0.85),
                "low_confidence_count": sum(1 for r in results if r.get("confidence", 0) < 0.60)
            },
            "records": results
        }, f, indent=2)
    print(f"[+] Output report written to '{args.output_report}'.")

    if args.sync_db:
        sync_to_inventory_db(inventory_db_path, results)

    if args.tag_containers:
        tag_video_containers(results)

if __name__ == "__main__":
    main()
