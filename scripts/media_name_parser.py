import os
import re
import sys
from typing import Dict, Any, Optional, Tuple

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Canonical Studio Mappings
STUDIO_MAP = {
    "brazzersexxtra": "Brazzers Exxtra",
    "brazzers": "Brazzers",
    "digitalplayground": "Digital Playground",
    "dpg": "Digital Playground",
    "vixen": "Vixen",
    "bangbus": "Bangbus",
    "bb": "Bangbus",
    "fuckedhard18": "FuckedHard18",
    "fh18": "FuckedHard18",
    "tonightsgirlfriend": "Tonights Girlfriend",
    "tonights.girlfriend": "Tonights Girlfriend",
    "tngf": "Tonights Girlfriend",
    "puretaboo": "Pure Taboo",
    "brattysis": "Brattysis",
    "blackedraw": "Blacked Raw",
    "blacked": "Blacked",
    "tushyraw": "Tushy Raw",
    "tushy": "Tushy",
    "naughtyamerica": "Naughty America",
    "realitykings": "Reality Kings",
    "backroomcastingcouch": "Backroom Casting Couch",
    "backroom.casting.couch": "Backroom Casting Couch",
    "brcc": "Backroom Casting Couch",
    "sweetheartvideo": "Sweetheart Video",
    "wicked": "Wicked Pictures",
    "twistys": "Twistys",
    "mofos": "Mofos",
    "evilangel": "Evil Angel",
    "julesjordan": "Jules Jordan",
    "teamskeet": "TeamSkeet",
    "fakehub": "Fake Hub",
    "faketaxi": "Fake Taxi",
    "freeze": "Freeze",
    "deeper": "Deeper",
    "tushy": "Tushy",
    "milfed": "Milfed",
    "sislovesme": "SisLovesMe",
    "familystrokes": "FamilyStrokes",
    "rk": "Reality Kings"
}

# Bloat Scene Patterns to strip
SCENE_BLOAT_PATTERNS = [
    re.compile(r"[-._\s]+XXX[-._\s]+", re.IGNORECASE),
    re.compile(r"[-._\s]+XXXClub\.to[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+rarbg[-._\s]*", re.IGNORECASE),
    re.compile(r"\[rarbg\]", re.IGNORECASE),
    re.compile(r"\[XC\]", re.IGNORECASE),
    re.compile(r"\[eztv\]", re.IGNORECASE),
    re.compile(r"[-._\s]+MP4-[A-Z0-9]+(\[[^\]]*\])?", re.IGNORECASE),
    re.compile(r"[-._\s]+MKV-[A-Z0-9]+(\[[^\]]*\])?", re.IGNORECASE),
    re.compile(r"[-._\s]+BDRip[-._\s]*[A-Z0-9]*", re.IGNORECASE),
    re.compile(r"[-._\s]+DVDRip[-._\s]*[A-Z0-9]*", re.IGNORECASE),
    re.compile(r"[-._\s]+WEB-DL[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+WEBRip[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+HDTV[-._\s]*", re.IGNORECASE),
    re.compile(r"\[720p\s*HD\]", re.IGNORECASE),
    re.compile(r"\[1080p\s*HD\]", re.IGNORECASE),
    re.compile(r"\[720p\]", re.IGNORECASE),
    re.compile(r"\[1080p\]", re.IGNORECASE),
    re.compile(r"\[4k\]", re.IGNORECASE),
    re.compile(r"\[2160p\]", re.IGNORECASE),
    re.compile(r"[-._\s]+(2160p|1080p|720p|480p|360p|4k|540p|1080|720|480)[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+(h264|h265|hevc|x264|x265|avc|av1|vp9|aac|mp3|dts|ac3)[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+_\d{3,4}$", re.IGNORECASE), # e.g. _3000, _2000
    re.compile(r"[-._\s]+_lrg$", re.IGNORECASE),
    re.compile(r"[-._\s]+--_fitgirl-repacks\.site[-._\s]*", re.IGNORECASE),
    re.compile(r"[-._\s]+Seaporn\.org[-._\s]*", re.IGNORECASE),
]

FORBIDDEN_WIN_CHARS = re.compile(r'[<>:"/\\|?*]')

def sanitize_win_filename(name: str) -> str:
    # Replace forbidden characters with safe equivalents
    clean = FORBIDDEN_WIN_CHARS.sub(" - ", name)
    # Collapse multiple spaces
    clean = re.sub(r"[ \t]+", " ", clean)
    # Collapse multiple consecutive dashes e.g. " -  - " -> " - "
    clean = re.sub(r"( - ){2,}", " - ", clean)
    # Strip leading/trailing dots and spaces
    clean = clean.strip(" .")
    return clean

def to_extended_path(p: str) -> str:
    r"""Format path with \\?\ if on Windows and length exceeds 240 chars."""
    norm = os.path.abspath(p)
    if os.name == "nt" and len(norm) > 240 and not norm.startswith("\\\\?\\"):
        return "\\\\?\\" + norm
    return norm

def normalize_date(date_str: str) -> Optional[str]:
    """Converts YY.MM.DD, YYYY.MM.DD, YYYY-MM-DD, or YYYY_MM_DD to YYYY-MM-DD."""
    if not date_str:
        return None
    date_str = date_str.strip()
    
    # Check YYYY-MM-DD or YYYY.MM.DD or YYYY_MM_DD
    m4 = re.match(r"^(\d{4})[-._](\d{2})[-._](\d{2})$", date_str)
    if m4:
        return f"{m4.group(1)}-{m4.group(2)}-{m4.group(3)}"
        
    # Check YY.MM.DD or YY-MM-DD or YY_MM_DD
    m2 = re.match(r"^(\d{2})[-._](\d{2})[-._](\d{2})$", date_str)
    if m2:
        yy = int(m2.group(1))
        # 1970 - 2069 threshold
        year = 1900 + yy if yy > 69 else 2000 + yy
        return f"{year:04d}-{m2.group(2)}-{m2.group(3)}"
        
    # Check single 4-digit year (YYYY)
    m_yr = re.match(r"^(\d{4})$", date_str)
    if m_yr:
        return f"{m_yr.group(1)}"
        
    return None

def clean_title_case(text: str) -> str:
    """Converts dot-separated or underscore-separated words into clean Title Case."""
    if not text:
        return ""
    words = re.split(r"[-._\s]+", text)
    clean_words = []
    minor_words = {"a", "an", "the", "and", "but", "or", "for", "nor", "on", "at", "to", "from", "by", "with", "in", "of", "my"}
    for i, w in enumerate(words):
        if not w:
            continue
        w_lower = w.lower()
        if i > 0 and w_lower in minor_words:
            clean_words.append(w_lower)
        else:
            clean_words.append(w.capitalize())
    return " ".join(clean_words)

def extract_studio_from_path(file_path: str, filename: str) -> Optional[str]:
    """Infers studio/source from directory hierarchy and filename tokens."""
    parts = os.path.normpath(file_path).split(os.sep)
    # Check parent directory names
    for part in reversed(parts[:-1]):
        part_clean = re.sub(r"[^a-zA-Z0-9]", "", part).lower()
        for k, v in STUDIO_MAP.items():
            if k == part_clean or part_clean.startswith(k):
                return v

    # Check filename prefix
    prefix = filename.split(".")[0].lower()
    prefix_clean = re.sub(r"[^a-zA-Z0-9]", "", prefix)
    for k, v in STUDIO_MAP.items():
        if k == prefix_clean:
            return v
    return None

def parse_video_filename(filename: str, parent_path: str = "", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Parses video filename and extracts:
    - studio
    - date (YYYY-MM-DD or YYYY)
    - performer(s)
    - title
    - resolution_tag (e.g. 1080p, 720p)
    - codec_tag (e.g. H264, AV1, HEVC)
    - clean standardized filename
    """
    base, ext = os.path.splitext(filename)
    meta = metadata or {}
    
    studio = extract_studio_from_path(parent_path, filename)
    date = None
    performers = []
    title = ""
    
    # 1. Check Scene Release format: Studio.YY.MM.DD.Performer.And.Performer.Title.XXX.Resolution...
    # e.g. BrazzersExxtra.21.11.13.Billie.Star.And.Tina.Fire.Big.Tits.Hit.The.Gym.XXX.480p.MP4-XXX
    scene_match = re.search(r"^([a-zA-Z0-9]+)[-._](\d{2}[-._]\d{2}[-._]\d{2}|\d{4}[-._]\d{2}[-._]\d{2})[-._](.*)$", base)
    if scene_match:
        studio_cand = scene_match.group(1).lower()
        matched_studio = STUDIO_MAP.get(studio_cand, STUDIO_MAP.get(re.sub(r"[^a-zA-Z0-9]", "", studio_cand), None))
        if matched_studio:
            studio = matched_studio
        date = normalize_date(scene_match.group(2))
        remainder = scene_match.group(3)
        
        # Strip bloat from remainder
        for pat in SCENE_BLOAT_PATTERNS:
            remainder = pat.sub(" ", remainder)
            
        # Look for "And" or "Featuring" or performer separator
        # e.g. Billie.Star.And.Tina.Fire.Big.Tits...
        rem_clean = clean_title_case(remainder.strip())
        title = rem_clean

    # 2. Check Standard "Studio - Performer - Title" or "Studio - Performer" format
    # e.g. Vixen - Ellie Eilish - Treat Me Right
    # e.g. FuckedHard18 - Janice Griffith [720p]
    elif " - " in base:
        parts = [p.strip() for p in base.split(" - ")]
        for pat in SCENE_BLOAT_PATTERNS:
            parts = [pat.sub(" ", p).strip() for p in parts]
            
        if len(parts) >= 3:
            # Studio - Performer - Title
            s_cand = parts[0].lower()
            studio = STUDIO_MAP.get(s_cand, STUDIO_MAP.get(re.sub(r"[^a-zA-Z0-9]", "", s_cand), parts[0]))
            performers.append(clean_title_case(parts[1]))
            title = clean_title_case(" - ".join(parts[2:]))
        elif len(parts) == 2:
            s_cand = parts[0].lower()
            studio = STUDIO_MAP.get(s_cand, STUDIO_MAP.get(re.sub(r"[^a-zA-Z0-9]", "", s_cand), parts[0]))
            title = clean_title_case(parts[1])
        else:
            title = clean_title_case(parts[0])

    # 3. Check Bangbus short code format: bb6463_3000.mp4
    elif re.match(r"^bb(\d{3,5})(_\d+)?$", base, re.IGNORECASE):
        m = re.match(r"^bb(\d{3,5})", base, re.IGNORECASE)
        code = m.group(1)
        studio = "Bangbus"
        title = f"Episode {code}"

    # 4. Check Tonights Girlfriend short code format: tngfalannahbrandon.1080.mp4
    elif base.lower().startswith("tngf"):
        studio = "Tonights Girlfriend"
        clean_rem = base[4:]
        for pat in SCENE_BLOAT_PATTERNS:
            clean_rem = pat.sub(" ", clean_rem)
        title = clean_title_case(clean_rem)

    # 5. Check Movie title with Year: e.g. Babysitters 2 XXX 2011 Digital Playground 720p WEB-DL
    # e.g. Stoya Workaholic (Robby D, Digital Playground) (2009) BDRip-AVC
    else:
        # Check if year exists e.g. (2009) or 2011
        yr_match = re.search(r"[\(\s](\d{4})[\)\s]", base)
        if yr_match:
            year = yr_match.group(1)
            if 1950 <= int(year) <= 2030:
                date = year
        
        clean_name = base
        for pat in SCENE_BLOAT_PATTERNS:
            clean_name = pat.sub(" ", clean_name)
        title = clean_title_case(clean_name)

    # Fallback to existing metadata if title is empty or generic
    if not title or title.lower() in ("untitled", "unknown", "video"):
        if meta.get("existing_title"):
            title = clean_title_case(meta["existing_title"])
        else:
            title = clean_title_case(base)

    # Format technical resolution & codec tag
    res_tier = meta.get("resolution_tier")
    if not res_tier or res_tier == "Unknown":
        w = meta.get("width", 0)
        h = meta.get("height", 0)
        if h >= 2160 or w >= 3840:
            res_tier = "4K"
        elif h >= 1080 or w >= 1920:
            res_tier = "1080p"
        elif h >= 720 or w >= 1280:
            res_tier = "720p"
        elif h >= 480 or w >= 854:
            res_tier = "480p"
        else:
            res_tier = ""

    v_codec = (meta.get("v_codec") or "").upper()
    if v_codec in ("AVC", "AVC1", "H264"):
        v_codec = "H264"
    elif v_codec in ("HEVC", "H265"):
        v_codec = "HEVC"
    elif v_codec == "AV1":
        v_codec = "AV1"

    tech_parts = []
    if res_tier and res_tier not in ("SD", "Unknown"):
        tech_parts.append(res_tier)
    if v_codec and v_codec not in ("NONE", "UNKNOWN", "OTHER"):
        tech_parts.append(v_codec)
    tech_tag = f"[{' '.join(tech_parts)}]" if tech_parts else ""

    # Construct Canonical Standard Standardized Filename
    # [Studio/Source] [YYYY-MM-DD] Performer(s) - Scene Title [Resolution Codec].ext
    name_components = []
    if studio:
        name_components.append(f"[{studio}]")
    if date:
        name_components.append(f"[{date}]")
        
    perf_str = ", ".join(performers) if performers else ""
    if perf_str and title and perf_str not in title:
        main_desc = f"{perf_str} - {title}"
    else:
        main_desc = title or "Scene"

    name_components.append(main_desc)
    if tech_tag:
        name_components.append(tech_tag)

    canonical_name = " ".join(name_components) + ext
    safe_name = sanitize_win_filename(canonical_name)

    return {
        "studio": studio,
        "date": date,
        "performers": performers,
        "title": title,
        "tech_tag": tech_tag,
        "standardized_filename": safe_name
    }

def parse_image_filename(filename: str, parent_path: str = "", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Parses image filename and formats:
    [Source/Set] [YYYY-MM-DD] Set Name - 001.jpg
    """
    base, ext = os.path.splitext(filename)
    meta = metadata or {}
    
    parent_dir = os.path.basename(parent_path) if parent_path else ""
    studio = extract_studio_from_path(parent_path, filename)
    
    # Check EXIF date
    date = None
    if meta.get("exif_datetime"):
        dt = meta["exif_datetime"].split()[0].replace(":", "-")
        date = normalize_date(dt)

    # Check parent directory for set name and date
    set_name = parent_dir
    for pat in SCENE_BLOAT_PATTERNS:
        set_name = pat.sub(" ", set_name)
    set_name = clean_title_case(set_name)
    if studio and set_name.lower().startswith(studio.lower()):
        set_name = set_name[len(studio):].strip(" -._")

    # Check if base is purely numeric index (e.g. "1", "02", "14")
    if base.strip().isdigit():
        idx_num = int(base.strip())
        idx_str = f"{idx_num:03d}"
        is_index = True
    else:
        # Descriptive image filename
        clean_base = base
        for pat in SCENE_BLOAT_PATTERNS:
            clean_base = pat.sub(" ", clean_base)
        idx_str = clean_title_case(clean_base)
        is_index = False

    components = []
    if studio:
        components.append(f"[{studio}]")
    if date:
        components.append(f"[{date}]")
        
    if set_name and set_name not in ("Aloha", "Temp", "Images", "Girls", "Celeb", "Gif"):
        if is_index:
            components.append(f"{set_name} - {idx_str}")
        else:
            if idx_str.lower() not in set_name.lower():
                components.append(f"{set_name} - {idx_str}")
            else:
                components.append(f"{idx_str}")
    else:
        components.append(f"{idx_str}")

    canonical_name = " ".join(components) + ext
    safe_name = sanitize_win_filename(canonical_name)

    return {
        "studio": studio,
        "date": date,
        "set_name": set_name,
        "index": idx_str,
        "standardized_filename": safe_name
    }

def parse_media_file(file_path: str, media_type: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    filename = os.path.basename(file_path)
    parent_path = os.path.dirname(file_path)
    if media_type == "video":
        return parse_video_filename(filename, parent_path, metadata)
    elif media_type == "image":
        return parse_image_filename(filename, parent_path, metadata)
    else:
        return {
            "studio": None,
            "date": None,
            "title": filename,
            "standardized_filename": sanitize_win_filename(filename)
        }
