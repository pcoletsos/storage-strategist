import os
import re
import sys
import json
import sqlite3
import argparse
from typing import Dict, Any, List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from mutagen.mp4 import MP4
except ImportError:
    MP4 = None


def normalize_title(filename: str) -> str:
    """Normalizes raw filename into clean human readable title."""
    base = os.path.splitext(filename)[0]
    # Strip resolution, codec, format tokens
    base = re.sub(r'\[(480p|720p|1080p|2160p|4k|av1|h264|hevc|x264|dvdrip|bluray)[^\]]*\]', '', base, flags=re.I)
    base = re.sub(r'\b(480p|720p|1080p|2160p|4k|av1|h264|hevc|x264|dvdrip|bluray)\b', '', base, flags=re.I)
    # Strip web scrapers and hosting domains
    base = re.sub(r'\[?(xvideos|dailymotion|youtube|vimeo|stagevu|xhamster|mrskin|sexesup)(?:\s+com)?\]?', '', base, flags=re.I)
    # Strip technical quality keywords
    base = re.sub(r'\b(Hd\s+W\s+\d+\s+Hi|Hd\s+\d+\s+Hi|Sat\s+Hi|Hi\s+\d+|Hd\s+Hi|Hd|Hi)\b', '', base, flags=re.I)
    # Clean brackets, underscores and excess whitespace
    base = re.sub(r'[_\.]+', ' ', base)
    base = re.sub(r'^\s*\[\s*', '', base)
    base = re.sub(r'\s*\]\s*$', '', base)
    base = re.sub(r'\s+', ' ', base).strip(' -_,:[]')
    return base.title()


def parse_celebrity_record(filename: str, relpath: str, existing_artist: Optional[str], existing_studio: Optional[str]) -> Dict[str, Any]:
    """Deterministically attributes performer entity, studio, and clean title."""
    fn = filename
    fn_lower = fn.lower()

    # Defaults
    artist = existing_artist
    studio = existing_studio or "Mr Skin"
    title = normalize_title(fn)
    needs_review = 1
    conf = 0.5

    # 1. Playlists and Thematic Compilations
    playlist_kws = [
        'playlist', 'countdown', 'top 10', 'top 100', 'top nude', 'outrageous celeb nude scenes',
        'reasons to be a shallow perv', 'celebrities sex scenes compilation',
        'sexycelebs42 4 year anniversary', 'bestofcartoonporn', 'summer shocker',
        'favorite backburger', 'favorite nude scenes', 'next top model nude shoot',
        'lapdance', 'mrskin com nude celebrity movie reviews'
    ]
    if any(kw in fn_lower for kw in playlist_kws):
        artist = "Compilation"
        studio = "Mr Skin"
        needs_review = 0
        conf = 0.95
        return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}

    # 2. Mr Skin Daily Video Bulletins and Editorial Segments
    if re.search(r'\[.*\]\s*(?:mrskin(?:\s*com)?\s*-\s*)?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{1,2},?\s+\d{4}', fn, re.I) or \
       any(k in fn_lower for k in [
           'skin for nurse', 'touchdowns and tits', 'shallow perv', 'boob tube debuts',
           'back to the boardwalk', 'royal rack', 'plenty of cans at cannes',
           'top 5 naked horror', 'hot new tv t&a', 'thanks for sharing, gwyneth',
           'night of the nudecomers'
       ]):
        studio = "Mr Skin"
        needs_review = 0
        conf = 0.92
        if 'gwyneth' in fn_lower:
            artist = "Gwyneth Paltrow"
            title = "Thanks For Sharing (2013)"
        elif 'nurse 3d' in fn_lower or 'doctor is skin for nurse' in fn_lower:
            artist = "Paz de la Huerta"
            title = "Nurse 3D (2014)"
        elif 'ginger lynn allen' in fn_lower:
            artist = "Ginger Lynn Allen"
            title = "The Devil's Rejects"
        elif 'exclusive fright night 2' in fn_lower:
            artist = "Jaime Murray"
            title = "Fright Night 2: New Blood"
        else:
            artist = "Compilation"
        return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}

    # 3. Playboy TV Series
    if 'playboytv-' in fn_lower or 'playboy tv' in fn_lower:
        artist = "Compilation"
        studio = "Playboy TV"
        needs_review = 0
        conf = 0.95
        return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}

    # 4. Hollywood Xposed Series
    if 'hollywood xposed' in fn_lower:
        artist = "Compilation"
        studio = "Mr Skin"
        needs_review = 0
        conf = 0.95
        return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}

    # 5. Greek Celebrities
    greek_map = {
        'asiki': ('Vina Asiki', 'Greek Cinema'),
        'mastrokosta': ('Gogo Mastrokosta', 'Greek Television'),
        'julia ii': ('Julia Alexandratou', 'Sirina Productions'),
        'kalomoira': ('Kalomoira', 'Greek Television'),
        'tzeni theona': ('Tzeni Theona', 'Greek Cinema'),
        'themos tsesmeli': ('Themos Anastasiadis, Tsesmeli', 'Greek Television'),
        'iakovidou': ('Kalliopi Iakovidou', 'Greek Television'),
        'greek blondie': ('Greek Celebrity', 'Greek Television'),
        'various gr celeb': ('Compilation', 'Greek Media'),
    }
    for kw, (g_artist, g_studio) in greek_map.items():
        if kw in fn_lower:
            artist = g_artist
            studio = g_studio
            needs_review = 0
            conf = 0.95
            return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}

    # 6. Specific Mainstream Stars, Online Scrapes, and Film Scenes
    bracket_stars = [
        ('barbara niven and jessica clark', 'Barbara Niven, Jessica Clark', 'A Perfect Ending', 'XVideos'),
        ('barbara niven', 'Barbara Niven', 'A Perfect Ending', 'XVideos'),
        ('blake lively', 'Blake Lively', 'Savages', 'XVideos'),
        ('gemma arterton', 'Gemma Arterton', 'The Disappearance of Alice Creed', 'Cinema'),
        ('ellen van der koogh', 'Ellen van der Koogh', 'Swingers', 'XVideos'),
        ('shyla stylez', 'Shyla Stylez', 'Educating Erin', 'XVideos'),
        ('susan featherly', 'Susan Featherly', 'Virtual Girl', 'XVideos'),
        ('wendy rice', 'Wendy Rice', 'Roommate Wanted', 'XVideos'),
        ('candice-michelle-roommate-wanted', 'Candice Michelle', 'Roommate Wanted', 'Dailymotion'),
        ('candice michelle', 'Candice Michelle', 'Candice Michelle Videos', 'Dailymotion'),
        ('cassie scerbo', 'Cassie Scerbo', 'Cassie Scerbo Videos', 'YouTube'),
        ('miley cyrus', 'Miley Cyrus', 'Miley Cyrus London Live', 'YouTube'),
        ('ragini mms-2', 'Sunny Leone', 'Ragini MMS-2', 'Bollywood'),
        ('sunny leone', 'Sunny Leone', 'Loves Being Besharam', 'Bollywood'),
        ('kathleen robertson', 'Kathleen Robertson', 'Boss', 'Starz'),
        ('jacqueline lovell', 'Jacqueline Lovell', 'Femalien', 'Full Moon Features'),
        ('la mujer de mi hermano', 'Barbara Mori', 'La Mujer De Mi Hermano', 'Cinema'),
        ('kill for me', 'Katie Cassidy, Tracy Spiridakos', 'Kill For Me (2013)', 'Sony Pictures'),
        ('embrace.of.the.vampire.2013', 'Sharon Hinnendael', 'Embrace Of The Vampire (2013)', 'Anchor Bay'),
        ('embrace of the vampire', 'Sharon Hinnendael', 'Embrace Of The Vampire (2013)', 'Anchor Bay'),
        ('ellenhollman spartacus', 'Ellen Hollman', 'Spartacus', 'Starz'),
        ('rita g in howard stern', 'Rita G', 'Howard Stern Show', 'Howard TV'),
        ('ginger lynn allen in the devil\'s rejects', 'Ginger Lynn Allen', 'The Devil\'s Rejects', 'Mr Skin'),
    ]
    for pattern, b_artist, b_movie, b_studio in bracket_stars:
        if pattern in fn_lower:
            artist = b_artist
            studio = b_studio
            needs_review = 0
            conf = 0.95
            return {'artist': artist, 'studio': studio, 'title': f"{b_movie}: {title}", 'needs_review': needs_review, 'conf': conf}

    # 7. Q (Desire) Feature Film Quartet
    if 'q (desire)' in fn_lower:
        if 'leticia belliccini' in fn_lower:
            artist = 'Leticia Belliccini'
        elif 'deborah revy' in fn_lower:
            artist = 'Deborah Revy'
        elif 'helene zimmer' in fn_lower:
            artist = 'Helene Zimmer'
        elif 'christelle benoit' in fn_lower:
            artist = 'Christelle Benoit'
        else:
            artist = 'Q (Desire) Ensemble'
        studio = 'Cinema'
        needs_review = 0
        conf = 0.95
        return {'artist': artist, 'studio': studio, 'title': f"Q (Desire): {title}", 'needs_review': needs_review, 'conf': conf}

    # 8. Mr Skin Abbreviation Scheme (<Movie> <LastName> <Index> Hi)
    abbr_stars = [
        (r'showgirls\s+berkley', 'Elizabeth Berkley', 'Showgirls', 'Mr Skin'),
        (r'wolfofwallstreet.*robbie', 'Margot Robbie', 'The Wolf of Wall Street', 'Mr Skin'),
        (r'wolfofwallstreet.*cas', 'Katarina Cas', 'The Wolf of Wall Street', 'Mr Skin'),
        (r'bigsur\s+bosworth', 'Kate Bosworth', 'Big Sur', 'Mr Skin'),
        (r'driveangry\s+ross', 'Charlotte Ross', 'Drive Angry', 'Mr Skin'),
        (r'10inch\s+harris', 'Danneel Harris', 'Ten Inch Hero', 'Mr Skin'),
        (r'lust\s+caution\s+tang', 'Tang Wei', 'Lust, Caution', 'Mr Skin'),
        (r'flirtingforty\s+locklear', 'Heather Locklear', 'Flirting with Forty', 'Mr Skin'),
        (r'flirtingdanger\s+carpenter', 'Charisma Carpenter', 'Flirting with Danger', 'Mr Skin'),
        (r'58emmy\s+kaling', 'Mindy Kaling', '58th Emmy Awards', 'Mr Skin'),
        (r'wuhrer|whurer|wuher', 'Kari Wuhrer', 'Kari Wuhrer Feature Clips', 'Mr Skin'),
        (r'gam\s+bea\s+chaplin', 'Oona Chaplin', 'Game of Thrones', 'HBO'),
        (r'gam\s+sec\s+vanhouten', 'Carice van Houten', 'Game of Thrones', 'HBO'),
        (r'gam\s+bla\s+knite', 'Sahara Knite', 'Game of Thrones', 'HBO'),
        (r'cal\s+hel\s+mcatee', 'Sarah McAtie', 'Californication', 'Showtime'),
        (r'cal\s+dea\s+grace', 'Maggie Grace', 'Californication', 'Showtime'),
        (r'ban\s+hal\s+milisevic', 'Ivana Milicevic', 'Banshee', 'Cinemax'),
        (r'underbelly.*gilbert', 'Camille Gilbert', 'Underbelly', 'Mr Skin'),
        (r'plusone.*hall', 'Ashley Hinshaw', 'Plus One', 'Mr Skin'),
        (r'friday13pt2\s+baker', 'Kirsten Baker', 'Friday the 13th Part 2', 'Mr Skin'),
        (r'shop\s+danes', 'Claire Danes', 'Shopgirl', 'Mr Skin'),
        (r'virginsof\s+newman', 'Anya Newman', 'Virgins of Sherwood Forest', 'Mr Skin'),
        (r'cityindustry\s+liu', 'Lucy Liu', 'City of Industry', 'Mr Skin'),
        (r'beautifullaund\s+wolf', 'Rita Wolf', 'My Beautiful Laundrette', 'Mr Skin'),
        (r'second\s+gen\s+nagra', 'Parminder Nagra', 'Second Generation', 'Mr Skin'),
        (r'ninjashe\s+asami', 'Asami', 'Ninja Cheerleaders', 'Mr Skin'),
        (r'marieou\s+coste', 'Marie-Christine Coste', 'Marie-Christine Coste Clips', 'Mr Skin'),
        (r'pleasurewoman72\s+digard', 'Claudine Digard', 'Claudine Digard Clips', 'Mr Skin'),
        (r'kamasutra\s+choudhury', 'Sarita Choudhury', 'Kama Sutra: A Tale of Love', 'Mr Skin'),
        (r'loo\s+ste\s+hinnendael', 'Sharon Hinnendael', 'The Stepsister', 'Mr Skin'),
        (r'johnnyfirecloud\s+littlefeather', 'Sacheen Littlefeather', 'Johnny Firecloud', 'Mr Skin'),
        (r'roxanna\s+mundae', 'Misty Mundae', 'Roxanna', 'Mr Skin'),
        (r'siddhartha\s+garewal', 'Simi Garewal', 'Siddhartha', 'Mr Skin'),
        (r'truewoman\s+shu', 'Shu Qi', 'Shu Qi Clips', 'Mr Skin'),
        (r'vampvixens\s+couvillion', 'Couvillion', 'Vampire Vixens', 'Mr Skin'),
        (r'spectreat\s+moussadek', 'Moussadek', 'Spectre At Moussadek', 'Mr Skin'),
        (r'pus\s+sme\s+chenoweth', 'Kristin Chenoweth', 'Pushing Daisies', 'Mr Skin'),
        (r'manwall\s+aoi', 'Sora Aoi', 'Sora Aoi Clips', 'Mr Skin'),
        (r'mangokiss\s+ferraro', 'Ferraro', 'Mango Kiss', 'Mr Skin'),
        (r'piratesblo\s+lakshmi', 'Lakshmi', 'Pirates Blood', 'Mr Skin'),
        (r'destricted\s+deville', 'Chloe Sevigny', 'Destricted', 'Mr Skin'),
        (r'darjeerling\s+kakan', 'Natalie Portman', 'The Darjeeling Limited', 'Mr Skin'),
        (r'elenaundone\s+dinwiddie', 'Traci Dinwiddie', 'Elena Undone', 'Mr Skin'),
        (r'betrayedpass\s+teles', 'Teles', 'Betrayed Passion', 'Mr Skin'),
        (r'dirty\s+kaylynn', 'Kaylynn', 'Dirty Kaylynn', 'Mr Skin'),
        (r'fire\s+das', 'Nandita Das', 'Fire (1996)', 'Mr Skin'),
        (r'41superbad.*dewulf', 'Noureen DeWulf', '41-Year-Old Virgin / Superbad', 'Mr Skin'),
        (r'awahen\s+kaminskala', 'Kaminskala', 'Kaminskala Clips', 'Mr Skin'),
        (r'son\s+wid\s+renton', 'Renton', 'Son Wid Renton', 'Mr Skin'),
        (r'carrie\s+allen', 'Carrie Allen', 'Carrie Allen Clips', 'Mr Skin'),
        (r'dar\s+dun1\s+che1', 'Kirsten Dunst', 'Kirsten Dunst Clips', 'Mr Skin'),
        (r'vampire\s+khan', 'Khan', 'Vampire Clips', 'Mr Skin'),
        (r'vip5\s+culter', 'Culter', 'VIP Season 5', 'Mr Skin'),
        (r'leap\s+pil\s+poon', 'Poon', 'Leap Clips', 'Mr Skin'),
        (r'klinik\s+nacht\s+tayde', 'Tayde', 'Klinik Nacht', 'Mr Skin'),
        (r'killfaster\s+ray', 'Ray', 'Kill Faster', 'Mr Skin'),
        (r'firstweeks.*bidasha', 'Bidita Bag', 'First Weeks', 'Mr Skin'),
    ]
    for pattern, star, movie, s_studio in abbr_stars:
        if re.search(pattern, fn, re.I):
            artist = star
            studio = s_studio
            needs_review = 0
            conf = 0.95
            return {'artist': artist, 'studio': studio, 'title': f"{movie}: {title}", 'needs_review': needs_review, 'conf': conf}

    # 9. Numeric Stubs, Raw Video Captures, and Code Stems (Retain needs_review = 1)
    if re.match(r'^\d+(\s+hi|\s+\[)', fn_lower) or re.match(r'^\d+\s*\[', fn_lower) or \
       re.match(r'^000\d+', fn_lower) or re.match(r'^\d+\.', fn_lower) or \
       any(k in fn_lower for k in ['vid0', 'tb3', 'tb5', 'videoplayback', 'stm e6']):
        artist = None
        studio = "Mr Skin" if 'update' in relpath.lower() else (existing_studio or "Unknown")
        needs_review = 1
        conf = 0.2
        return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}

    # Default fallback: keep needs_review
    return {'artist': artist, 'studio': studio, 'title': title, 'needs_review': needs_review, 'conf': conf}


def tag_mp4_container(file_path: str, artist: Optional[str], title: Optional[str], studio: Optional[str]) -> bool:
    """Injects QuickTime iTunes metadata atoms into MP4 container while preserving mtime."""
    if not MP4:
        return False
    if not os.path.exists(file_path):
        return False
    if not file_path.lower().endswith(('.mp4', '.m4v')):
        return False

    original_mtime = os.path.getmtime(file_path)
    try:
        mp4 = MP4(file_path)
        if mp4.tags is None:
            mp4.add_tags()

        if artist:
            mp4.tags['\xa9ART'] = [artist]
        if title:
            mp4.tags['\xa9nam'] = [title]
        if studio:
            mp4.tags['\xa9cmt'] = [f"Studio: {studio}"]

        mp4.save()
        # Strictly restore original filesystem timestamp
        os.utime(file_path, (original_mtime, original_mtime))
        return True
    except Exception as e:
        # Gracefully handle atom parsing issues without corrupting payload
        sys.stderr.write(f"Warning: Container tag skipped for {os.path.basename(file_path)}: {e}\n")
        return False


def run_triage(db_path: str, preview_path: str, apply_changes: bool = False, skip_tagging: bool = False) -> Dict[str, Any]:
    """Coordinates parsing, preview generation, database synchronization, and container tagging."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found at '{db_path}'")

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("""
        SELECT id, file_path, filename, extension, file_size, existing_artist, studio, needs_review
        FROM media_files
        WHERE file_path LIKE 'F:\\Aloha\\Celebrities\\%' AND needs_review = 1
    """)
    rows = c.fetchall()

    results = []
    resolved_count = 0
    retained_count = 0
    tagged_count = 0

    for fid, fpath, fname, ext, size, ex_artist, ex_studio, nr in rows:
        rel = os.path.relpath(fpath, 'F:\\Aloha\\Celebrities')
        parsed = parse_celebrity_record(fname, rel, ex_artist, ex_studio)

        is_resolved = (parsed['needs_review'] == 0)
        if is_resolved:
            resolved_count += 1
        else:
            retained_count += 1

        results.append({
            'id': fid,
            'relpath': rel,
            'filename': fname,
            'extension': ext,
            'original_artist': ex_artist,
            'original_studio': ex_studio,
            'resolved_artist': parsed['artist'],
            'resolved_studio': parsed['studio'],
            'resolved_title': parsed['title'],
            'needs_review': parsed['needs_review'],
            'confidence': parsed['conf'],
            'file_path': fpath
        })

    # Save preview JSON
    with open(preview_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total_processed': len(rows),
            'resolved_count': resolved_count,
            'retained_count': retained_count,
            'records': results
        }, f, indent=2)

    print("Celebrities Needs-Review Triage Preview Summary:")
    print(f"  Total records processed: {len(rows)}")
    print(f"  Successfully resolved (needs_review -> 0): {resolved_count} ({resolved_count/len(rows)*100:.1f}%)")
    print(f"  Retained for manual visual review (needs_review = 1): {retained_count} ({retained_count/len(rows)*100:.1f}%)")
    print(f"  Audit report written to: {preview_path}")

    if apply_changes:
        print("\nApplying updates to media_inventory.db...")
        update_count = 0
        for item in results:
            c.execute("""
                UPDATE media_files
                SET existing_artist = ?,
                    studio = ?,
                    existing_title = ?,
                    needs_review = ?,
                    confidence_score = ?
                WHERE id = ?
            """, (
                item['resolved_artist'],
                item['resolved_studio'],
                item['resolved_title'],
                item['needs_review'],
                item['confidence'],
                item['id']
            ))
            update_count += 1

        conn.commit()
        print(f"Updated {update_count} records in database.")

        if not skip_tagging and MP4:
            print("\nExecuting lossless MP4 container tagging with timestamp preservation...")
            for item in results:
                if item['extension'].lower() == '.mp4' and item['needs_review'] == 0:
                    success = tag_mp4_container(
                        item['file_path'],
                        item['resolved_artist'],
                        item['resolved_title'],
                        item['resolved_studio']
                    )
                    if success:
                        tagged_count += 1
            print(f"Successfully tagged {tagged_count} MP4 video containers.")

    conn.close()
    return {
        'total': len(rows),
        'resolved': resolved_count,
        'retained': retained_count,
        'tagged': tagged_count
    }


def main():
    parser = argparse.ArgumentParser(description="Triage Celebrities needs_review assets on Aloha.")
    parser.add_argument("--db-path", default="media_inventory.db", help="Path to SQLite database.")
    parser.add_argument("--preview-path", default="celebrities_triage_preview.json", help="Path to audit preview JSON.")
    parser.add_argument("--apply", action="store_true", help="Apply updates to database and container tags.")
    parser.add_argument("--dry-run", action="store_true", help="Dry run only (default).")
    parser.add_argument("--skip-tagging", action="store_true", help="Skip modifying MP4 container tags.")

    args = parser.parse_args()
    apply_mode = args.apply and not args.dry_run

    run_triage(args.db_path, args.preview_path, apply_changes=apply_mode, skip_tagging=args.skip_tagging)


if __name__ == '__main__':
    main()
