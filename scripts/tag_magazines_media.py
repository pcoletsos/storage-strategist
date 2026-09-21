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

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

try:
    from media_name_parser import clean_title_case, sanitize_win_filename
except ImportError:
    def clean_title_case(s: str) -> str:
        return s.title()
    def sanitize_win_filename(s: str) -> str:
        return s

# Entity recognition for Greek and international models in magazines
MAGAZINE_PERFORMER_RULES = [
    (re.compile(r"olga\s*farmak", re.IGNORECASE), "Olga Farmaki"),
    (re.compile(r"katerina\s*stikoud", re.IGNORECASE), "Katerina Stikoudi"),
    (re.compile(r"dimitra\s*alexandraki", re.IGNORECASE), "Dimitra Alexandraki"),
    (re.compile(r"petroula", re.IGNORECASE), "Petroula Kostidou"),
    (re.compile(r"(?:xristina|christina)\s*moustaka", re.IGNORECASE), "Christina Moustaka"),
    (re.compile(r"nomiko[yu]", re.IGNORECASE), "Doukissa Nomikou"),
    (re.compile(r"julia(?:0|\b)", re.IGNORECASE), "Julia Alexandratou"),
    (re.compile(r"ceadcebbceb5cebdceb1", re.IGNORECASE), "Elena Paparizou"),
    (re.compile(r"elena\s*paparizou", re.IGNORECASE), "Elena Paparizou"),
]

# Publisher and Magazine Title Mapping
PUBLISHER_RULES = [
    (re.compile(r"playboy", re.IGNORECASE), "Playboy"),
    (re.compile(r"nitro", re.IGNORECASE), "Nitro Magazine"),
    (re.compile(r"max(?:\s*june|\b)", re.IGNORECASE), "Max Magazine"),
    (re.compile(r"greek\s*periodika", re.IGNORECASE), "Greek Periodika"),
]

# Date extraction patterns
DATE_BRACKET_REGEX = re.compile(r"\[(\d{4}-\d{2}-\d{2})\]")
MONTH_YEAR_REGEXES = [
    (re.compile(r"june\s*(\d{4})", re.IGNORECASE), "06"),
    (re.compile(r"oktovriou\s*(\d{4})", re.IGNORECASE), "10"),
    (re.compile(r"march\s*(\d{4})", re.IGNORECASE), "03"),
    (re.compile(r"august\s*(\d{4})", re.IGNORECASE), "08"),
    (re.compile(r"may\s*(\d{4})", re.IGNORECASE), "05"),
]


def extract_magazine_metadata(filename: str) -> Tuple[str, str, Optional[str], str, float]:
    """Extracts performer, publisher/studio, release date, normalized title, and confidence score."""
    # 1. Performer detection
    performer = "Compilation"
    conf = 0.85
    for pattern, name in MAGAZINE_PERFORMER_RULES:
        if pattern.search(filename):
            performer = name
            conf = 0.95
            break

    # 2. Publisher detection
    publisher = "Greek Periodika"
    for pattern, pub in PUBLISHER_RULES:
        if pattern.search(filename):
            publisher = pub
            break

    # 3. Date detection
    date_str: Optional[str] = None
    m_bracket = DATE_BRACKET_REGEX.search(filename)
    if m_bracket:
        date_str = m_bracket.group(1)
    else:
        for pat, month_num in MONTH_YEAR_REGEXES:
            m_my = pat.search(filename)
            if m_my:
                year = m_my.group(1)
                date_str = f"{year}-{month_num}"
                break

    # 4. Title normalization
    clean_name = re.sub(r"\[\d{4}-\d{2}-\d{2}\]", "", filename)
    clean_name = os.path.splitext(clean_name)[0]
    clean_name = re.sub(r"[-._\s]+", " ", clean_name).strip()
    # Decode known hex or stub names if needed
    if "Ceadcebbceb5cebdceb1" in filename:
        clean_name = "Elena Paparizou Magazine Scan"
    elif "Greek Periodika" in clean_name:
        clean_name = clean_name.replace("Greek Periodika", "").strip(" -_")
        if clean_name:
            clean_name = f"Greek Periodika {clean_name}"
        else:
            clean_name = "Greek Periodika Scan"

    title = clean_title_case(clean_name)
    if not title:
        title = "Magazine Scan"

    return performer, publisher, date_str, title, conf


def tag_magazines(db_path: str, dry_run: bool = True, output_report: Optional[str] = None) -> Dict[str, Any]:
    """Tags and catalogs all assets in Magazines & Docs."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        SELECT id, file_path, filename, existing_artist, existing_date, studio 
        FROM media_files 
        WHERE file_path LIKE 'F:\\Aloha\\Magazines & Docs\\%'
    """)
    rows = c.fetchall()

    results = []
    for r in rows:
        fid, fpath, fname, cur_artist, cur_date, cur_studio = r
        perf, pub, date_val, title, conf = extract_magazine_metadata(fname)
        results.append({
            "id": fid,
            "file_path": fpath,
            "filename": fname,
            "artist": perf,
            "studio": pub,
            "date": date_val,
            "title": title,
            "confidence_score": conf,
        })

    if not dry_run:
        for res in results:
            c.execute("""
                UPDATE media_files
                SET existing_artist = ?,
                    studio = ?,
                    existing_date = ?,
                    existing_title = ?,
                    confidence_score = ?,
                    needs_review = 0
                WHERE id = ?
            """, (res["artist"], res["studio"], res["date"], res["title"], res["confidence_score"], res["id"]))
        conn.commit()

    conn.close()

    summary = {
        "total_evaluated": len(results),
        "attributed_artists": sum(1 for r in results if r["artist"] != "Compilation"),
        "compilations": sum(1 for r in results if r["artist"] == "Compilation"),
        "with_dates": sum(1 for r in results if r["date"] is not None),
        "dry_run": dry_run,
        "results": results
    }

    if output_report:
        with open(output_report, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    return summary


def main():
    parser = argparse.ArgumentParser(description="Catalog and tag digital magazine scans on Aloha.")
    parser.add_argument("--db", default="media_inventory.db", help="Path to media_inventory.db")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Run without writing changes")
    parser.add_argument("--commit", action="store_true", default=False, help="Commit updates to SQLite")
    parser.add_argument("--output-report", default="magazines_tagging_preview.json", help="Report output path")

    args = parser.parse_args()
    is_dry_run = not args.commit

    summary = tag_magazines(args.db, dry_run=is_dry_run, output_report=args.output_report)
    print(f"Evaluated {summary['total_evaluated']} magazine assets.")
    print(f"Attributed specific models: {summary['attributed_artists']}.")
    print(f"Dated issues: {summary['with_dates']}.")
    print(f"Mode: {'DRY RUN' if is_dry_run else 'COMMITTED TO DATABASE'}.")
    print(f"Report exported to {args.output_report}")


if __name__ == "__main__":
    main()
