import os
import sys
import sqlite3
import pytest

# Ensure scripts dir is on sys.path
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from triage_remaining_inventory import (
    classify_studios_item,
    classify_movies_item,
    classify_collections_item,
    classify_celebrities_item,
    classify_photos_item,
    triage_item,
    run_triage,
)


def test_classify_studios_xart_photos():
    fn = "[2009-03-08] X Art Nella Orange Crush Lrg - X Art Nella Orange Crush 09 Lrg.jpg"
    artist, studio, title, conf = classify_studios_item(fn, "X-Art")
    assert artist == "Nella"
    assert studio == "X-Art"
    assert "Nella" in title
    assert conf >= 0.90


def test_classify_studios_fuckedhard18_performers():
    artist, studio, title, _ = classify_studios_item("Fh18 August [480p AV1].mkv", "FuckedHard18")
    assert artist == "August Ames"
    assert studio == "FuckedHard18"

    artist2, studio2, title2, _ = classify_studios_item("[FuckedHard18] Fh18 Lexi [480p AV1].mkv", "FuckedHard18")
    assert artist2 == "Lexi Belle"

    artist3, studio3, title3, _ = classify_studios_item("[FuckedHard18] [2015-11-09] Kimmy [1080p AV1].mkv", "FuckedHard18")
    assert artist3 == "Kimmy Granger"


def test_classify_movies():
    fn = "Latina Island Girls [480p AV1].mkv"
    artist, studio, title, conf = classify_movies_item(fn, "Wicked Pictures")
    assert artist == "Compilation"
    assert studio == "Wicked Pictures"
    assert title == "Latina Island Girls"


def test_classify_collections():
    fn = "Taras Titties Jiggly [AV1].mkv"
    artist, studio, title, conf = classify_collections_item(fn, "Digital Playground")
    assert "Tara Lynn Foxx" in artist
    assert studio == "Digital Playground"


def test_classify_celebrities():
    fn = "Ahaze Rhard Stw 01 [480p AV1].mkv"
    artist, studio, title, conf = classify_celebrities_item(fn, "Mr Skin")
    assert artist == "Keeley Hazell"
    assert studio == "Mr Skin"


def test_classify_photos():
    fn = "New Folder - 0a689194d536dd1665a4bbf52906cec9.jpg"
    artist, studio, title, conf = classify_photos_item(fn, "Miscellaneous Sets")
    assert artist == "Compilation"
    assert "0a689194d536dd1665a4bbf52906cec9" in title


def test_run_triage_in_memory_db():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            filename TEXT NOT NULL,
            existing_artist TEXT,
            existing_title TEXT,
            studio TEXT,
            confidence_score REAL,
            needs_review INTEGER
        )
    """)
    c.execute("""
        INSERT INTO media_files (file_path, filename, existing_artist, existing_title, studio, needs_review)
        VALUES 
        ('F:\\Aloha\\Studios\\FuckedHard18\\Fh18 August [480p AV1].mkv', 'Fh18 August [480p AV1].mkv', NULL, 'Fh18 August', 'FuckedHard18', 1),
        ('F:\\Aloha\\Movies\\Latina Island Girls [480p AV1].mkv', 'Latina Island Girls [480p AV1].mkv', NULL, 'Latina Island Girls', 'Wicked Pictures', 1)
    """)
    conn.commit()

    # Dry run
    # For testing, we mock connect using an in-memory helper
    # We can test triage_item directly
    item1 = {
        "id": 1,
        "file_path": "F:\\Aloha\\Studios\\FuckedHard18\\Fh18 August [480p AV1].mkv",
        "filename": "Fh18 August [480p AV1].mkv",
        "studio": "FuckedHard18"
    }
    res1 = triage_item(item1)
    assert res1["new_artist"] == "August Ames"
    assert res1["needs_review"] == 0

    item2 = {
        "id": 2,
        "file_path": "F:\\Aloha\\Movies\\Latina Island Girls [480p AV1].mkv",
        "filename": "Latina Island Girls [480p AV1].mkv",
        "studio": "Wicked Pictures"
    }
    res2 = triage_item(item2)
    assert res2["new_artist"] == "Compilation"
    assert res2["needs_review"] == 0
