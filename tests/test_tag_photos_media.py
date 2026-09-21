"""Unit tests for tag_photos_media.py performer recognition and metadata tagging.

Validates subfolder attribution, Vixen photo set mapping, filename entity extraction,
thematic gallery classification, title cleaning, and database synchronization.
"""

import os
import sys
import sqlite3
import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from tag_photos_media import (
    clean_photo_title,
    parse_photo_asset,
    sync_to_database,
)


def test_clean_photo_title():
    """Verifies removal of technical prefixes, duplicates, and percent-encodings."""
    assert clean_photo_title("Sexy Avatars - 003.jpg") == "003"
    assert clean_photo_title("Kocicky Babes - 006 (2).jpg") == "006"
    assert clean_photo_title("Greek Stars - Dimitramatsouka018%5b1%5d.jpg") == "Dimitramatsouka018[1]"
    assert clean_photo_title("Actors - 1024x768 Wallpaper Angelina Jolie 11.jpg") == "Wallpaper Angelina Jolie 11"
    assert clean_photo_title("[2016-04-18] [Digital Playground] Stella Cox Force Awakens - 001.jpg") == "Stella Cox Force Awakens - 001"


def test_subfolder_direct_performer_attribution():
    """Verifies dedicated actress and model folder attribution."""
    res_kate = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Kate Beckinsale\Kate Beckinsale 002.jpg",
        filename="Kate Beckinsale 002.jpg",
        directory=r"F:\Aloha\Photos & Sets\Kate Beckinsale",
    )
    assert res_kate["detected_artist"] == "Kate Beckinsale"
    assert res_kate["confidence"] >= 0.95
    assert res_kate["needs_review"] == 0
    assert res_kate["method"] == "folder_direct_performer"

    res_adriana = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Adriana Lima]\Adriana Lima 01.jpg",
        filename="Adriana Lima 01.jpg",
        directory=r"F:\Aloha\Photos & Sets\Adriana Lima]",
    )
    assert res_adriana["detected_artist"] == "Adriana Lima"
    assert res_adriana["confidence"] >= 0.95


def test_stella_cox_parody_set():
    """Verifies complete metadata extraction for Digital Playground parody image set."""
    res = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Stella Cox - Force Awakens\[Digital Playground] [2016-04-18] Stella Cox Force Awakens - 001.jpg",
        filename="[Digital Playground] [2016-04-18] Stella Cox Force Awakens - 001.jpg",
        directory=r"F:\Aloha\Photos & Sets\Stella Cox - Force Awakens",
    )
    assert res["detected_artist"] == "Stella Cox"
    assert res["detected_studio"] == "Digital Playground"
    assert res["detected_date"] == "2016-04-18"
    assert res["confidence"] == 0.98
    assert res["needs_review"] == 0


def test_vixen_subfolder_set():
    """Verifies Vixen photo set mapping with performer and studio attribution."""
    res_ellie = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Vixen Sets\Vixen Ellie Eilish Treat Me Right\[Vixen] Ellie Eilish Treat Me Right - 001.jpg",
        filename="[Vixen] Ellie Eilish Treat Me Right - 001.jpg",
        directory=r"F:\Aloha\Photos & Sets\Vixen Sets\Vixen Ellie Eilish Treat Me Right",
    )
    assert res_ellie["detected_artist"] == "Ellie Eilish"
    assert res_ellie["detected_studio"] == "Vixen"
    assert res_ellie["detected_title"] == "Treat Me Right - Photo Set"
    assert res_ellie["confidence"] == 0.98

    res_gabbie = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Vixen Sets\Vixen Gabbie Carter Take a Chance\[Vixen] Gabbie Carter Take a Chance - 001.jpg",
        filename="[Vixen] Gabbie Carter Take a Chance - 001.jpg",
        directory=r"F:\Aloha\Photos & Sets\Vixen Sets\Vixen Gabbie Carter Take a Chance",
    )
    assert res_gabbie["detected_artist"] == "Gabbie Carter"
    assert res_gabbie["detected_studio"] == "Vixen"
    assert res_gabbie["confidence"] == 0.98


def test_filename_entity_recognition():
    """Verifies multi-star entity recognition from filenames across miscellaneous galleries."""
    res_dimitra = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Greek Stars\Greek Stars - Dimitra Matsouka Great Ass.jpg",
        filename="Greek Stars - Dimitra Matsouka Great Ass.jpg",
        directory=r"F:\Aloha\Photos & Sets\Greek Stars",
    )
    assert res_dimitra["detected_artist"] == "Dimitra Matsouka"
    assert res_dimitra["confidence"] >= 0.95

    res_angelina = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Actors\Actors - 1024x768 Wallpaper Angelina Jolie 11.jpg",
        filename="Actors - 1024x768 Wallpaper Angelina Jolie 11.jpg",
        directory=r"F:\Aloha\Photos & Sets\Actors",
    )
    assert res_angelina["detected_artist"] == "Angelina Jolie"
    assert res_angelina["confidence"] >= 0.95

    res_alizee = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Singers\Singers - Alizee Beau Cul.jpg",
        filename="Singers - Alizee Beau Cul.jpg",
        directory=r"F:\Aloha\Photos & Sets\Singers",
    )
    assert res_alizee["detected_artist"] == "Alizée"
    assert res_alizee["confidence"] >= 0.95

    res_carmen = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Top Models\Top Models - Carmen Electra Wallpaper.jpg",
        filename="Top Models - Carmen Electra Wallpaper.jpg",
        directory=r"F:\Aloha\Photos & Sets\Top Models",
    )
    assert res_carmen["detected_artist"] == "Carmen Electra"

    res_alison = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Guns\Guns - Alisondoody.jpg",
        filename="Guns - Alisondoody.jpg",
        directory=r"F:\Aloha\Photos & Sets\Guns",
    )
    assert res_alison["detected_artist"] == "Alison Doody"


def test_thematic_gallery_compilation():
    """Verifies compilation attribution for generic thematic galleries."""
    res_kocicky = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Kocicky Babes\Kocicky Babes - 001.jpg",
        filename="Kocicky Babes - 001.jpg",
        directory=r"F:\Aloha\Photos & Sets\Kocicky Babes",
    )
    assert res_kocicky["detected_artist"] == "Compilation"
    assert res_kocicky["detected_studio"] == "Kocicky Babes"
    assert res_kocicky["confidence"] >= 0.85
    assert res_kocicky["needs_review"] == 0

    res_sexy = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Sexy Avatars\Sexy Avatars - 003.jpg",
        filename="Sexy Avatars - 003.jpg",
        directory=r"F:\Aloha\Photos & Sets\Sexy Avatars",
    )
    assert res_sexy["detected_artist"] == "Compilation"
    assert res_sexy["detected_studio"] == "Sexy Avatars"
    assert res_sexy["needs_review"] == 0


def test_loose_root_photos_and_residuals():
    """Verifies classification of loose root photos and residual folder items."""
    res_root = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\Med 6kd91899.jpg",
        filename="Med 6kd91899.jpg",
        directory=r"F:\Aloha\Photos & Sets",
    )
    assert res_root["detected_artist"] == "Compilation"
    assert res_root["detected_studio"] == "Loose Photos"
    assert res_root["needs_review"] == 1

    res_res = parse_photo_asset(
        file_path=r"F:\Aloha\Photos & Sets\New Folder\New Folder - 001.jpg",
        filename="New Folder - 001.jpg",
        directory=r"F:\Aloha\Photos & Sets\New Folder",
    )
    assert res_res["detected_artist"] == "Compilation"
    assert res_res["detected_studio"] == "Miscellaneous Sets"
    assert res_res["needs_review"] == 1


def test_database_synchronization(tmp_path):
    """Verifies atomic database update and rowcount reconciliation."""
    test_db = str(tmp_path / "test_inventory.db")
    conn = sqlite3.connect(test_db)
    conn.execute("""
        CREATE TABLE media_files (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            filename TEXT,
            directory TEXT,
            media_type TEXT,
            existing_artist TEXT,
            existing_title TEXT,
            studio TEXT,
            existing_date TEXT,
            confidence_score REAL,
            needs_review INTEGER
        )
    """)
    conn.execute("""
        INSERT INTO media_files (id, file_path, filename, directory, media_type, needs_review)
        VALUES (1, 'F:\\Aloha\\Photos & Sets\\Kate Beckinsale\\Kate 01.jpg', 'Kate 01.jpg', 'F:\\Aloha\\Photos & Sets\\Kate Beckinsale', 'image', 0)
    """)
    conn.execute("""
        INSERT INTO media_files (id, file_path, filename, directory, media_type, needs_review)
        VALUES (2, 'F:\\Aloha\\Photos & Sets\\Kocicky Babes\\001.jpg', '001.jpg', 'F:\\Aloha\\Photos & Sets\\Kocicky Babes', 'image', 0)
    """)
    conn.commit()
    conn.close()

    results = [
        {
            "id": 1,
            "file_path": r"F:\Aloha\Photos & Sets\Kate Beckinsale\Kate 01.jpg",
            "detected_artist": "Kate Beckinsale",
            "detected_title": "Kate 01",
            "detected_studio": None,
            "detected_date": None,
            "confidence": 0.98,
            "needs_review": 0,
        },
        {
            "id": 2,
            "file_path": r"F:\Aloha\Photos & Sets\Kocicky Babes\001.jpg",
            "detected_artist": "Compilation",
            "detected_title": "001",
            "detected_studio": "Kocicky Babes",
            "detected_date": None,
            "confidence": 0.90,
            "needs_review": 0,
        },
    ]

    updated_records, updated_artists = sync_to_database(test_db, results)
    assert updated_records == 2
    assert updated_artists == 2

    # Verify rows in database
    conn = sqlite3.connect(test_db)
    r1 = conn.execute("SELECT existing_artist, studio, confidence_score, needs_review FROM media_files WHERE id = 1").fetchone()
    assert r1[0] == "Kate Beckinsale"
    assert r1[2] == 0.98
    assert r1[3] == 0

    r2 = conn.execute("SELECT existing_artist, studio, confidence_score, needs_review FROM media_files WHERE id = 2").fetchone()
    assert r2[0] == "Compilation"
    assert r2[1] == "Kocicky Babes"
    assert r2[2] == 0.90
    assert r2[3] == 0
    conn.close()
