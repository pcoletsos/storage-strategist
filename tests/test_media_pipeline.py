import os
import sys
import unittest
import tempfile
import sqlite3
import shutil

# Ensure scripts path is importable
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import (
    parse_video_filename,
    parse_image_filename,
    sanitize_win_filename,
    normalize_date,
    clean_title_case
)
from media_inventory_scanner import init_db
from media_rename_pipeline import plan_renames, execute_pipeline
from media_rollback import rollback_transactions

class TestMediaNameParser(unittest.TestCase):
    def test_normalize_date(self):
        self.assertEqual(normalize_date("21.11.13"), "2021-11-13")
        self.assertEqual(normalize_date("17-10-23"), "2017-10-23")
        self.assertEqual(normalize_date("2019.12.25"), "2019-12-25")
        self.assertEqual(normalize_date("2009"), "2009")

    def test_clean_title_case(self):
        self.assertEqual(
            clean_title_case("billie.star.and.tina.fire.big.tits.hit.the.gym"),
            "Billie Star and Tina Fire Big Tits Hit the Gym"
        )
        self.assertEqual(
            clean_title_case("penny_pax_and_emily_willis"),
            "Penny Pax and Emily Willis"
        )

    def test_sanitize_win_filename(self):
        bad_name = 'Vixen: "Special" <Holiday> Episode *1* | Part? 2.mp4'
        clean = sanitize_win_filename(bad_name)
        self.assertNotIn(":", clean)
        self.assertNotIn('"', clean)
        self.assertNotIn("<", clean)
        self.assertNotIn(">", clean)
        self.assertNotIn("|", clean)
        self.assertNotIn("?", clean)
        self.assertNotIn("*", clean)

    def test_parse_scene_brazzers(self):
        fname = "brazzersexxtra.21.11.13.billie.star.and.tina.fire.big.tits.hit.the.gym.mp4"
        meta = {"v_codec": "h264", "width": 854, "height": 480, "resolution_tier": "480p"}
        res = parse_video_filename(fname, r"F:\Aloha\Brazzers", meta)
        self.assertEqual(res["studio"], "Brazzers Exxtra")
        self.assertEqual(res["date"], "2021-11-13")
        self.assertIn("[Brazzers Exxtra]", res["standardized_filename"])
        self.assertIn("[2021-11-13]", res["standardized_filename"])
        self.assertIn("[480p H264]", res["standardized_filename"])

    def test_parse_scene_digital_playground(self):
        fname = "dpg.17.10.23.cassidy.banks.soapy.step.siblings.mp4"
        meta = {"v_codec": "h264", "width": 1920, "height": 1080, "resolution_tier": "1080p"}
        res = parse_video_filename(fname, r"F:\Aloha\DigitalPlayground", meta)
        self.assertEqual(res["studio"], "Digital Playground")
        self.assertEqual(res["date"], "2017-10-23")
        self.assertIn("[Digital Playground]", res["standardized_filename"])
        self.assertIn("[2017-10-23]", res["standardized_filename"])
        self.assertIn("[1080p H264]", res["standardized_filename"])

    def test_parse_scene_vixen(self):
        fname = "Vixen - Ellie Eilish - Treat Me Right.mp4"
        meta = {"v_codec": "h264", "width": 1920, "height": 1080, "resolution_tier": "1080p"}
        res = parse_video_filename(fname, r"F:\Aloha\Vixen", meta)
        self.assertEqual(res["studio"], "Vixen")
        self.assertIn("[Vixen]", res["standardized_filename"])
        self.assertIn("Ellie Eilish", res["standardized_filename"])
        self.assertIn("Treat Me Right", res["standardized_filename"])

    def test_parse_bangbus_code(self):
        fname = "bb6463_3000.mp4"
        meta = {"v_codec": "h264", "width": 1280, "height": 720, "resolution_tier": "720p"}
        res = parse_video_filename(fname, r"F:\Aloha\Bangbus ALL 2010 videos 720p", meta)
        self.assertEqual(res["studio"], "Bangbus")
        self.assertIn("Episode 6463", res["standardized_filename"])
        self.assertIn("[720p H264]", res["standardized_filename"])

    def test_parse_image_set(self):
        fname = "1.jpg"
        meta = {"exif_datetime": "2020:05:15 14:30:00"}
        res = parse_image_filename(fname, r"F:\Aloha\Vixen\Vixen - Ellie Eilish - Treat Me Right", meta)
        self.assertEqual(res["studio"], "Vixen")
        self.assertEqual(res["date"], "2020-05-15")
        self.assertEqual(res["index"], "001")
        self.assertIn("[Vixen]", res["standardized_filename"])
        self.assertIn("[2020-05-15]", res["standardized_filename"])
        self.assertIn("001.jpg", res["standardized_filename"])

class TestPipelineAndRollbackRoundTrip(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="aloha_test_")
        self.db_path = os.path.join(self.test_dir, "test_inventory.db")
        self.ledger_path = os.path.join(self.test_dir, "test_undo.db")

        # Create synthetic files
        self.vixen_dir = os.path.join(self.test_dir, "Vixen")
        os.makedirs(self.vixen_dir, exist_ok=True)
        
        self.f1 = os.path.join(self.vixen_dir, "Vixen - Ellie Eilish - Treat Me Right.mp4")
        with open(self.f1, "w") as f:
            f.write("mock video 1")
            
        self.f2 = os.path.join(self.vixen_dir, "bb6463_3000.mp4")
        with open(self.f2, "w") as f:
            f.write("mock video 2")

        # Duplicate that creates collision
        self.f3 = os.path.join(self.vixen_dir, "bb6463_2000.mp4")
        with open(self.f3, "w") as f:
            f.write("mock video 3 duplicate episode")

        # Populate synthetic inventory
        conn = init_db(self.db_path)
        with conn:
            conn.execute("""
                INSERT INTO media_files (file_path, directory, filename, extension, media_type, file_size, mtime, v_codec, width, height, resolution_tier)
                VALUES (?, ?, ?, '.mp4', 'video', 100, 1600000000.0, 'h264', 1920, 1080, '1080p')
            """, (self.f1, self.vixen_dir, os.path.basename(self.f1)))
            conn.execute("""
                INSERT INTO media_files (file_path, directory, filename, extension, media_type, file_size, mtime, v_codec, width, height, resolution_tier)
                VALUES (?, ?, ?, '.mp4', 'video', 200, 1600000000.0, 'h264', 1280, 720, '720p')
            """, (self.f2, self.vixen_dir, os.path.basename(self.f2)))
            conn.execute("""
                INSERT INTO media_files (file_path, directory, filename, extension, media_type, file_size, mtime, v_codec, width, height, resolution_tier)
                VALUES (?, ?, ?, '.mp4', 'video', 300, 1600000000.0, 'h264', 1280, 720, '720p')
            """, (self.f3, self.vixen_dir, os.path.basename(self.f3)))
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_plan_and_collision_disambiguation(self):
        plans, stats = plan_renames(self.db_path)
        self.assertEqual(stats["total_records"], 3)
        self.assertEqual(stats["collisions_resolved"], 1)
        
        target_names = [p["target_filename"] for p in plans]
        # Should have Episode 6463 and Episode 6463 (2)
        has_ep = any("Episode 6463" in n and "(2)" not in n for n in target_names)
        has_ep2 = any("Episode 6463" in n and "(2)" in n for n in target_names)
        self.assertTrue(has_ep)
        self.assertTrue(has_ep2)

    def test_full_execution_and_rollback_roundtrip(self):
        plans, stats = plan_renames(self.db_path)
        
        # 1. Execute rename
        execute_pipeline(plans, self.ledger_path, apply_tags=False)

        # Assert original files do not exist
        self.assertFalse(os.path.exists(self.f1))
        self.assertFalse(os.path.exists(self.f2))
        self.assertFalse(os.path.exists(self.f3))

        # Assert target files exist on disk
        for p in plans:
            self.assertTrue(os.path.exists(p["target_path"]))

        # 2. Rollback
        rollback_transactions(self.ledger_path)

        # Assert original files are restored exactly
        self.assertTrue(os.path.exists(self.f1))
        self.assertTrue(os.path.exists(self.f2))
        self.assertTrue(os.path.exists(self.f3))

        # Verify content
        with open(self.f1) as f:
            self.assertEqual(f.read(), "mock video 1")
        with open(self.f2) as f:
            self.assertEqual(f.read(), "mock video 2")
        with open(self.f3) as f:
            self.assertEqual(f.read(), "mock video 3 duplicate episode")

if __name__ == "__main__":
    unittest.main()
