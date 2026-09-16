import os
import sys
import unittest
import tempfile
import sqlite3
import shutil
import time

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from execute_folder_restructure import (
    init_dir_undo_ledger,
    execute_restructure,
    prune_empty_directories
)
from rollback_folders import rollback_directory_restructure

class TestFolderRestructureLedger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="aloha_restructure_test_")
        self.ledger_path = os.path.join(self.temp_dir, "test_dir_undo.db")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_restructure_execution_and_rollback_roundtrip(self):
        root = os.path.join(self.temp_dir, "Aloha")
        os.makedirs(root, exist_ok=True)

        # Create mock folders
        # 1. Bangbus videos
        bb_dir = os.path.join(root, "Bangbus ALL 2010 videos 720p")
        os.makedirs(bb_dir, exist_ok=True)
        bb_file = os.path.join(bb_dir, "[Bangbus] Episode 101 [720p H264].mp4")
        with open(bb_file, "w") as f:
            f.write("content 1")
        test_mtime = 1600000000.0
        os.utime(bb_file, (test_mtime, test_mtime))

        # 2. Brazzers single-release wrapper
        bz_wrap = os.path.join(root, "Brazzers", "BrazzersExxtra.21.11.13.Billie.Star.XXX.480p.MP4-XXX")
        os.makedirs(bz_wrap, exist_ok=True)
        bz_file = os.path.join(bz_wrap, "[Brazzers Exxtra] Episode 202 [480p H264].mp4")
        with open(bz_file, "w") as f:
            f.write("content 2")
        os.utime(bz_file, (test_mtime, test_mtime))

        # 3. GIF file
        gif_dir = os.path.join(root, "GIF")
        os.makedirs(gif_dir, exist_ok=True)
        gif_file = os.path.join(gif_dir, "animation.gif")
        with open(gif_file, "w") as f:
            f.write("content 3")

        # Execute restructure
        execute_restructure(root, self.ledger_path, dry_run=False)

        # Verify new layout
        target_bb = os.path.join(root, "Studios", "Bangbus", "[Bangbus] Episode 101 [720p H264].mp4")
        target_bz = os.path.join(root, "Studios", "Brazzers", "[Brazzers Exxtra] Episode 202 [480p H264].mp4")
        target_gif = os.path.join(root, "Photos & Sets", "GIFs", "animation.gif")

        self.assertTrue(os.path.exists(target_bb))
        self.assertTrue(os.path.exists(target_bz))
        self.assertTrue(os.path.exists(target_gif))

        # Verify old wrappers are pruned
        self.assertFalse(os.path.exists(bz_wrap))

        # Verify mtime preserved
        self.assertAlmostEqual(os.path.getmtime(target_bb), test_mtime, delta=2.0)

        # Verify ledger entries
        conn = sqlite3.connect(self.ledger_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM transactions WHERE status = 'completed'")
        completed_count = cur.fetchone()[0]
        self.assertEqual(completed_count, 3)
        conn.close()

        # Execute rollback
        rollback_directory_restructure(self.ledger_path, root_dir=root, dry_run=False)

        # Verify original files are restored
        self.assertTrue(os.path.exists(bb_file))
        self.assertTrue(os.path.exists(bz_file))
        self.assertTrue(os.path.exists(gif_file))

        # Verify target folders are gone/reverted
        self.assertFalse(os.path.exists(target_bb))
        self.assertFalse(os.path.exists(target_bz))
        self.assertFalse(os.path.exists(target_gif))

        # Verify ledger status updated to reverted
        conn = sqlite3.connect(self.ledger_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM transactions WHERE status = 'reverted'")
        reverted_count = cur.fetchone()[0]
        self.assertEqual(reverted_count, 3)
        conn.close()

if __name__ == "__main__":
    unittest.main()
