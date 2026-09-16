import os
import sys
import unittest
import tempfile
import shutil

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from dir_structure_planner import (
    clean_folder_name,
    detect_studio_from_path_or_name,
    plan_directory_restructure,
    CANONICAL_ROOTS
)

class TestDirStructurePlanner(unittest.TestCase):
    def test_clean_folder_name(self):
        raw = "BrazzersExxtra.21.11.13.Billie.Star.And.Tina.Fire.Big.Tits.Hit.The.Gym.XXX.480p.MP4-XXX"
        cleaned = clean_folder_name(raw)
        self.assertNotIn("XXX", cleaned)
        self.assertNotIn("480p", cleaned)
        self.assertIn("Billie Star", cleaned)
        self.assertIn("and", cleaned)

    def test_detect_studio(self):
        self.assertEqual(detect_studio_from_path_or_name("Brazzers\\sub", "test.mp4"), "Brazzers")
        self.assertEqual(detect_studio_from_path_or_name("", "[Bangbus] Episode 123.mp4"), "Bangbus")
        self.assertEqual(detect_studio_from_path_or_name("DigitalPlayground\\release", "scene.mp4"), "Digital Playground")
        self.assertEqual(detect_studio_from_path_or_name("Torrents\\Freeze.24.03.08", "scene.mkv"), "Freeze")
        self.assertEqual(detect_studio_from_path_or_name("siterips\\Backroom.Casting.Couch.SITERIP", "clip.mkv"), "Backroom Casting Couch")

    def test_plan_restructure_mock_tree(self):
        with tempfile.TemporaryDirectory() as temp_root:
            # Create synthetic mock tree
            # 1. Studio with single-file release wrapper
            bb_dir = os.path.join(temp_root, "Bangbus ALL 2010 videos 720p")
            os.makedirs(bb_dir, exist_ok=True)
            with open(os.path.join(bb_dir, "[Bangbus] Episode 100 [720p H264].mp4"), "w") as f:
                f.write("dummy")

            bz_wrapper = os.path.join(temp_root, "Brazzers", "BrazzersExxtra.21.11.13.Billie.Star.XXX.480p.MP4-XXX")
            os.makedirs(bz_wrapper, exist_ok=True)
            with open(os.path.join(bz_wrapper, "[Brazzers Exxtra] Episode 200 [480p H264].mp4"), "w") as f:
                f.write("dummy")

            # 2. Games folder with internal tree
            game_internal = os.path.join(temp_root, "Games", "MyGame", "assets", "images")
            os.makedirs(game_internal, exist_ok=True)
            with open(os.path.join(game_internal, "hero.webp"), "w") as f:
                f.write("dummy")

            # 3. Photo set
            photo_dir = os.path.join(temp_root, "GIF")
            os.makedirs(photo_dir, exist_ok=True)
            with open(os.path.join(photo_dir, "sample.gif"), "w") as f:
                f.write("dummy")

            # Run planner
            relocations, stats = plan_directory_restructure(temp_root)

            # Check stats
            self.assertEqual(stats["total_scanned_files"], 4)
            # Bangbus moved to Studios\Bangbus
            # Brazzers flattened to Studios\Brazzers
            # Games remains untouched in Games\MyGame\assets\images
            # GIF moved to Photos & Sets\GIFs

            reloc_by_src = {r["relative_source"]: r for r in relocations}
            
            # Bangbus
            bb_key = os.path.join("Bangbus ALL 2010 videos 720p", "[Bangbus] Episode 100 [720p H264].mp4")
            self.assertIn(bb_key, reloc_by_src)
            self.assertEqual(reloc_by_src[bb_key]["category"], "Studios")
            self.assertEqual(reloc_by_src[bb_key]["relative_target"], os.path.join("Studios", "Bangbus", "[Bangbus] Episode 100 [720p H264].mp4"))

            # Brazzers wrapper flattened
            bz_key = os.path.join("Brazzers", "BrazzersExxtra.21.11.13.Billie.Star.XXX.480p.MP4-XXX", "[Brazzers Exxtra] Episode 200 [480p H264].mp4")
            self.assertIn(bz_key, reloc_by_src)
            self.assertEqual(reloc_by_src[bz_key]["category"], "Studios")
            self.assertEqual(reloc_by_src[bz_key]["relative_target"], os.path.join("Studios", "Brazzers", "[Brazzers Exxtra] Episode 200 [480p H264].mp4"))

            # Games untouched
            game_key = os.path.join("Games", "MyGame", "assets", "images", "hero.webp")
            self.assertIn(game_key, reloc_by_src)
            self.assertEqual(reloc_by_src[game_key]["category"], "Games")
            self.assertFalse(reloc_by_src[game_key]["is_moved"])

if __name__ == "__main__":
    unittest.main()
