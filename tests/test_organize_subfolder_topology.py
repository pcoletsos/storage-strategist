import os
import sys
import tempfile
import sqlite3
import pytest

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from organize_subfolder_topology import (
    plan_subfolder_hygiene,
    init_dir_undo_ledger,
    safe_move_file,
    prune_empty_dirs,
    execute_subfolder_hygiene
)


def test_plan_subfolder_hygiene_in_memory():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_inv.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE media_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                directory TEXT,
                filename TEXT,
                file_size INTEGER,
                mtime REAL
            )
        """)
        conn.execute("""
            INSERT INTO media_files (file_path, directory, filename, file_size, mtime)
            VALUES 
            ('F:\\Aloha\\Magazines & Docs\\Greek Periodika - 01.jpg', 'F:\\Aloha\\Magazines & Docs', 'Greek Periodika - 01.jpg', 1000, 1000.0),
            ('F:\\Aloha\\Movies\\New folder\\Dpg Nurses.mkv', 'F:\\Aloha\\Movies\\New folder', 'Dpg Nurses.mkv', 2000, 2000.0),
            ('F:\\Aloha\\Celebrities\\New Folder\\Blake Lively Savages.mp4', 'F:\\Aloha\\Celebrities\\New Folder', 'Blake Lively Savages.mp4', 3000, 3000.0),
            ('F:\\Aloha\\Celebrities\\Updates\\Update1\\Clip1.mp4', 'F:\\Aloha\\Celebrities\\Updates\\Update1', 'Clip1.mp4', 4000, 4000.0),
            ('F:\\Aloha\\Photos & Sets\\New Folder\\Photo1.jpg', 'F:\\Aloha\\Photos & Sets\\New Folder', 'Photo1.jpg', 500, 500.0),
            ('F:\\Aloha\\Photos & Sets\\New Folder3\\P2p_Malware.jpg', 'F:\\Aloha\\Photos & Sets\\New Folder3', 'P2p_Malware.jpg', 600, 600.0),
            ('F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Scr\\01.jpg', 'F:\\Aloha\\Collections & Siterips\\Izzy Green (OnlyFans)\\Izzy Green Pack\\Scr', '01.jpg', 700, 700.0)
        """)
        conn.commit()
        conn.close()

        plans = plan_subfolder_hygiene(db_path)
        assert len(plans) == 7

        # Verify mapping destinations
        plan_dict = {p["filename"]: p for p in plans}
        assert r"Magazines & Docs\Greek Periodika" in plan_dict["Greek Periodika - 01.jpg"]["target_path"]
        assert r"Movies\Digital Playground" in plan_dict["Dpg Nurses.mkv"]["target_path"]
        assert r"Celebrities\Blake Lively" in plan_dict["Blake Lively Savages.mp4"]["target_path"]
        assert r"Celebrities\Mr Skin Updates\Update 1" in plan_dict["Clip1.mp4"]["target_path"]
        assert r"Photos & Sets\Miscellaneous Sets\Album 1" in plan_dict["Photo1.jpg"]["target_path"]
        assert r".quarantine_flagged\new_folder3" in plan_dict["P2p_Malware.jpg"]["target_path"]
        assert plan_dict["P2p_Malware.jpg"]["is_quarantine"] is True
        assert r"Screenshots" in plan_dict["01.jpg"]["target_path"]


def test_safe_move_file_and_timestamp():
    with tempfile.TemporaryDirectory() as tmp_dir:
        src = os.path.join(tmp_dir, "sub1", "file.txt")
        dst = os.path.join(tmp_dir, "sub2", "file.txt")
        os.makedirs(os.path.dirname(src), exist_ok=True)

        target_mtime = 1500000000.0
        with open(src, "w") as f:
            f.write("content")
        os.utime(src, (target_mtime, target_mtime))

        safe_move_file(src, dst, target_mtime)

        assert not os.path.exists(src)
        assert os.path.exists(dst)
        assert abs(os.path.getmtime(dst) - target_mtime) < 2.0


def test_prune_empty_dirs():
    with tempfile.TemporaryDirectory() as tmp_dir:
        empty_sub = os.path.join(tmp_dir, "Movies", "New folder")
        os.makedirs(empty_sub, exist_ok=True)

        # Include thumbs.db in empty folder
        with open(os.path.join(empty_sub, "Thumbs.db"), "w") as f:
            f.write("cache")

        pruned = prune_empty_dirs(tmp_dir)
        assert pruned >= 1
        assert not os.path.exists(empty_sub)
