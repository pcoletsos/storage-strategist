import os
import sys
import pytest

# Ensure scripts dir is on sys.path
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from find_media_duplicates import (
    is_game_path,
    BKTree,
    DisjointSet,
    select_video_master,
)


def test_is_game_path():
    assert is_game_path(r"F:\Aloha\Games\Cutscenes\intro.mp4") is True
    assert is_game_path(r"F:\Aloha\Studios\Brazzers\scene.mp4") is False
    assert is_game_path(r"F:\Aloha\Movies\feature.mp4") is False
    assert is_game_path(r"F:\Aloha\Collections & Siterips\clip.mp4") is False


def test_cross_pool_master_selection_prefers_feature_or_studio():
    # Studio scene (1080p) vs Collections compilation clip (720p)
    studio_item = {
        "file_path": r"F:\Aloha\Studios\Brazzers\Full_Scene.mp4",
        "file_size": 1500000000,
        "width": 1920,
        "height": 1080,
        "bitrate": 5000000,
        "duration": 1800.0,
        "resolution_tier": "1080p",
        "existing_title": "Full Scene",
        "studio": "Brazzers",
    }
    clip_item = {
        "file_path": r"F:\Aloha\Collections & Siterips\Compilations\Clip_Cut.mp4",
        "file_size": 400000000,
        "width": 1280,
        "height": 720,
        "bitrate": 2000000,
        "duration": 1800.5,
        "resolution_tier": "720p",
        "existing_title": "Clip Cut",
        "studio": "Collections",
    }
    master, dupes = select_video_master([studio_item, clip_item])
    assert master["file_path"] == studio_item["file_path"]
    assert len(dupes) == 1
    assert dupes[0]["file_path"] == clip_item["file_path"]


def test_cross_pool_master_selection_prefers_higher_resolution():
    movie_item = {
        "file_path": r"F:\Aloha\Movies\Blockbuster.mp4",
        "file_size": 3000000000,
        "width": 1920,
        "height": 1080,
        "bitrate": 6000000,
        "duration": 5400.0,
        "resolution_tier": "1080p",
    }
    celeb_clip = {
        "file_path": r"F:\Aloha\Celebrities\Star\Scene_Rip.mp4",
        "file_size": 500000000,
        "width": 720,
        "height": 480,
        "bitrate": 1200000,
        "duration": 5401.0,
        "resolution_tier": "480p",
    }
    master, dupes = select_video_master([movie_item, celeb_clip])
    assert master["file_path"] == movie_item["file_path"]
    assert dupes[0]["file_path"] == celeb_clip["file_path"]
