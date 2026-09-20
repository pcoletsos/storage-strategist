#!/usr/bin/env python3
"""Multi-tier media deduplication pipeline for Aloha.

Performs exact byte matching (fast partial + full SHA-256), perceptual image
deduplication (pHash + dHash with BK-Tree indexing), and video keyframe
fingerprinting (multi-frame sampling via OpenCV). Provides non-destructive
preview reports, reversible quarantine staging, and transactional SQLite
ledger tracking with full rollback support.
"""

import os
import sys
import stat
import time
import json
import shutil
import hashlib
import sqlite3
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set

# Reconfigure console output for Windows UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from media_name_parser import to_extended_path

DEFAULT_TARGET_DIR = r"F:\Aloha"
DEFAULT_DB_PATH = os.path.join(os.path.dirname(SCRIPTS_DIR), "media_inventory.db")
DEFAULT_LEDGER_PATH = os.path.join(os.path.dirname(SCRIPTS_DIR), "deduplication_ledger.db")
DEFAULT_REPORT_PATH = os.path.join(os.path.dirname(SCRIPTS_DIR), "deduplication_preview.json")

CANONICAL_ROOTS = [
    "Studios",
    "Movies",
    "Celebrities",
    "Collections & Siterips",
    "Photos & Sets",
    "Magazines & Docs",
]

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff"}
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".m4v"}

FILE_ATTRIBUTE_NORMAL = 0x80


def clear_readonly(file_path: str) -> None:
    """Clears read-only file attributes using Windows kernel32 and os.chmod."""
    try:
        norm = to_extended_path(file_path)
        if os.path.exists(norm):
            os.chmod(norm, stat.S_IWRITE | stat.S_IREAD)
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(norm, FILE_ATTRIBUTE_NORMAL)
    except Exception:
        pass


def is_game_path(file_path: str) -> bool:
    """Checks whether path resides within isolated Games directory."""
    norm = file_path.replace("/", "\\")
    return "\\Aloha\\Games\\" in norm or norm.endswith("\\Aloha\\Games") or "\\Games\\" in norm


def init_ledger(ledger_path: str) -> sqlite3.Connection:
    """Initializes transactional SQLite ledger with WAL mode and tables."""
    conn = sqlite3.connect(ledger_path, timeout=60.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS duplicate_clusters (
                cluster_id TEXT PRIMARY KEY,
                detection_type TEXT NOT NULL,
                master_path TEXT NOT NULL,
                duplicate_count INTEGER NOT NULL,
                potential_savings_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS duplicate_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT NOT NULL,
                original_path TEXT NOT NULL UNIQUE,
                quarantine_path TEXT,
                file_size INTEGER NOT NULL,
                hash_signature TEXT NOT NULL,
                hamming_distance INTEGER,
                original_mtime REAL,
                status TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                FOREIGN KEY(cluster_id) REFERENCES duplicate_clusters(cluster_id)
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dup_files_cluster ON duplicate_files(cluster_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dup_files_status ON duplicate_files(status);")
    return conn


def compute_partial_hash(file_path: str, chunk_size: int = 65536) -> Optional[str]:
    """Computes fast partial SHA-256 from first 64KB and last 64KB of file."""
    try:
        norm = to_extended_path(file_path)
        file_size = os.path.getsize(norm)
        hasher = hashlib.sha256()

        with open(norm, "rb") as f:
            if file_size <= chunk_size * 2:
                hasher.update(f.read())
            else:
                hasher.update(f.read(chunk_size))
                f.seek(file_size - chunk_size)
                hasher.update(f.read(chunk_size))

        return hasher.hexdigest()
    except Exception as e:
        print(f"[WARN] Failed to compute partial hash for {file_path}: {e}")
        return None


def compute_full_hash(file_path: str, chunk_size: int = 65536) -> Optional[str]:
    """Computes full SHA-256 digest of file."""
    try:
        norm = to_extended_path(file_path)
        hasher = hashlib.sha256()
        with open(norm, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"[WARN] Failed to compute full hash for {file_path}: {e}")
        return None


class BKTree:
    """Burkhard-Keller Tree for fast metric space near-neighbor lookup."""

    def __init__(self):
        self.tree: Optional[Tuple[Tuple[int, Any], Dict[int, Any]]] = None

    @staticmethod
    def hamming_distance(h1: int, h2: int) -> int:
        """Calculates Hamming distance between two 64-bit integer hashes."""
        return (h1 ^ h2).bit_count()

    def add(self, node: Tuple[int, Any]) -> None:
        """Inserts (hash_int, metadata) node into the BK-Tree."""
        if self.tree is None:
            self.tree = (node, {})
            return

        curr, children = self.tree
        while True:
            dist = self.hamming_distance(curr[0], node[0])
            if dist not in children:
                children[dist] = (node, {})
                break
            curr, children = children[dist]

    def find(self, query_hash: int, max_dist: int) -> List[Tuple[int, Tuple[int, Any]]]:
        """Finds all nodes within max_dist Hamming distance."""
        if self.tree is None:
            return []

        candidates = [self.tree]
        results: List[Tuple[int, Tuple[int, Any]]] = []

        while candidates:
            curr, children = candidates.pop()
            dist = self.hamming_distance(curr[0], query_hash)
            if dist <= max_dist:
                results.append((dist, curr))

            low = dist - max_dist
            high = dist + max_dist
            for d_val, child in children.items():
                if low <= d_val <= high:
                    candidates.append(child)

        return results


class DisjointSet:
    """Disjoint Set (Union-Find) data structure with path compression."""

    def __init__(self):
        self.parent: Dict[str, str] = {}

    def find(self, item: str) -> str:
        if item not in self.parent:
            self.parent[item] = item
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: str, b: str) -> None:
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a


def select_exact_master(file_records: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Selects canonical master from exact duplicates based on path hierarchy and quality."""
    def sort_key(rec: Dict[str, Any]) -> Tuple[int, int, str]:
        path = rec["file_path"].replace("/", "\\")
        has_metadata = 1 if rec.get("existing_title") or rec.get("studio") else 0
        depth = len(path.split("\\"))
        return (-has_metadata, depth, path)

    sorted_records = sorted(file_records, key=sort_key)
    master = sorted_records[0]
    duplicates = sorted_records[1:]
    return master, duplicates


def select_image_master(file_records: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Selects master image based on resolution, then file size, then earliest mtime."""
    def sort_key(rec: Dict[str, Any]) -> Tuple[int, int, float, str]:
        width = rec.get("width") or 0
        height = rec.get("height") or 0
        pixel_count = width * height
        file_size = rec.get("file_size") or 0
        mtime = rec.get("mtime") or 0.0
        path = rec["file_path"].replace("/", "\\")
        return (-pixel_count, -file_size, mtime, path)

    sorted_records = sorted(file_records, key=sort_key)
    master = sorted_records[0]
    duplicates = sorted_records[1:]
    return master, duplicates


def select_video_master(file_records: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Selects master video based on resolution tier, bitrate, file size, and metadata."""
    def resolution_score(tier: Optional[str]) -> int:
        if not tier:
            return 0
        t = tier.upper()
        if "4K" in t or "2160P" in t:
            return 4
        elif "1080P" in t:
            return 3
        elif "720P" in t:
            return 2
        elif "480P" in t:
            return 1
        return 0

    def sort_key(rec: Dict[str, Any]) -> Tuple[int, int, int, int, str]:
        r_score = resolution_score(rec.get("resolution_tier"))
        bitrate = rec.get("bitrate") or 0
        file_size = rec.get("file_size") or 0
        has_meta = 1 if rec.get("studio") or rec.get("existing_title") else 0
        path = rec["file_path"].replace("/", "\\")
        return (-r_score, -bitrate, -file_size, -has_meta, path)

    sorted_records = sorted(file_records, key=sort_key)
    master = sorted_records[0]
    duplicates = sorted_records[1:]
    return master, duplicates


# ==============================================================================
# Tier 1: Exact Byte Matching
# ==============================================================================

def find_exact_duplicates(
    db_path: str,
    target_dir: str = DEFAULT_TARGET_DIR,
    pools: Optional[List[str]] = None,
    min_size: int = 1048576,
) -> List[Dict[str, Any]]:
    """Identifies exact byte-for-byte duplicate clusters using fast partial and full SHA-256."""
    clusters: List[Dict[str, Any]] = []

    if not os.path.exists(db_path):
        print(f"[ERROR] Media inventory database not found at {db_path}")
        return clusters

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, file_path, file_size, width, height, duration, bitrate,
               resolution_tier, existing_title, studio, mtime
        FROM media_files
        WHERE file_size >= ?
    """
    params: List[Any] = [min_size]

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    # Group candidate records by identical file size
    size_groups: Dict[int, List[Dict[str, Any]]] = {}
    for row in rows:
        rec = dict(row)
        path = rec["file_path"]
        if is_game_path(path):
            continue
        if pools:
            norm = path.replace("/", "\\")
            if not any(f"\\Aloha\\{pool}\\" in norm for pool in pools):
                continue
        size_groups.setdefault(rec["file_size"], []).append(rec)

    potential_groups = [g for g in size_groups.values() if len(g) > 1]
    print(f"[INFO] Evaluating {len(potential_groups)} file size collision groups (>={min_size} bytes)")

    for group in potential_groups:
        # Step 2: Partial SHA-256 filter
        partial_map: Dict[str, List[Dict[str, Any]]] = {}
        for rec in group:
            p_hash = compute_partial_hash(rec["file_path"])
            if p_hash:
                rec["partial_hash"] = p_hash
                partial_map.setdefault(p_hash, []).append(rec)

        for p_hash, partial_candidates in partial_map.items():
            if len(partial_candidates) < 2:
                continue

            # Step 3: Full SHA-256 verification
            full_map: Dict[str, List[Dict[str, Any]]] = {}
            for rec in partial_candidates:
                f_hash = compute_full_hash(rec["file_path"])
                if f_hash:
                    rec["full_hash"] = f_hash
                    full_map.setdefault(f_hash, []).append(rec)

            for f_hash, exact_members in full_map.items():
                if len(exact_members) < 2:
                    continue

                master, duplicates = select_exact_master(exact_members)
                cluster_id = f"cluster_exact_{f_hash[:12]}"
                savings = sum(d["file_size"] for d in duplicates)

                clusters.append({
                    "cluster_id": cluster_id,
                    "detection_type": "exact_byte",
                    "master_path": master["file_path"],
                    "master_record": master,
                    "duplicate_count": len(duplicates),
                    "potential_savings_bytes": savings,
                    "duplicates": [
                        {
                            "original_path": d["file_path"],
                            "file_size": d["file_size"],
                            "hash_signature": f_hash,
                            "hamming_distance": 0,
                            "original_mtime": d.get("mtime") or 0.0,
                        }
                        for d in duplicates
                    ],
                })

    return clusters


# ==============================================================================
# Tier 2: Perceptual Image Deduplication
# ==============================================================================

def compute_image_hashes(file_path: str) -> Optional[Tuple[int, int, int, int]]:
    """Computes pHash, dHash, width, and height for an image file."""
    try:
        from PIL import Image
        import imagehash

        norm = to_extended_path(file_path)
        with Image.open(norm) as img:
            width, height = img.size
            p_hash = imagehash.phash(img)
            d_hash = imagehash.dhash(img)
            p_int = int(str(p_hash), 16)
            d_int = int(str(d_hash), 16)
            return p_int, d_int, width, height
    except Exception:
        return None


def find_image_duplicates(
    db_path: str,
    target_dir: str = DEFAULT_TARGET_DIR,
    pools: Optional[List[str]] = None,
    threshold: int = 4,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Identifies perceptual image duplicate clusters using pHash and BK-Tree search."""
    clusters: List[Dict[str, Any]] = []

    if not os.path.exists(db_path):
        print(f"[ERROR] Media inventory database not found at {db_path}")
        return clusters

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, file_path, file_size, width, height, mtime
        FROM media_files
        WHERE media_type = 'image'
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    image_records: List[Dict[str, Any]] = []
    for row in rows:
        rec = dict(row)
        path = rec["file_path"]
        if is_game_path(path):
            continue
        if pools:
            norm = path.replace("/", "\\")
            if not any(f"\\Aloha\\{pool}\\" in norm for pool in pools):
                continue
        image_records.append(rec)

    if limit:
        image_records = image_records[:limit]

    print(f"[INFO] Computing perceptual image hashes across {len(image_records)} assets")
    bk_tree = BKTree()
    hash_map: Dict[str, Dict[str, Any]] = {}
    valid_records: List[Dict[str, Any]] = []

    for idx, rec in enumerate(image_records, 1):
        fpath = rec["file_path"]
        hashes = compute_image_hashes(fpath)
        if not hashes:
            continue
        p_int, d_int, w, h = hashes
        rec["p_hash"] = p_int
        rec["d_hash"] = d_int
        rec["width"] = w
        rec["height"] = h
        bk_tree.add((p_int, fpath))
        hash_map[fpath] = rec
        valid_records.append(rec)

        if idx % 1000 == 0 or idx == len(image_records):
            print(f"[PROGRESS] Hashed {idx}/{len(image_records)} images")

    print(f"[INFO] Indexing complete ({len(valid_records)} indexed). Searching near-neighbors (threshold <= {threshold})...")
    dset = DisjointSet()
    pair_distances: Dict[Tuple[str, str], int] = {}

    for rec in valid_records:
        fpath = rec["file_path"]
        p_int = rec["p_hash"]
        neighbors = bk_tree.find(p_int, threshold)
        for dist, (n_hash, n_path) in neighbors:
            if n_path == fpath:
                continue
            # Check secondary dHash distance to verify visual consistency
            n_rec = hash_map[n_path]
            d_dist = BKTree.hamming_distance(rec["d_hash"], n_rec["d_hash"])
            if d_dist <= threshold + 4:
                dset.union(fpath, n_path)
                pair_key = (min(fpath, n_path), max(fpath, n_path))
                pair_distances[pair_key] = dist

    # Group connected components into clusters
    cluster_groups: Dict[str, List[Dict[str, Any]]] = {}
    for rec in valid_records:
        fpath = rec["file_path"]
        root = dset.find(fpath)
        cluster_groups.setdefault(root, []).append(rec)

    multi_item_clusters = [g for g in cluster_groups.values() if len(g) > 1]
    print(f"[INFO] Identified {len(multi_item_clusters)} perceptual image duplicate clusters")

    for group in multi_item_clusters:
        master, duplicates = select_image_master(group)
        cluster_id = f"cluster_img_{master['p_hash']:016x}"
        savings = sum(d["file_size"] for d in duplicates)

        cluster_dupes = []
        for d in duplicates:
            pair_key = (min(master["file_path"], d["file_path"]), max(master["file_path"], d["file_path"]))
            dist = pair_distances.get(pair_key, threshold)
            cluster_dupes.append({
                "original_path": d["file_path"],
                "file_size": d["file_size"],
                "hash_signature": f"{d['p_hash']:016x}",
                "hamming_distance": dist,
                "original_mtime": d.get("mtime") or 0.0,
            })

        clusters.append({
            "cluster_id": cluster_id,
            "detection_type": "perceptual_image",
            "master_path": master["file_path"],
            "master_record": master,
            "duplicate_count": len(duplicates),
            "potential_savings_bytes": savings,
            "duplicates": cluster_dupes,
        })

    return clusters


# ==============================================================================
# Tier 3: Video Keyframe Fingerprinting
# ==============================================================================

def compute_video_fingerprint(file_path: str, duration: float) -> Optional[List[int]]:
    """Extracts 3 keyframes at 20%, 50%, and 80% duration and computes pHash integer for each."""
    try:
        import cv2
        from PIL import Image
        import imagehash

        norm = to_extended_path(file_path)
        cap = cv2.VideoCapture(norm)
        if not cap.isOpened():
            return None

        sample_pcts = [0.20, 0.50, 0.80]
        hashes = []

        for pct in sample_pcts:
            pos_msec = (duration * pct) * 1000.0
            cap.set(cv2.CAP_PROP_POS_MSEC, pos_msec)
            ret, frame = cap.read()
            if not ret or frame is None:
                cap.release()
                return None

            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(rgb_frame)
            ph = imagehash.phash(pil_img)
            hashes.append(int(str(ph), 16))

        cap.release()
        return hashes
    except Exception:
        return None


def find_video_duplicates(
    db_path: str,
    target_dir: str = DEFAULT_TARGET_DIR,
    pools: Optional[List[str]] = None,
    duration_tolerance: float = 2.0,
    threshold: int = 6,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Identifies perceptual video duplicates by duration bucketing and keyframe fingerprinting."""
    clusters: List[Dict[str, Any]] = []

    if not os.path.exists(db_path):
        print(f"[ERROR] Media inventory database not found at {db_path}")
        return clusters

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, file_path, file_size, width, height, duration, bitrate,
               resolution_tier, existing_title, studio, mtime
        FROM media_files
        WHERE media_type = 'video' AND duration IS NOT NULL AND duration > 10.0
        ORDER BY duration ASC
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    candidate_videos: List[Dict[str, Any]] = []
    for row in rows:
        rec = dict(row)
        path = rec["file_path"]
        if is_game_path(path):
            continue
        if pools:
            norm = path.replace("/", "\\")
            if not any(f"\\Aloha\\{pool}\\" in norm for pool in pools):
                continue
        candidate_videos.append(rec)

    if limit:
        candidate_videos = candidate_videos[:limit]

    print(f"[INFO] Filtering {len(candidate_videos)} video assets into duration collision windows (+/- {duration_tolerance}s)")

    # Group candidate video pairs by duration window
    duration_clusters: List[List[Dict[str, Any]]] = []
    n = len(candidate_videos)
    i = 0
    while i < n:
        group = [candidate_videos[i]]
        j = i + 1
        while j < n and (candidate_videos[j]["duration"] - candidate_videos[i]["duration"]) <= duration_tolerance:
            group.append(candidate_videos[j])
            j += 1
        if len(group) > 1:
            duration_clusters.append(group)
        i += 1

    print(f"[INFO] Found {len(duration_clusters)} duration collision candidate groups")
    video_fingerprints: Dict[str, List[int]] = {}
    dset = DisjointSet()
    matched_pairs: Dict[Tuple[str, str], int] = {}

    for grp_idx, group in enumerate(duration_clusters, 1):
        for v in group:
            v_path = v["file_path"]
            if v_path not in video_fingerprints:
                fps = compute_video_fingerprint(v_path, v["duration"])
                if fps:
                    video_fingerprints[v_path] = fps

        for idx_a in range(len(group)):
            for idx_b in range(idx_a + 1, len(group)):
                v_a = group[idx_a]["file_path"]
                v_b = group[idx_b]["file_path"]
                fps_a = video_fingerprints.get(v_a)
                fps_b = video_fingerprints.get(v_b)
                if not fps_a or not fps_b:
                    continue

                # Compare 3 keyframes
                distances = [BKTree.hamming_distance(fps_a[k], fps_b[k]) for k in range(3)]
                mean_dist = sum(distances) / 3.0

                # Match if all 3 frames match within threshold or average distance <= threshold
                if max(distances) <= threshold or mean_dist <= threshold - 1:
                    dset.union(v_a, v_b)
                    pair_key = (min(v_a, v_b), max(v_a, v_b))
                    matched_pairs[pair_key] = int(mean_dist)

    # Collect connected components
    comp_groups: Dict[str, List[Dict[str, Any]]] = {}
    for v in candidate_videos:
        v_path = v["file_path"]
        if v_path in video_fingerprints:
            root = dset.find(v_path)
            comp_groups.setdefault(root, []).append(v)

    multi_video_clusters = [g for g in comp_groups.values() if len(g) > 1]
    print(f"[INFO] Identified {len(multi_video_clusters)} perceptual video duplicate clusters")

    for group in multi_video_clusters:
        master, duplicates = select_video_master(group)
        cluster_id = f"cluster_vid_{master['id']}"
        savings = sum(d["file_size"] for d in duplicates)

        cluster_dupes = []
        for d in duplicates:
            pair_key = (min(master["file_path"], d["file_path"]), max(master["file_path"], d["file_path"]))
            dist = matched_pairs.get(pair_key, threshold)
            cluster_dupes.append({
                "original_path": d["file_path"],
                "file_size": d["file_size"],
                "hash_signature": f"vid_fp_{d['id']}",
                "hamming_distance": dist,
                "original_mtime": d.get("mtime") or 0.0,
            })

        clusters.append({
            "cluster_id": cluster_id,
            "detection_type": "video_keyframe",
            "master_path": master["file_path"],
            "master_record": master,
            "duplicate_count": len(duplicates),
            "potential_savings_bytes": savings,
            "duplicates": cluster_dupes,
        })

    return clusters


# ==============================================================================
# Quarantine Staging and Rollback
# ==============================================================================

def execute_quarantine(
    clusters: List[Dict[str, Any]],
    ledger_conn: sqlite3.Connection,
    target_dir: str = DEFAULT_TARGET_DIR,
) -> int:
    """Stages duplicate candidates into safe reversible quarantine folder."""
    quarantine_base = os.path.join(target_dir, ".quarantine_duplicates")
    moved_count = 0
    now_str = datetime.now().isoformat()

    with ledger_conn:
        for cluster in clusters:
            cluster_id = cluster["cluster_id"]
            detection_type = cluster["detection_type"]
            master_path = cluster["master_path"]
            dup_count = cluster["duplicate_count"]
            savings = cluster["potential_savings_bytes"]

            ledger_conn.execute("""
                INSERT OR REPLACE INTO duplicate_clusters
                (cluster_id, detection_type, master_path, duplicate_count, potential_savings_bytes, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cluster_id, detection_type, master_path, dup_count, savings, now_str))

            cluster_quarantine_dir = os.path.join(quarantine_base, cluster_id)

            for d in cluster["duplicates"]:
                orig_path = d["original_path"]
                if is_game_path(orig_path):
                    print(f"[SAFETY] Skipping game file: {orig_path}")
                    continue

                norm_orig = to_extended_path(orig_path)
                if not os.path.exists(norm_orig):
                    print(f"[WARN] Original file does not exist: {orig_path}")
                    continue

                filename = os.path.basename(orig_path)
                os.makedirs(cluster_quarantine_dir, exist_ok=True)

                dest_path = os.path.join(cluster_quarantine_dir, filename)
                norm_dest = to_extended_path(dest_path)

                # Disambiguate destination if already exists
                counter = 1
                base_name, ext = os.path.splitext(filename)
                while os.path.exists(norm_dest):
                    dest_path = os.path.join(cluster_quarantine_dir, f"{base_name}_{counter}{ext}")
                    norm_dest = to_extended_path(dest_path)
                    counter += 1

                # Record in ledger before moving
                ledger_conn.execute("""
                    INSERT OR REPLACE INTO duplicate_files
                    (cluster_id, original_path, quarantine_path, file_size, hash_signature,
                     hamming_distance, original_mtime, status, executed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cluster_id,
                    orig_path,
                    dest_path,
                    d["file_size"],
                    d["hash_signature"],
                    d.get("hamming_distance", 0),
                    d.get("original_mtime", 0.0),
                    "quarantined",
                    now_str,
                ))

                clear_readonly(norm_orig)
                shutil.move(norm_orig, norm_dest)
                moved_count += 1
                print(f"[QUARANTINE] Staged item {moved_count} ({d['file_size']:,} bytes) in {cluster_id}")

    return moved_count


def execute_rollback(ledger_conn: sqlite3.Connection) -> int:
    """Restores all quarantined files back to their exact original paths."""
    restored_count = 0
    cursor = ledger_conn.cursor()
    cursor.execute("""
        SELECT id, original_path, quarantine_path, original_mtime
        FROM duplicate_files
        WHERE status = 'quarantined'
    """)
    rows = cursor.fetchall()
    now_str = datetime.now().isoformat()

    with ledger_conn:
        for row in rows:
            rec_id, orig_path, quar_path, orig_mtime = row
            norm_quar = to_extended_path(quar_path)
            norm_orig = to_extended_path(orig_path)

            if not os.path.exists(norm_quar):
                print(f"[WARN] Quarantined file not found: {quar_path}")
                continue

            orig_dir = os.path.dirname(norm_orig)
            os.makedirs(orig_dir, exist_ok=True)

            clear_readonly(norm_quar)
            shutil.move(norm_quar, norm_orig)

            if orig_mtime and orig_mtime > 0:
                try:
                    os.utime(norm_orig, (orig_mtime, orig_mtime))
                except Exception:
                    pass

            ledger_conn.execute("""
                UPDATE duplicate_files
                SET status = 'restored', executed_at = ?
                WHERE id = ?
            """, (now_str, rec_id))

            restored_count += 1
            print(f"[RESTORED] Restored item {restored_count} (record id {rec_id})")

    return restored_count


# ==============================================================================
# CLI Orchestrator
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Perceptual Image and Video Deduplication Pipeline for Aloha"
    )
    parser.add_argument(
        "--mode",
        choices=["exact", "images", "videos", "all"],
        default="all",
        help="Deduplication mode: exact byte matching, perceptual images, video keyframes, or all",
    )
    parser.add_argument(
        "--target-dir",
        default=DEFAULT_TARGET_DIR,
        help="Target base directory (default: F:\\Aloha)",
    )
    parser.add_argument(
        "--pool",
        help="Comma-separated target pools (e.g. Studios,Movies,'Photos & Sets')",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Hamming distance threshold for perceptual matches (default: 4)",
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=1048576,
        help="Minimum file size in bytes for Tier 1 exact collisions (default: 1048576 / 1MB)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate deduplication run and produce JSON preview report without moving files",
    )
    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="Execute quarantine staging by moving duplicate candidates into .quarantine_duplicates",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Restore quarantined files back to original paths from ledger",
    )
    parser.add_argument(
        "--report",
        default=DEFAULT_REPORT_PATH,
        help="Output path for deduplication preview/audit JSON report",
    )
    parser.add_argument(
        "--db-path",
        default=DEFAULT_DB_PATH,
        help="Path to media_inventory.db",
    )
    parser.add_argument(
        "--ledger-path",
        default=DEFAULT_LEDGER_PATH,
        help="Path to deduplication_ledger.db",
    )
    parser.add_argument(
        "--from-preview",
        help="Load pre-computed duplicate clusters from JSON preview report",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of candidate assets to process (useful for pilot validation)",
    )

    args = parser.parse_args()

    ledger_conn = init_ledger(args.ledger_path)

    if args.rollback:
        print("[INFO] Initiating quarantine rollback...")
        restored = execute_rollback(ledger_conn)
        print(f"[COMPLETE] Restored {restored} files from quarantine.")
        ledger_conn.close()
        return

    all_clusters: List[Dict[str, Any]] = []

    if args.from_preview:
        if not os.path.exists(args.from_preview):
            print(f"[ERROR] Preview report not found at {args.from_preview}")
            ledger_conn.close()
            return
        with open(args.from_preview, "r", encoding="utf-8") as f:
            preview_data = json.load(f)
        all_clusters = preview_data.get("clusters", [])
        print(f"[INFO] Loaded {len(all_clusters)} duplicate clusters from {args.from_preview}")
    else:
        pools = [p.strip() for p in args.pool.split(",") if p.strip()] if args.pool else None

        if args.mode in ("exact", "all"):
            print("\n--- Tier 1: Exact Byte Matching ---")
            exact_clusters = find_exact_duplicates(
                db_path=args.db_path,
                target_dir=args.target_dir,
                pools=pools,
                min_size=args.min_size,
            )
            all_clusters.extend(exact_clusters)
            print(f"Tier 1 identified {len(exact_clusters)} exact duplicate clusters.")

        if args.mode in ("images", "all"):
            print("\n--- Tier 2: Perceptual Image Deduplication ---")
            img_clusters = find_image_duplicates(
                db_path=args.db_path,
                target_dir=args.target_dir,
                pools=pools,
                threshold=args.threshold,
                limit=args.limit,
            )
            all_clusters.extend(img_clusters)
            print(f"Tier 2 identified {len(img_clusters)} perceptual image duplicate clusters.")

        if args.mode in ("videos", "all"):
            print("\n--- Tier 3: Video Keyframe Fingerprinting ---")
            vid_clusters = find_video_duplicates(
                db_path=args.db_path,
                target_dir=args.target_dir,
                pools=pools,
                threshold=args.threshold,
                limit=args.limit,
            )
            all_clusters.extend(vid_clusters)
            print(f"Tier 3 identified {len(vid_clusters)} perceptual video duplicate clusters.")

    total_duplicates = sum(c["duplicate_count"] for c in all_clusters)
    total_savings_bytes = sum(c["potential_savings_bytes"] for c in all_clusters)
    total_savings_mb = total_savings_bytes / (1024 * 1024)
    total_savings_gb = total_savings_bytes / (1024 * 1024 * 1024)

    print("\n==================================================")
    print("DEDUPLICATION AUDIT SUMMARY")
    print("==================================================")
    print(f"Total Duplicate Clusters: {len(all_clusters)}")
    print(f"Total Duplicate Files:    {total_duplicates}")
    print(f"Potential Space Savings:  {total_savings_bytes:,} bytes ({total_savings_mb:.2f} MB / {total_savings_gb:.2f} GB)")
    print("==================================================")

    # Export report if generated from scans
    if not args.from_preview or args.report != DEFAULT_REPORT_PATH:
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "mode": args.mode,
            "target_dir": args.target_dir,
            "pools": pools if not args.from_preview else None,
            "threshold": args.threshold,
            "total_clusters": len(all_clusters),
            "total_duplicates": total_duplicates,
            "potential_savings_bytes": total_savings_bytes,
            "potential_savings_mb": round(total_savings_mb, 2),
            "potential_savings_gb": round(total_savings_gb, 2),
            "clusters": all_clusters,
        }

        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[REPORT] Written audit report to {args.report}")

    if args.quarantine:
        if args.dry_run:
            print("[INFO] --dry-run active: Quarantine staging skipped.")
        else:
            print(f"\n[QUARANTINE] Staging {total_duplicates} duplicate candidates into quarantine...")
            moved = execute_quarantine(all_clusters, ledger_conn, target_dir=args.target_dir)
            print(f"[COMPLETE] Quarantined {moved} duplicate files into .quarantine_duplicates.")

    ledger_conn.close()


if __name__ == "__main__":
    main()
