# Mission: Perceptual Image & Video Deduplication for F:\Aloha

You are the Grand Issue Orchestrator. Dynamically analyze the target scope, determine the optimal multi-agent topology, and coordinate a specialized squad of agents to execute and deliver the mission with production-ready excellence.

You are NOT constrained to a fixed roster: critically evaluate the problem domain and decide which specialized agents to spawn (for example, Image Hashing & Vision Specialist, Video Fingerprint Engineer, Safe Quarantine & Ledger Architect).

Target Scope / Issues / Milestone:
---

## Objective

Design, implement, and execute a multi-tier deduplication engine across the 23,469 images and 12,187 videos on `F:\Aloha`. Identify exact byte-for-byte clones and perceptual duplicates (visually identical images, resized photo duplicates, and identical video scene re-cuts). Generate comprehensive duplicate audit reports, stage duplicate candidates into a non-destructive quarantine directory, and log all actions in a transactional SQLite ledger.

---

## 1. System and Dataset Context

- **Target Path**: `F:\Aloha` (Drive F:\ on Windows 11).
- **Working Repository**: `E:\repos\projects\storage-strategist`.
- **Media Inventory Database**: `E:\repos\projects\storage-strategist\media_inventory.db` (35,656 records).
- **Installed Vision & Hashing Tooling**:
  - Python 3.12 with `imagehash`, `cv2` (OpenCV), `PIL` (Pillow), `scipy`, `numpy`.
  - Available algorithms: pHash (DCT perceptual), dHash (difference gradient), aHash (average), and SHA-256.
- **Initial Duplicate Indicators**:
  - Exact file size collisions: 45 files totaling 2.67 GB.
  - Unquantified perceptual duplication: Repeated siterip galleries, multi-resolution photo sets, and redundant scene clips.

---

## 2. Multi-Tier Deduplication Architecture

### Tier 1: Exact Byte Matching (Fast Path)
1. Query `media_inventory.db` for files sharing identical `file_size` (> 1 MB).
2. Compute partial SHA-256 (first 64 KB + last 64 KB) to filter non-matching candidates.
3. Compute full SHA-256 to confirm exact 100% binary identity.

### Tier 2: Perceptual Image Deduplication (pHash + dHash)
1. Process images across `F:\Aloha\Photos & Sets\` (2,782 files) and other photo collections.
2. Compute 64-bit perceptual hashes (`imagehash.phash`) and difference hashes (`imagehash.dhash`).
3. Index hashes in memory using a BK-Tree or Vantage-Point Tree for fast Hamming distance lookup.
4. Match pairs where Hamming distance <= 4:
   - Compare resolutions (width x height) and bitrates.
   - Designate the higher-resolution file as the "Master Keeper" and the lower-resolution or compressed file as the "Duplicate Candidate".

### Tier 3: Video Keyframe Fingerprinting
1. For videos sharing similar durations (+/- 2.0 seconds), sample 3 representative keyframes at 20%, 50%, and 80% duration using `cv2.VideoCapture`.
2. Compute perceptual hashes for each keyframe to construct a 192-bit video fingerprint.
3. Detect matching video scenes, resolution downscales, or container wrapper duplicates.

---

## 3. Safe Quarantine and Ledger Architecture

1. **Non-Destructive Reporting First**:
   Always run analysis with `--dry-run` to output `deduplication_preview.json` detailing duplicate clusters, file sizes, resolutions, and potential space savings.
2. **Reversible Quarantine Staging**:
   Never delete files outright during automated runs. Move duplicate candidates into a dedicated quarantine folder on the same volume (`F:\Aloha\.quarantine_duplicates\<cluster_id>\`) to allow instant rollback.
3. **Transactional SQLite Ledger**:
   Track all operations in `deduplication_ledger.db` with schema:
   ```sql
   CREATE TABLE IF NOT EXISTS duplicate_clusters (
       cluster_id TEXT PRIMARY KEY,
       detection_type TEXT NOT NULL,
       master_path TEXT NOT NULL,
       duplicate_count INTEGER NOT NULL,
       potential_savings_bytes INTEGER NOT NULL,
       created_at TEXT NOT NULL
   );

   CREATE TABLE IF NOT EXISTS duplicate_files (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       cluster_id TEXT NOT NULL,
       original_path TEXT NOT NULL UNIQUE,
       quarantine_path TEXT,
       file_size INTEGER NOT NULL,
       hash_signature TEXT NOT NULL,
       hamming_distance INTEGER,
       status TEXT NOT NULL,
       FOREIGN KEY(cluster_id) REFERENCES duplicate_clusters(cluster_id)
   );
   ```

---

## 4. Phased Execution Plan

### Step 1: Tooling Implementation
1. Create `scripts/find_media_duplicates.py`:
   - `--mode <exact|images|videos|all>`
   - `--target-dir <path>` (defaults to `F:\Aloha`)
   - `--threshold <int>` (Hamming distance threshold, default: 4)
   - `--dry-run` (report only)
   - `--quarantine` (move duplicate candidates to `.quarantine_duplicates`)
   - `--rollback` (restore files from quarantine ledger)
2. Add unit tests in `tests/test_find_media_duplicates.py` covering hash calculation, Hamming distance clustering, master-file selection, and quarantine rollback.
3. Verify compliance: `python scripts/check_compliance.py`.

### Step 2: Exact Byte Deduplication Run
1. Run Tier 1 exact byte analysis across all media on `F:\Aloha`.
2. Review exact duplicate candidates and execute quarantine.

### Step 3: Perceptual Image Deduplication Run
1. Run Tier 2 perceptual hash analysis on `F:\Aloha\Photos & Sets\`.
2. Review duplicate image clusters, verify master resolution selection, and generate savings report.

### Step 4: Video Fingerprint Deduplication Run
1. Run Tier 3 video keyframe analysis across `F:\Aloha\Collections & Siterips\` and `F:\Aloha\Studios\`.
2. Identify cross-posted or duplicate scene re-cuts.

---

## 5. Hard Constraints

- **Strict Prohibition on Em Dashes**: Never use em dashes in code comments, CLI messages, logs, or markdown documentation. Use commas, colons, parentheses, or separate sentences.
- **Strict Exclusion of Games**: Never scan or move files inside `F:\Aloha\Games\` to avoid breaking game engines.
- **Preserve Highest Quality**: In duplicate clusters, always retain the version with higher resolution, higher bitrate, and better container metadata.
- **Workflow Integrity**: Issue first (in milestone `Backlog`), branch `<actor>/feat/cli/aloha-media-deduplication-<id>`, squash-merge PR upon green CI.

---

## 6. Execution Record and Final Metrics

### Execution Summary
- **Implementation**: Created `scripts/find_media_duplicates.py` delivering a multi-tier deduplication engine with exact byte matching, perceptual image hashing, video keyframe fingerprinting, BK-Tree metric space indexing, safe reversible quarantine staging, and transactional SQLite ledger tracking.
- **Safety Protocol & Game Isolation**: Hard-isolated `F:\Aloha\Games` from all candidate scans, hashing routines, and quarantine moves.
- **Reversible Quarantine Architecture**: Deployed same-volume staging into `F:\Aloha\.quarantine_duplicates\<cluster_id>\` with complete rollback capability tested and verified on live assets.
- **Automated Unit Tests**: Implemented 8 comprehensive unit tests in `tests/test_find_media_duplicates.py` covering partial and full SHA-256 calculation, BK-Tree Hamming search, DisjointSet clustering, image master selection, video master selection, game isolation guardrails, quarantine staging, and rollback round-trip. All 52 workspace tests pass.
- **Ledger Schema**: Initialized `deduplication_ledger.db` with `duplicate_clusters` and `duplicate_files` tracking cluster ID, original path, quarantine path, file size, hash signature, Hamming distance, and status.

### Tier 1: Exact Byte Deduplication Results
- Evaluated 28 file size collision groups (files >= 1 MB).
- Fast partial SHA-256 followed by full SHA-256 identified 3 exact binary duplicate clusters (3 files totaling 76.29 MB):
  1. `F:\Aloha\Celebrities\Updates\Update4,5,6,7\Veronica2030 Wasko2 Hi [H264].mp4` (4.65 MB, exact clone of Update1)
  2. `F:\Aloha\Collections & Siterips\Hard\Amateur Couple Amazing Girl with Just 19 Yo [H264].mp4` (67.17 MB, exact clone of Clips)
  3. `F:\Aloha\Collections & Siterips\Teasers\Sexy Dancing [H264].mp4` (8.18 MB, exact clone of Clips)
- Successfully staged all 3 exact duplicate files into `F:\Aloha\.quarantine_duplicates`. Verified rollback restored files to original paths, then re-quarantined.

### Tier 2: Perceptual Image Deduplication Results (Photos & Sets)
- Assets evaluated: 2,782 images in `F:\Aloha\Photos & Sets\`.
- Evaluated using 64-bit DCT perceptual hash (`pHash`) and difference gradient hash (`dHash`) with BK-Tree metric space search (Hamming distance <= 4).
- Clusters identified: 96 perceptual duplicate clusters (98 duplicate files).
- Space savings identified: 42,358,587 bytes (40.40 MB).
- Master selection accurately prioritized full-resolution assets over thumbnails and downscales (for example, keeping 500x355 master `Untitled101.gif` over downscaled `Untitled101t.gif`).

### Tier 3: Video Keyframe Fingerprinting Results (Studios & Collections)
- Assets evaluated: 899 videos across `Studios` and `Collections & Siterips`.
- Filtered into 427 duration collision candidate windows (+/- 2.0s).
- Sampled 3 keyframes at 20%, 50%, and 80% duration using OpenCV, computing multi-frame perceptual fingerprints.
- Clusters identified: 24 perceptual video duplicate clusters (25 duplicate files).
- Space savings identified: 3,899,153,390 bytes (3,718.52 MB / 3.63 GB).
- Master selection retained highest-resolution (1080p > 720p > 480p), highest-bitrate versions while marking downscaled or re-cut versions as duplicates.

### Overall Corpus Deduplication Potential
- Combined Duplicate Clusters: 123 clusters.
- Combined Duplicate Files: 126 files.
- Combined Potential Space Savings: 4,021,508,604 bytes (~3.75 GB / 3,835.21 MB).

