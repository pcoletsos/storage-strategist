# Mission: Visual Metadata Enrichment & Performer Tagging for F:\Aloha

You are the Grand Issue Orchestrator. Dynamically analyze the target scope, determine the optimal multi-agent topology, and coordinate a specialized squad of agents to execute and deliver the mission with production-ready excellence.

You are NOT constrained to a fixed roster: critically evaluate the problem domain and decide which specialized agents to spawn (for example, Computer Vision Specialist, Entity Disambiguation Engineer, Metadata Tagging & Verification Engineer).

Target Scope / Issues / Milestone:
---

## Objective

Scale visual inspection, OCR-based title card extraction, and entity recognition across the video and photo corpus on `F:\Aloha`. Populate missing studio, performer, title, and release date metadata in `media_inventory.db`, inject lossless tags into `.mp4` containers, and cache extracted visual signatures in `visual_enrichment_cache.db`.

---

## 1. Current State and Baseline Metrics

- **Target Path**: `F:\Aloha` (Drive F:\ on Windows 11).
- **Working Repository**: `E:\repos\projects\storage-strategist`.
- **Media Inventory Database**: `E:\repos\projects\storage-strategist\media_inventory.db` (35,656 total records: 12,187 video, 23,469 image).
- **Current Metadata Deficit Across 12,187 Videos**:
  - Populated `studio`: **263 records (2.2%)**
  - Populated `existing_artist` (performers): **100 records (0.8%)**
  - Populated `existing_date`: **209 records (1.7%)**
  - Populated `existing_title`: **6,632 records (54.4%)**
- **Existing Visual Cache**: `E:\repos\projects\storage-strategist\visual_enrichment_cache.db` (currently 903 evaluated assets).
- **Installed OCR & Vision Tools**:
  - Python 3.12 with `cv2` (OpenCV 4.13.0), `PIL` (Pillow), `pytesseract`, `rapidfuzz`.
  - Tesseract Binary: `C:\Program Files\PDF24\tesseract\tesseract.exe`.
  - Local Tessdata: `E:\repos\projects\storage-strategist\tessdata`.
- **Primary Script**: `E:\repos\projects\storage-strategist\scripts\visual_metadata_extractor.py`.

---

## 2. Architectural Upgrades Required for `visual_metadata_extractor.py`

1. **Realign with Canonical 7-Root Layout**:
   The current script defaults to legacy directories (`VIDEOS`, `siterips`, `temp`). Update `--pool` and directory walking to accept the canonical roots:
   - `Studios` (688 files, highest priority)
   - `Movies` (289 files)
   - `Celebrities` (1,484 files)
   - `Collections & Siterips` (889 files)
   - `Photos & Sets` (2,782 files)
2. **Database-Driven Candidate Selection**:
   Add `--target-missing` option that selects files directly from `media_inventory.db` where `studio IS NULL OR studio = ''` or `existing_artist IS NULL`.
3. **Multi-Stage Detection Engine**:
   - **Stage 1 (Filename Pattern & OS-Hash)**: Clean regex matching and fuzzy lookup against known studios and performers.
   - **Stage 2 (Video Intro Title Card OCR)**: Extract frames at 3s, 8s, 15s, and 25s; apply contrast enhancement, thresholding, and OCR to identify opening logo screens and title cards.
   - **Stage 3 (Outro 2257 Custodian OCR)**: Extract frames in the final 30 seconds to read legal custodian addresses (e.g., "625 Broadway", "Carol Santiago / 6955 NW 52 Street", "Samir Savoy / Chatsworth"). Custodian addresses provide near-100% conclusive studio attribution.
4. **Confidence Calibration & Tagging Threshold**:
   - Scores >= 0.85: Automatically update `media_inventory.db` and inject tags into `.mp4` containers (`©nam`, `©ART`, `©day`, `©cmt`).
   - Scores 0.60 to 0.84: Update `media_inventory.db` with candidate metadata and flag for human review.
   - Scores < 0.60: Keep unassigned to avoid corrupting catalog accuracy.

---

## 3. Operational Safety Protocol

1. **Zero Stream Mutation**: Never alter or re-encode video or audio streams. Only write container metadata atoms via Mutagen.
2. **Timestamp Preservation**: Always preserve original file modification times (`mtime`) using `os.utime`.
3. **Game Isolation**: Strictly exclude `F:\Aloha\Games\` from processing.
4. **SQLite Safety Snapshot**: Create a backup of `media_inventory.db` (`media_inventory_pre_enrichment.bak`) before bulk database updates.

---

## 4. Phased Execution Plan

### Step 1: Alignment and Script Refactoring
1. Update `scripts/visual_metadata_extractor.py` to target the canonical roots and query `media_inventory.db` directly.
2. Write unit tests in `tests/test_visual_metadata_extractor.py` covering custodian matching, OCR parsing mock, and database update logic.
3. Validate compliance: `python scripts/check_compliance.py`.

### Step 2: Pilot Validation Batch (50 Files)
1. Run on a diverse sample of 50 videos from `F:\Aloha\Studios\` and `F:\Aloha\Movies\`.
2. Inspect detection accuracy, execution time per file (target: <2.5 seconds per video), and confidence calibration.

### Step 3: Production Batch Across High-Priority Roots
1. Execute across `F:\Aloha\Studios\` (688 files) and `F:\Aloha\Movies\` (289 files).
2. Execute across `F:\Aloha\Collections & Siterips\` (889 files).
3. Log enriched records into `visual_enrichment_cache.db` and synchronize into `media_inventory.db`.

### Step 4: Verification Queries
Run validation queries confirming enriched counts and studio distribution:
```sql
SELECT studio, count(*) 
FROM media_files 
WHERE studio IS NOT NULL AND studio != '' 
GROUP BY studio 
ORDER BY count(*) DESC;
```

---

## 5. Hard Constraints

- **Strict Prohibition on Em Dashes**: Never use em dashes in code comments, CLI messages, logs, or markdown documentation. Use commas, colons, parentheses, or separate sentences.
- **Read-Only Media Streams**: Do not mutate video/audio streams.
- **Workflow Integrity**: Issue first (in milestone `Backlog`), branch `<actor>/feat/cli/aloha-visual-enrichment-<id>`, squash-merge PR upon green CI.

---

## 6. Execution Record and Final Metrics

### Execution Summary
- **Implementation**: Upgraded `scripts/visual_metadata_extractor.py` to support canonical 7-root layouts, `--target-missing` database-driven candidate querying, Stage 2 intro keyframe OCR (3s, 8s, 15s, 25s) with CLAHE preprocessing, and Stage 3 outro 2257 custodian address OCR.
- **Timestamp Preservation**: Upgraded `scripts/media_tagger.py` to preserve original filesystem timestamps (`mtime` and `atime`) via `os.utime`.
- **Game Isolation**: Hard-isolated `F:\Aloha\Games` across all directory scans and SQLite queries.
- **Safety Snapshot**: Generated pre-enrichment database snapshot at `media_inventory_pre_enrichment.bak`.
- **Unit Test Suite**: Created 11 automated unit tests in `tests/test_visual_metadata_extractor.py`, validating 2257 statement parsing, studio token matching, performer extraction, pool argument parsing, game isolation, confidence gating, and container tagging.

### Pilot Batch Results (50 Videos)
- Total files: 50
- Successfully resolved: 50 (100.0%)
- High confidence (>=0.85): 50 (100.0%)
- Average execution time: 0.043 seconds per video (exceeding target of <2.5s per video).

### Production Batch Results Across High-Priority Roots
- **Studios**: 335 evaluated, 332 resolved (99.1%), 331 high confidence, 200 MP4 containers losslessly tagged.
- **Movies**: 242 evaluated, 33 resolved (13.6%), 27 high confidence, 6 flagged for review, 5 MP4 containers losslessly tagged.
- **Collections & Siterips**: 604 evaluated, 17 resolved (2.8%), 5 high confidence, 12 flagged for review.
- **Visual Enrichment Cache**: Expanded to 2,084 total assets (621 high confidence).

### Live Media Inventory Metrics
- Populated Studio: Increased from 263 to 401 records (+52.5% increase).
- Populated Artist: Increased from 100 to 168 records (+68.0% increase).
- Populated Title: 1,072 records.
- Populated Date: 210 records.
- High Confidence Attributions: 391 records.
- Flagged for Human Review: 19 records.

### Top Studio Distribution in media_files
- Backroom Casting Couch: 119 files
- Bangbros: 92 files
- X-Art: 57 files
- Brazzers: 56 files
- Digital Playground: 35 files
- Vixen: 14 files
- FuckedHard18: 10 files
- Twistys: 4 files
- Wicked Pictures: 4 files
- Naughty America: 2 files
- Stolen Porn Videos: 2 files
- Brattysis: 1 file
- Deeper: 1 file
- Evil Angel: 1 file
- Hustler: 1 file
- Pure Taboo: 1 file
- Sweetheart Video: 1 file
