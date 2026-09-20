You are the Grand Issue Orchestrator. Dynamically analyze the target scope, determine the optimal multi-agent topology, and coordinate a specialized squad of agents to execute and deliver the mission with production-ready excellence.

You are NOT constrained to a fixed roster: critically evaluate the problem domain and decide which specialized agents to spawn (for example, Database Migration Specialist, Media Inventory Prober, Quality & Verification Engineer).

Target Scope / Issues / Milestone:
---
# Mission: Media Inventory Database Refresh & Canonical Synchronization for F:\Aloha

## Objective
Refresh, re-index, and synchronize `media_inventory.db` across `F:\Aloha` following the completion of the canonical 7-root directory restructuring and lossless container tag injection. Update all 35,656+ records so that `file_path` and `directory` entries reflect the live filesystem layout (`Studios`, `Movies`, `Celebrities`, `Collections & Siterips`, `Photos & Sets`, `Games`, `Magazines & Docs`), update container metadata fields with newly injected MP4 tags (`©nam`, `©ART`, `©cmt`, `©day`), preserve additive schema attributes (`studio`, `confidence_score`), and purge stale or orphaned records.

## 1. System & Runtime Context
- Target Path: `F:\Aloha` (Drive F:\ on Windows 11).
- SQLite Media Inventory: `e:\repos\projects\storage-strategist\media_inventory.db` (35,656 probed records).
- Directory Restructure Undo Ledger: `e:\repos\projects\storage-strategist\dir_undo_ledger.db` (6,725 atomic path relocations).
- Visual Enrichment Cache: `e:\repos\projects\storage-strategist\visual_enrichment_cache.db` (903 OCR and visual evaluated assets, 263 confirmed studios).
- MP4 Tagging Audit Report: `e:\repos\projects\storage-strategist\mp4_tagging_report.json` (6,561 tagged MP4 files).
- Scanner Utility: `e:\repos\projects\storage-strategist\scripts\media_inventory_scanner.py`.
- FFprobe Binary: `C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe`.
- Python Environment: Python 3.12 (Always initialize scripts with `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`).

## 2. Canonical Directory Landscape on F:\Aloha
All assets on `F:\Aloha` have been relocated into seven canonical root directories:
1. `F:\Aloha\Studios\[Studio Name]\`: Studio scene releases and siterips (Brazzers, Bangbus, Digital Playground, Vixen, Tonights Girlfriend, etc.).
2. `F:\Aloha\Movies\`: Feature-length adult films and themed movie releases.
3. `F:\Aloha\Celebrities\`: Celebrity scenes, mainstream appearances, and clips.
4. `F:\Aloha\Collections & Siterips\`: Compilations, scene archives, and multi-performer collections.
5. `F:\Aloha\Photos & Sets\[Studio or Set Name]\`: Structured image sets, galleries, and photos.
6. `F:\Aloha\Games\`: Visual novels, interactive games, and game archives.
7. `F:\Aloha\Magazines & Docs\`: PDF magazines, documents, and reference archives.

Root protected files to preserve untouched:
- `F:\Aloha\VHDX-ai.vhdx`
- `F:\Aloha\HANDOFF_METADATA_RENAME.md`

## 3. Scope & Execution Plan

### Step 1: Safety Snapshot and Schema Verification
1. Create a timestamped backup copy of `media_inventory.db` to `media_inventory_pre_refresh.bak`.
2. Verify table schema in `media_inventory.db` contains all expected columns:
   - Base probe columns: `id`, `file_path`, `directory`, `filename`, `extension`, `media_type`, `file_size`, `mtime`, `v_codec`, `a_codec`, `width`, `height`, `duration`, `bitrate`, `resolution_tier`.
   - Metadata tag columns: `existing_title`, `existing_artist`, `existing_date`, `existing_comment`, `exif_datetime`, `exif_artist`, `scanned_at`, `error`.
   - Additive enrichment columns: `studio TEXT`, `confidence_score REAL`.

### Step 2: Transactional Path Alignment via Directory Undo Ledger
1. Fast-path remap: Read all 6,725 completed move transactions from `dir_undo_ledger.db` (`original_path` -> `target_path`).
2. Execute batch updates on `media_files` in `media_inventory.db`:
   ```sql
   UPDATE media_files
   SET file_path = ?, directory = ?
   WHERE file_path = ?;
   ```
3. This instantaneously maps all existing stream probes and metadata to the new canonical file locations without expensive re-probing.

### Step 3: Container Tag and Visual Metadata Sync
1. Ingest `visual_enrichment_cache.db`: Update `studio`, `confidence_score`, `existing_title`, and `existing_artist` for all assets where visual OCR or 2257 custodian matches exist.
2. Ingest `mp4_tagging_report.json`: Ensure records for the 6,561 tagged MP4 files have their `existing_title`, `existing_artist`, `existing_date`, and `existing_comment` fields synchronized with the container headers.

### Step 4: Filesystem Scan for Untracked Assets and Stale Record Purge
1. Walk `F:\Aloha` to detect any media files (video or image) missing from `media_inventory.db`.
2. Probe any newly discovered assets using `scripts/media_inventory_scanner.py` with multi-threading (up to 16 workers) to extract codecs, dimensions, durations, and bitrates.
3. Identify and purge obsolete records from `media_files` where the file no longer exists on `F:\Aloha`:
   - Verify non-existence before deletion.
   - Record count of pruned records.

### Step 5: Validation and Consistency Queries
Run validation queries to confirm data integrity:
1. Canonical Root Distribution:
   ```sql
   SELECT 
     substr(directory, 10, instr(substr(directory, 10) || '\', '\') - 1) as root_folder,
     count(*) as asset_count,
     round(sum(file_size) / (1024.0 * 1024.0 * 1024.0), 2) as size_gb
   FROM media_files
   GROUP BY root_folder
   ORDER BY asset_count DESC;
   ```
2. Zero Obsolete Directory Paths:
   Verify 0 records reference legacy top-level folders (`VIDEOS\`, `siterips\`, `temp\`, `Bangbus ALL 2010\`, `Brazzers\`, `DigitalPlayground\`, `Torrents\`, `Celeb\`).
3. Total Asset Alignment:
   Confirm total database records match the physical file count on `F:\Aloha`.
4. Run compliance checks:
   ```bash
   python scripts/check_compliance.py
   ```

## 4. Hard Constraints & Operational Safety
- **No Em Dashes**: Do not use em dashes in any generated code comments, terminal logs, or markdown documentation. Use commas, colons, parentheses, or separate sentences instead.
- **Zero Media Stream Mutation**: Never re-encode or alter audio/video streams.
- **Read-Only Posture for Existing Media**: Database refresh must not move, rename, or delete any actual media files on `F:\Aloha`.
- **Atomic Operations**: Perform database updates inside SQLite transactions (`with conn:`).

---

## 5. Mission Execution & Final Results (Completed)

All synchronization and refresh phases have completed with production verification:
- **Safety Snapshot**: Verified schema and created atomic SQLite snapshot at `media_inventory_pre_refresh.bak`.
- **Path Realignment**: Evaluated 35,458 file renames and 6,725 directory move mappings across 35,656 total database records. Confirmed 35,656 direct disk matches (100% path alignment, 0 unresolved paths, 0 legacy directory references).
- **Visual Enrichment Ingestion**: Ingested 903 entries from `visual_enrichment_cache.db`, matched 801 canonical assets, updated 207 studio values, and synced 76 metadata fields (263 total records carry studio enrichment).
- **Container Tag Synchronization**: Inspected 6,737 MP4 containers across disk using Mutagen, discovering 6,623 tagged MP4 files (increased from 6,561 to 6,623 following AV1 transcode operations) and writing container tags (`©nam`, `©ART`, `©day`, `©cmt`) into `media_inventory.db`.
- **Filesystem Reconciliation & Audit**: Verified 35,656 physical media assets (12,187 video, 23,469 image) across `F:\Aloha`. Discovered 0 untracked files and 0 stale records.
- **Canonical Root Distribution**:
  - `Games`: 29,253 assets (36.95 GB)
  - `Photos & Sets`: 2,782 assets (0.59 GB)
  - `Celebrities`: 1,484 assets (34.92 GB)
  - `Collections & Siterips`: 889 assets (64.70 GB)
  - `Studios`: 688 assets (199.04 GB)
  - `Movies`: 289 assets (51.57 GB)
  - `Magazines & Docs`: 271 assets (0.05 GB)
- **Synchronization Report**: Live execution metrics recorded in `media_inventory_refresh_report.json`.
- **Quality Assurance & Verification**: All 33 pytest unit tests passed, all 47 cargo tests passed, and `check_compliance.py` passed with 0 violations.

---

## 6. Post-Quarantine Deduplication Reconciliation (Completed)

Following the staging of duplicate media assets into `F:\Aloha\.quarantine_duplicates` via `scripts/find_media_duplicates.py` (Issue #43), `media_inventory.db` was reconciled to purge stale records and ensure complete alignment with live disk assets.

### Key Enhancements & Implementation
1. **Quarantine Directory Isolation**:
   - Updated `scripts/refresh_media_inventory.py` and `scripts/media_inventory_scanner.py` to prune directories matching `.quarantine_duplicates` or starting with `.` during `os.walk`.
   - Quarantined assets are excluded from physical media accounting and untracked asset discovery.
2. **Fast Reconciliation Mode (`--reconcile-only`)**:
   - Added `--reconcile-only` CLI parameter to execute schema validation, filesystem reconciliation, stale record purge, and validation queries while bypassing expensive full-tree container tag re-probing.
3. **Execution Results**:
   - **Pre-Reconciliation Records**: 35,656
   - **Physical Media Files on Disk**: 35,532 (12,161 video, 23,371 image)
   - **Stale Records Purged**: 124 (3 exact byte duplicates, 98 image duplicates, 23 video duplicates)
   - **Untracked Discovered**: 0
   - **Post-Reconciliation Records**: 35,532 (100% disk alignment, 0 missing files, 0 quarantine references)
   - **Safety Snapshot**: Created `media_inventory_pre_quarantine_reconcile.bak` prior to live execution.
4. **Updated Canonical Root Distribution**:
   - `Games`: 29,253 assets (36.95 GB)
   - `Photos & Sets`: 2,684 assets (0.55 GB)
   - `Celebrities`: 1,483 assets (34.92 GB)
   - `Collections & Siterips`: 873 assets (63.13 GB)
   - `Studios`: 679 assets (196.98 GB)
   - `Movies`: 289 assets (51.57 GB)
   - `Magazines & Docs`: 271 assets (0.05 GB)

