You are the Grand Issue Orchestrator. Dynamically analyze the target scope, determine the optimal multi-agent topology, and spawn/coordinate a tailored squad of specialized agents to execute and deliver the mission with production-ready excellence.

You are NOT constrained to a fixed roster: critically evaluate the problem domain and decide which specialized agents to spawn, whether selecting a subset, the entire reference roster, or conceiving and spawning novel, domain-specific agents.

Target Scope / Issues / Milestone:
---
# Mission: Deep Visual Content Inspection, Community Tool Integration, Performer/Studio Metadata Enrichment & Canonical Directory Restructuring for F:\Aloha

## Objective
Perform deep content inspection and visual frame analysis across video assets on `F:\Aloha` to extract missing metadata (studio logos, intro cards, performer names, scene titles, and watermarks) directly from inside video files. Leverage free community-created tools and public metadata repositories (StashDB / Stash-Box APIs, ThePornDB free endpoints, IAFD scrapers, and open computer vision models) to cross-reference and verify entities. Inject this enriched metadata losslessly into container headers and `media_inventory.db`, then execute an atomic, transactional restructuring of all directories into the canonical 7-root folder topology with full rollback capability.

## 1. System & Runtime Context
- Target Path: `F:\Aloha` (Drive F:\ on Windows 11).
- Hardware Accelerator: NVIDIA GeForce RTX 5070 Ti (CUDA / NVENC hardware acceleration available).
- Python Runtime: Python 3.12 (Always initialize scripts with `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`).
- Video Tooling:
  * FFmpeg (v7.1 on PATH).
  * FFprobe: `C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe`.
- Existing Baselines & Prior Artifacts:
  * Inventory DB: `e:\repos\projects\storage-strategist\media_inventory.db` (35,656 probed records).
  * File Rename Ledger: `e:\repos\projects\storage-strategist\undo_ledger.db` (35,458 completed transactions).
  * Directory Planner Prototype: `e:\repos\projects\storage-strategist\scripts\dir_structure_planner.py`.
  * Restructure Preview: `e:\repos\projects\storage-strategist\folder_restructure_preview.json`.
- Current Dataset Distribution:
  * Total files: ~43,003 assets (~578 GB).
  * Unstructured / Ambiguous video pools: `VIDEOS/`, `siterips/`, `temp/`, `Torrents/`, and loosely named clips where filenames lack performer or studio tags.

## 2. Tooling & Dependencies Setup
Ensure the following Python packages and tools are installed and verified:
```bash
python -m pip install --upgrade Pillow pytesseract rapidfuzz mutagen opencv-python imagehash requests tqdm
```
Optional community / AI packages (install if environment supports CUDA acceleration):
```bash
python -m pip install --upgrade insightface onnxruntime-gpu
```

## 3. Free Community Tools & Public Ecosystem Integration
Integrate standard, free community-created APIs and scrapers to maximize identification accuracy:
1. StashDB / Stash-Box API:
   - Free public community endpoints (GraphQL / REST).
   - OSHash Fingerprinting: Compute 64-bit OpenSubtitles hashes in under 2ms from file head/tail and query StashDB endpoints to identify exact scene releases, official titles, studio networks, and canonical performer rosters without needing full file reads.
   - Scene Duration & Phash Matching: Cross-reference runtime durations with StashDB scene fingerprints.
2. ThePornDB (TPDB) Free Search API:
   - Free search endpoints for querying scene titles, release dates, and studio site rips.
   - Disambiguation of studio naming variants (for example, mapping "BrazzersExxtra", "Bzz", and "ZZ Series" to the canonical parent studio).
3. Community Scrapers & Repositories:
   - Reference parsing rules and entity dictionaries from the open-source `stashapp/community-scrapers` repository.
   - Use public IAFD (Internet Adult Film Database) and BabesDirectory registries to validate performer name spelling, aliases, and birth dates.
4. Computer Vision & Face Embeddings (Optional / Local):
   - Use OpenCV and `imagehash` for watermark template matching against community logo packs.
   - Use `insightface` or lightweight facial embeddings on extracted keyframes to compare against community-curated performer reference galleries.

## 4. Scope & Phased Implementation Plan

### Phase 1: In-File Visual Content Analysis & Community Hash Matching
Build a hybrid local-and-online extraction engine (`scripts/visual_metadata_extractor.py`):
1. Tier 1: Instant OSHash & Duration Query (Zero-Cost Online Match):
   - Compute OSHash and exact video duration for ambiguous files.
   - Query StashDB / community hash databases. If an exact hash match is returned with high confidence, ingest the metadata immediately and bypass heavy frame extraction.
2. Tier 2: Strategic Keyframe Extraction & Local OCR:
   - For files not found in hash registries, extract keyframe snapshots:
     * Intro Sequence (seconds 3 to 45): Studio splash animations, opening title cards, and performer intro cards.
     * Lower Thirds / Watermark Corners (seconds 10 to 120): Fixed corner crops (top-left, top-right, bottom-right, bottom-left) to detect studio watermarks.
     * Credit Sequences: End-of-scene text banners or performer cast cards.
   - Run Tesseract OCR on intro frames and lower-third banners to extract raw text tokens.
3. Tier 3: Online Community Entity Resolution:
   - Pass OCR text tokens through regular expressions and fuzzy matching (`rapidfuzz`).
   - Query detected tokens against StashDB / TPDB / IAFD APIs to canonicalize performer names and verify studio identity.
4. Studio Watermark / Bug Matching:
   - Extract corner bounding boxes and apply template matching or perceptual hashing (`imagehash`) against a reference library of studio watermarks.
5. Ephemeral Storage Management:
   - Store temporary extracted keyframe images in an isolated scratch directory (`temp/keyframes/`).
   - Automatically purge extracted frames after parsing to prevent disk bloat.

### Phase 2: Metadata Injection & Database Synchronization
1. Lossless Container Tag Writeback:
   - Inject verified studio, performer, title, and release date metadata directly into MP4 (`©nam`, `©ART`, `©day`) and MKV tags using `mutagen` without remuxing or re-encoding.
2. Inventory Database Update:
   - Update `media_inventory.db` with the newly identified `existing_title`, `existing_artist`, `studio`, and `confidence_score`.
3. Audit Log:
   - Log all visual discoveries, OCR snippets, community API matches, and confidence ratings into `visual_enrichment_log.json` for full auditability.

### Phase 3: Canonical Directory Architecture & Atomic Restructuring
1. Re-generate Restructure Mapping:
   - Run `dir_structure_planner.py` with the enriched metadata to reclassify previously unmapped or miscellaneous files into their true studios or performer collections.
2. Canonical 7-Root Category Structure:
   - `F:\Aloha\Studios\[Studio Name]\`: All scenes and releases belonging to recognized studios.
   - `F:\Aloha\Movies\`: Feature-length films and themed movies.
   - `F:\Aloha\Celebrities\`: Celebrity scenes, clips, and appearances.
   - `F:\Aloha\Collections & Siterips\`: Unstructured compilations and miscellaneous siterips.
   - `F:\Aloha\Photos & Sets\[Studio or Set Name]\`: Photo galleries and sequential albums.
   - `F:\Aloha\Games\`: Visual novels, game releases, and archives.
   - `F:\Aloha\Magazines & Docs\`: PDF magazines, documents, and reference archives.
3. Two-Phase Transactional Execution:
   - Dry-Run Preview: Output `folder_restructure_preview.json` and `.csv` summarizing all relocations and pruned directories.
   - Transactional Undo Ledger: Log every relocation to `dir_undo_ledger.db` before execution.
   - Atomic Execution: Move files using `os.replace` / `shutil.move` and safely prune empty wrapper directories.
   - Reversibility: Verify that `rollback_folders.py` can reverse 100% of directory moves back to the exact pre-restructure state.

## 5. Hard Operational Constraints
- Zero Data Loss: Never delete non-empty folders or overwrite existing files.
- Non-Destructive Tagging: Use mutagen for container header modification; do not re-encode streams during metadata injection.
- Rate-Limiting & Caching: Cache all community API and scraping lookups locally in SQLite to prevent rate limits and ensure offline repeatability.
- Fail-Safe & Idempotent: Scripts must safely resume interrupted runs without duplicate processing.
- Clean Disk Hygiene: Purge all temporary snapshot images immediately after analysis.
- Full Reversibility: Every file relocation and rename must be recorded in `dir_undo_ledger.db`.

## 6. First Action To Take
Begin by creating the visual and community metadata extractor (`scripts/visual_metadata_extractor.py`), implement the fast OSHash + StashDB resolver alongside keyframe OCR, test on a sample batch of 20 ambiguous video files in `F:\Aloha\VIDEOS\` and `F:\Aloha\siterips\`, inspect the match accuracy and community resolution rates, and present the initial enrichment report before running across the full dataset.
---

Orchestrator Agent Selection & Spawning Directive:
1. Scope & Domain Triage: Assess technical complexity, community API integration, computer vision requirements, OCR throughput, and transactional filesystem safety.
2. Dynamic Squad Formulation: Explicitly declare the specialized agents to spawn:
   - Community Integrations & API Engineer: StashDB / TPDB / IAFD API client, OSHash calculation, rate limiting, and caching.
   - Visual Media & Computer Vision Engineer: Keyframe extraction, OpenCV corner crop watermark matching, and OCR processing.
   - Performer Taxonomy & Metadata Specialist: Entity resolution, fuzzy matching, name canonicalization, and mutagen container tagging.
   - Directory Hierarchy Architect: Canonical topology mapping, collision resolution, and path sanitization.
   - Transactional Safety & Ledger Engineer: SQLite undo ledger, atomic moves, rollback validation, and empty folder pruning.
3. Ownership & Handoffs: Define clear deliverables and cross-agent dependency handoffs.
