You are the Grand Issue Orchestrator. Dynamically analyze the target scope, determine the optimal multi-agent topology, and spawn/coordinate a tailored squad of specialized agents to execute and deliver the mission with production-ready excellence.

You are NOT constrained to a fixed roster: critically evaluate the problem domain and decide which specialized agents to spawn—whether selecting a subset, the entire reference roster, or conceiving and spawning novel, domain-specific agents.

Target Scope / Issues / Milestone:
---
# Mission: Directory Hierarchy Analysis, Restructuring & Uniform Folder Organization Pipeline for F:\Aloha

## Objective
Analyze, design a clean canonical folder topology, and execute an atomic, transactional restructuring and renaming of all folders across `F:\Aloha` (~12,189 video files, ~23,469 image assets, ~450+ GB). Build a resilient, high-speed, two-phase directory reorganization pipeline (Dry-Run Hierarchy Preview + Transactional Undo Ledger -> Atomic Directory Move & Empty Folder Pruning) with 100% rollback capability.

## 1. System & Runtime Context
- Target Path: `F:\Aloha` (Drive F:\ on Windows 11).
- Prior Baseline & Artifacts:
  * File-level metadata enrichment and uniform file renaming completed across 35,458 assets.
  * SQLite Media Inventory DB: `e:\repos\projects\storage-strategist\media_inventory.db` (35,656 probed assets).
  * File Rename Undo Ledger: `e:\repos\projects\storage-strategist\undo_ledger.db` (35,458 completed transactions).
- Environment: Python 3.12 (Always initialize scripts with `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`).
- Current Top-Level Directory Landscape:
  * `Bangbus ALL 2010 videos 720p`
  * `Brazzers` (contains deeply nested scene release subdirectories)
  * `Celeb` (contains `from movies`, loose clips, GIFs)
  * `DigitalPlayground` (contains scene releases, NFOs, movie rips)
  * `FuckedHard18`
  * `Games` (ZIP/RAR visual novels and game archives)
  * `GIF` (loose animated GIFs and flash files)
  * `girls` (deeply nested image archives, RARs, PDF magazines)
  * `L & S`
  * `MOVIES` (full-length feature films and movie releases)
  * `siterips` (nested site rip directories like `Backroom.Casting.Couch.SITERIP`)
  * `temp` (loose video downloads)
  * `Tonights.Girlfriend.SiteRip.1080p`
  * `Torrents` (torrent subfolders with NFOs, RARs, MKVs)
  * `VIDEOS` (contains `hard`, amateur clips, loose videos)
  * `Vixen` (contains videos and photo sets)

## 2. Scope & Workflow Requirements

### Phase 1: Directory Tree & Hierarchy Analysis
1. Directory Inventory & Anomaly Scanner:
   - Walk `F:\Aloha` to map all existing directories, calculating folder depth, file counts by media type (video, image, archive, document, game), total byte size, and directory naming anomalies.
   - Detect and classify structural patterns:
     * Deeply nested single-file release folders (e.g., `Brazzers\BrazzersExxtra.21.11.13...\[Brazzers Exxtra] ...mp4`).
     * Scene bloat in folder names (`.XXX.`, `1080p`, `SiteRip`, `ALL 2010 videos 720p`, `MP4-KTR[rarbg]`).
     * Empty directories and redundant intermediate folders (e.g. `New Folder`, `temp`, `rar/women/...`).
     * Mixed content folders (e.g., photo sets mixed with videos).

### Phase 2: Canonical Directory Architecture & Restructuring Rules
Design and enforce a clean, standardized folder hierarchy:
1. Canonical Root Categorization:
   - `F:\Aloha\Studios\[Studio Name]\` -> All scenes, site rips, and releases belonging to recognized studios (e.g., `Studios\Brazzers\`, `Studios\Digital Playground\`, `Studios\Bangbus\`, `Studios\Vixen\`, `Studios\Tonights Girlfriend\`, `Studios\Backroom Casting Couch\`, `Studios\Pure Taboo\`, `Studios\FuckedHard18\`).
   - `F:\Aloha\Movies\` -> Feature-length films and themed movies (from `MOVIES` and loose film rips).
   - `F:\Aloha\Celebrities\` -> Celebrity scenes, clips, and appearances (cleaned from `Celeb`).
   - `F:\Aloha\Collections & Siterips\` -> Unstructured compilations, playlists, and miscellaneous siterips.
   - `F:\Aloha\Photos & Sets\[Studio or Set Name]\` -> Clean photo sets, image galleries, and sequential photo albums.
   - `F:\Aloha\Games\` -> Visual novels, game releases, and archives.
   - `F:\Aloha\Magazines & Docs\` -> PDF magazines, documents, and reference archives.
2. Flattening & Unnesting Rules:
   - Flatten single-video release folders: move the video directly into its parent Studio folder and remove the redundant wrapper folder.
   - Group photo sets into designated subfolders with clean `[Set Name]` taxonomy.
3. Cleaners & Sanitizers:
   - Standardize folder names to clean Title Case.
   - Strip release bloat tokens (`.XXX.`, `[720p HD]`, `SiteRip`, `MP4-KTR`, `[rarbg]`, etc.).
   - Enforce Windows filesystem path safety and handle extended paths (`\\?\`).

### Phase 3: Reversible Two-Phase Directory Execution Pipeline
1. Dry-Run & Hierarchy Preview:
   - Generate `folder_restructure_preview.csv` and `folder_restructure_preview.json` mapping Old Directory / File Path -> Proposed New Path.
   - Summary statistics: Folders to create, folders to rename, files to relocate, folders to prune, collision count.
2. Transactional SQLite Undo Ledger (`dir_undo_ledger.db`):
   - Record every file relocation and folder rename `(original_path, target_path, original_mtime, operation_type)` before execution.
   - Provide an instant `rollback_folders.py` script that can reverse 100% of directory moves back to the exact pre-restructure state.
3. Safe Execution & Empty Folder Cleanup:
   - Execute file relocations and folder renames atomically (`os.replace` / `shutil.move`).
   - Clean up remaining empty directories safely (never deleting non-empty folders).

## 3. Hard Operational Constraints
- Zero Data Loss & Strict Non-Destructive Operations: Never delete non-empty folders or overwrite existing files.
- Atomic Operations: Use transactional logging with SQLite ledger.
- Idempotency & Reversibility: Full rollback capability via `rollback_folders.py`.

## 4. First Action To Take
Begin by inspecting the SQLite inventory database (`media_inventory.db`), build the directory analysis and hierarchy planner module (`scripts/dir_structure_planner.py`), and generate a comprehensive dry-run restructuring report for review.
---

Orchestrator Agent Selection & Spawning Directive:
1. Scope & Domain Triage: Assess technical complexity, hierarchy depth, safety constraints, and volume of relocations.
2. Dynamic Squad Formulation: Declare the specialized agents to spawn (e.g. Directory Topology Architect, Hierarchy & Taxonomy Specialist, Transactional Safety & Ledger Engineer, QA Test Automation Engineer).
3. Ownership & Handoffs: Define clear boundaries, deliverables, and cross-agent dependency handoffs.
