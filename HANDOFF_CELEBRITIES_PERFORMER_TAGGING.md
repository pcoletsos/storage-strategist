# Mission: Performer Entity Recognition and Metadata Tagging for Celebrities Media Pool

## Objective

Design, implement, validate, and execute an entity recognition, title normalization, studio attribution, and lossless MP4 container tagging pipeline across the `Celebrities` media pool on `F:\Aloha`. Synchronize all extracted performer metadata into `media_inventory.db` and embed standardized container tags into compatible MP4 media assets while strictly preserving original file modification timestamps (`mtime`).

---

## 1. Scope and Corpus Context

- **Target Directory**: `F:\Aloha\Celebrities\` (Drive F:\ on Windows 11).
- **Target Inventory Records**: 1,462 media assets (1,186 videos, 276 images).
- **Primary Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Pre-Tagging Baseline**:
  - Performer attribution: 56 files (3.8% coverage).
  - Studio attribution: 0 files (0.0% coverage).
  - Title normalization: Unstructured raw filenames with brackets, numbers, site tags, and resolution tokens.
  - Legacy catalog defects: 18 assets had `"Mrskin Com"` erroneously stored in `existing_artist`.

---

## 2. Architecture and Extraction Strategy

The pipeline was implemented in `scripts/tag_celebrities_media.py` with multi-stage deterministic rules ordered from highest to lowest specificity:

### Rule A: Subfolder Identity Attribution
- Dedicated celebrity directories (such as `Celebrities\Megan Fox\`, `Celebrities\Sasha Grey\`, `Celebrities\Olivia Wilde\`) contain 463 assets (both videos and images).
- High confidence extraction (0.98) assigns the folder name directly as the performer entity while stripping redundant prefixes from filenames.

### Rule B: Top 300 Celebrity Nude Scenes Bracket Parsing
- Pattern: `[### Performer Name] Scene Title` or `[### Performer1 & Performer2] Scene Title`.
- Extracts normalized performer name and scene title, assigns studio as `Mr Skin`, and sets high confidence (0.95).

### Rule C: Top 300 Celebrity Nude Scenes Numeric Prefix Parsing
- Pattern: `### Performer Name Scene Title` (e.g., `007 Denise Richards Wild Things`).
- Parses leading rank number, identifies celebrity token, separates scene or movie title, and assigns studio as `Mr Skin` (0.92 confidence).

### Rule D: Attached Clip Token and Abbreviation Normalization
- Pattern: Attached alphanumeric tokens such as `Jovovich6`, `Kidman Hd`, `Theron Hd`, `Prepon Hd`.
- De-attaches clip numbers and quality suffixes to map to canonical entities (`Milla Jovovich`, `Nicole Kidman`, `Charlize Theron`, `Laura Prepon`).

### Rule E: 120+ Celebrity Entity Dictionary Recognition
- Curated regex dictionary covering Hollywood, international, and mainstream adult performers active in mainstream media.
- Multi-word matching priority handles first and last name combinations before short names.

### Rule F: Multi-Performer Scene Handling
- Detects ampersand and conjunction separators (`&`, `And`, `+`).
- Formats multi-performer scenes as standard comma-separated lists (e.g., `Dana Delany, Stephanie Niznik`) compatible with QuickTime and media server standards.

### Rule G: Studio Attribution and Legacy Cleanup
- Recognizes Mr Skin playlists, features, and Top 300 collections, assigning `studio = "Mr Skin"`.
- Recognizes Pornhub, YouTube, and Dailymotion web clips.
- Explicitly purges 18 legacy instances where `"Mrskin Com"` was recorded in `existing_artist`, clearing the artist field or reassigning it to the true actress.

### Rule H: Title Normalization and Noise Stripping
- Strips ranking brackets (`[001 ...]`), numeric prefixes, resolution tags (`[H264]`, `[1080p]`, `[720p]`, `[480p]`, `[DVD]`), codec tags, site watermarks (`Mrskin Com`, `Pornhub`), and trailing underscores/hyphens.

---

## 3. Container Tagging Protocol

- **Target Container**: Native MP4 / M4V / MOV files supporting QuickTime iTunes metadata atoms (`©ART`, `©nam`, `©cmt`, `©day`).
- **Safety and Payloads**:
  - v1 read-only constraint strictly preserved for audio and video streams. Container tagging is purely metadata-level via `mutagen.mp4.MP4`.
  - Non-MP4 containers (WMV, AVI, RM, FLV, MKV) remain untouched on disk; their enriched metadata is recorded in `media_inventory.db`.
- **Timestamp Preservation**:
  - File modification times (`mtime`) and access times (`atime`) are captured before tagging and restored via `os.utime`.

---

## 4. Execution Metrics and Reconciliation

### Database Reconciliation (`media_inventory.db`)
- **Safety Backup**: Created backup at `media_inventory_pre_celebrities_tagging.bak`.
- **Total Assets Evaluated**: 1,462 records in `F:\Aloha\Celebrities\`.
- **Performer Attribution**:
  - Baseline: 56 files (3.8%).
  - Post-Execution: 897 files (61.4%).
  - Video Performer Coverage: 622 videos (52.4%).
  - Image Performer Coverage: 275 images (99.6%).
- **Studio Attribution**:
  - Baseline: 0 files (0.0%).
  - Post-Execution: 736 files (50.3%), primarily `Mr Skin`.
- **Title Normalization**:
  - Baseline: 0 clean titles.
  - Post-Execution: 1,462 clean titles (100.0%).
- **Legacy Defect Correction**:
  - 18 records with `"Mrskin Com"` artist values corrected to true actress names or cleaned with `studio = "Mr Skin"`.

### Live Container Tagging (`F:\Aloha\Celebrities\`)
- **MP4 Media Assets Tagged**: 489 videos.
- **Failures / Errors**: 0.
- **Timestamp Preservation Rate**: 100% verified via `os.utime`.

---

## 5. Automated Testing and Verification

- **Unit Tests**: `tests/test_tag_celebrities_media.py` (8 test cases).
  - Folder-based attribution (Sasha Grey, Megan Fox).
  - Top 300 bracket extraction (`[001 Halle Berry] Monsters Ball`).
  - Unbracketed numeric prefix extraction (`007 Denise Richards Wild Things`).
  - Attached clip tokens (`Jovovich6`, `Kidman Hd`, `Theron Hd`).
  - Multi-performer scene parsing (`Dana Delany, Stephanie Niznik`).
  - Legacy artist string purge and studio reassignment.
  - Database record synchronization.
  - Container tagging and timestamp preservation mock.
- **Workspace Test Suite**: All 70 pytest tests passing in 4.60 seconds.
- **Compliance Check**: `python scripts/check_compliance.py` passing without warnings.
