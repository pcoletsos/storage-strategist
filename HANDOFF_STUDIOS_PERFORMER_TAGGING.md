# Mission: Performer Entity Recognition and Metadata Tagging for Studios Media Pool

## Objective

Design, implement, validate, and execute an entity recognition, studio attribution correction, title normalization, and lossless MP4 container tagging pipeline across the `Studios` media pool on `F:\Aloha`. Synchronize all extracted performer and studio metadata into `media_inventory.db` and embed standardized QuickTime container tags into compatible MP4 media assets while strictly preserving original file modification timestamps (`mtime`).

---

## 1. Scope and Corpus Context

- **Target Directory**: `F:\Aloha\Studios\` (Drive F:\ on Windows 11).
- **Target Inventory Records**: 677 media assets (352 videos, 325 images, 195.61 GB).
- **Primary Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Pre-Tagging Baseline**:
  - Performer attribution: 84 files (12.4% coverage).
  - Studio attribution: 351 files (51.8% coverage).
  - Legacy siterip defect: All 30 videos in `Tonights Girlfriend` were erroneously tagged as `studio = "Brazzers"`.
  - Untagged image sets: 29 screen images in `Tonights Girlfriend\Screens` and 281 photo assets in `X-Art` lacked performer and studio tags.

---

## 2. Architecture and Extraction Strategy

The pipeline was implemented in `scripts/tag_studios_media.py` with multi-stage deterministic rules tailored to each studio's release conventions:

### Rule A: Canonical Studio Attribution and Correction
- Replaces legacy siterip scraping errors, assigning `studio = "Tonights Girlfriend"` across all 30 video releases and 29 screen images.
- Enforces canonical studio identity across all subdirectories: `X-Art`, `Backroom Casting Couch`, `Bangbus`, `Bangbros`, `Brazzers`, `Digital Playground`, `Vixen`, `FuckedHard18`, `Twistys`, `Brattysis`, `Freeze`, `Naughty America`, `Pure Taboo`, `Stolen Porn Videos`, and `Sweetheart Video`.

### Rule B: X-Art Photo and Video Performer Recognition
- Analyzes 338 assets (57 videos, 281 photos).
- Recognizes solo models and duos (Caprice, Carlie, Carla, Capri, Eufrat, Francesca, Georgia, Kat, Katka, Kristen, Leila, Lilly, Megan, Mina, Monique, Nella, Ophelia, Regina, Reina, Ruby, Shyla Stylez, Silvie, Star, Stevie, Susie, Tori Black, Vicky, Christian, Jennifer, Patsy).
- Normalizes clean scene titles by removing site prefixes (`Bigwai@18p2p`, `X Art`) and resolution flags (`1080p`, `1920x1080`).

### Rule C: Backroom Casting Couch Auditions and Episodes
- Analyzes 126 assets (113 videos, 13 photos).
- Extracts named performers from audition patterns (`[Performer] Brcc`, `[Performer]2 Brcc`, `Brcchaley2`) and numbered series (`Ktr Bcc E### [Performers]`).
- Standardizes episode titles to `Casting: [Performer]` or `Episode ###: [Performers]`.

### Rule D: Tonights Girlfriend Screen Token Mapping
- Maps 29 image assets in `Tonights Girlfriend\Screens` using token dictionary `TG_SCREEN_TOKEN_MAP` (e.g. `Tngfalannahbrandon` to `Alanah Rae, Brandon Fox`, `Tngfcapribil` to `Capri Anderson, Bill Bailey`, `Tngfphoenixbary` to `Phoenix Marie, Barry Scott`).
- Reconciles 100% of screencap assets with corresponding video scenes.

### Rule E: Bangbus and Bangbros Episode Normalization
- Extracts episode indices from `[Bangbus] Episode ####` (50 videos) and `Di##### 3000` (42 Dorm Invasion videos).
- Standardizes titles to `Episode ####` and `Dorm Invasion: Episode #####`.

### Rule F: Brazzers Multi-Performer and Series Parsing
- Resolves release dates (`[YYYY-MM-DD]`), multi-performer conjunctions (`Billie Star and Tina Fire`, `Dana Dearmond and Coco Lovelock`), and subseries tokens (`Doctor Adventures`, `Real Wife Stories`, `Big Guns`).

### Rule G: Digital Playground, Vixen, FuckedHard18, and Twistys
- Extracts recognized stars: Stoya, Cassidy Banks, Ariana Marie, Quinn Wilde, Alessandra Jane, Riley Steele, Lexie Fux, Mia Melano, Nia Nacci, Honey Gold, Naomi Swann, Talia Mint, Ellie Eilish, Gabbie Carter, Emily Willis, Little Caprice, Apolonia Lapiedra, Kyler Quinn, Lexi Belle, August Ames, Kimmy Granger, Remy LaCroix, Janice Griffith, Capri Anderson, Kayden Kross, Lela Star, Savannah Sixx, Scarlit Scandal, Penny Pax.

---

## 3. Container Tagging Protocol

- **Target Container**: Compatible MP4 media files supporting QuickTime iTunes metadata atoms (`©ART`, `©nam`, `©cmt`, `©day`).
- **Read-Only Stream Integrity**: Stream payloads remain strictly read-only. Only container metadata atoms are updated via `mutagen.mp4.MP4`.
- **Timestamp Preservation**: Original file modification times (`mtime`) and access times (`atime`) are saved prior to write operations and restored with `os.utime`.

---

## 4. Execution Metrics and Reconciliation

### Database Reconciliation (`media_inventory.db`)
- **Safety Backup**: Created backup at `media_inventory_pre_studios_tagging.bak`.
- **Total Assets Evaluated**: 677 records in `F:\Aloha\Studios\`.
- **Performer Attribution**:
  - Baseline: 84 files (12.4%).
  - Post-Execution: 485 files (71.6%).
  - Delta: +401 files (+59.2%).
  - Remaining 192 assets without individual performer tags consist of 50 Bangbus episodes, 42 Bangbros episodes, 60 X-Art gallery cover index sheets, and general compilation clips.
- **Studio Attribution**:
  - Baseline: 351 files (51.8%).
  - Post-Execution: 677 files (100.0%).
  - Delta: +326 files (+48.2%).
- **Legacy Defect Correction**:
  - Corrected all 30 `Tonights Girlfriend` video records and 29 screen records from legacy `Brazzers` tags to `Tonights Girlfriend`.
- **Title Normalization**:
  - Baseline: Inconsistent raw filenames.
  - Post-Execution: 655 clean titles (96.8%).

### Live Container Tagging (`F:\Aloha\Studios\`)
- **Queued MP4 Videos**: 197 videos.
- **Tagged Losslessly**: 194 videos (3 videos already had identical tags).
- **Timestamp Preservation Rate**: 100% verified via `os.utime`.
- **Non-MP4 Assets**: 149 MKV files and 325 images remain payload-untouched on disk while fully enriched inside `media_inventory.db`.

---

## 5. Automated Testing and Verification

- **Unit Tests**: `tests/test_tag_studios_media.py` (9 test cases).
  - Title noise stripping and prefix cleaning.
  - X-Art solo and duo video performer extraction.
  - X-Art photo set model extraction.
  - Backroom Casting Couch auditions and numbered episodes.
  - Tonights Girlfriend studio reattribution and screen mapping.
  - Bangbus and Bangbros episode numbering.
  - Brazzers Exxtra multi-performer parsing.
  - Database record synchronization.
  - MP4 container tagging and timestamp preservation mock.
- **Workspace Test Suite**: All 79 pytest tests passing in 4.62 seconds.
- **Compliance Check**: `python scripts/check_compliance.py` passing without warnings.
