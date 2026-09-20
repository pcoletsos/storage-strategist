# Mission: Performer Entity Recognition and Siterip Normalization for Collections & Siterips

## Objective

Design, implement, validate, and execute an entity recognition, siterip attribution, scene title normalization, and lossless MP4 container tagging pipeline across the `Collections & Siterips` media pool on `F:\Aloha`. Synchronize all extracted performer and siterip metadata into `media_inventory.db` and embed standardized QuickTime container atoms into compatible MP4 media assets while strictly preserving original file modification timestamps (`mtime`).

---

## 1. Scope and Corpus Context

- **Target Directory**: `F:\Aloha\Collections & Siterips\` (Drive F:\ on Windows 11).
- **Target Inventory Records**: 856 media assets (571 videos, 285 images, 52.36 GB).
- **Primary Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Pre-Tagging Baseline**:
  - Performer attribution: 10 files (1.1% coverage).
  - Studio attribution: 10 files (1.2% coverage).
  - Unattributed pack: 535 assets in `Izzy Green (OnlyFans)\Izzy Green Pack` (264 videos, 271 screencap images, 20.99 GB) had 0% metadata coverage.
  - Siterip / collection directories (`OnlyFans Mix`, `Twins`, `Alice`, `Girls Gone Wild`, `Anime`, `L & S Erotica`, `Hard`, `Teasers`, `Pov`) lacked canonical studio and performer tags.

---

## 2. Architecture and Extraction Strategy

The pipeline was implemented in `scripts/tag_collections_media.py` with multi-stage deterministic rules tailored to each collection's release conventions:

### Rule A: Izzy Green OnlyFans Pack
- Analyzes 535 assets (264 videos, 271 screencaps).
- Assigns `existing_artist = "Izzy Green"`, `studio = "OnlyFans"`.
- Normalizes video scene titles from `Onf Izzygreen <NUM> [resolution codec]` to `Izzy Green Clip <NUM>`.
- Normalizes screencap titles from `Scr - Onf Izzygreen <NUM> Mp4.jpg` to `Screens: Izzy Green Clip <NUM>`.

### Rule B: OnlyFans Mix Performer Recognition
- Analyzes 12 video releases (2.61 GB).
- Extracts star performers from handles and filenames: `Brittanya Razavi`, `Ashley Adams`, `Mouchette`, `Amouranth`, `Mini Blondie` (`@miniblondie`), `Indica Flower`, `Luna Okko`, `Olivia Young` (`Oliviayoung188`), `Turn Up Monster`.
- Assigns `studio = "OnlyFans"`.

### Rule C: Porn Twins Duo Attribution
- Analyzes 12 video releases (3.96 GB).
- Assigns `studio = "Porn Twins"`.
- Extracts featured duo models: `Chantel & Chloe Stevens`, `Lacey & Lyndsay`, `Anna Michelle & Katja`, `Cherish & Cali Milton`, `Marika & Dominica`.
- Normalizes release titles: `Love Twins: Two Hot`, `Love Twins: My Evil Twin`, `Love Twins: Twindom`, `Love Twins: Joined at the Hip`, `Love Twins: True Hollywood Twins`.

### Rule D: Girls Gone Wild Series Normalization
- Analyzes 6 feature releases (1.51 GB).
- Assigns `studio = "Girls Gone Wild"`.
- Normalizes volume titles: `Girls Gone Wild: Ultimate Rush 2006`, `Girls Gone Wild: Best Breasts Ever`, `Girls Gone Wild: Best of Blondes 2`, `Girls Gone Wild: First Timers Vol 1`, `Girls Gone Wild: Sex Starved College Girls 4`, `Girls Gone Wild: SUV Vol 2`.

### Rule E: Miss Alice 18 Date and Clip Parsing
- Analyzes 8 video releases (0.17 GB).
- Assigns `existing_artist = "Miss Alice 18"`, `studio = "Miss Alice 18"`.
- Standardizes clip titles: `Miss Alice Clip 1` through `Clip 7`, `Miss Alice 2012-05-10`.

### Rule F: Anime & Night Shift Nurses
- Analyzes 32 releases (1.07 GB).
- Assigns `studio = "Vanilla"` for Night Shift Nurses releases and `studio = "Anime"` for standalone series.
- Normalizes episode series: `Night Shift Nurses: Episode <#>`, `Akibakei Kanojyo <#>`, `Cool Devices 1`, `Crimson Climax 2`.

### Rule G: L & S Erotica Educational Series
- Analyzes 12 video releases (4.72 GB).
- Assigns `studio = "L & S Erotica"` or `The Lovers' Guide`.
- Normalizes clean educational titles in Greek and English (`The Lovers' Guide: Sexual Positions`, `Μυστικά Του Σημείου G`, `Τεχνικές Του Kama Sutra`, `Η Απόλαυση Του Ερωτικού Μασάζ`).

### Rule H: Thematic Categories and Star Recognition
- Analyzes 180 assets across `Hard`, `Teasers`, `Pov`, `Girl on Girl Action`, `Extreme & Kinky & Stories`, `Amateur`, `Squirts`, `Clips`, `Blowjob`, and `Strip`.
- Extracts recognized stars: `Anetta Keys`, `Abbie Cat`, `Bruna Ferraz`, `Elena Grimaldi`, `Andrea Rincon`, `Heather Vandeven`, `Bree Olson`, `Brianna Frost`, `Carmen Electra`, `Alexis Love`, `Kayden Kross`, `Lolly Badcock`, `Cassie Young`, `Michelle B`, `Lacie Heart`, `Sindee Jennings`, `Jenni Lee`, `Veronica Vanoza`, `Natasha Nice`, `Monica Sweetheart`, `Melissa Lauren`, `Veronica Da Souza`, `Veronika Zemanova`.
- Assigns specific siterip studios where present (`DDF Network`, `Drunk Sex Orgy`, `Private Amateure`, `Pound the Round`, `Squirting Orgasms`) and categorizes thematic series (`POV`, `Teasers`, `Girl on Girl`, `Hard Erotica`, etc.).

---

## 3. Container Tagging Protocol

- **Target Container**: Compatible MP4 media files supporting QuickTime iTunes metadata atoms (`©ART`, `©nam`, `©cmt`, `©day`).
- **Read-Only Stream Integrity**: Stream payloads remain strictly read-only. Only container metadata atoms are updated via Mutagen.
- **Timestamp Preservation**: Original file modification times (`mtime`) and access times (`atime`) are captured prior to write operations and restored with `os.utime`.

---

## 4. Execution Metrics and Reconciliation

### Database Reconciliation (`media_inventory.db`)
- **Safety Backup**: Created backup at `media_inventory_pre_collections_tagging.bak` (27.07 MB).
- **Total Assets Evaluated**: 856 records in `F:\Aloha\Collections & Siterips\`.
- **Performer Attribution**:
  - Baseline: 10 files (1.1%).
  - Post-Execution: 591 files (69.0%).
  - Delta: +581 files (+67.9%).
  - Remaining 265 assets without individual performer tags consist of generic thematic compilations, amateur clips, and educational series.
- **Studio Attribution**:
  - Baseline: 10 files (1.2%).
  - Post-Execution: 856 files (100.0%).
  - Delta: +846 files (+98.8%).
- **Title Normalization**:
  - Baseline: Inconsistent raw filenames with scrapers and technical resolution tags.
  - Post-Execution: 856 clean normalized titles (100.0%).

### Live Container Tagging (`F:\Aloha\Collections & Siterips\`)
- **Queued MP4 Videos**: 234 videos.
- **Tagged Losslessly**: 234 videos (100% of eligible files).
- **Timestamp Preservation Rate**: 100% verified via `os.utime`.
- **Non-MP4 Assets**: 337 MKV files and 285 images remain payload-untouched on disk while fully enriched inside `media_inventory.db`.

---

## 5. Automated Testing and Verification

- **Unit Tests**: `tests/test_tag_collections_media.py` (10 test cases).
  - Title noise stripping and series number normalization.
  - Izzy Green video clip parsing and screencap token mapping.
  - OnlyFans Mix handle parsing and star extraction.
  - Porn Twins duo parsing.
  - Girls Gone Wild volume normalization.
  - Miss Alice 18 clip and date extraction.
  - Anime and Night Shift Nurses episode normalization.
  - Thematic star extraction across Hard, Teasers, and POV.
  - Database record synchronization on SQLite fixture.
  - MP4 container tagging and timestamp preservation mock.
- **Workspace Test Suite**: All 89 pytest tests passing in 4.45 seconds.
- **Compliance Check**: `python scripts/check_compliance.py` passing without warnings.
- **Rust Toolchain**: `cargo fmt --all --check` and `cargo clippy` passing with zero warnings.
