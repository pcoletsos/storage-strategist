# Mission: Performer Entity Recognition and Studio Attribution for Movies Media Pool

## Objective

Design, implement, validate, and execute an entity recognition, studio attribution, movie title normalization, and lossless MP4 container tagging pipeline across the `Movies` media pool on `F:\Aloha`. Synchronize all extracted performer, studio, and release metadata into `media_inventory.db` and embed standardized QuickTime container atoms into compatible MP4 media assets while strictly preserving original file modification timestamps (`mtime`).

---

## 1. Scope and Corpus Context

- **Target Directory**: `F:\Aloha\Movies\` (Drive F:\ on Windows 11).
- **Target Inventory Records**: 284 media assets (237 videos, 47 images, 51.18 GB).
- **Primary Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Pre-Tagging Baseline**:
  - Performer attribution: 10 files (3.5% coverage).
  - Studio attribution: 29 files (10.2% coverage).
  - Legacy state: Digital Playground feature movies (`Pirates`, `Babysitters 2`, `The Smiths`, `MILFlicious`, DPG collections), Stoya releases (`Video Nasty`, `Love and Other Mishaps`), Wicked Pictures fairy tales, porn parodies, Private films, and Greek productions lacked clean canonical studios and performer entities.

---

## 2. Architecture and Extraction Strategy

The pipeline was implemented in `scripts/tag_movies_media.py` with multi-stage deterministic rules tailored to feature cinema conventions:

### Rule A: Digital Playground Feature Films & DPG Collections
- Analyzes 17 releases in `Movies\New folder` and root feature files.
- Maps release codes: `Dpg Teachrs` (`Teachers`), `Dpg Jjatmictease` (`Jesse Jane: Atomic Tease`), `Dpg Nrses` (`Nurses`), `Dpg Flygrls` (`Fly Girls`), `Dpg Cheerleadrs` (`Cheerleaders`), `Dpg Babysttrs` (`Babysitters`), `Dpg Jjplyful` (`Jesse Jane: Playful`), `Dpg Intoxicatd` (`Intoxicated`), `Dpg Jjhomewrk` (`Jesse Jane: Homework`).
- Assigns `studio = "Digital Playground"` and attributes contract star `Jesse Jane`.

### Rule B: Pirates Franchise (Digital Playground)
- Resolves `Pirates (2005)` and `Pirates II: Stagnetti's Revenge (2008)` across 17 files.
- Assigns `studio = "Digital Playground"`.
- Attributes featured stars (`Jesse Jane, Belladonna, Stoya` for Pirates II; `Jesse Jane, Carmen Luvana, Janine Lindemulder` for Pirates 2005).

### Rule C: Stoya Debut & Feature Releases
- Analyzes 63 assets in `Movies\Stoya Video Nasty 2008\` and root feature `Stoya in Love and Other Mishaps`.
- Assigns `existing_artist = "Stoya"`, `studio = "Digital Playground"`, `existing_date = "2008"`.
- Normalizes scene and title sequences.

### Rule D: Wicked Pictures Fairy Tales
- Analyzes `Movies\[wicked Fairy Tales] Peter Pan...`.
- Assigns `studio = "Wicked Pictures"`.
- Extracts featured performers: `Keira Nicole`, `Riley Steele`, `Aiden Ashley`, `Mia Malkova`, `Vicki Chase`.
- Standardizes scene titles: `Wicked Fairy Tales: Peter Pan XXX Scene <#>`.

### Rule E: Commercial Studio Parodies & Private Features
- `The Avengers: A XXX Porn Parody` -> `studio = "Vivid Entertainment"`.
- `Friends: A XXX Porn Parody` -> `studio = "New Sensations"`.
- `The Sexth Element (2008)` & `Private Specials 34: Italian Milfs Mama Mia` -> `studio = "Private"`.

### Rule F: Greek Cinema & Sirina Productions
- Analyzes Greek feature releases across `Greek Videos`, `Ελληνικο Αντρικο Casting`, `Greek\Tzoulia`, `Kafto Sex Stin Ammo`, `To Palamari Toy Barkarh`.
- Assigns `studio = "Sirina Productions"` or `Greek Erotica`.
- Attributes recognized performers (`Julia Alexandratou`, `Aris`, `Laoura`, `Katerina, Eirini`).
- Standardizes titles (`Show Bitch`, `Sirina: Agrotisa`, `Gatakia Parte To`, `Το Παλαμάρι Του Βαρκάρη`, `Καυτό Σεξ Στην Άμμο`, `Sex in the City of Athens`).

### Rule G: Classic Cinema
- `Deep Throat (1972)`: Attributes `existing_artist = "Linda Lovelace"`, `studio = "Bryanston Distributing"`, `existing_date = "1972"`.

---

## 3. Container Tagging Protocol

- **Target Container**: Compatible MP4 media files supporting QuickTime iTunes metadata atoms (`©ART`, `©nam`, `©cmt`, `©day`).
- **Read-Only Stream Integrity**: Stream payloads remain strictly read-only. Only container metadata atoms are updated via Mutagen.
- **Timestamp Preservation**: Original file modification times (`mtime`) and access times (`atime`) are captured prior to write operations and restored with `os.utime`.

---

## 4. Execution Metrics and Reconciliation

### Database Reconciliation (`media_inventory.db`)
- **Safety Backup**: Created backup at `media_inventory_pre_movies_tagging.bak` (27.12 MB).
- **Total Assets Evaluated**: 284 records in `F:\Aloha\Movies\`.
- **Performer Attribution**:
  - Baseline: 10 files (3.5%).
  - Post-Execution: 129 files (45.4%).
  - Delta: +119 files (+41.9%).
  - Remaining 155 assets without individual performer tags consist of ensemble features, compilation discs, and educational or themed movie series.
- **Studio Attribution**:
  - Baseline: 29 files (10.2%).
  - Post-Execution: 284 files (100.0%).
  - Delta: +255 files (+89.8%).
- **Title Normalization**:
  - Baseline: Inconsistent raw filenames with scrapers, release tags, and resolution indicators.
  - Post-Execution: 284 clean normalized titles (100.0%).

### Live Container Tagging (`F:\Aloha\Movies\`)
- **Queued MP4 Videos**: 31 videos.
- **Tagged Losslessly**: 30 videos.
- **Skipped Gracefully**: 1 video (`[Night Shift Nurses] Ren Nanase - 01 [H264].mp4` contained a malformed zero-length inner atom; skipped without payload modification).
- **Timestamp Preservation Rate**: 100% verified via `os.utime`.
- **Non-MP4 Assets**: 206 MKV files and 47 images remain payload-untouched on disk while fully enriched inside `media_inventory.db`.

---

## 5. Automated Testing and Verification

- **Unit Tests**: `tests/test_tag_movies_media.py` (10 test cases).
  - Title noise stripping and release group cleaning.
  - Digital Playground DPG code mapping and Jesse Jane recognition.
  - Pirates franchise parsing (Pirates 2005 and Pirates II Stagnetti's Revenge 2008).
  - Stoya Video Nasty and Love and Other Mishaps attribution.
  - Wicked Pictures Peter Pan XXX star extraction and scene indexing.
  - Parody attribution (Vivid and New Sensations).
  - Sirina Greek movie attribution and Julia Alexandratou parsing.
  - Deep Throat classic cinema and Linda Lovelace attribution.
  - Database record synchronization on SQLite fixture.
  - MP4 container tagging and timestamp preservation mock.
- **Workspace Test Suite**: All 99 pytest tests passing in 5.86 seconds.
- **Compliance Check**: `python scripts/check_compliance.py` passing without warnings.
- **Rust Toolchain**: `cargo fmt --all --check` and `cargo clippy` passing with zero warnings.
