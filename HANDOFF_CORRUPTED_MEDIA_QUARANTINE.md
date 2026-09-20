# Mission: Corrupted & Truncated Media Quarantine for F:\Aloha

Isolate, safely stage, and reconcile corrupted and truncated video files across `F:\Aloha` into a reversible quarantine directory (`F:\Aloha\.quarantine_corrupted`), backed by a transactional SQLite ledger (`corrupted_media_ledger.db`).

---

## 1. Context & Baseline Metrics

- **Target Path**: `F:\Aloha` (NTFS, Drive F:\ on Windows 11).
- **Working Repository**: `E:\repos\projects\storage-strategist`.
- **Media Inventory Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Quarantine Staging Directory**: `F:\Aloha\.quarantine_corrupted`.
- **Quarantine Ledger**: `E:\repos\projects\storage-strategist\corrupted_media_ledger.db`.
- **Target Candidates Discovered**: 24 unplayable video files totaling **12.53 GB (13,448,646,844 bytes)**.

---

## 2. Target Corpus Breakdown

| Error Classification | File Count | Total Size | Description |
|---|---|---|---|
| `truncated_mp4_missing_moov` | 18 | 10.78 GB | Truncated MP4 files missing container `moov` atom headers |
| `invalid_container_data` | 5 | 1.42 GB | Malformed AVI and WMV files failing container demuxers |
| `corrupted_ebml_header` | 1 | 0.33 GB | Invalid EBML headers (`0x00 at pos 0 invalid as first byte`) |
| **Total** | **24** | **12.53 GB** | **All confirmed unplayable via ffprobe / ffmpeg** |

### Distribution by Canonical Root Folder

| Canonical Root | File Count | Storage Size |
|---|---|---|
| `Collections & Siterips` | 17 | 10.77 GB |
| `Movies` | 5 | 0.39 GB |
| `Studios` | 2 | 1.36 GB |
| `Games` | 0 | 0.00 GB (Strictly isolated) |
| `Celebrities` | 0 | 0.00 GB |
| `Photos & Sets` | 0 | 0.00 GB |
| `Magazines & Docs` | 0 | 0.00 GB |

---

## 3. Tooling Architecture

1. **Detection & Verification Tool** (`scripts/quarantine_corrupted_media.py`):
   - Integrates with `ffprobe` to validate container streams and format headers.
   - Detects fatal container faults (`moov atom not found`, `EBML header parsing failed`, `Invalid data found when processing input`).
   - Supports `--dry-run`, `--quarantine`, `--rollback`, and `--check-all`.
2. **Transactional SQLite Ledger** (`corrupted_media_ledger.db`):
   - Schema tracks `id`, `original_path`, `quarantine_path`, `file_size`, `error_class`, `error_detail`, `original_mtime`, `quarantined_at`, and `status`.
   - Supports 100% reversible rollbacks via `python scripts/quarantine_corrupted_media.py --rollback`.
3. **Safety & Quarantine Exclusions**:
   - `scripts/media_inventory_scanner.py` and `scripts/refresh_media_inventory.py` updated to prune all `.quarantine_*` staging directories from filesystem walks.
   - `F:\Aloha\Games` strictly isolated from all scans and move operations.

---

## 4. Execution Record & Final Results (Completed)

All phases executed with production verification:
- **Safety Snapshot**: Created atomic backup at `media_inventory_pre_corrupted_quarantine.bak`.
- **Live Quarantine Staging**: Staged all 24 corrupted assets into `F:\Aloha\.quarantine_corrupted` (12.53 GB isolated from active folders).
- **Rollback Round-Trip Verification**: Verified sample restoration to original path and re-quarantine with byte-for-byte fidelity and mtime preservation.
- **Inventory Reconciliation**:
  - Pre-purge records: 35,532
  - Stale records purged: 24
  - Untracked discovered: 0
  - Post-purge active catalog: 35,508 records (100% disk alignment, 0 broken paths, 0 unplayable videos).
- **Automated Tests**: 61 pytest tests passing, cargo workspace tests passing, compliance check passed.

---

## 5. Rollback Instructions

If any quarantined file needs to be restored to its original directory:

```bash
# Restore a specific file by ledger ID
python scripts/quarantine_corrupted_media.py --rollback --target-id <id>

# Restore all quarantined files
python scripts/quarantine_corrupted_media.py --rollback

# Reconcile inventory after rollback
python scripts/refresh_media_inventory.py --reconcile-only --force-purge
```
