# Mission: Phase 2 AV1 High-Efficiency Space Optimization for F:\Aloha

You are the Grand Issue Orchestrator. Dynamically analyze the target scope, determine the optimal multi-agent topology, and coordinate a specialized squad of agents to execute and deliver the mission with production-ready excellence.

You are NOT constrained to a fixed roster: critically evaluate the problem domain and decide which specialized agents to spawn (for example, GPU Encoding Specialist, Quality & VMAF Benchmark Engineer, Safety & Transaction Ledger Engineer).

Target Scope / Issues / Milestone:
---

## Objective

Design, benchmark, and execute a hardware-accelerated AV1 space-optimization pipeline across the high-capacity H.264 video corpus on `F:\Aloha`. Target a 35% to 50% storage footprint reduction (projected 100 GB to 140 GB recovered) while maintaining visually lossless quality, retaining original container tags and file timestamps, tracking all swaps in a transactional SQLite ledger, and keeping `media_inventory.db` in live synchronization.

---

## 1. System and Hardware Runtime Context

- **Host GPU**: NVIDIA GeForce RTX 5070 Ti (Blackwell architecture, Driver 591.86).
- **Hardware Encoder**: Dual 9th Generation NVENC supporting native hardware `av1_nvenc`.
- **Target Drive**: `F:\Aloha` (NTFS, Drive F:\ on Windows 11).
- **Working Repository**: `E:\repos\projects\storage-strategist`.
- **Python Environment**: Python 3.12 (Always initialize scripts with `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`).
- **FFmpeg Binary**: `C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffmpeg.exe`.
- **FFprobe Binary**: `C:\Users\takja\AppData\Local\Programs\Python\Python312\Lib\site-packages\static_ffmpeg\bin\win32\ffprobe.exe`.
- **Media Inventory Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Active Branching Standard**: Create issue first (in milestone `Backlog`), use branch format `<actor>/feat/cli/aloha-av1-optimization-<id>`.

---

## 2. Dataset Profiling and Pareto Targeting

A full query of `media_inventory.db` reveals 6,721 H.264 video files totaling **305.65 GB**.

### Distribution by Canonical Root Folder

| Canonical Root | File Count | Total Size | Average File Size | Strategy |
|---|---|---|---|---|
| `Studios` | 208 | 201.55 GB | 992.4 MB | **Tier A Priority**: 66.0% of total volume in only 208 files |
| `Movies` | 32 | 44.41 GB | 1,421.1 MB | **Tier B Priority**: 14.5% of total volume in 32 feature films |
| `Collections & Siterips` | 243 | 39.90 GB | 168.2 MB | **Tier C Priority**: 13.0% of total volume in 243 files |
| `Celebrities` | 676 | 9.38 GB | 14.2 MB | **Optional Tier D**: Short clips, low byte yield |
| `Games` | 5,562 | 10.42 GB | 1.9 MB | **STRICT EXCLUSION**: Game cutscenes/assets (risk of breaking engine players) |

### Key Architectural Constraint: The Pareto Boundary

Focusing strictly on **Tier A + Tier B + Tier C** covers **483 files** accounting for **285.86 GB (93.5% of total H.264 storage)**.
- `F:\Aloha\Games\` must be **strictly excluded** from transcoding to prevent breaking game engine video decoders (RPG Maker, Ren'Py, Unity).
- Protected root files (`F:\Aloha\VHDX-ai.vhdx`, `HANDOFF_*.md`) must remain untouched.

---

## 3. Encoding Architecture and Parameters

### Hardware Transcode Specification
- **Video Codec**: `av1_nvenc`
- **Pixel Format**: `-pix_fmt yuv420p` (Mandatory for NVENC input compatibility)
- **Rate Control**: Variable Bitrate with Constant Quality (`-rc:v vbr -cq:v 26 -b:v 0`)
- **Preset**: High Quality (`-preset p6 -tune hq`)
- **Audio Stream**: Lossless copy (`-c:a copy`) to preserve original audio bitstreams with zero re-encoding overhead.
- **Container**: Universal `.mp4` with `-movflags +faststart` for immediate streaming and broad OS compatibility.

### FFmpeg Command Template
```bash
ffmpeg -y -i "{source_path}" \
  -c:v av1_nvenc -pix_fmt yuv420p -rc:v vbr -cq:v 26 -b:v 0 -preset p6 -tune hq \
  -c:a copy \
  -movflags +faststart \
  "{temp_output_path}"
```

---

## 4. Operational Safety and Verification Protocol

1. **Local Same-Volume Staging**:
   Write output to a temporary hidden file in the same directory (`._tmp_av1_<filename>.mp4`). This ensures `os.replace` executes an instantaneous atomic inode/metadata pointer swap rather than a cross-volume copy.
2. **Negative Delta Guardrail**:
   If the transcoded AV1 file size is equal to or larger than the source file (`output_size >= original_size`), reject the transcode immediately, delete the temporary file, and preserve the original H.264 file.
3. **Multi-layer Stream Verification**:
   Before replacing the original file, execute `ffprobe` on the temp file:
   - Video stream exists and reports `codec_name == "av1"`.
   - Audio stream exists and matches original channel count and codec.
   - Container duration matches the original file within 2.0 seconds tolerance.
4. **Metadata and Timestamp Continuity**:
   - Transfer MP4 metadata tags (`©nam`, `©ART`, `©day`, `©cmt`) using Mutagen before swap.
   - Restore original filesystem modification time (`os.utime`).
5. **Transactional SQLite Ledger**:
   Log all operations to `av1_transcode_ledger.db` with schema:
   ```sql
   CREATE TABLE IF NOT EXISTS transactions (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       file_path TEXT NOT NULL UNIQUE,
       original_size INTEGER NOT NULL,
       av1_size INTEGER NOT NULL,
       saved_bytes INTEGER NOT NULL,
       compression_ratio REAL NOT NULL,
       duration REAL,
       vmaf_score REAL,
       transcode_time_sec REAL,
       executed_at TEXT NOT NULL,
       status TEXT NOT NULL
   );
   ```
6. **Live Inventory Synchronization**:
   Update `media_inventory.db` immediately after each successful transaction:
   ```sql
   UPDATE media_files
   SET v_codec = 'av1',
       file_size = ?,
       bitrate = ?
   WHERE file_path = ?;
   ```

---

## 5. Phased Execution Plan

### Step 1: Benchmark and Quality Calibration (Pilot Phase)
1. Select 5 representative test files from `F:\Aloha\Studios\` spanning different resolutions (1080p, 720p, high bitrate, dark scenes).
2. Test CQ values `24`, `26`, `28`, and `30` on 60-second clips.
3. Measure encoding speed (frames per second, GPU utilization via `nvidia-smi`), size reduction percentage, and visual parity.
4. Confirm target CQ value (recommended default: `CQ 26`).

### Step 2: Implementation of CLI Pipeline Script
1. Create `scripts/optimize_av1_corpus.py`:
   - Dry-run mode (`--dry-run`) to catalog target candidates and estimate space savings.
   - Single-file mode (`--file <path>`) for targeted execution.
   - Batch mode (`--tier <A|B|C|all>`) with optional thread/concurrency control.
   - Safety rollback flag (`--rollback`) to restore files from ledger if ever needed.
2. Add unit tests in `tests/test_optimize_av1_corpus.py` validating command generation, probe validation, and guardrail logic.
3. Verify existing compliance: `python scripts/check_compliance.py`.

### Step 3: Tier A Execution (Studios: 208 Files, 201.55 GB)
1. Run dry run to verify the candidate list.
2. Execute automated transcode pipeline across Tier A.
3. Monitor GPU temperatures and encoding throughput.
4. Verify database updates and space reclaimed on drive `F:\`.

### Step 4: Tier B and Tier C Execution (Movies and Siterips: 275 Files, 84.31 GB)
1. Execute transcode pipeline across Tier B (32 feature movies) and Tier C (243 siterips).
2. Log aggregate space recovered and update summary metrics.

---

## 6. Hard Constraints

- **Strict Prohibition on Em Dashes**: Never use em dashes in code comments, CLI messages, logs, or markdown documentation. Use commas, colons, parentheses, or separate sentences.
- **Audio Integrity**: Never re-encode audio; always use `-c:a copy`.
- **Game Engine Isolation**: Never modify files inside `F:\Aloha\Games\`.
- **No In-Place Overwrite Without Probe**: The source file must not be removed until the modernized temp file has passed all probe and duration checks.
- **PR & Merge Policy**: All code must follow the standard repository workflow (create issue in `Backlog`, branch `<actor>/feat/cli/aloha-av1-optimization-<id>`, passing CI checks, squash-merge).
