# Mission: Second-Pass Deduplication across Celebrities for F:\Aloha

Execution record and operational audit for the second-pass perceptual deduplication campaign targeting the `Celebrities` media pool on `F:\Aloha`.

---

## 1. Scope and System Context

- **Target Path**: `F:\Aloha\Celebrities\` (Drive `F:\` on Windows 11).
- **Working Repository**: `E:\repos\projects\storage-strategist`.
- **Linked Issue**: GitHub Issue #48 (`feat(cli): second-pass perceptual deduplication across Celebrities for Aloha`).
- **Media Inventory Database**: `E:\repos\projects\storage-strategist\media_inventory.db`.
- **Deduplication Ledger**: `E:\repos\projects\storage-strategist\deduplication_ledger.db`.
- **Audit Preview Artifact**: `E:\repos\projects\storage-strategist\celebrities_deduplication_preview.json`.
- **Quarantine Staging Directory**: `F:\Aloha\.quarantine_duplicates\`.

---

## 2. Engineering and Tooling Enhancements

### Multi-Threaded Keyframe Fingerprinting
`scripts/find_media_duplicates.py` was enhanced to support concurrent video processing:
- Added `--workers` CLI parameter (default: 8) powering parallel keyframe extraction via `concurrent.futures.ThreadPoolExecutor`.
- Isolated unique video candidates across sliding duration collision windows to eliminate redundant video file decodes.
- Added real-time terminal progress indicators: `[PROGRESS] Fingerprinted {done}/{total} videos ({percent:.1f}%)`.
- Reduced total fingerprinting runtime across 1,028 candidate video assets from over 7 minutes to 290 seconds.
- Added comprehensive unit test `test_find_video_duplicates_threaded` in `tests/test_find_media_duplicates.py`.

---

## 3. Execution Record and Candidate Findings

### Candidate Corpus Overview
- Total Video Assets in `Celebrities`: 1,204 files (34.87 GB).
- Total Image Assets in `Celebrities`: 279 files (40.70 MB).
- Candidate Video Assets Evaluated (>10.0s duration): 1,173 files.
- Duration Collision Windows Evaluated (+/- 2.0s): 988 groups.
- Unique Candidate Videos Requiring Keyframe Fingerprints: 1,028 assets.

### Tier 1: Exact Byte Matching
- Evaluated 14 file size collision groups (>=1 MB).
- Exact Clones Discovered in Pass 2: 0 (the single exact binary duplicate, `Veronica2030 Wasko2 Hi [H264].mp4`, was safely staged during Pass 1).
- Non-matching collision pairs reflected minor MP4 container metadata variances, differing QuickTime tags, or compression deltas.

### Tier 2: Perceptual Image Deduplication
- Processed 279 image assets in `F:\Aloha\Celebrities\`.
- Evaluated with 64-bit DCT perceptual hash (`pHash`) and difference gradient hash (`dHash`) using BK-Tree metric space search (Hamming distance <= 4).
- Clusters Identified: 3 perceptual image clusters (3 duplicate files, 1,514,942 bytes / 1.44 MB) in `F:\Aloha\Celebrities\Megan Fox\`.
- Master Selection: Preserved highest-resolution, highest-pixel-count images (for example, retaining full-resolution promo photoshoot master over resized variant).

### Tier 3: Perceptual Video Keyframe Fingerprinting
- Fingerprinted 1,028 unique candidate videos across 3 representative keyframes (sampled at 20%, 50%, and 80% duration).
- Matched candidate pairs within duration collision windows using Hamming distance threshold <= 4.
- Clusters Identified: 18 perceptual video duplicate clusters (18 duplicate files, 251,268,155 bytes / 239.63 MB).
- Precision: 100% precision across all clusters. 13 clusters matched with Hamming distance 0 (exact visual keyframe identity), 2 clusters matched with distance 1, and 3 clusters matched with distance 2.
- Master Selection: Retained higher-resolution, higher-bitrate, and richer-metadata masters (such as keeping 1080p master over 720p clip, or retaining canonical update release over secondary copy).

---

## 4. Confirmed Duplicate Clusters Summary

| Cluster ID | Detection Type | Master Asset Path | Quarantined Duplicate Path | Duplicate Size | Distance |
|---|---|---|---|---|---|
| `cluster_img_ea9d86669d6a3348` | `perceptual_image` | `Celebrities\Megan Fox\...06.jpg` | `Celebrities\Megan Fox\...07.jpg` | 50.53 KB | 4 |
| `cluster_img_8ed4606bfb909467` | `perceptual_image` | `Celebrities\Megan Fox\...18171.jpg` | `Celebrities\Megan Fox\...18171(2).jpg` | 84.43 KB | 0 |
| `cluster_img_a824f6d20b39d5cb` | `perceptual_image` | `Celebrities\Megan Fox\...2074.jpg` | `Celebrities\Megan Fox\...2079.jpg` | 180.50 KB | 0 |
| `cluster_vid_813` | `video_keyframe` | `Updates\Update1\Diane Lane Her Career...` | `Updates\Update8\[2013] The Hottest Babes...6` | 2.25 MB | 0 |
| `cluster_vid_910` | `video_keyframe` | `Updates\Update1\The L Word Every Nude...12` | `Updates\Update4,5,6,7\Caught in the Act...5` | 3.66 MB | 0 |
| `cluster_vid_1108` | `video_keyframe` | `Updates\Update4,5,6,7\Hottest Naked...2` | `From Movies\80s Teen Sex Comedies...4` | 3.32 MB | 1 |
| `cluster_vid_958` | `video_keyframe` | `Updates\Update1\Weeds Every Nude Scene...2` | `From Movies\All of the Hottest Mary Louise...` | 3.29 MB | 2 |
| `cluster_vid_1010` | `video_keyframe` | `Updates\Update2\Top 10 Nude Celebs...5` | `Updates\Update8\Ban Pil Milicevic 1 Hd Hi` | 8.09 MB | 0 |
| `cluster_vid_1056` | `video_keyframe` | `Updates\Update4,5,6,7\Dirty Kaylynn1 Hi 2` | `Updates\Update4,5,6,7\Dirty Kaylynn1 Hi` | 6.30 MB | 0 |
| `cluster_vid_931` | `video_keyframe` | `Updates\Update1\The Naked Babes of Batman...2` | `Updates\Update8\Marion Cotillard Every Nude...` | 6.42 MB | 0 |
| `cluster_vid_1107` | `video_keyframe` | `Updates\Update4,5,6,7\Kikuchi Babel4 Hd Hi` | `Updates\Update8\[2013] The Hottest Babes...16` | 7.26 MB | 0 |
| `cluster_vid_1018` | `video_keyframe` | `Updates\Update4,5,6,7\191704 Hi 2` | `Updates\Update4,5,6,7\191704 Hi` | 9.61 MB | 0 |
| `cluster_vid_1145` | `video_keyframe` | `Updates\Update4,5,6,7\Pleasurewoman72...2` | `Updates\Update4,5,6,7\Pleasurewoman72...` | 7.54 MB | 0 |
| `cluster_vid_1005` | `video_keyframe` | `Updates\Update3\Naked Babes of Comic Con...3` | `Updates\Update8\The Naked Babes of Game...` | 8.38 MB | 0 |
| `cluster_vid_379` | `video_keyframe` | `Old\Magnificent Mams You May Have Missed` | `Updates\Update4,5,6,7\Magnificent Mams...` | 8.55 MB | 0 |
| `cluster_vid_986` | `video_keyframe` | `Updates\Update2\Top 10 Nude Celebs...3` | `Updates\Update8\Ms Orangeisthenewblack...` | 11.59 MB | 0 |
| `cluster_vid_1023` | `video_keyframe` | `Updates\Update4,5,6,7\210275 Hi 2` | `Updates\Update4,5,6,7\210275 Hi` | 14.28 MB | 0 |
| `cluster_vid_1193` | `video_keyframe` | `Updates\Update4,5,6,7\[2013] The Top 10 Racks` | `Updates\Update4,5,6,7\[The Peepers Choice]...8` | 14.55 MB | 0 |
| `cluster_vid_991` | `video_keyframe` | `Updates\Update3\Did I Just See a Butthole...2` | `Updates\Update4,5,6,7\Top Naked and Blindfolded...4` | 18.57 MB | 0 |
| `cluster_vid_33871` | `video_keyframe` | `Celebrities\Sasha Grey\Sasha Grey Head Case 2` | `Celebrities\Sasha Grey\Sasha Grey Loves to Fuck` | 36.92 MB | 1 |
| `cluster_vid_33861` | `video_keyframe` | `Celebrities\Sasha Grey\Black Cock Addiction 2` | `Celebrities\Sasha Grey\Take 2 Black Cocks` | 70.18 MB | 2 |

---

## 5. Safe Quarantine Staging and Inventory Reconciliation

1. **Quarantine Staging**:
   - All 21 duplicate files were safely moved from `F:\Aloha\Celebrities\` into cluster-scoped subdirectories under `F:\Aloha\.quarantine_duplicates\<cluster_id>\`.
   - Recovered Primary Storage on `F:\`: 252,783,097 bytes (241.07 MB).
2. **Cumulative Ledger Metrics (`deduplication_ledger.db`)**:
   - Total Quarantined Clusters: 142 clusters (3 exact byte, 99 perceptual image, 40 video keyframe).
   - Total Quarantined Files: 145 files.
   - Total Recovered Primary Storage: 4,195,233,571 bytes (4,004.42 MB / ~3.91 GB).
   - Rollback capability: Complete round-trip recovery available for all staged items via `--rollback`.
3. **Database Reconciliation (`media_inventory.db`)**:
   - Ran `python scripts/refresh_media_inventory.py --reconcile-only --force-purge`.
   - Purged 21 stale records corresponding to the staged duplicate files.
   - Active database records updated from 35,508 to 35,487.
   - Zero missing files, zero untracked files, and zero quarantine directory leaks.
