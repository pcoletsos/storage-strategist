import os
import sys
import sqlite3
import tempfile
import pytest

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from purge_quarantine_media import purge_quarantine


def test_purge_quarantine_dry_run_and_commit():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Setup mock quarantine dirs
        q_dupes = os.path.join(tmp_dir, ".quarantine_duplicates", "cluster_1")
        q_corr = os.path.join(tmp_dir, ".quarantine_corrupted")
        os.makedirs(q_dupes, exist_ok=True)
        os.makedirs(q_corr, exist_ok=True)

        fake_dupe_file = os.path.join(q_dupes, "dupe1.mp4")
        with open(fake_dupe_file, "wb") as f:
            f.write(b"0" * 1024)

        fake_corr_file = os.path.join(q_corr, "corr1.mp4")
        with open(fake_corr_file, "wb") as f:
            f.write(b"1" * 2048)

        # Setup mock ledgers
        dedup_db = os.path.join(tmp_dir, "dedup.db")
        conn_d = sqlite3.connect(dedup_db)
        conn_d.execute("""
            CREATE TABLE duplicate_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_path TEXT,
                file_size INTEGER,
                status TEXT,
                executed_at TEXT
            )
        """)
        conn_d.execute("INSERT INTO duplicate_files (quarantine_path, file_size, status) VALUES (?, ?, ?)",
                       (fake_dupe_file, 1024, "quarantined"))
        conn_d.commit()
        conn_d.close()

        corr_db = os.path.join(tmp_dir, "corr.db")
        conn_c = sqlite3.connect(corr_db)
        conn_c.execute("""
            CREATE TABLE corrupted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_path TEXT,
                file_size INTEGER,
                status TEXT
            )
        """)
        conn_c.execute("INSERT INTO corrupted_files (quarantine_path, file_size, status) VALUES (?, ?, ?)",
                       (fake_corr_file, 2048, "quarantined"))
        conn_c.commit()
        conn_c.close()

        inv_db = os.path.join(tmp_dir, "inv.db")
        conn_i = sqlite3.connect(inv_db)
        conn_i.execute("CREATE TABLE media_files (id INTEGER PRIMARY KEY, file_path TEXT)")
        conn_i.commit()
        conn_i.close()

        # 1. Test dry run: files must NOT be deleted
        res_dry = purge_quarantine(
            target_dir=tmp_dir,
            dedup_ledger_path=dedup_db,
            corrupted_ledger_path=corr_db,
            inventory_db_path=inv_db,
            dry_run=True,
            output_report=os.path.join(tmp_dir, "report_dry.json")
        )
        assert res_dry["dry_run"] is True
        assert res_dry["total_files_purged"] == 2
        assert res_dry["total_bytes_reclaimed"] == 3072
        assert os.path.exists(fake_dupe_file)
        assert os.path.exists(fake_corr_file)

        # 2. Test commit: files must be deleted and ledger updated
        res_commit = purge_quarantine(
            target_dir=tmp_dir,
            dedup_ledger_path=dedup_db,
            corrupted_ledger_path=corr_db,
            inventory_db_path=inv_db,
            dry_run=False,
            output_report=os.path.join(tmp_dir, "report_commit.json")
        )
        assert res_commit["dry_run"] is False
        assert not os.path.exists(fake_dupe_file)
        assert not os.path.exists(fake_corr_file)

        # Check ledger status
        conn_d = sqlite3.connect(dedup_db)
        status_d = conn_d.execute("SELECT status FROM duplicate_files").fetchone()[0]
        conn_d.close()
        assert status_d == "purged"

        conn_c = sqlite3.connect(corr_db)
        status_c = conn_c.execute("SELECT status FROM corrupted_files").fetchone()[0]
        conn_c.close()
        assert status_c == "purged"
