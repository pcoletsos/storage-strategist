import os
import sys
import pytest

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from tag_magazines_media import extract_magazine_metadata


def test_extract_olga_farmaki_playboy():
    fn = "Olga Farmaki Ollandiko Playboy - 01.jpg"
    artist, publisher, date_str, title, conf = extract_magazine_metadata(fn)
    assert artist == "Olga Farmaki"
    assert publisher == "Playboy"
    assert conf >= 0.90


def test_extract_katerina_stikoudi_nitro():
    fn = "Katerina Stikoudi Nitro Oktovriou 2010 - 05.jpg"
    artist, publisher, date_str, title, conf = extract_magazine_metadata(fn)
    assert artist == "Katerina Stikoudi"
    assert publisher == "Nitro Magazine"
    assert date_str == "2010-10"


def test_extract_greek_periodika_with_date():
    fn = "[2009-12-22] Greek Periodika - 100.jpg"
    artist, publisher, date_str, title, conf = extract_magazine_metadata(fn)
    assert artist == "Compilation"
    assert publisher == "Greek Periodika"
    assert date_str == "2009-12-22"
    assert "Greek Periodika 100" in title


def test_extract_dimitra_alexandraki():
    fn = "[2010-01-23] Greek Periodika - Dimitra Alexandraki 2.jpg"
    artist, publisher, date_str, title, conf = extract_magazine_metadata(fn)
    assert artist == "Dimitra Alexandraki"
    assert publisher == "Greek Periodika"
    assert date_str == "2010-01-23"


def test_extract_elena_paparizou():
    fn = "[2009-12-21] Greek Periodika - Ceadcebbceb5cebdceb1 Cf80ceb1cf80ceb1cf81ceafceb6cebfcf85 5.jpg"
    artist, publisher, date_str, title, conf = extract_magazine_metadata(fn)
    assert artist == "Elena Paparizou"
    assert publisher == "Greek Periodika"
    assert date_str == "2009-12-21"
