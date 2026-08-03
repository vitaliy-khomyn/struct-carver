"""Unit tests for newly added forensic features in Struct Carver!

This test suite verifies:
1. CryptoHasher (SHA-256, MD5, SHA-1, SHA-512, manifest text, and manifest CSV).
2. FileValidator (payload integrity checks for ZIP, SQLite, JSON, XML, HTML, PNG, BMP, GIF, JPEG, PDF).
3. CheckpointManager (atomic persistence, worker progress tracking, and session resumption).
4. Boundary deduplication for multi-worker chunk overlaps.
5. End-to-end Carver integration with hashing, validation, and checkpointing.
"""

import os
import json
import zlib
import struct
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from typing import Dict, Any

from struct_carver.core.hasher import CryptoHasher, SUPPORTED_HASH_ALGOS
from struct_carver.core.validator import FileValidator
from struct_carver.core.checkpoint import CheckpointManager
from struct_carver.core.carver import Carver
from struct_carver.cli import deduplicate_boundary_overlaps, merge_worker_reports


class TestCryptoHasher(unittest.TestCase):
    """Tests for CryptoHasher algorithm support and manifest generators."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_supported_algorithms(self):
        """Verifies that all supported algorithms can be instantiated and unsupported raises."""
        for algo in SUPPORTED_HASH_ALGOS:
            hasher = CryptoHasher(algo)
            self.assertEqual(hasher.algo_name, algo)

        with self.assertRaises(ValueError):
            CryptoHasher("unsupported_algo_123")

    def test_hash_bytes_and_file(self):
        """Verifies hash calculation for in-memory bytes and streaming files."""
        data = b"Forensic evidence data payload 12345"
        test_file = os.path.join(self.test_dir, "sample.bin")
        with open(test_file, "wb") as f:
            f.write(data)

        hasher = CryptoHasher("sha256")
        bytes_digest = hasher.hash_bytes(data)
        file_digest = hasher.hash_file(test_file)

        # sha256 of the data string
        self.assertEqual(len(bytes_digest), 64)
        self.assertEqual(bytes_digest, file_digest)

        # test md5
        md5_hasher = CryptoHasher("md5")
        self.assertEqual(len(md5_hasher.hash_bytes(data)), 32)

    def test_generate_manifest_content(self):
        """Verifies standard checksum manifest generation."""
        files = [
            {"filename": "carved_w0_0.pdf", "file_hash": "abcdef123456"},
            {"filename": "carved_w0_1.png", "file_hash": "7890fedcba98"},
        ]
        hasher = CryptoHasher("sha256")
        content = hasher.generate_manifest_content(files)
        expected = "abcdef123456  carved_w0_0.pdf\n7890fedcba98  carved_w0_1.png\n"
        self.assertEqual(content, expected)

    def test_generate_csv_manifest(self):
        """Verifies structured CSV forensic manifest generation."""
        files = [
            {
                "file_id": 0,
                "filename": "carved_w0_0.png",
                "format": "png",
                "status": "complete",
                "validation": {"is_valid": True, "details": "PNG verified"},
                "hash_algo": "sha256",
                "file_hash": "112233445566",
                "total_size": 4096,
                "fragments": [{"start_offset": 0, "end_offset": 4096, "size": 4096}],
            }
        ]
        hasher = CryptoHasher("sha256")
        csv_out = hasher.generate_csv_manifest(files)
        self.assertIn("file_id,filename,format,status,is_valid", csv_out)
        self.assertIn('"carved_w0_0.png"', csv_out)
        self.assertIn('"True"', csv_out)
        self.assertIn('"112233445566"', csv_out)


class TestFileValidator(unittest.TestCase):
    """Tests for format-specific payload integrity validation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.validator = FileValidator()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_nonexistent_and_empty_files(self):
        """Verifies validator handles missing and 0-byte files gracefully."""
        res_missing = self.validator.validate(os.path.join(self.test_dir, "ghost.png"), "png")
        self.assertFalse(res_missing["is_valid"])

        empty_file = os.path.join(self.test_dir, "empty.png")
        with open(empty_file, "wb") as f:
            pass
        res_empty = self.validator.validate(empty_file, "png")
        self.assertFalse(res_empty["is_valid"])

    def test_zip_validation(self):
        """Verifies ZIP archive verification and corrupted archive detection."""
        valid_zip = os.path.join(self.test_dir, "valid.zip")
        with zipfile.ZipFile(valid_zip, "w") as zf:
            zf.writestr("test.txt", "hello world")

        res_valid = self.validator.validate(valid_zip, "zip")
        self.assertTrue(res_valid["is_valid"])

        corrupt_zip = os.path.join(self.test_dir, "corrupt.zip")
        with open(valid_zip, "rb") as f_in:
            data = bytearray(f_in.read())
        # corrupt bytes in the payload
        data[25:35] = b"XXXXXXXXXX"
        with open(corrupt_zip, "wb") as f_out:
            f_out.write(data)

        res_corrupt = self.validator.validate(corrupt_zip, "zip")
        self.assertFalse(res_corrupt["is_valid"])

    def test_sqlite_validation(self):
        """Verifies SQLite PRAGMA integrity check on valid vs corrupted databases."""
        valid_db = os.path.join(self.test_dir, "valid.db")
        conn = sqlite3.connect(valid_db)
        cur = conn.cursor()
        cur.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, note TEXT);")
        cur.execute("INSERT INTO evidence (note) VALUES ('forensic record');")
        conn.commit()
        conn.close()

        res_valid = self.validator.validate(valid_db, "sqlite")
        self.assertTrue(res_valid["is_valid"])

        corrupt_db = os.path.join(self.test_dir, "corrupt.db")
        with open(corrupt_db, "wb") as f:
            # write sqlite magic header followed by garbage
            f.write(b"SQLite format 3\x00" + b"\xff" * 512)

        res_corrupt = self.validator.validate(corrupt_db, "sqlite")
        self.assertFalse(res_corrupt["is_valid"])

    def test_json_validation(self):
        """Verifies JSON syntax validation on valid vs corrupted documents."""
        valid_json = os.path.join(self.test_dir, "valid.json")
        with open(valid_json, "w", encoding="utf-8") as f:
            f.write('{"evidence_id": 42, "tags": ["verified", "intact"]}')

        self.assertTrue(self.validator.validate(valid_json, "json")["is_valid"])

        corrupt_json = os.path.join(self.test_dir, "corrupt.json")
        with open(corrupt_json, "w", encoding="utf-8") as f:
            f.write('{"evidence_id": 42, "unclosed_string": ')

        self.assertFalse(self.validator.validate(corrupt_json, "json")["is_valid"])

    def test_xml_validation(self):
        """Verifies XML tree parse validation on valid vs broken XML."""
        valid_xml = os.path.join(self.test_dir, "valid.xml")
        with open(valid_xml, "w", encoding="utf-8") as f:
            f.write('<case><item id="1">Log</item></case>')

        self.assertTrue(self.validator.validate(valid_xml, "xml")["is_valid"])

        broken_xml = os.path.join(self.test_dir, "broken.xml")
        with open(broken_xml, "w", encoding="utf-8") as f:
            f.write('<case><item id="1">Log</item>')

        self.assertFalse(self.validator.validate(broken_xml, "xml")["is_valid"])

    def test_png_validation(self):
        """Verifies PNG chunk CRC32 checksum validation."""
        # build a minimal 1x1 valid PNG in memory
        png_path = os.path.join(self.test_dir, "test.png")
        header = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
        ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

        iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

        with open(png_path, "wb") as f:
            f.write(header + ihdr_chunk + iend_chunk)

        self.assertTrue(self.validator.validate(png_path, "png")["is_valid"])

        # corrupt the IHDR chunk CRC
        corrupt_png = os.path.join(self.test_dir, "corrupt.png")
        bad_ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", 0x12345678)
        with open(corrupt_png, "wb") as f:
            f.write(header + bad_ihdr_chunk + iend_chunk)

        self.assertFalse(self.validator.validate(corrupt_png, "png")["is_valid"])

    def test_bmp_gif_jpeg_pdf_validation(self):
        """Verifies validation logic for BMP, GIF, JPEG, and PDF."""
        # bmp
        bmp_path = os.path.join(self.test_dir, "test.bmp")
        with open(bmp_path, "wb") as f:
            f.write(b"BM" + struct.pack("<I", 14) + b"\x00" * 8)
        self.assertTrue(self.validator.validate(bmp_path, "bmp")["is_valid"])

        # gif
        gif_path = os.path.join(self.test_dir, "test.gif")
        with open(gif_path, "wb") as f:
            f.write(b"GIF89a" + b"\x00" * 10 + b"\x3B")
        self.assertTrue(self.validator.validate(gif_path, "gif")["is_valid"])

        bad_gif = os.path.join(self.test_dir, "bad.gif")
        with open(bad_gif, "wb") as f:
            f.write(b"GIF89a" + b"\x00" * 10)
        self.assertFalse(self.validator.validate(bad_gif, "gif")["is_valid"])

        # jpeg
        jpg_path = os.path.join(self.test_dir, "test.jpg")
        with open(jpg_path, "wb") as f:
            f.write(b"\xFF\xD8" + b"\x00" * 10 + b"\xFF\xD9")
        self.assertTrue(self.validator.validate(jpg_path, "jpg")["is_valid"])

        # pdf
        pdf_path = os.path.join(self.test_dir, "test.pdf")
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
        self.assertTrue(self.validator.validate(pdf_path, "pdf")["is_valid"])


class TestCheckpointManager(unittest.TestCase):
    """Tests for CheckpointManager persistence and session resumption."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ckpt_path = os.path.join(self.test_dir, "checkpoint.json")
        self.mgr = CheckpointManager(self.ckpt_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_empty_load(self):
        """Verifies default template returned when checkpoint does not exist."""
        data = self.mgr.load()
        self.assertEqual(data, {"workers": {}, "files": []})

    def test_save_and_resume_progress(self):
        """Verifies worker progress and recovered files persistence."""
        file_record = {
            "file_id": 0,
            "filename": "carved_w0_0.json",
            "format": "json",
            "status": "complete",
            "total_size": 2048,
        }

        # save progress for worker 0 at offset 16384
        self.mgr.save_worker_progress(0, 16384, [file_record])

        # verify loaded state
        data = self.mgr.load()
        self.assertEqual(data["workers"]["0"], 16384)
        self.assertEqual(len(data["files"]), 1)
        self.assertEqual(data["files"][0]["filename"], "carved_w0_0.json")

        # verify resumed start offset
        start = self.mgr.get_worker_start_offset(0, 0)
        self.assertEqual(start, 16384)

        # verify start offset for an unrecorded worker returns default
        start_w1 = self.mgr.get_worker_start_offset(1, 40960)
        self.assertEqual(start_w1, 40960)

    def test_clear_checkpoint(self):
        """Verifies checkpoint removal upon clear()."""
        self.mgr.save_worker_progress(0, 4096)
        self.assertTrue(os.path.exists(self.ckpt_path))
        self.mgr.clear()
        self.assertFalse(os.path.exists(self.ckpt_path))


class TestBoundaryDeduplication(unittest.TestCase):
    """Tests for multi-worker boundary deduplication."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_duplicate_file_hash(self):
        """Verifies that duplicate files with identical hashes are removed and unlinked."""
        # create mock carved files on disk
        f1_path = os.path.join(self.test_dir, "carved_w0_0.bin")
        f2_path = os.path.join(self.test_dir, "carved_w1_0.bin")
        with open(f1_path, "wb") as f:
            f.write(b"content")
        with open(f2_path, "wb") as f:
            f.write(b"content")

        files = [
            {
                "file_id": 0,
                "filename": "carved_w0_0.bin",
                "file_hash": "hash_xyz_123",
                "status": "complete",
                "fragments": [{"start_offset": 0, "end_offset": 4096, "size": 4096}],
            },
            {
                "file_id": 1,
                "filename": "carved_w1_0.bin",
                "file_hash": "hash_xyz_123",
                "status": "complete",
                "fragments": [{"start_offset": 0, "end_offset": 4096, "size": 4096}],
            },
        ]

        deduped = deduplicate_boundary_overlaps(files, self.test_dir)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["filename"], "carved_w0_0.bin")
        # verify f2 was deleted from disk
        self.assertTrue(os.path.exists(f1_path))
        self.assertFalse(os.path.exists(f2_path))

    def test_overlap_inside_earlier_complete_fragment(self):
        """Verifies that a file whose start offset falls inside an earlier file's span is discarded."""
        # file 0 spans offset 10000 to 20000
        # file 1 carved by worker 1 starts at offset 15000 (inside file 0)
        f1_path = os.path.join(self.test_dir, "carved_w0_0.bin")
        f2_path = os.path.join(self.test_dir, "carved_w1_0.bin")
        with open(f1_path, "wb") as f:
            f.write(b"full_file")
        with open(f2_path, "wb") as f:
            f.write(b"corrupted_slice")

        files = [
            {
                "file_id": 0,
                "filename": "carved_w0_0.bin",
                "file_hash": "hash_a",
                "status": "complete",
                "fragments": [{"start_offset": 10000, "end_offset": 20000, "size": 10000}],
            },
            {
                "file_id": 1,
                "filename": "carved_w1_0.bin",
                "file_hash": "hash_b",
                "status": "partial",
                "fragments": [{"start_offset": 15000, "end_offset": 20000, "size": 5000}],
            },
        ]

        deduped = deduplicate_boundary_overlaps(files, self.test_dir)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["filename"], "carved_w0_0.bin")
        self.assertFalse(os.path.exists(f2_path))


class TestForensicIntegration(unittest.TestCase):
    """End-to-end carving test with hashing, validation, and checkpointing enabled."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.image_path = os.path.join(self.test_dir, "disk.raw")
        self.output_dir = os.path.join(self.test_dir, "output")
        os.makedirs(self.output_dir, exist_ok=True)

        # construct synthetic image containing a valid JSON file
        cluster_size = 512
        json_content = b'{"forensic_test": "intact", "version": 2}'
        padding = b"\x00" * (cluster_size - len(json_content))

        with open(self.image_path, "wb") as f:
            # cluster 0: zeros
            f.write(b"\x00" * cluster_size)
            # cluster 1: valid JSON
            f.write(json_content + padding)
            # cluster 2: zeros
            f.write(b"\x00" * cluster_size)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_carver_with_forensic_pipeline(self):
        """Carves image and verifies report contains hashes, fragment hashes, and validation."""
        ckpt_mgr = CheckpointManager(os.path.join(self.output_dir, "checkpoint.json"))
        carver = Carver(
            cluster_size=512,
            formats=["json"],
            hasher="sha256",
            validator=True,
            checkpoint_mgr=ckpt_mgr,
        )

        carver.carve(self.image_path, self.output_dir)

        # read worker report
        report_path = os.path.join(self.output_dir, "carve_report_w0.json")
        self.assertTrue(os.path.exists(report_path))

        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        files = report.get("files", [])
        self.assertEqual(len(files), 1)

        file_entry = files[0]
        self.assertEqual(file_entry["format"], "json")
        self.assertEqual(file_entry["status"], "complete")

        # verify cryptographic hashing
        self.assertEqual(file_entry.get("hash_algo"), "sha256")
        self.assertTrue("file_hash" in file_entry and len(file_entry["file_hash"]) == 64)

        # verify fragment hashing
        frags = file_entry.get("fragments", [])
        self.assertEqual(len(frags), 1)
        self.assertTrue("fragment_hash" in frags[0] and len(frags[0]["fragment_hash"]) == 64)

        # verify validation result
        val_result = file_entry.get("validation", {})
        self.assertTrue(val_result.get("is_valid"))
        self.assertIn("JSON syntax and structure valid", val_result.get("details", ""))

        # merge reports and verify manifest creation
        merge_worker_reports(self.output_dir, hash_algo="sha256")

        manifest_sha = os.path.join(self.output_dir, "manifest.sha256")
        manifest_csv = os.path.join(self.output_dir, "manifest.csv")
        self.assertTrue(os.path.exists(manifest_sha))
        self.assertTrue(os.path.exists(manifest_csv))

        with open(manifest_sha, "r", encoding="utf-8") as f:
            sha_content = f.read()
            self.assertIn(file_entry["file_hash"], sha_content)
            self.assertIn(file_entry["filename"], sha_content)

        with open(manifest_csv, "r", encoding="utf-8") as f:
            csv_content = f.read()
            self.assertIn(file_entry["file_hash"], csv_content)
            self.assertIn('"True"', csv_content)


if __name__ == "__main__":
    unittest.main()
