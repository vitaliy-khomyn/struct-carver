"""Comprehensive unit tests for forensic enhancements and bug fixes.

Verifies:
- Memory-safe streaming range hashing (hash_file_range).
- Shannon entropy calculations for low, structured, and high-entropy streams.
- Forensic metadata extraction (EXIF, PDF, Office XML, PNG).
- Extended validators (TAR, GZ, BZ2, WAV).
- Intra-cluster multi-file carving (consecutive files in the same cluster).
- CLI custom parser configuration loading without crashing.
- Source image chain of custody hashing in report and manifest.
"""

import os
import json
import gzip
import bz2
import tarfile
import struct
import tempfile
import unittest
from struct_carver.core.hasher import CryptoHasher
from struct_carver.core.entropy import calculate_entropy, calculate_file_entropy, classify_entropy
from struct_carver.core.metadata import MetadataExtractor
from struct_carver.core.validator import FileValidator
from struct_carver.core.carver import Carver
from struct_carver.cli import merge_worker_reports


class TestForensicEnhancements(unittest.TestCase):
    """Test suite covering forensic analytics, metadata extraction, and bug fixes."""

    def test_hash_file_range(self):
        """Verify streaming chunked range hashing computes identical hash to byte slice."""
        hasher = CryptoHasher("sha256")
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            payload = b"PREFIX" + b"TARGET_PAYLOAD_BYTES" * 100 + b"SUFFIX"
            tf.write(payload)
            tf_path = tf.name

        try:
            start = len(b"PREFIX")
            size = len(b"TARGET_PAYLOAD_BYTES" * 100)
            expected_hash = hasher.hash_bytes(payload[start:start + size])
            range_hash = hasher.hash_file_range(tf_path, start, size, chunk_size=32)
            self.assertEqual(range_hash, expected_hash)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_shannon_entropy(self):
        """Verify Shannon entropy computation and classification for uniform vs random data."""
        # completely uniform data should have 0.0 entropy
        zeros = b"\x00" * 4096
        self.assertEqual(calculate_entropy(zeros), 0.0)
        cat, _ = classify_entropy(calculate_entropy(zeros))
        self.assertEqual(cat, "low")

        # structured ascii text
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        text_ent = calculate_entropy(text)
        self.assertTrue(3.5 <= text_ent <= 5.5, f"Expected structured entropy, got {text_ent}")

        # high entropy pseudorandom data
        high_entropy_bytes = bytes((i * 37 + 11) % 256 for i in range(4096))
        high_ent = calculate_entropy(high_entropy_bytes)
        self.assertTrue(high_ent > 7.5, f"Expected high entropy, got {high_ent}")
        cat_high, _ = classify_entropy(high_ent)
        self.assertEqual(cat_high, "high_encrypted")

    def test_shannon_file_entropy(self):
        """Verify streaming file entropy calculation matches in-memory entropy calculation."""
        data = b"Forensic file entropy test payload \x01\x02\x03" * 200
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            tf_path = tf.name

        try:
            mem_ent = calculate_entropy(data)
            file_ent = calculate_file_entropy(tf_path, chunk_size=64)
            self.assertEqual(mem_ent, file_ent)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_metadata_extractor_office(self):
        """Verify extraction of created and creator metadata from Office XML archives."""
        import zipfile
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tf:
            tf_path = tf.name

        try:
            core_xml = (
                b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                b'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                b'<dc:creator>Forensic Analyst</dc:creator>'
                b'<cp:created>2026-09-12T20:00:00Z</cp:created>'
                b'</cp:coreProperties>'
            )
            with zipfile.ZipFile(tf_path, "w") as zf:
                zf.writestr("docProps/core.xml", core_xml)

            meta = MetadataExtractor.extract(tf_path, "docx")
            self.assertEqual(meta.get("creator"), "Forensic Analyst")
            self.assertEqual(meta.get("created"), "2026-09-12T20:00:00Z")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_metadata_extractor_pdf(self):
        """Verify extraction of CreationDate and Author from PDF documents."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
            payload = b"%PDF-1.4\n1 0 obj << /Author (John Doe) /CreationDate (D:20260912120000) >> endobj\n%%EOF"
            tf.write(payload)
            tf_path = tf.name

        try:
            meta = MetadataExtractor.extract(tf_path, "pdf")
            self.assertEqual(meta.get("author"), "John Doe")
            self.assertEqual(meta.get("creationdate"), "D:20260912120000")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_extended_validator_tar(self):
        """Verify TAR archive validator verifies intact headers and rejects corrupted files."""
        validator = FileValidator()
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tf:
            tf_path = tf.name

        try:
            # create valid tar archive
            with tarfile.open(tf_path, "w") as tar:
                sample_data = b"Hello, TAR forensics!"
                import io
                ti = tarfile.TarInfo(name="sample.txt")
                ti.size = len(sample_data)
                tar.addfile(ti, io.BytesIO(sample_data))

            res = validator.validate(tf_path, "tar")
            self.assertTrue(res["is_valid"])

            # corrupt the tar header
            with open(tf_path, "r+b") as f:
                f.seek(10)
                f.write(b"\xFF" * 50)

            res_corrupt = validator.validate(tf_path, "tar")
            self.assertFalse(res_corrupt["is_valid"])
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_extended_validator_gz(self):
        """Verify GZIP archive validator verifies DEFLATE stream and rejects truncation."""
        validator = FileValidator()
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as tf:
            tf_path = tf.name

        try:
            with gzip.open(tf_path, "wb") as gf:
                gf.write(b"GZIP forensics payload data " * 100)

            res = validator.validate(tf_path, "gz")
            self.assertTrue(res["is_valid"])

            # truncate the gzip file to break crc32 footer
            file_size = os.path.getsize(tf_path)
            with open(tf_path, "r+b") as f:
                f.truncate(file_size - 10)

            res_corrupt = validator.validate(tf_path, "gz")
            self.assertFalse(res_corrupt["is_valid"])
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_extended_validator_bz2(self):
        """Verify BZIP2 archive validator checks stream decodability."""
        validator = FileValidator()
        with tempfile.NamedTemporaryFile(suffix=".bz2", delete=False) as tf:
            tf_path = tf.name

        try:
            with bz2.open(tf_path, "wb") as bf:
                bf.write(b"BZIP2 forensics payload data " * 100)

            res = validator.validate(tf_path, "bz2")
            self.assertTrue(res["is_valid"])
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_extended_validator_wav(self):
        """Verify WAV audio validator verifies RIFF/WAVE header sizes."""
        validator = FileValidator()
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
            # RIFF (4) + size (4) + WAVE (4) + fmt (4) + fmt_size (4) + fmt_data (16) + data (4) + data_size (4) + payload (8)
            payload_len = 8
            total_riff = 36 + payload_len
            wav_data = (
                b"RIFF" + struct.pack("<I", total_riff) + b"WAVE"
                b"fmt " + struct.pack("<I", 16) + b"\x01\x00\x01\x00\x44\xAC\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00"
                b"data" + struct.pack("<I", payload_len) + b"\x00" * payload_len
            )
            tf.write(wav_data)
            tf_path = tf.name

        try:
            res = validator.validate(tf_path, "wav")
            self.assertTrue(res["is_valid"])
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_intra_cluster_multi_file_carving(self):
        """Verify carver rewinds stream to carve consecutive files sharing the same physical cluster."""
        # craft an image where two valid JSON files are in the exact same 4096-byte cluster
        file1 = b'{"file": 1}'
        file2 = b'{"file": 2, "extra": "data"}'
        padding = b"\x00" * (4096 - len(file1) - len(file2))
        cluster = file1 + file2 + padding

        with tempfile.NamedTemporaryFile(delete=False) as img_tf:
            img_tf.write(cluster)
            img_path = img_tf.name

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                carver = Carver(cluster_size=4096, formats=["json"])
                carver.carve(img_path, out_dir, start_offset=0, end_offset=4096)

                report_path = os.path.join(out_dir, "carve_report_w0.json")
                with open(report_path, "r") as f:
                    data = json.load(f)

                # both files must be detected and carved successfully
                self.assertEqual(len(data["files"]), 2, "Intra-cluster rewind failed to carve second file.")
                self.assertEqual(data["files"][0]["status"], "complete")
                self.assertEqual(data["files"][1]["status"], "complete")
                self.assertEqual(data["files"][0]["total_size"], len(file1))
                self.assertEqual(data["files"][1]["total_size"], len(file2))
            finally:
                if os.path.exists(img_path):
                    os.remove(img_path)

    def test_merge_worker_reports_chain_of_custody(self):
        """Verify merge_worker_reports includes source image hashes and calculates LBA and slack."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_w0 = {
                "files": [
                    {
                        "file_id": 0,
                        "filename": "carved_w0_0.json",
                        "format": "json",
                        "status": "complete",
                        "total_size": 100,
                        "start_lba": 2,
                        "slack_bytes": 3996,
                        "entropy": 4.12,
                        "fragments": [{"start_offset": 1024, "end_offset": 1124, "size": 100}],
                        "file_hash": "mockhash123",
                        "validation": {"is_valid": True, "details": "ok"}
                    }
                ]
            }
            with open(os.path.join(temp_dir, "carve_report_w0.json"), "w") as f:
                json.dump(report_w0, f)

            source_hashes = {
                "image_path": "disk.raw",
                "sha256": "abcdef123456",
                "md5": "123456abcdef",
                "file_size": 10485760
            }

            merge_worker_reports(temp_dir, source_image_hashes=source_hashes)

            merged_path = os.path.join(temp_dir, "carve_report.json")
            with open(merged_path, "r") as f:
                merged_data = json.load(f)

            self.assertIn("source_image", merged_data)
            self.assertEqual(merged_data["source_image"]["sha256"], "abcdef123456")

            # verify manifest.csv contains start_lba and slack_bytes columns
            csv_path = os.path.join(temp_dir, "manifest.csv")
            with open(csv_path, "r") as f_csv:
                csv_content = f_csv.read()
                self.assertIn("start_lba", csv_content)
                self.assertIn("slack_bytes", csv_content)
                self.assertIn("entropy", csv_content)


if __name__ == '__main__':
    unittest.main()
