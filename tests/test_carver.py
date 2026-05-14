import os
import tempfile
import unittest
from struct_carver.core.carver import Carver


class TestCarverIntegration(unittest.TestCase):
    def test_non_sequential_gap_jumping(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            cluster1 = b'<?xml version="1.0"?><root><item>A</item>'.ljust(cluster_size, b'\x00')
            cluster2 = b'stray text data </div> random noise'.ljust(cluster_size, b'\x00')
            cluster3 = b'<item>B</item></root>'.ljust(cluster_size, b'\x00')

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)
                f.write(cluster3)

            carver = Carver(cluster_size=cluster_size, formats=['xml'])
            carver.carve(img_path, out_dir)

            carved_files = os.listdir(out_dir)
            self.assertEqual(len(carved_files), 1, "Carver should have recovered exactly one file.")

            with open(os.path.join(out_dir, carved_files[0]), 'rb') as f:
                data = f.read()

            self.assertIn(b'<item>B</item>', data, "The second part of the file was not recovered.")
            self.assertNotIn(b'stray text data', data, "The gap-jumping failed; noise was included.")

    def test_nested_state_retention_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_json.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            # Stack expects: {, {, [
            cluster1 = b'{"root": {"child": ["item1", '.ljust(cluster_size, b' ')
            # Corrupt cluster: introduces mismatched brackets/braces
            cluster2 = b' "stray text", } ] random noise'.ljust(cluster_size, b' ')
            # Valid continuation: properly closes [, }, }
            cluster3 = b'"item2"]}}'.ljust(cluster_size, b' ')

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)
                f.write(cluster3)

            carver = Carver(cluster_size=cluster_size, formats=['json'])
            carver.carve(img_path, out_dir)

            carved_files = os.listdir(out_dir)
            self.assertEqual(len(carved_files), 1, "Carver should have recovered exactly one JSON file.")

            with open(os.path.join(out_dir, carved_files[0]), 'rb') as f:
                data = f.read()

            self.assertIn(b'"item1","item2"', data.replace(b' ', b''), "State was lost during gap jump.")
            self.assertNotIn(b'stray text', data, "Gap jumping failed to exclude corrupt cluster.")

    def test_binary_state_retention_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_pdf.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            # 48 bytes before stream data. Stream Length is 20.
            pre = b"%pdf-1.4\n1 0 obj << /Length 20 >> endobj stream\n"
            # cluster 1 gives 16 bytes of the stream, leaving 4 bytes remaining for the next chunk
            cluster1 = pre + (b'A' * 16)

            # cluster 2 is corrupt. It supplies the last 4 bytes of the stream,
            # but fails the 'endstream' validation immediately after.
            cluster2 = (b'B' * 64)

            # cluster 3 is a valid continuation. Supplies last 4 bytes of stream, then endstream.
            cluster3 = b'CCCC\nendstream\n%%eof'.ljust(64, b'\x00')

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)
                f.write(cluster3)

            carver = Carver(cluster_size=cluster_size, formats=['pdf'])
            carver.carve(img_path, out_dir)

            carved_files = os.listdir(out_dir)
            self.assertEqual(len(carved_files), 1, "Carver should have recovered exactly one PDF file.")

            with open(os.path.join(out_dir, carved_files[0]), 'rb') as f:
                data = f.read()

            # Stream should cleanly concatenate the 16 'A's and 4 'C's.
            self.assertIn(b'A'*16 + b'CCCC\nendstream', data, "Binary stream state was lost during gap jump.")
            self.assertNotIn(b'B'*64, data, "Gap jumping failed to exclude corrupt binary cluster.")
