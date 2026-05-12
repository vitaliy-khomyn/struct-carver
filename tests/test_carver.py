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
