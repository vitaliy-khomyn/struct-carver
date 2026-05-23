import os
import json
import tempfile
import unittest
import concurrent.futures
from struct_carver.core.carver import Carver
from struct_carver.formats.dynamic_binary_parser import DynamicBinaryParser


def _run_carve_worker(args):
    img_path, out_dir, cluster_size, formats, start_offset, end_offset, worker_id = args
    carver = Carver(cluster_size=cluster_size, formats=formats)
    carver.carve(img_path, out_dir, start_offset=start_offset, end_offset=end_offset, worker_id=worker_id)


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

            carved_files = [f for f in os.listdir(out_dir) if not f.startswith("carve_report") and not f.endswith(".log")]
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

            carved_files = [f for f in os.listdir(out_dir) if not f.startswith("carve_report") and not f.endswith(".log")]
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

            carved_files = [f for f in os.listdir(out_dir) if not f.startswith("carve_report") and not f.endswith(".log")]
            self.assertEqual(len(carved_files), 1, "Carver should have recovered exactly one PDF file.")

            with open(os.path.join(out_dir, carved_files[0]), 'rb') as f:
                data = f.read()

            # Stream should cleanly concatenate the 16 'A's and 4 'C's.
            self.assertIn(b'A'*16 + b'CCCC\nendstream', data, "Binary stream state was lost during gap jump.")
            self.assertNotIn(b'B'*64, data, "Gap jumping failed to exclude corrupt binary cluster.")

    def test_carve_report_generation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_report.dd")
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

            report_path = os.path.join(out_dir, "carve_report_w0.json")
            self.assertTrue(os.path.exists(report_path), "Carve report JSON was not generated.")

            with open(report_path, 'r') as f:
                report = json.load(f)

            self.assertIn("files", report)
            self.assertEqual(len(report["files"]), 1, "Report should contain exactly one recovered file.")

            file_record = report["files"][0]
            self.assertEqual(file_record["status"], "complete", "File status should be logged as complete.")
            self.assertEqual(file_record["fragments"][0]["start_offset"], 0, "First fragment should start at offset 0.")
            self.assertEqual(file_record["fragments"][1]["start_offset"], 128, "Second fragment should start at offset 128 after gap-jumping.")

    def test_multithreaded_carving(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_multithread.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            # Worker 0 (offset 0 - 128)
            cluster1 = b'<?xml version="1.0"?><root><item>W0</item>'.ljust(cluster_size, b'\x00')
            cluster2 = b'<item>W0_END</item></root>'.ljust(cluster_size, b'\x00')

            # Worker 1 (offset 128 - 256)
            cluster3 = b'{"worker1": ["part1", '.ljust(cluster_size, b' ')
            cluster4 = b'"part2"]}'.ljust(cluster_size, b' ')

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)
                f.write(cluster3)
                f.write(cluster4)

            worker_args = [
                (img_path, out_dir, cluster_size, ['xml', 'json'], 0, 128, 0),
                (img_path, out_dir, cluster_size, ['xml', 'json'], 128, 256, 1)
            ]

            with concurrent.futures.ProcessPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(_run_carve_worker, arg) for arg in worker_args]
                for future in concurrent.futures.as_completed(futures):
                    future.result()

            carved_files = [f for f in os.listdir(out_dir) if not f.startswith("carve_report") and not f.endswith(".log")]
            self.assertEqual(len(carved_files), 2, "Should have recovered exactly two files concurrently.")

            # Verify files were generated by distinct workers
            self.assertTrue(any("w0" in f and f.endswith(".xml") for f in carved_files), "Worker 0 XML missing")
            self.assertTrue(any("w1" in f and f.endswith(".json") for f in carved_files), "Worker 1 JSON missing")

            # Verify reports were generated separately per worker
            report_files = [f for f in os.listdir(out_dir) if f.startswith("carve_report")]
            self.assertEqual(len(report_files), 2, "Should have generated two distinct worker reports.")
            self.assertIn("carve_report_w0.json", report_files)
            self.assertIn("carve_report_w1.json", report_files)

    def test_custom_dynamic_binary_carving(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_custom.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            # mock a custom linear image format (e.g., PNG-like signature)
            header = b'\x89PNG\r\n'
            footer = b'IEND\xaeB`\x82'

            cluster1 = header + (b'A' * (cluster_size - len(header)))
            cluster2 = (b'B' * 20) + footer + (b'\x00' * (cluster_size - len(footer) - 20))

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)

            custom_parser = DynamicBinaryParser('png', header, footer)
            carver = Carver(cluster_size=cluster_size, formats=[], custom_parsers=[custom_parser])
            carver.carve(img_path, out_dir)

            carved_files = [f for f in os.listdir(out_dir) if not f.startswith("carve_report") and not f.endswith(".log")]
            self.assertEqual(len(carved_files), 1, "Carver should have recovered exactly one custom file.")
            self.assertTrue(carved_files[0].endswith(".png"), "Carved file should use the custom extension.")

            with open(os.path.join(out_dir, carved_files[0]), 'rb') as f:
                data = f.read()

            self.assertTrue(data.startswith(header), "Carved file should start with the custom header.")
            self.assertTrue(data.endswith(footer), "Carved file should end with the custom footer.")
            self.assertEqual(len(data), cluster_size + 20 + len(footer), "File should be accurately trimmed after the footer.")

    def test_cluster_cache_population(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_cache.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            cluster1 = b'<?xml version="1.0"?><root><item>A</item>'.ljust(cluster_size, b'\x00')
            # corrupt block to trigger gap-jump and populate cache
            cluster2 = b'stray text data </div> random noise'.ljust(cluster_size, b'\x00')
            cluster3 = b'<item>B</item></root>'.ljust(cluster_size, b'\x00')

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)
                f.write(cluster3)

            carver = Carver(cluster_size=cluster_size, formats=['xml'])
            carver.carve(img_path, out_dir)

            # verify cache was populated during the gap jump over cluster 2
            self.assertGreater(len(carver.cluster_cache), 0, "Cluster cache should be populated after a gap jump.")

    def test_garbage_prefix_slicing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "evidence_garbage.dd")
            out_dir = os.path.join(temp_dir, "recovered_files")

            cluster_size = 64
            # Signature starts at offset 20
            cluster1 = b'random garbage bytes' + b'<?xml version="1.0"?><root><item>A</item>'
            cluster1 = cluster1[:cluster_size].ljust(cluster_size, b'\x00')
            cluster2 = b'<item>B</item></root>'.ljust(cluster_size, b'\x00')

            with open(img_path, 'wb') as f:
                f.write(cluster1)
                f.write(cluster2)

            carver = Carver(cluster_size=cluster_size, formats=['xml'])
            carver.carve(img_path, out_dir)

            carved_files = [f for f in os.listdir(out_dir) if not f.startswith("carve_report") and not f.endswith(".log")]
            self.assertEqual(len(carved_files), 1, "Carver should have recovered exactly one file.")

            with open(os.path.join(out_dir, carved_files[0]), 'rb') as f:
                data = f.read()

            self.assertTrue(data.startswith(b'<?xml'), "Recovered file should start exactly with the XML header, not garbage prefix.")
