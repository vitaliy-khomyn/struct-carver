"""Unit tests for the CLI component."""
import os
import json
import tempfile
import unittest
from struct_carver.cli import merge_worker_reports


class TestCLI(unittest.TestCase):
    """Test suite for CLI parsing and carving."""
    def test_merge_worker_reports(self):
        """Tests that merge worker reports."""
        with tempfile.TemporaryDirectory() as temp_dir:
            report_w0 = {
                "files": [
                    {
                        "file_id": 0,
                        "filename": "carved_w0_0.xml",
                        "fragments": [{"start_offset": 500, "end_offset": 600, "size": 100}]
                    }
                ]
            }
            report_w1 = {
                "files": [
                    {
                        "file_id": 0,
                        "filename": "carved_w1_0.json",
                        "fragments": [{"start_offset": 100, "end_offset": 200, "size": 100}]
                    }
                ]
            }
            report_w2 = {
                "files": [
                    {
                        "file_id": 0,
                        "filename": "carved_w2_0.pdf",
                        "fragments": []  # empty fragments test edge case sorting
                    }
                ]
            }

            for i, report in enumerate([report_w0, report_w1, report_w2]):
                with open(os.path.join(temp_dir, f"carve_report_w{i}.json"), "w") as f:
                    json.dump(report, f)

            merge_worker_reports(temp_dir)

            merged_path = os.path.join(temp_dir, "carve_report.json")
            self.assertTrue(os.path.exists(merged_path), "Merged report was not created.")
            for i in range(3):
                self.assertFalse(os.path.exists(os.path.join(temp_dir, f"carve_report_w{i}.json")), f"Worker {i} report was not deleted.")

            with open(merged_path, "r") as f:
                merged_data = json.load(f)

            self.assertEqual(len(merged_data["files"]), 3, "Merged report should contain all three files.")

            # check if it was sorted correctly by the first fragment's start_offset (0, 100, 500)
            self.assertEqual(merged_data["files"][0]["filename"], "carved_w2_0.pdf")
            self.assertEqual(merged_data["files"][1]["filename"], "carved_w1_0.json")
            self.assertEqual(merged_data["files"][2]["filename"], "carved_w0_0.xml")
