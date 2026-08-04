"""Unit tests for the forensic dashboard generation.

Verifies HTML dashboard compilation from carve_report.json, metric card rendering,
and fragment map layout.
"""

import os
import json
import tempfile
import unittest
from struct_carver.dashboard import generate_dashboard


class TestDashboard(unittest.TestCase):
    """Test suite verifying interactive HTML dashboard generation."""

    def test_generate_dashboard(self):
        """Verifies HTML dashboard generation, filename rendering, and recovery metrics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = os.path.join(temp_dir, "carve_report.json")
            html_path = os.path.join(temp_dir, "dashboard.html")

            mock_report = {
                "hash_algo": "sha256",
                "source_image": {
                    "image_path": "/path/to/test.dd",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                },
                "files": [
                    {
                        "file_id": 0,
                        "filename": "carved_w0_0.xml",
                        "format": "xml",
                        "status": "complete",
                        "total_size": 1024,
                        "file_hash": "a" * 64,
                        "hash_algo": "sha256",
                        "fragments": [{"start_offset": 0, "end_offset": 1024, "size": 1024}],
                        "metadata": {
                            "creator": "tester",
                            "lastmodifiedby": "tester",
                            "created": "2012-07-05T17:27:56Z",
                            "revision": "4",
                        },
                    }
                ]
            }
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(mock_report, f)

            generate_dashboard(json_path, html_path)
            self.assertTrue(os.path.exists(html_path), "Dashboard HTML file was not generated.")

            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
                self.assertIn("carved_w0_0.xml", html_content)
                self.assertIn("Complete Recoveries", html_content)
                # verify chain of custody box
                self.assertIn("Forensic Chain of Custody &amp; Image Integrity", html_content.replace("&", "&amp;"))
                self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", html_content)
                # verify full hash is present without ellipsis
                self.assertIn("a" * 64, html_content)
                self.assertNotIn("a" * 16 + "...", html_content)
                self.assertIn("hash-scrollable", html_content)
                # verify algorithm in header and tag
                self.assertIn("Forensic Hash (SHA256)", html_content)
                self.assertIn("<span class=\"algo-tag\">SHA256</span>", html_content)
                # verify metadata dropdown
                self.assertIn("meta-dropdown", html_content)
                self.assertIn("+1 more", html_content)


if __name__ == '__main__':
    unittest.main()
