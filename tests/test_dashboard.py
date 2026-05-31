"""Unit tests for the DASHBOARD component."""
import os
import json
import tempfile
import unittest
from struct_carver.dashboard import generate_dashboard


class TestDashboard(unittest.TestCase):
    """Test suite for Dashboard parsing and carving."""
    def test_generate_dashboard(self):
        """Tests that generate dashboard."""
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = os.path.join(temp_dir, "carve_report.json")
            html_path = os.path.join(temp_dir, "dashboard.html")

            mock_report = {
                "files": [
                    {
                        "file_id": 0,
                        "filename": "carved_w0_0.xml",
                        "format": "xml",
                        "status": "complete",
                        "total_size": 1024,
                        "fragments": [{"start_offset": 0, "end_offset": 1024, "size": 1024}]
                    }
                ]
            }
            with open(json_path, 'w') as f:
                json.dump(mock_report, f)

            generate_dashboard(json_path, html_path)
            self.assertTrue(os.path.exists(html_path), "Dashboard HTML file was not generated.")

            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
                self.assertIn("carved_w0_0.xml", html_content)
                self.assertIn("Complete Recoveries", html_content)
