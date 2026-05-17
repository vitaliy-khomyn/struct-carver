import os
import json
import argparse


def generate_dashboard(json_path: str, output_html: str):
    if not os.path.exists(json_path):
        print(f"[!] Error: JSON report '{json_path}' not found.")
        return

    with open(json_path, 'r') as f:
        try:
            report = json.load(f)
        except json.JSONDecodeError:
            print("[!] Error: Invalid JSON file.")
            return

    files = report.get("files", [])

    total_files = len(files)
    complete_files = sum(1 for f in files if f.get("status") == "complete")
    partial_files = sum(1 for f in files if f.get("status") == "partial")
    incomplete_files = sum(1 for f in files if f.get("status") == "incomplete_eof")

    rows_html = ""
    for f in files:
        file_id = f.get("file_id", "N/A")
        filename = f.get("filename", "N/A")
        file_format = f.get("format", "N/A")
        status = f.get("status", "unknown")
        total_size = f.get("total_size", 0)
        fragments = f.get("fragments", [])

        # Build fragment details text
        frag_text = "<br>".join([
            f"Start: <code>{frag['start_offset']}</code> | End: <code>{frag['end_offset']}</code> | Size: {frag['size']} B"
            for frag in fragments
        ])

        # Build a visual map representation (blocks)
        map_blocks = ""
        for frag in fragments:
            map_blocks += f"<div class='frag-block' title='Offset: {frag['start_offset']} - Size: {frag['size']}'></div>"

        rows_html += f"""
        <tr class="status-{status}">
            <td>{file_id}</td>
            <td>{filename}</td>
            <td><span class="format-badge">{file_format.upper()}</span></td>
            <td><span class="status-badge status-{status}">{status.capitalize()}</span></td>
            <td>{total_size:,}</td>
            <td>
                <details>
                    <summary>{len(fragments)} Fragment(s)</summary>
                    <div class="frag-details">{frag_text}</div>
                </details>
            </td>
            <td class="map-cell">
                <div class="frag-map">{map_blocks}</div>
            </td>
        </tr>
        """

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StructCarve Forensic Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary-cards {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); flex: 1; text-align: center; }}
        .card h3 {{ margin: 0; font-size: 24px; color: #2c3e50; }}
        .card p {{ margin: 5px 0 0; color: #7f8c8d; text-transform: uppercase; font-size: 12px; font-weight: bold; }}
        .controls {{ margin-bottom: 15px; }}
        button {{ padding: 8px 16px; margin-right: 10px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; transition: background 0.3s; }}
        button:hover {{ opacity: 0.8; }}
        .btn-all {{ background: #95a5a6; color: white; }}
        .btn-complete {{ background: #2ecc71; color: white; }}
        .btn-partial {{ background: #f39c12; color: white; }}
        .btn-incomplete {{ background: #e74c3c; color: white; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        tr:hover {{ background-color: #f1f2f6; }}
        .format-badge {{ background: #3498db; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
        .status-complete {{ background-color: #2ecc71; }}
        .status-partial {{ background-color: #f39c12; }}
        .status-incomplete_eof {{ background-color: #e74c3c; }}
        details {{ cursor: pointer; }}
        .frag-details {{ margin-top: 5px; font-size: 12px; background: #ecf0f1; padding: 8px; border-radius: 4px; }}
        code {{ background: #dfe6e9; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
        .frag-map {{ display: flex; gap: 2px; align-items: center; height: 100%; }}
        .frag-block {{ width: 15px; height: 15px; background: #3498db; border-radius: 2px; cursor: pointer; }}
        .frag-block:hover {{ background: #2980b9; transform: scale(1.2); }}
        .status-partial .frag-block:last-child {{ background: #f39c12; }}
        .status-incomplete_eof .frag-block:last-child {{ background: #e74c3c; }}
    </style>
</head>
<body>

    <h1>StructCarve Forensic Dashboard</h1>
    <div class="summary-cards">
        <div class="card"><h3>{total_files}</h3><p>Total Files Extracted</p></div>
        <div class="card" style="border-bottom: 4px solid #2ecc71;"><h3>{complete_files}</h3><p>Complete Recoveries</p></div>
        <div class="card" style="border-bottom: 4px solid #f39c12;"><h3>{partial_files}</h3><p>Partial Recoveries</p></div>
        <div class="card" style="border-bottom: 4px solid #e74c3c;"><h3>{incomplete_files}</h3><p>Incomplete (EOF)</p></div>
    </div>
    <div class="controls">
        <button class="btn-all" onclick="filterTable('all')">Show All</button>
        <button class="btn-complete" onclick="filterTable('status-complete')">Complete Only</button>
        <button class="btn-partial" onclick="filterTable('status-partial')">Partial Only</button>
        <button class="btn-incomplete" onclick="filterTable('status-incomplete_eof')">Incomplete Only</button>
    </div>

    <table id="reportTable">
        <thead>
            <tr>
                <th>File ID</th>
                <th>Filename</th>
                <th>Format</th>
                <th>Status</th>
                <th>Size (Bytes)</th>
                <th>Fragments Map</th>
                <th>Visual Blocks</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <script>
        function filterTable(statusClass) {{
            const rows = document.querySelectorAll('#reportTable tbody tr');
            rows.forEach(row => {{
                if (statusClass === 'all') {{
                    row.style.display = '';
                }} else {{
                    if (row.classList.contains(statusClass)) {{
                        row.style.display = '';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_template)

    print(f"[*] Dashboard successfully generated at: {output_html}")


def main():
    parser = argparse.ArgumentParser(description="Generate an interactive HTML dashboard from a StructCarve JSON report.")
    parser.add_argument(
        '-i', '--input',
        required=True,
        help="Path to the carve_report.json file"
    )
    parser.add_argument(
        '-o', '--output',
        default="dashboard.html",
        help="Path for the output HTML file (default: dashboard.html)"
    )

    args = parser.parse_args()
    generate_dashboard(args.input, args.output)


if __name__ == "__main__":
    main()
