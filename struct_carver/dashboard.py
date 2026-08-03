"""Forensic dashboard generator.

This module generates an interactive HTML dashboard summarizing the carved
files, their reconstruction status (complete, partial, incomplete), and a
visual representation of the file fragment distribution on disk.
"""

import os
import json
import argparse
from struct_carver.logger import setup_logger


def generate_dashboard(json_path: str, output_html: str):
    """Generates an interactive HTML dashboard from a carve report JSON file.

    Args:
        json_path (str): Path to the input carve_report.json.
        output_html (str): Path where the HTML dashboard file should be written.
    """
    logger = setup_logger("Dashboard")

    if not os.path.exists(json_path):
        logger.error(f"JSON report '{json_path}' not found.")
        return

    with open(json_path, 'r') as f:
        try:
            report = json.load(f)
        except json.JSONDecodeError:
            logger.error("Invalid JSON file.")
            return

    files = report.get("files", [])

    source_img = report.get("source_image", {})
    img_chain_card = ""
    if source_img:
        img_sha256 = source_img.get("sha256", "N/A")
        img_md5 = source_img.get("md5", "N/A")
        img_path = source_img.get("image_path", "N/A")
        img_chain_card = f"""
        <div class="chain-box">
            <h4>Forensic Chain of Custody & Image Integrity</h4>
            <div class="chain-grid">
                <div><strong>Source Image:</strong> <code>{img_path}</code></div>
                <div><strong>SHA-256:</strong> <code class="hash-code">{img_sha256}</code></div>
                <div><strong>MD5:</strong> <code class="hash-code">{img_md5}</code></div>
            </div>
        </div>
        """

    total_files = len(files)
    complete_files = sum(1 for f in files if f.get("status") == "complete")
    partial_files = sum(1 for f in files if f.get("status") == "partial")
    incomplete_files = sum(1 for f in files if f.get("status") == "incomplete_eof")
    valid_files = sum(1 for f in files if f.get("validation", {}).get("is_valid") is True)
    corrupt_files = sum(1 for f in files if f.get("validation", {}).get("is_valid") is False)

    rows_html = ""
    for f in files:
        file_id = f.get("file_id", "N/A")
        filename = f.get("filename", "N/A")
        file_format = f.get("format", "N/A")
        status = f.get("status", "unknown")
        total_size = f.get("total_size", 0)
        fragments = f.get("fragments", [])
        start_lba = f.get("start_lba", fragments[0]["start_offset"] // 512 if fragments else 0)
        slack_bytes = f.get("slack_bytes", 0)
        entropy = f.get("entropy")
        metadata = f.get("metadata", {})

        if entropy is not None:
            if entropy < 4.0:
                entropy_badge = f"<span class='entropy-badge ent-low' title='Low entropy (plain text / zeros)'>{entropy:.2f}</span>"
            elif entropy < 7.2:
                entropy_badge = f"<span class='entropy-badge ent-mid' title='Moderate entropy (structured data)'>{entropy:.2f}</span>"
            else:
                entropy_badge = f"<span class='entropy-badge ent-high' title='High entropy (compressed/encrypted)'>{entropy:.2f}</span>"
        else:
            entropy_badge = "<span class='text-muted'>-</span>"

        if metadata:
            meta_items = [f"<strong>{k}:</strong> {v}" for k, v in metadata.items()]
            meta_display = "<br>".join(meta_items[:3])
            if len(meta_items) > 3:
                meta_display += f"<br><small>+{len(meta_items) - 3} more</small>"
        else:
            meta_display = "<span class='text-muted'>None</span>"

        val_info = f.get("validation", {})
        is_valid = val_info.get("is_valid")
        val_details = val_info.get("details", "")
        if is_valid is True:
            val_badge = f"<span class='val-badge val-valid' title='{val_details}'>VERIFIED</span>"
            val_class = "val-is-valid"
        elif is_valid is False:
            val_badge = f"<span class='val-badge val-corrupt' title='{val_details}'>CORRUPTED</span>"
            val_class = "val-is-corrupt"
        else:
            val_badge = "<span class='val-badge val-na'>N/A</span>"
            val_class = "val-is-na"

        file_hash = f.get("file_hash", "")
        hash_algo = f.get("hash_algo", "sha256").upper()
        if file_hash:
            hash_display = f"<code class='hash-code' title='{file_hash}'>{file_hash[:16]}...</code> <span class='algo-tag'>{hash_algo}</span>"
        else:
            hash_display = "<span class='text-muted'>-</span>"

        # build fragment details text
        frag_text = "<br>".join([
            f"Start: <code>{frag['start_offset']}</code> | End: <code>{frag['end_offset']}</code> | Size: {frag['size']} B"
            for frag in fragments
        ])

        # build a visual map representation (tracks and segments)
        visual_map = ""
        if fragments:
            span_start = fragments[0]["start_offset"]
            span_end = fragments[-1]["end_offset"]
            total_span = span_end - span_start
            
            map_blocks = ""
            for idx, frag in enumerate(fragments):
                if total_span > 0:
                    left_pct = ((frag["start_offset"] - span_start) / total_span) * 100
                    width_pct = (frag["size"] / total_span) * 100
                else:
                    left_pct = 0
                    width_pct = 100
                
                # cap minimum width at 2% for visual clarity
                width_pct = max(2.0, width_pct)
                
                color_class = "segment-normal"
                if idx == len(fragments) - 1:
                    if status == "partial":
                        color_class = "segment-partial"
                    elif status == "incomplete_eof":
                        color_class = "segment-incomplete"
                
                map_blocks += f"<div class='frag-segment {color_class}' style='left: {left_pct}%; width: {width_pct}%;' title='Offset: {frag['start_offset']} - Size: {frag['size']} B'></div>"
            
            visual_map = f"<div class='frag-track'>{map_blocks}</div>"
        else:
            visual_map = "<span class='text-muted'>No fragments</span>"

        rows_html += f"""
        <tr class="status-{status} {val_class}">
            <td>{file_id}</td>
            <td>{filename}</td>
            <td><span class="format-badge">{file_format.upper()}</span></td>
            <td><span class="status-badge status-{status}">{status.capitalize()}</span></td>
            <td><code>LBA #{start_lba}</code></td>
            <td>{total_size:,} B <br><small class="text-muted">Slack: {slack_bytes} B</small></td>
            <td>{entropy_badge}</td>
            <td>{val_badge}</td>
            <td>{hash_display}</td>
            <td><small>{meta_display}</small></td>
            <td>
                <details>
                    <summary>{len(fragments)} Frag(s)</summary>
                    <div class="frag-details">{frag_text}</div>
                </details>
            </td>
            <td class="map-cell">
                {visual_map}
            </td>
        </tr>
        """

    # load external HTML template
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f_tpl:
            template_str = f_tpl.read()
    else:
        logger.error(f"HTML dashboard template not found at '{template_path}'.")
        return

    # substitute template variables
    rendered_html = (
        template_str
        .replace("{{img_chain_card}}", img_chain_card)
        .replace("{{total_files}}", str(total_files))
        .replace("{{complete_files}}", str(complete_files))
        .replace("{{partial_files}}", str(partial_files))
        .replace("{{incomplete_files}}", str(incomplete_files))
        .replace("{{valid_files}}", str(valid_files))
        .replace("{{corrupt_files}}", str(corrupt_files))
        .replace("{{rows_html}}", rows_html)
    )

    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(rendered_html)

    logger.info(f"Dashboard successfully generated at: {output_html}")


def main():
    """CLI entrypoint to generate the HTML dashboard from an existing JSON report."""
    parser = argparse.ArgumentParser(description="Generate an interactive HTML dashboard from a carve report JSON file.")
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
