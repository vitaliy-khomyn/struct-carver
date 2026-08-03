"""Post-processor module.

This module provides the PostProcessor class, which executes post-carving hooks,
detecting sub-types (e.g. Microsoft Office documents inside ZIP containers) and
handling archive extraction.
"""

import os
import zipfile
from typing import Tuple, Any


class PostProcessor:
    """Handles format-specific post-processing after a file is carved to disk."""

    def post_process(self, file_path: str, ext: str, output_dir: str, filename: str, logger: Any) -> Tuple[str, str]:
        """Executes format-specific post-processing routines on carved output files.

        Args:
            file_path (str): Full path to the carved file on disk.
            ext (str): Original format extension string.
            output_dir (str): Output folder path.
            filename (str): Carved output filename.
            logger (Any): Active worker logger instance.

        Returns:
            Tuple[str, str]: Final detected extension and final filename.
        """
        if ext == "zip":
            detected_ext = "zip"
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    namelist = zf.namelist()
                    if "word/document.xml" in namelist:
                        detected_ext = "docx"
                    elif "xl/workbook.xml" in namelist:
                        detected_ext = "xlsx"
                    elif "ppt/presentation.xml" in namelist:
                        detected_ext = "pptx"
            except (zipfile.BadZipFile, OSError, KeyError) as e:
                logger.error(f"Failed to read ZIP structure for Office detection: {e}")
                return ext, filename

            if detected_ext != "zip":
                new_filename = filename.rsplit('.', 1)[0] + f".{detected_ext}"
                new_path = os.path.join(output_dir, new_filename)
                try:
                    if os.path.exists(file_path):
                        os.rename(file_path, new_path)
                    logger.info(f"Detected Office document. Renamed {filename} to {new_filename}")
                    return detected_ext, new_filename
                except OSError as e:
                    logger.error(f"Failed to rename Office document: {e}")
            else:
                zip_out_dir = f"{file_path}_extracted"
                try:
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        zf.extractall(zip_out_dir)
                    logger.info(f"Extracted ZIP contents to {zip_out_dir}")
                except (zipfile.BadZipFile, OSError, RuntimeError) as e:
                    logger.error(f"Recovered ZIP extraction failed: {e}")
        return ext, filename
