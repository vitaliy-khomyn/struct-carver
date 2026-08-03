"""Post-processor module.

This module provides the PostProcessor class, which executes post-carving hooks,
detecting sub-types (e.g. Microsoft Office documents inside ZIP containers) and
handling archive extraction.
"""

import os
import zipfile
import shutil
from typing import Tuple, Any


class PostProcessor:
    """Handles format-specific post-processing after a file is carved to disk."""

    def __init__(
        self,
        extract_archives: bool = False,
        max_extract_size: int = 250 * 1024 * 1024,
        max_extract_files: int = 10000,
    ):
        """Initializes the post processor with archive extraction safety limits.

        Args:
            extract_archives (bool, optional): Whether to extract carved archives (default: False).
            max_extract_size (int, optional): Max cumulative uncompressed extraction size (default: 250MB).
            max_extract_files (int, optional): Max number of extracted files per archive (default: 10000).
        """
        self.extract_archives = extract_archives
        self.max_extract_size = max_extract_size
        self.max_extract_files = max_extract_files

    def _safe_extract_zip(self, zf: zipfile.ZipFile, target_dir: str, logger: Any) -> bool:
        """Safely extracts a ZIP archive guarding against path traversal and decompression bombs.

        Args:
            zf (zipfile.ZipFile): Open ZIP archive.
            target_dir (str): Target extraction directory.
            logger (Any): Logger instance.

        Returns:
            bool: True if extraction completed safely, False if aborted due to security bounds.
        """
        target_dir_abs = os.path.abspath(target_dir)
        total_extracted_size = 0
        extracted_file_count = 0

        for member in zf.infolist():
            # sanitize target path against Zip Slip traversal
            dest_path = os.path.abspath(os.path.join(target_dir_abs, member.filename))
            try:
                if os.path.commonpath([target_dir_abs, dest_path]) != target_dir_abs:
                    logger.warning(f"Blocked Zip Slip path traversal attempt: {member.filename}")
                    continue
            except ValueError:
                logger.warning(f"Invalid cross-drive path in archive: {member.filename}")
                continue

            extracted_file_count += 1
            if extracted_file_count > self.max_extract_files:
                logger.warning(f"Aborted extraction: exceeded max file limit ({self.max_extract_files})")
                return False

            total_extracted_size += member.file_size
            if total_extracted_size > self.max_extract_size:
                logger.warning(f"Aborted extraction: exceeded max size limit ({self.max_extract_size} bytes)")
                return False

            if member.is_dir():
                os.makedirs(dest_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with zf.open(member) as source, open(dest_path, "wb") as target:
                    shutil.copyfileobj(source, target)

        return True

    def post_process(
        self,
        file_path: str,
        ext: str,
        output_dir: str,
        filename: str,
        logger: Any,
        extract_archives: bool = None,
    ) -> Tuple[str, str]:
        """Executes format-specific post-processing routines on carved output files.

        Args:
            file_path (str): Full path to the carved file on disk.
            ext (str): Original format extension string.
            output_dir (str): Output folder path.
            filename (str): Carved output filename.
            logger (Any): Active worker logger instance.
            extract_archives (bool, optional): Overrides archive extraction toggle.

        Returns:
            Tuple[str, str]: Final detected extension and final filename.
        """
        should_extract = self.extract_archives if extract_archives is None else extract_archives

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
            elif should_extract:
                zip_out_dir = f"{file_path}_extracted"
                try:
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        success = self._safe_extract_zip(zf, zip_out_dir, logger)
                    if success:
                        logger.info(f"Safely extracted ZIP contents to {zip_out_dir}")
                except (zipfile.BadZipFile, OSError, RuntimeError) as e:
                    logger.error(f"Recovered ZIP extraction failed: {e}")
        return ext, filename
