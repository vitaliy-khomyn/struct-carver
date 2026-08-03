"""Session checkpoint manager.

This module provides the CheckpointManager class, allowing carving operations
to periodically persist scan offsets and recovered files, enabling graceful
resumption (--resume) after an interruption or crash.
"""

import os
import json
import tempfile
from typing import Dict, Any, List, Optional


class CheckpointManager:
    """Manages carving session checkpoints on disk.

    Attributes:
        checkpoint_path (str): File path to the checkpoint JSON file.
    """

    def __init__(self, checkpoint_path: str):
        """Initializes the CheckpointManager.

        Args:
            checkpoint_path (str): Path to checkpoint file (e.g. output_dir/checkpoint.json).
        """
        self.checkpoint_path = checkpoint_path

    def load(self) -> Dict[str, Any]:
        """Loads checkpoint state from disk if it exists.

        Returns:
            Dict[str, Any]: Loaded checkpoint state dictionary, or an empty template.
        """
        if not os.path.exists(self.checkpoint_path):
            return {"workers": {}, "files": []}

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    data.setdefault("workers", {})
                    data.setdefault("files", [])
                    return data
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass
        return {"workers": {}, "files": []}

    def save_worker_progress(
        self,
        worker_id: int,
        current_offset: int,
        new_files: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Atomically saves progress for a specific worker.

        Args:
            worker_id (int): Identifier of the worker thread/process.
            current_offset (int): Current byte offset scanned in the image.
            new_files (Optional[List[Dict[str, Any]]], optional): Newly recovered file records.
        """
        data = self.load()
        data["workers"][str(worker_id)] = current_offset

        if new_files:
            # deduplicate by file_id or filename
            existing_names = {f.get("filename") for f in data["files"] if f.get("filename")}
            for item in new_files:
                fname = item.get("filename")
                if not fname or fname not in existing_names:
                    data["files"].append(item)
                    if fname:
                        existing_names.add(fname)

        # atomic write using tempfile in same directory
        dir_name = os.path.dirname(self.checkpoint_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

        tmp_fd, tmp_path = tempfile.mkstemp(dir=dir_name if dir_name else None, prefix="ckpt_", suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            # atomic replace on Windows/POSIX
            os.replace(tmp_path, self.checkpoint_path)
        except (OSError, ValueError):
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def get_worker_start_offset(self, worker_id: int, initial_start: int) -> int:
        """Gets the resumed start offset for a worker, or returns initial_start.

        Args:
            worker_id (int): Worker identifier.
            initial_start (int): Original start offset for this worker's chunk.

        Returns:
            int: The offset from which the worker should begin scanning.
        """
        data = self.load()
        worker_key = str(worker_id)
        if worker_key in data.get("workers", {}):
            saved_offset = data["workers"][worker_key]
            if isinstance(saved_offset, int) and saved_offset >= initial_start:
                return saved_offset
        return initial_start

    def get_recovered_files(self) -> List[Dict[str, Any]]:
        """Returns all completed file records stored in the checkpoint.

        Returns:
            List[Dict[str, Any]]: List of file dictionaries.
        """
        data = self.load()
        return data.get("files", [])

    def clear(self) -> None:
        """Removes the checkpoint file from disk if present."""
        if os.path.exists(self.checkpoint_path):
            try:
                os.remove(self.checkpoint_path)
            except OSError:
                pass
