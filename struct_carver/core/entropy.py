"""Shannon entropy calculation module.

This module provides functions to calculate the Shannon entropy of byte sequences
and entire files, enabling the detection of encrypted or compressed containers,
as well as identifying anti-forensic secure wiper patterns in unallocated space.
"""

import os
import math
from typing import Tuple


def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence.

    Shannon entropy measures the uncertainty or information density in a signal.
    Values range from 0.0 (completely uniform/constant bytes) to 8.0 (completely
    random, encrypted, or maximally compressed data).

    Args:
        data (bytes): Input byte buffer.

    Returns:
        float: Shannon entropy value in the range [0.0, 8.0].
    """
    if not data:
        return 0.0

    length = len(data)
    # count byte frequencies
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1

    entropy = 0.0
    for count in frequencies:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def calculate_file_entropy(file_path: str, chunk_size: int = 1024 * 1024) -> float:
    """Calculates the Shannon entropy of a file on disk streamingly.

    Args:
        file_path (str): Path to the target file.
        chunk_size (int, optional): Buffer read size in bytes (default: 1MB).

    Returns:
        float: Shannon entropy value in the range [0.0, 8.0].
    """
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return 0.0

    frequencies = [0] * 256
    total_bytes = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            for b in chunk:
                frequencies[b] += 1

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in frequencies:
        if count > 0:
            prob = count / total_bytes
            entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def classify_entropy(entropy: float) -> Tuple[str, str]:
    """Classifies an entropy score into a human-readable forensic category.

    Args:
        entropy (float): Shannon entropy score (0.0 to 8.0).

    Returns:
        Tuple[str, str]: (category_code, description) where category_code is
            one of 'low', 'structured', or 'high_encrypted'.
    """
    if entropy < 4.0:
        return "low", "Low entropy (plain text, repetitive, or zero-padded)"
    elif entropy < 7.2:
        return "structured", "Moderate entropy (structured code, markup, or raster image)"
    else:
        return "high_encrypted", "High entropy (compressed archive, media payload, or encrypted container)"
