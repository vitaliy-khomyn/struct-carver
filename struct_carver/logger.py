"""Logging utilities for Struct Carver!

This module sets up logging handlers and formatters to support progress bar
reporting using tqdm alongside standard file and console logging.
"""

import logging
import os
from tqdm import tqdm


class TqdmLoggingHandler(logging.Handler):
    """Logging handler that redirects console messages through tqdm.write.

    This prevents standard log statements from breaking or messing up the tqdm
    progress bars displayed in the console.
    """

    def __init__(self, level=logging.NOTSET):
        """Initializes the tqdm logging handler."""
        super().__init__(level)

    def emit(self, record):
        """Emits a log record via tqdm.write.

        Args:
            record (logging.LogRecord): The log record to be emitted.
        """
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)


def setup_logger(name: str, log_file: str = None, level=logging.INFO) -> logging.Logger:
    """Sets up a logger with tqdm console output and optional file output.

    Args:
        name (str): Name of the logger.
        log_file (str, optional): Path to the output log file.
        level (int, optional): Logging level (default: logging.INFO).

    Returns:
        logging.Logger: The configured Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        console_handler = TqdmLoggingHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if log_file:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
