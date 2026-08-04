"""Command-line interface.

This module provides the main entry point to run the carving process, handle
command line argument parsing, spawn parallel carving workers, merge reports,
and generate the forensic dashboard.
"""

import os
import sys
import signal
import multiprocessing

# intercept SIGINT and unhandled KeyboardInterrupt immediately before heavy imports
def _global_excepthook(exc_type, exc_value, exc_traceback):
    """Intercepts unhandled KeyboardInterrupt globally to prevent Python tracebacks."""
    if issubclass(exc_type, KeyboardInterrupt):
        try:
            is_main = multiprocessing.current_process().name == "MainProcess"
        except Exception:
            is_main = True
        if is_main:
            sys.stderr.write("\n[-] Carving process aborted by user. Exiting...\n")
        sys.exit(130)
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


sys.excepthook = _global_excepthook


def _sigint_handler(signum, frame):
    """Handles SIGINT signal directly across threads and during imports."""
    try:
        is_main = multiprocessing.current_process().name == "MainProcess"
    except Exception:
        is_main = True
    if is_main:
        sys.stderr.write("\n[-] Carving process aborted by user. Exiting...\n")
    sys.exit(130)


try:
    signal.signal(signal.SIGINT, _sigint_handler)
except (ValueError, AttributeError):
    pass

import glob
import json
import logging
import argparse
import concurrent.futures
from struct_carver.core.carver import Carver
from struct_carver.core.buffered_reader import get_image_size
from struct_carver.core.hasher import CryptoHasher, SUPPORTED_HASH_ALGOS
from struct_carver.core.validator import FileValidator
from struct_carver.core.checkpoint import CheckpointManager
from struct_carver.dashboard import generate_dashboard
from struct_carver.formats.registry import ParserRegistry, expand_format_categories
from struct_carver.formats.dynamic_binary_parser import DynamicBinaryParser
from struct_carver.logger import setup_logger

SUPPORTED_FORMATS = ParserRegistry.get_supported_formats()


def carve_worker(args):
    """Worker function for running Carver on a specific segment of the image file.

    Args:
        args (tuple): A tuple containing all parameters for Carver execution.
    """
    max_file_size = 2 * 1024 * 1024 * 1024
    extract_archives = False
    quiet = False
    carved_dir = None

    if len(args) >= 19:
        (image, output, cluster_size, formats, start, end, worker_id,
         custom_configs, max_search, density, profile, max_gap_fill,
         hash_algo, validate, resume, max_file_size, extract_archives, quiet,
         carved_dir) = args[:19]
    elif len(args) >= 18:
        (image, output, cluster_size, formats, start, end, worker_id,
         custom_configs, max_search, density, profile, max_gap_fill,
         hash_algo, validate, resume, max_file_size, extract_archives, quiet) = args[:18]
        carved_dir = os.path.join(output, "carved")
    elif len(args) >= 17:
        (image, output, cluster_size, formats, start, end, worker_id,
         custom_configs, max_search, density, profile, max_gap_fill,
         hash_algo, validate, resume, max_file_size, extract_archives) = args[:17]
        carved_dir = os.path.join(output, "carved")
    elif len(args) == 15:
        (image, output, cluster_size, formats, start, end, worker_id,
         custom_configs, max_search, density, profile, max_gap_fill,
         hash_algo, validate, resume) = args
        carved_dir = os.path.join(output, "carved")
    elif len(args) == 12:
        (image, output, cluster_size, formats, start, end, worker_id,
         custom_configs, max_search, density, profile, max_gap_fill) = args
        hash_algo, validate, resume = 'sha256', True, False
        carved_dir = os.path.join(output, "carved")
    else:
        (image, output, cluster_size, formats, start, end, worker_id,
         custom_configs, max_search, density, profile) = args
        max_gap_fill = 100 * 1024 * 1024
        hash_algo, validate, resume = 'sha256', True, False
        carved_dir = os.path.join(output, "carved")

    if not carved_dir:
        carved_dir = os.path.join(output, "carved")

    custom_parsers = []
    for cfg in custom_configs:
        header = bytes.fromhex(cfg['header_hex'])
        footer = bytes.fromhex(cfg['footer_hex'])
        custom_parsers.append(DynamicBinaryParser(cfg['extension'], header, footer))

    hasher = CryptoHasher(hash_algo) if hash_algo else None
    validator = FileValidator() if validate else None
    ckpt_path = os.path.join(output, "checkpoint.json")
    checkpoint_mgr = CheckpointManager(ckpt_path) if resume else None

    carver = Carver(
        cluster_size=cluster_size, formats=formats, custom_parsers=custom_parsers,
        max_search_clusters=max_search, text_density_threshold=density,
        max_gap_fill_bytes=max_gap_fill,
        hasher=hasher,
        validator=validator,
        checkpoint_mgr=checkpoint_mgr,
        max_file_size=max_file_size,
        extract_archives=extract_archives,
        quiet=quiet,
        carved_dir=carved_dir
    )

    try:
        if profile:
            import cProfile
            profiler = cProfile.Profile()
            profiler.enable()
            carver.carve(image, output, start, end, worker_id, carved_dir=carved_dir)
            profiler.disable()
            stats_path = os.path.join(output, f"profile_w{worker_id}.prof")
            profiler.dump_stats(stats_path)
        else:
            carver.carve(image, output, start, end, worker_id, carved_dir=carved_dir)
    except KeyboardInterrupt:
        sys.exit(130)


def deduplicate_boundary_overlaps(files, output_dir):
    """Removes duplicate files carved across worker boundary chunk overlaps.

    When multi-worker carving splits an image, a file beginning near the boundary of
    Worker N may be carved fully across the boundary, while Worker N+1 also detects
    a signature within that same span. This function detects and removes such duplicates.

    Args:
        files (list): List of recovered file dictionaries.
        output_dir (str): Directory where carved files reside.

    Returns:
        list: Deduplicated list of file dictionaries.
    """
    if not files:
        return []

    # sort chronologically by physical start offset
    sorted_files = sorted(
        files,
        key=lambda x: x["fragments"][0]["start_offset"] if x.get("fragments") else 0
    )

    deduped = []
    seen_hashes = set()

    for file_entry in sorted_files:
        frags = file_entry.get("fragments", [])
        if not frags:
            deduped.append(file_entry)
            continue

        first_offset = frags[0]["start_offset"]
        last_offset = frags[-1]["end_offset"]
        file_hash = file_entry.get("file_hash", "")
        status = file_entry.get("status", "")

        is_duplicate = False

        # check 1: identical file content hash
        if file_hash and file_hash in seen_hashes:
            is_duplicate = True

        # check 2: start offset falls inside an earlier complete file's fragment span
        if not is_duplicate:
            for prior in deduped:
                if prior.get("status") == "complete":
                    for p_frag in prior.get("fragments", []):
                        if p_frag["start_offset"] <= first_offset < p_frag["end_offset"]:
                            is_duplicate = True
                            break
                    if is_duplicate:
                        break

        # check 3: if current is complete, check if it supersedes an earlier partial file
        if not is_duplicate and status == "complete":
            to_remove = []
            for prior in deduped:
                if prior.get("status") in ["partial", "incomplete_eof"]:
                    p_frags = prior.get("fragments", [])
                    if p_frags:
                        p_start = p_frags[0]["start_offset"]
                        p_end = p_frags[-1]["end_offset"]
                        if first_offset <= p_start and p_end <= last_offset:
                            to_remove.append(prior)
            for old in to_remove:
                deduped.remove(old)
                carved_sub = os.path.join(output_dir, "carved")
                target_folder = carved_sub if os.path.isdir(carved_sub) else output_dir
                old_file = os.path.join(target_folder, old.get("filename", ""))
                if os.path.exists(old_file):
                    try:
                        os.remove(old_file)
                    except OSError:
                        pass

        if is_duplicate:
            # remove redundant duplicate file from disk
            filename = file_entry.get("filename", "")
            carved_sub = os.path.join(output_dir, "carved")
            target_folder = carved_sub if os.path.isdir(carved_sub) else output_dir
            file_path = os.path.join(target_folder, filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass
        else:
            if file_hash:
                seen_hashes.add(file_hash)
            deduped.append(file_entry)

    return deduped


def merge_worker_reports(output_dir, error_message=None, hash_algo="sha256", source_image_hashes=None):
    """Merges separate JSON reports from individual worker threads into a single report.

    Also runs boundary overlap deduplication and generates forensic evidence manifests.

    Args:
        output_dir (str): Directory containing the worker report files.
        error_message (str, optional): An optional error message to attach to the report.
        hash_algo (str, optional): Algorithm name for forensic checksum manifests.
        source_image_hashes (dict, optional): Cryptographic hashes of the source image.
    """
    report_files = glob.glob(os.path.join(output_dir, "carve_report_w*.json"))
    if not report_files and not error_message:
        return

    merged_report = {"files": []}
    if hash_algo:
        merged_report["hash_algo"] = hash_algo
    if source_image_hashes:
        merged_report["source_image"] = source_image_hashes
    if error_message:
        merged_report["error"] = error_message

    for rf in report_files:
        try:
            with open(rf, 'r', encoding='utf-8') as f:
                data = json.load(f)
                merged_report["files"].extend(data.get("files", []))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass

    # apply multi-worker boundary deduplication
    merged_report["files"] = deduplicate_boundary_overlaps(merged_report["files"], output_dir)

    # sort recovered files chronologically by their starting physical offset
    merged_report["files"].sort(key=lambda x: x["fragments"][0]["start_offset"] if x.get("fragments") else 0)

    # write consolidated carve report
    merged_path = os.path.join(output_dir, "carve_report.json")
    with open(merged_path, 'w', encoding='utf-8') as f:
        json.dump(merged_report, f, indent=4)

    # generate forensic evidence manifests and timeline exports
    try:
        hasher = CryptoHasher(hash_algo)
        manifest_name = f"manifest.{hash_algo}"
        manifest_path = os.path.join(output_dir, manifest_name)
        with open(manifest_path, "w", encoding="utf-8") as f_man:
            f_man.write(hasher.generate_manifest_content(merged_report["files"]))

        csv_path = os.path.join(output_dir, "manifest.csv")
        with open(csv_path, "w", encoding="utf-8") as f_csv:
            f_csv.write(hasher.generate_csv_manifest(merged_report["files"]))

        bodyfile_path = os.path.join(output_dir, "bodyfile.txt")
        with open(bodyfile_path, "w", encoding="utf-8") as f_body:
            f_body.write(hasher.generate_bodyfile_content(merged_report["files"]))

        jsonl_path = os.path.join(output_dir, "carve_report.jsonl")
        with open(jsonl_path, "w", encoding="utf-8") as f_jsonl:
            f_jsonl.write(hasher.generate_jsonl_content(merged_report["files"]))
    except (OSError, ValueError):
        pass

    # clean up temporary worker reports
    for rf in report_files:
        try:
            os.remove(rf)
        except OSError:
            pass

    logger = setup_logger("Merge")
    logger.info("Worker reports successfully merged into single carve_report.json and manifests created")


def _run_main():
    """Internal runner for parsing arguments and orchestrating carving execution."""
    parser = argparse.ArgumentParser(description="Struct Carver: A semantic, non-sequential file carver for digital forensics.")
    parser.add_argument('-i', '--image', required=True, help="Path to the raw forensic image (.dd, .raw)")
    parser.add_argument('-o', '--output', required=True, help="Directory to save the reassembled files")
    parser.add_argument('-f', '--formats', default=",".join(SUPPORTED_FORMATS), help=f"Comma-separated list of formats. Supported: {', '.join(SUPPORTED_FORMATS)} (default: all)")
    parser.add_argument('-c', '--cluster-size', type=int, default=4096, help="Disk cluster size in bytes (default: 4096)")
    parser.add_argument('-w', '--workers', type=int, default=1, help="Number of concurrent workers (default: 1)")
    parser.add_argument('--config', type=str, help="Path to a custom JSON config file for defining additional linear binary formats.")
    parser.add_argument('--max-search', type=int, default=1000, help="Max clusters to scan during a gap-jump (default: 1000)")
    parser.add_argument('--text-density', type=float, default=0.8, help="Text density threshold for accepting tagless clusters (default: 0.8)")
    parser.add_argument('--max-gap-fill', type=int, default=100 * 1024 * 1024, help="Max bytes to zero-fill across a gap jump in bytes (default: 100MB)")
    parser.add_argument('--hash-algo', default='sha256', choices=SUPPORTED_HASH_ALGOS, help=f"Cryptographic hash algorithm for evidence manifest (default: sha256). Choices: {', '.join(SUPPORTED_HASH_ALGOS)}")
    parser.add_argument('--validate', dest='validate', action='store_true', default=True, help="Perform forensic validation pass on carved files (default: True)")
    parser.add_argument('--no-validate', dest='validate', action='store_false', help="Disable forensic payload validation")
    parser.add_argument('--resume', action='store_true', help="Resume an interrupted carving session from checkpoint")
    parser.add_argument('-d', '--dashboard', action='store_true', help="Automatically generate an interactive HTML dashboard upon completion.")
    parser.add_argument('--profile', action='store_true', help="Enable cProfile performance profiling per worker.")
    parser.add_argument('--max-file-size', type=int, default=2 * 1024 * 1024 * 1024, help="Maximum allowed carved file size in bytes before truncation (default: 2GB)")
    parser.add_argument('--extract-archives', action='store_true', help="Safely unpack carved ZIP/TAR archives into subdirectories")
    parser.add_argument('-q', '--quiet', action='store_true', help="Suppress non-essential console logs and progress indicators")

    args = parser.parse_args()

    # dynamically determine the numbered output directory based on original image filename
    img_name = os.path.basename(args.image)
    if args.resume:
        # locate the most recent candidate directory containing a checkpoint
        latest_candidate = None
        i = 1
        while True:
            candidate = os.path.join(args.output, f"{img_name}.{i}")
            if os.path.exists(candidate):
                latest_candidate = candidate
                i += 1
            else:
                break
        if latest_candidate and os.path.exists(os.path.join(latest_candidate, "checkpoint.json")):
            args.output = latest_candidate
        elif os.path.exists(os.path.join(args.output, "checkpoint.json")):
            pass
        elif latest_candidate:
            args.output = latest_candidate
    else:
        i = 1
        while True:
            candidate = os.path.join(args.output, f"{img_name}.{i}")
            if not os.path.exists(candidate):
                args.output = candidate
                break
            i += 1

    # ensure output directory exists before configuring loggers
    os.makedirs(args.output, exist_ok=True)
    log_level = logging.WARNING if args.quiet else logging.INFO
    logger = setup_logger("Main", os.path.join(args.output, "audit_main.log"), level=log_level)

    # ensure dedicated carved files directory exists and is empty
    carved_dir = os.path.join(args.output, "carved")
    if os.path.exists(carved_dir) and os.path.isdir(carved_dir):
        if any(os.scandir(carved_dir)):
            if not args.resume:
                logger.error(f"Carved output subfolder '{carved_dir}' already exists and contains files.")
                sys.exit(1)
    os.makedirs(carved_dir, exist_ok=True)

    if not os.path.isfile(args.image):
        logger.error(f"Image file '{args.image}' not found.")
        sys.exit(1)

    if args.cluster_size <= 0:
        logger.error("Cluster size must be a positive integer.")
        sys.exit(1)

    if getattr(args, 'workers', 1) < 1:
        logger.error("Workers must be a positive integer.")
        sys.exit(1)

    if args.max_search <= 0:
        logger.error("Max search clusters must be greater than 0.")
        sys.exit(1)

    if not (0.0 <= args.text_density <= 1.0):
        logger.error("Text density threshold must be between 0.0 and 1.0.")
        sys.exit(1)

    if args.max_gap_fill <= 0:
        logger.error("Max gap fill bytes must be greater than 0.")
        sys.exit(1)

    custom_configs = []
    if args.config:
        if not os.path.isfile(args.config):
            logger.error(f"Config file '{args.config}' not found.")
            sys.exit(1)
        with open(args.config, 'r') as f:
            custom_configs = json.load(f)
        SUPPORTED_FORMATS.update([cfg['extension'].lower() for cfg in custom_configs])

    raw_formats = [fmt.strip().lower() for fmt in args.formats.split(',')]
    expanded_formats = expand_format_categories(raw_formats)
    valid_formats = [fmt for fmt in expanded_formats if fmt in SUPPORTED_FORMATS]
    known_categories = ParserRegistry.get_supported_categories()
    invalid_formats = [fmt for fmt in raw_formats if fmt not in SUPPORTED_FORMATS and fmt not in known_categories]

    if invalid_formats:
        logger.warning(f"Ignoring unsupported formats: {', '.join(invalid_formats)}")

    if not valid_formats:
        logger.error("No valid formats specified to carve. Exiting.")
        sys.exit(1)

    # compute cryptographic chain of custody hashes for target forensic image
    logger.info("Computing source image cryptographic integrity verification hashes...")
    total_size = get_image_size(args.image)
    sha256_hasher = CryptoHasher("sha256")
    md5_hasher = CryptoHasher("md5")
    source_sha256 = sha256_hasher.hash_file(args.image)
    source_md5 = md5_hasher.hash_file(args.image)
    source_image_hashes = {
        "image_path": os.path.abspath(args.image),
        "sha256": source_sha256,
        "md5": source_md5,
        "file_size": total_size
    }

    logger.info("========================================")
    logger.info("Starting Struct Carver")
    logger.info(f"Target Image: {args.image}")
    logger.info(f"Image SHA256: {source_sha256}")
    logger.info(f"Image MD5:    {source_md5}")
    logger.info(f"Output Dir:   {args.output}")
    logger.info(f"Cluster Size: {args.cluster_size} bytes")
    logger.info(f"Formats:      {', '.join(valid_formats)}")
    logger.info(f"Max Search:   {args.max_search} clusters")
    logger.info(f"Text Density: {args.text_density * 100}%")
    logger.info(f"Max Gap Fill: {args.max_gap_fill // (1024 * 1024)} MB")
    logger.info(f"Hash Algo:    {args.hash_algo.upper()}")
    logger.info(f"Validation:   {'Enabled' if args.validate else 'Disabled'}")
    logger.info(f"Resume Mode:  {'Enabled' if args.resume else 'Disabled'}")
    logger.info(f"Workers:      {args.workers}")
    if custom_configs:
        logger.info(f"Custom Types: {len(custom_configs)} formats loaded from config")
    if args.profile:
        logger.info("Profiling:    Enabled (Output to .prof files)")
    logger.info("========================================")

    chunk_size = total_size // args.workers
    # ensure chunk size aligns with cluster size
    chunk_size = (chunk_size // args.cluster_size) * args.cluster_size

    worker_args = []
    for i in range(args.workers):
        start = i * chunk_size
        end = start + chunk_size if i < args.workers - 1 else total_size
        worker_args.append((
            args.image, args.output, args.cluster_size, valid_formats, start, end, i,
            custom_configs, args.max_search, args.text_density, args.profile, args.max_gap_fill,
            args.hash_algo, args.validate, args.resume, args.max_file_size, args.extract_archives, args.quiet,
            carved_dir
        ))

    try:
        if args.workers == 1:
            carve_worker(worker_args[0])
        else:
            executor = concurrent.futures.ProcessPoolExecutor(max_workers=args.workers)
            try:
                futures = [executor.submit(carve_worker, arg) for arg in worker_args]
                for future in concurrent.futures.as_completed(futures):
                    future.result()  # raises exceptions if any occurred
            except (KeyboardInterrupt, concurrent.futures.process.BrokenProcessPool):
                executor.shutdown(wait=False, cancel_futures=True)
                for pid, process in getattr(executor, '_processes', {}).items():
                    try:
                        process.terminate()
                    except (OSError, AttributeError):
                        pass
                raise KeyboardInterrupt
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        # add newlines to push terminal prompt safely below the multiprocess tqdm output bars
        print("\n" * args.workers)
        logger.info("Carving process completed successfully.")
        merge_worker_reports(args.output, hash_algo=args.hash_algo, source_image_hashes=source_image_hashes)

        if args.dashboard:
            json_report = os.path.join(args.output, "carve_report.json")
            html_out = os.path.join(args.output, "dashboard.html")
            generate_dashboard(json_report, html_out)
    except KeyboardInterrupt:
        logger.warning("Carving aborted by user.")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        try:
            merge_worker_reports(args.output, error_message=str(e), hash_algo=args.hash_algo, source_image_hashes=source_image_hashes)
            if args.dashboard:
                json_report = os.path.join(args.output, "carve_report.json")
                html_out = os.path.join(args.output, "dashboard.html")
                generate_dashboard(json_report, html_out)
        except Exception as merge_err:
            logger.error(f"Failed to generate error report: {merge_err}")
        sys.exit(1)


def main():
    """Main execution entrypoint for parsing command line arguments and starting the carving task."""
    try:
        _run_main()
    except KeyboardInterrupt:
        sys.stderr.write("\n[-] Carving process aborted by user. Exiting...\n")
        sys.exit(130)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\n[-] Carving process aborted by user. Exiting...\n")
        sys.exit(130)
