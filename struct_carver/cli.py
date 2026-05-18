import os
import sys
import glob
import json
import argparse
import concurrent.futures
from struct_carver.core.carver import Carver
from struct_carver.dashboard import generate_dashboard
from struct_carver.formats.dynamic_binary_parser import DynamicBinaryParser

SUPPORTED_FORMATS = ['xml', 'html', 'pdf', 'json', 'rtf', 'zip', 'sqlite', 'sqlitewal']


def carve_worker(args):
    image, output, cluster_size, formats, start, end, worker_id, custom_configs, max_search, density, profile = args

    custom_parsers = []
    for cfg in custom_configs:
        header = bytes.fromhex(cfg['header_hex'])
        footer = bytes.fromhex(cfg['footer_hex'])
        custom_parsers.append(DynamicBinaryParser(cfg['extension'], header, footer))

    carver = Carver(
        cluster_size=cluster_size, formats=formats, custom_parsers=custom_parsers,
        max_search_clusters=max_search, text_density_threshold=density
    )

    if profile:
        import cProfile
        profiler = cProfile.Profile()
        profiler.enable()
        carver.carve(image, output, start, end, worker_id)
        profiler.disable()
        stats_path = os.path.join(output, f"profile_w{worker_id}.prof")
        profiler.dump_stats(stats_path)
    else:
        carver.carve(image, output, start, end, worker_id)


def merge_worker_reports(output_dir):
    report_files = glob.glob(os.path.join(output_dir, "carve_report_w*.json"))
    if not report_files:
        return

    merged_report = {"files": []}
    for rf in report_files:
        try:
            with open(rf, 'r') as f:
                data = json.load(f)
                merged_report["files"].extend(data.get("files", []))
        except Exception:
            pass

    # sort recovered files chronologically by their starting physical offset
    merged_report["files"].sort(key=lambda x: x["fragments"][0]["start_offset"] if x["fragments"] else 0)

    merged_path = os.path.join(output_dir, "carve_report.json")
    with open(merged_path, 'w') as f:
        json.dump(merged_report, f, indent=4)

    # Clean up temporary worker reports
    for rf in report_files:
        os.remove(rf)


def main():
    parser = argparse.ArgumentParser(description="StructCarve: A semantic, non-sequential file carver for digital forensics.")
    parser.add_argument('-i', '--image', required=True, help="Path to the raw forensic image (.dd, .raw)")
    parser.add_argument('-o', '--output', required=True, help="Directory to save the reassembled files")
    parser.add_argument('-f', '--formats', default="xml,html", help=f"Comma-separated list of formats. Supported: {', '.join(SUPPORTED_FORMATS)} (default: xml,html)")
    parser.add_argument('-c', '--cluster-size', type=int, default=4096, help="Disk cluster size in bytes (default: 4096)")
    parser.add_argument('-w', '--workers', type=int, default=1, help="Number of concurrent workers (default: 1)")
    parser.add_argument('--config', type=str, help="Path to a custom JSON config file for defining additional linear binary formats.")
    parser.add_argument('--max-search', type=int, default=1000, help="Max clusters to scan during a gap-jump (default: 1000)")
    parser.add_argument('--text-density', type=float, default=0.8, help="Text density threshold for accepting tagless clusters (default: 0.8)")
    parser.add_argument('-d', '--dashboard', action='store_true', help="Automatically generate an interactive HTML dashboard upon completion.")
    parser.add_argument('--profile', action='store_true', help="Enable cProfile performance profiling per worker.")

    args = parser.parse_args()

    if not os.path.isfile(args.image):
        print(f"[!] Error: Image file '{args.image}' not found.")
        sys.exit(1)

    if args.cluster_size <= 0:
        print("[!] Error: Cluster size must be a positive integer.")
        sys.exit(1)

    if getattr(args, 'workers', 1) < 1:
        print("[!] Error: Workers must be a positive integer.")
        sys.exit(1)

    if args.max_search <= 0:
        print("[!] Error: Max search clusters must be greater than 0.")
        sys.exit(1)

    if not (0.0 <= args.text_density <= 1.0):
        print("[!] Error: Text density threshold must be between 0.0 and 1.0.")
        sys.exit(1)

    custom_configs = []
    if args.config:
        if not os.path.isfile(args.config):
            print(f"[!] Error: Config file '{args.config}' not found.")
            sys.exit(1)
        with open(args.config, 'r') as f:
            custom_configs = json.load(f)
        SUPPORTED_FORMATS.extend([cfg['extension'].lower() for cfg in custom_configs])

    raw_formats = [fmt.strip().lower() for fmt in args.formats.split(',')]
    valid_formats = [fmt for fmt in raw_formats if fmt in SUPPORTED_FORMATS]
    invalid_formats = [fmt for fmt in raw_formats if fmt not in SUPPORTED_FORMATS]

    if invalid_formats:
        print(f"[!] Warning: Ignoring unsupported formats: {', '.join(invalid_formats)}")

    if not valid_formats:
        print("[!] Error: No valid formats specified to carve. Exiting.")
        sys.exit(1)

    print("========================================")
    print("[*] Starting StructCarve")
    print(f"[*] Target Image: {args.image}")
    print(f"[*] Output Dir:   {args.output}")
    print(f"[*] Cluster Size: {args.cluster_size} bytes")
    print(f"[*] Formats:      {', '.join(valid_formats)}")
    print(f"[*] Max Search:   {args.max_search} clusters")
    print(f"[*] Text Density: {args.text_density * 100}%")
    print(f"[*] Workers:      {args.workers}")
    if custom_configs:
        print(f"[*] Custom Types: {len(custom_configs)} formats loaded from config")
    if args.profile:
        print("[*] Profiling:    Enabled (Output to .prof files)")
    print("========================================\n")

    total_size = os.path.getsize(args.image)
    chunk_size = total_size // args.workers
    # ensure chunk size aligns with cluster size
    chunk_size = (chunk_size // args.cluster_size) * args.cluster_size

    worker_args = []
    for i in range(args.workers):
        start = i * chunk_size
        end = start + chunk_size if i < args.workers - 1 else total_size
        worker_args.append((args.image, args.output, args.cluster_size, valid_formats, start, end, i, custom_configs, args.max_search, args.text_density, args.profile))

    try:
        if args.workers == 1:
            carve_worker(worker_args[0])
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as executor:
                futures = [executor.submit(carve_worker, arg) for arg in worker_args]
                for future in concurrent.futures.as_completed(futures):
                    future.result()  # raises exceptions if any occurred
        # add newlines to push terminal prompt safely below the multiprocess tqdm output bars
        print("\n" * args.workers)
        print("[*] Carving process completed successfully.")
        merge_worker_reports(args.output)

        if args.dashboard:
            json_report = os.path.join(args.output, "carve_report.json")
            html_out = os.path.join(args.output, "dashboard.html")
            generate_dashboard(json_report, html_out)
    except KeyboardInterrupt:
        print("\n[!] Carving aborted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
