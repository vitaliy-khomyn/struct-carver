import os
import sys
import argparse
from struct_carver.core.carver import Carver

SUPPORTED_FORMATS = ['xml', 'html', 'pdf', 'json', 'rtf', 'zip']


def main():
    parser = argparse.ArgumentParser(description="StructCarve: A semantic, non-sequential file carver for digital forensics.")
    parser.add_argument('-i', '--image', required=True, help="Path to the raw forensic image (.dd, .raw)")
    parser.add_argument('-o', '--output', required=True, help="Directory to save the reassembled files")
    parser.add_argument('-f', '--formats', default="xml,html", help=f"Comma-separated list of formats. Supported: {', '.join(SUPPORTED_FORMATS)} (default: xml,html)")
    parser.add_argument('-c', '--cluster-size', type=int, default=4096, help="Disk cluster size in bytes (default: 4096)")

    args = parser.parse_args()

    if not os.path.isfile(args.image):
        print(f"[!] Error: Image file '{args.image}' not found.")
        sys.exit(1)

    if args.cluster_size <= 0:
        print("[!] Error: Cluster size must be a positive integer.")
        sys.exit(1)

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
    print("========================================\n")

    carver = Carver(cluster_size=args.cluster_size, formats=valid_formats)
    try:
        carver.carve(args.image, args.output)
        print("\n[*] Carving process completed successfully.")
    except KeyboardInterrupt:
        print("\n[!] Carving aborted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
