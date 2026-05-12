import argparse
from struct_carver.core.carver import Carver


def main():
    parser = argparse.ArgumentParser(description="StructCarve: A semantic, non-sequential file carver.")
    parser.add_argument('-i', '--image', required=True, help="Path to the raw forensic image (.dd, .raw)")
    parser.add_argument('-o', '--output', required=True, help="Directory to save the reassembled files")
    parser.add_argument('-f', '--formats', default="xml,html", help="Comma-separated list of formats (default: xml,html)")
    parser.add_argument('-c', '--cluster-size', type=int, default=4096, help="Disk cluster size in bytes (default: 4096)")

    args = parser.parse_args()

    formats_list = [fmt.strip().lower() for fmt in args.formats.split(',')]

    print("========================================")
    print("[*] Starting StructCarve")
    print(f"[*] Target Image: {args.image}")
    print(f"[*] Formats to carve: {formats_list}")
    print("========================================\n")

    carver = Carver(cluster_size=args.cluster_size, formats=formats_list)
    carver.carve(args.image, args.output)


if __name__ == "__main__":
    main()
