"""
Command-line entry point.

    python -m checker.cli --ip 8.8.8.8
    python -m checker.cli --file ips.txt --output json
    python -m checker.cli --file ips.txt --output csv --outfile report.csv

All the actual checking logic lives in checker.engine, shared with the
live dashboard app — this file is just argument parsing + output.
"""
import argparse
import sys

from .engine import build_sources, check_ip
from .reporter import report
from .validator import validate_ip_list


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="checker",
        description="Check one or more IPs against VirusTotal, AbuseIPDB, and Shodan.",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--ip", help="Single IP address to check")
    target.add_argument("--file", help="Path to a file with one IP per line")

    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--outfile", default=None, help="Write output to this file instead of stdout")

    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    sources = build_sources()

    if not any(source.is_configured for source in sources):
        print(
            "WARNING: no API keys configured (VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / "
            "SHODAN_API_KEY). Every source will report UNKNOWN. See .env.example.",
            file=sys.stderr,
        )

    if args.ip:
        ips = [args.ip]
    else:
        with open(args.file) as fh:
            raw_text = fh.read()
        ips, errors = validate_ip_list(raw_text)
        for error in errors:
            print(f"WARNING: {error}", file=sys.stderr)
        if not ips:
            print("No valid IPs to check.", file=sys.stderr)
            return 1

    results = [check_ip(ip, sources) for ip in ips]
    report(results, fmt=args.output, outfile=args.outfile)
    return 0


if __name__ == "__main__":
    sys.exit(main())
