#!/usr/bin/env python3
"""jshunter CLI: harvest JavaScript files for secrets and hidden endpoints.

Passive recon only. Only run against targets you are authorized to test:
your own assets, a bug-bounty program scope that permits it, or a lab.

Usage:
    python -m jshunter.cli https://target.example
    python -m jshunter.cli https://target.example --json -o report.json
"""
import argparse
import sys

from .hunter import hunt
from .report import to_json, to_text


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Harvest JS files for leaked secrets and hidden endpoints (passive recon).")
    ap.add_argument("target", help="Target page URL or domain (e.g. https://example.com)")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of text")
    ap.add_argument("-o", "--output", help="Write report to file instead of stdout")
    ap.add_argument("--max-js", type=int, default=40, help="Max JS files to fetch (default 40)")
    ap.add_argument("--no-sourcemaps", action="store_true", help="Skip sourcemap discovery")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout seconds (default 15)")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="Confirm you are authorized to test this target")
    args = ap.parse_args(argv)

    if not args.i_am_authorized:
        print("Refusing to run: pass --i-am-authorized to confirm you may test this target.",
              file=sys.stderr)
        print("Only test your own assets, in-scope bug-bounty targets, or labs.", file=sys.stderr)
        return 2

    report = hunt(args.target, max_js=args.max_js,
                  include_sourcemaps=not args.no_sourcemaps,
                  timeout=args.timeout)
    out = to_json(report) if args.json else to_text(report)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
