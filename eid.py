#!/usr/bin/env python3
# eid: quick lookup of Windows related event IDs for forensics.
#
# Usage:
#   eid.py 4768                 # meaning of event 4768 in every source
#   eid.py 4624 4672 4688       # several IDs at once
#   eid.py "46*"                # wildcard, quote it so the shell does not expand it
#   eid.py --sysmon 1           # restrict the search to one source
#   eid.py -s locked            # search descriptions by text
#   eid.py --sysmon -s pipe     # search descriptions by text in one source
#   eid.py --list               # sources, event counts and the log file each one lives in
#   eid.py --list security      # every event of a source
#
# Data layout, all CSV with a header row:
#   data/sources.csv         name,description,files
#   data/<source>.csv        id,description
# To add an event, append a line to the right file. To add a source,
# create data/<name>.csv and add one line to data/sources.csv.
# Run build.sh or build.bat to produce a single binary with the data inside.

import argparse
import csv
import fnmatch
import os
import sys

VERSION = "1.0.0"
AUTHOR = "Developed by Cristian Souza (cristianmsbr@gmail.com)"

# For PyInstaller
DATA_DIR = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "data")


def read_csv(name):
    # Returns the rows of data/<name>.csv as dicts keyed by the header, blank lines skipped.
    path = os.path.join(DATA_DIR, name + ".csv")
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return [{k: v.strip() for k, v in row.items()} for row in csv.DictReader(f) if any(row.values())]
    except FileNotFoundError:
        sys.exit(f"data file not found: {path}")


def load_sources():
    # name -> (description, files)
    return {r["name"]: (r["description"], r["files"]) for r in read_csv("sources")}


def load_events(source):
    # list of (source, id, description) in file order
    return [(source, r["id"], r["description"]) for r in read_csv(source)]


def match_id(source, patterns):
    return [e for e in load_events(source) if any(fnmatch.fnmatchcase(e[1], p) for p in patterns)]


def match_text(source, text):
    text = text.lower()
    return [e for e in load_events(source) if text in e[2].lower()]


def show(events, with_source):
    src_width = max((len(s) for s, _, _ in events), default=0) + 2
    id_width = max((len(i) for _, i, _ in events), default=0)
    for source, eid, desc in events:
        prefix = source.ljust(src_width) if with_source else ""
        print(f"{prefix}{eid.rjust(id_width)}  {desc}")


def show_sources(sources):
    width = max(len(n) for n in sources) + 2
    for name, (desc, files) in sources.items():
        print(f"{name.ljust(width)}{len(load_events(name)):>5}  {desc}")
        print(f"{'':{width + 7}}{files}")


def build_parser(sources):
    parser = argparse.ArgumentParser(
        prog="eid",
        description="Quick lookup of Windows related event IDs for forensics.",
        epilog='Patterns accept shell style wildcards, e.g. "46*" or "47?8". '
    )
    parser.add_argument("patterns", nargs="*", metavar="ID", help="event ID or wildcard pattern, one or more")
    parser.add_argument("-s", "--search", metavar="TEXT", help="search descriptions for TEXT instead of matching IDs")
    parser.add_argument("--list", nargs="?", const="", metavar="SOURCE",
                        help="list the sources, or every event of one. Any source also works as a flag to restrict a search, e.g. --sysmon 1")
    parser.add_argument("--version", action="store_true", help="show version and exit")

    group = parser.add_mutually_exclusive_group()
    for name in sources:
        group.add_argument(f"--{name}", dest="source", action="store_const", const=name, help=argparse.SUPPRESS)
    return parser


def main():
    sources = load_sources()
    parser = build_parser(sources)
    args = parser.parse_args()

    if args.version:
        print(f"eid {VERSION}")
        print(AUTHOR)
        return
    if args.list is not None:
        if not args.list:
            show_sources(sources)
        elif args.list in sources:
            show(load_events(args.list), with_source=False)
        else:
            parser.error(f"unknown source {args.list!r}, run --list to see them")
        return
    if not args.patterns and not args.search:
        parser.print_help()
        return

    selected = [args.source] if args.source else list(sources)
    if args.search:
        events = [e for s in selected for e in match_text(s, args.search)]
        what = f"no description contains {args.search!r}"
    else:
        events = [e for s in selected for e in match_id(s, args.patterns)]
        what = f"no event matches {' '.join(args.patterns)}"
    if not events:
        sys.exit(what + (f" in {args.source}" if args.source else ""))
    show(events, with_source=args.source is None)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
