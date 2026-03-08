#!/usr/bin/env python3
"""
ResidentReaper LOLBin Ingress Detector

Detects file ingress via Living-off-the-Land Binaries by analyzing USN Journal
CSV output. Currently detects:

  - certutil:   Correlates CryptnetUrlCache + INetCache activity to identify
                downloaded files and their final destination paths.
  - BITSAdmin:  Tracks BIT*.tmp rename chains to reveal BITS transfer targets.

Usage:
    python lolbin_ingress.py -f usn.csv
    python lolbin_ingress.py -f usn.csv -o findings.csv
    python lolbin_ingress.py -f usn.csv --method certutil
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

def parse_timestamp(ts_str):
    """Parse ResidentReaper timestamp format: yyyy-MM-dd HH:mm:ss.fffffff"""
    if not ts_str or not ts_str.strip():
        return None
    ts_str = ts_str.strip()
    try:
        if "." in ts_str:
            date_part, frac = ts_str.rsplit(".", 1)
            frac = frac[:6].ljust(6, "0")
            return datetime.strptime(f"{date_part}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
        else:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def fmt_ts(ts):
    """Format timestamp for display."""
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def build_full_path(parent_path, filename):
    if not parent_path or parent_path == ".":
        return filename
    return f"{parent_path}\\{filename}"


USER_RE = re.compile(r"\\Users\\([^\\]+)\\", re.IGNORECASE)
PROFILE_RE = re.compile(r"\\(LocalService|NetworkService|systemprofile)\\", re.IGNORECASE)


def extract_username(path):
    """Extract username from a file path."""
    m = USER_RE.search(path)
    if m:
        return m.group(1)
    m = PROFILE_RE.search(path)
    if m:
        return f"SYSTEM ({m.group(1)})"
    return ""


# ---------------------------------------------------------------------------
# certutil detection
# ---------------------------------------------------------------------------

CRYPTNET_CONTENT_RE = re.compile(r"CryptnetUrlCache\\Content", re.IGNORECASE)
CRYPTNET_RE = re.compile(r"CryptnetUrlCache", re.IGNORECASE)
INETCACHE_IE_RE = re.compile(r"INetCache\\IE\\", re.IGNORECASE)
INETCACHE_NAME_RE = re.compile(r"^(.+)\[\d+\](\.\w+)$")
NOISE_PATH_RE = re.compile(
    r"\\(AC|AppCache|DOMStore|Microsoft\\Internet Explorer|NativeImages|assembly\\)",
    re.IGNORECASE,
)


def clean_inetcache_name(filename):
    """Remove [N] suffix: sisisisam[1].exe -> sisisisam.exe"""
    m = INETCACHE_NAME_RE.match(filename)
    return f"{m.group(1)}{m.group(2)}" if m else filename


def detect_certutil(usn_path):
    """Detect certutil downloads by correlating CryptnetUrlCache + INetCache events."""
    cryptnet_events = []
    inetcache_events = []
    all_creates = []

    with open(usn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reasons = row.get("UpdateReasons", "")
            if "FileCreate" not in reasons:
                continue

            filename = row.get("Name", "")
            parent_path = row.get("ParentPath", "")
            ts = parse_timestamp(row.get("UpdateTimestamp", ""))
            if not ts:
                continue

            full_path = build_full_path(parent_path, filename)

            record = {
                "FileName": filename,
                "Extension": row.get("Extension", ""),
                "ParentPath": parent_path,
                "FullPath": full_path,
                "Timestamp": ts,
                "TimestampKey": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "UpdateReasons": reasons,
                "EntryNumber": row.get("EntryNumber", ""),
                "User": extract_username(full_path),
            }

            if CRYPTNET_CONTENT_RE.search(parent_path):
                cryptnet_events.append(record)
            elif INETCACHE_IE_RE.search(parent_path):
                inetcache_events.append(record)

            all_creates.append(record)

    # Index by timestamp
    inetcache_by_ts = defaultdict(list)
    for r in inetcache_events:
        inetcache_by_ts[r["TimestampKey"]].append(r)

    creates_by_ts = defaultdict(list)
    for r in all_creates:
        creates_by_ts[r["TimestampKey"]].append(r)

    downloads = []
    seen = set()

    for cn in cryptnet_events:
        ts_key = cn["TimestampKey"]
        user = cn["User"]
        if (ts_key, user) in seen:
            continue
        seen.add((ts_key, user))

        # Find INetCache file at same timestamp (original URL filename)
        inet_matches = [r for r in inetcache_by_ts.get(ts_key, [])
                        if r["User"] == user or not user]

        original_name = ""
        original_raw = ""
        original_ext = ""
        if inet_matches:
            inet = inet_matches[0]
            original_raw = inet["FileName"]
            original_name = clean_inetcache_name(inet["FileName"])
            original_ext = inet["Extension"].lower()

        # Find destination file at same timestamp
        dest_candidates = [
            r for r in creates_by_ts.get(ts_key, [])
            if not CRYPTNET_RE.search(r["ParentPath"])
            and not INETCACHE_IE_RE.search(r["ParentPath"])
            and not NOISE_PATH_RE.search(r["ParentPath"])
            and "Close" in r["UpdateReasons"]
            and r["Extension"]
        ]

        if original_ext and dest_candidates:
            ext_match = [r for r in dest_candidates if r["Extension"].lower() == original_ext]
            if ext_match:
                dest_candidates = ext_match

        dest_path = dest_candidates[0]["FullPath"] if dest_candidates else ""
        dest_name = dest_candidates[0]["FileName"] if dest_candidates else ""

        downloads.append({
            "Timestamp": cn["Timestamp"],
            "User": user,
            "CacheHash": cn["FileName"],
            "OriginalName": original_name,
            "OriginalRaw": original_raw,
            "DestPath": dest_path,
            "DestName": dest_name,
            "EntryNumber": cn["EntryNumber"],
            "Confirmed": bool(original_name),
        })

    return downloads


# ---------------------------------------------------------------------------
# BITS detection
# ---------------------------------------------------------------------------

BITS_TEMP_RE = re.compile(r"^BIT[S0-9A-F]*\.tmp$", re.IGNORECASE)


def detect_bits(usn_path):
    """Detect BITS transfers by tracking BIT*.tmp rename chains."""
    entry_records = defaultdict(list)

    with open(usn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            reasons = row.get("UpdateReasons", "")
            filename = row.get("Name", "")

            if not BITS_TEMP_RE.match(filename) and "Rename" not in reasons:
                continue

            entry_num = row.get("EntryNumber", "")
            parent_path = row.get("ParentPath", "")
            ts = parse_timestamp(row.get("UpdateTimestamp", ""))

            entry_records[entry_num].append({
                "FileName": filename,
                "ParentPath": parent_path,
                "FullPath": build_full_path(parent_path, filename),
                "Timestamp": ts,
                "UpdateReasons": reasons,
                "EntryNumber": entry_num,
            })

    chains = []
    seen = set()

    for entry_num, records in entry_records.items():
        old_names = [r for r in records if "RenameOldName" in r["UpdateReasons"]]
        new_names = [r for r in records if "RenameNewName" in r["UpdateReasons"]]

        for old in old_names:
            if not BITS_TEMP_RE.match(old["FileName"]):
                continue
            for new in new_names:
                if new["Timestamp"] and old["Timestamp"]:
                    diff = abs((new["Timestamp"] - old["Timestamp"]).total_seconds())
                    if diff < 5:
                        dedup = (entry_num, new["FileName"], new["FullPath"])
                        if dedup in seen:
                            continue
                        seen.add(dedup)
                        chains.append({
                            "Timestamp": new["Timestamp"],
                            "TempFile": old["FileName"],
                            "FinalName": new["FileName"],
                            "FinalPath": new["FullPath"],
                            "User": extract_username(new["FullPath"]),
                            "EntryNumber": entry_num,
                        })

    return chains


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

BANNER = """
  ======================================================================
   ResidentReaper - LOLBin Ingress Detector
  ======================================================================"""


def print_summary(certutil_dl, bits_dl):
    """Print detection summary."""
    confirmed = sum(1 for d in certutil_dl if d["Confirmed"])
    cache_only = len(certutil_dl) - confirmed
    total = confirmed + len(bits_dl)

    print(f"\n  {'Method':<14s} {'Findings':>8s}   Notes")
    print(f"  {'-' * 14} {'-' * 8}   {'-' * 40}")
    print(f"  {'certutil':<14s} {confirmed:>8d}   confirmed downloads (INetCache correlated)")
    if cache_only:
        print(f"  {'':<14s} {cache_only:>8d}   cache-only (normal TLS/cert validation)")
    print(f"  {'BITSAdmin':<14s} {len(bits_dl):>8d}   temp-to-final rename chains")
    print(f"  {'-' * 14} {'-' * 8}")
    print(f"  {'TOTAL':<14s} {total:>8d}")


def print_certutil_findings(downloads):
    """Print certutil detection details."""
    confirmed = [d for d in downloads if d["Confirmed"]]
    if not confirmed:
        print(f"\n  No confirmed certutil downloads.")
        return

    print(f"\n  +- certutil Downloads ({len(confirmed)} found)")
    print(f"  |")

    for i, d in enumerate(sorted(confirmed, key=lambda x: x["Timestamp"]), 1):
        ts = fmt_ts(d["Timestamp"])
        user = d["User"] or "unknown"
        orig = d["OriginalName"]
        dest = d["DestPath"] or "(destination unknown)"

        print(f"  |  [{i}] {ts}")
        print(f"  |      User:        {user}")
        print(f"  |      Downloaded:  {orig}")
        print(f"  |      Saved to:    {dest}")
        print(f"  |      Cache hash:  {d['CacheHash']}")
        if d["OriginalRaw"] != d["OriginalName"]:
            print(f"  |      INetCache:   {d['OriginalRaw']}")
        print(f"  |")

    print(f"  +{'-' * 68}")


def print_bits_findings(chains):
    """Print BITS detection details."""
    if not chains:
        print(f"\n  No BITS transfers detected.")
        return

    print(f"\n  +- BITS Transfers ({len(chains)} found)")
    print(f"  |")

    for i, c in enumerate(sorted(chains, key=lambda x: x["Timestamp"]), 1):
        ts = fmt_ts(c["Timestamp"])
        user = c["User"] or "unknown"

        print(f"  |  [{i}] {ts}")
        print(f"  |      User:      {user}")
        print(f"  |      Temp file: {c['TempFile']}")
        print(f"  |      Final:     {c['FinalPath']}")
        print(f"  |")

    print(f"  +{'-' * 68}")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

EXPORT_HEADERS = ["Method", "Timestamp", "User", "OriginalName", "FinalPath",
                  "CacheHash", "TempFile", "EntryNumber"]


def export_csv(certutil_dl, bits_dl, output_path):
    """Export all findings to CSV."""
    rows = []

    for d in certutil_dl:
        if d["Confirmed"]:
            rows.append({
                "Method": "certutil",
                "Timestamp": d["Timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f"),
                "User": d["User"],
                "OriginalName": d["OriginalName"],
                "FinalPath": d["DestPath"],
                "CacheHash": d["CacheHash"],
                "TempFile": "",
                "EntryNumber": d["EntryNumber"],
            })

    for c in bits_dl:
        rows.append({
            "Method": "BITSAdmin",
            "Timestamp": c["Timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f"),
            "User": c["User"],
            "OriginalName": "",
            "FinalPath": c["FinalPath"],
            "CacheHash": "",
            "TempFile": c["TempFile"],
            "EntryNumber": c["EntryNumber"],
        })

    rows.sort(key=lambda x: x["Timestamp"])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"  Exported {len(rows)} finding(s) to {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ResidentReaper LOLBin Ingress Detector — Detect certutil and BITS downloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
detection methods:

  certutil:
    Correlates CryptnetUrlCache, INetCache, and destination file creation
    events at the same timestamp to identify certutil-based downloads.

  BITSAdmin:
    Tracks BIT*.tmp file creation and rename chains to reveal the final
    destination of BITS transfer jobs.

examples:
  python lolbin_ingress.py -f usn.csv
  python lolbin_ingress.py -f usn.csv -o findings.csv
  python lolbin_ingress.py -f usn.csv --method certutil
""",
    )
    parser.add_argument("-f", "--file", required=True, help="Path to USN Journal CSV file")
    parser.add_argument("-o", "--output", help="Export findings to CSV")
    parser.add_argument("--method", choices=["certutil", "bits", "all"], default="all",
                        help="Detection method to run (default: all)")

    args = parser.parse_args()

    print(BANNER)
    print(f"  Input: {args.file}", file=sys.stderr)

    certutil_dl = []
    bits_dl = []

    if args.method in ("certutil", "all"):
        certutil_dl = detect_certutil(args.file)
        confirmed = sum(1 for d in certutil_dl if d["Confirmed"])
        print(f"  certutil: {confirmed} confirmed download(s)", file=sys.stderr)

    if args.method in ("bits", "all"):
        bits_dl = detect_bits(args.file)
        print(f"  BITS:     {len(bits_dl)} transfer(s)", file=sys.stderr)

    print_summary(certutil_dl, bits_dl)
    print_certutil_findings(certutil_dl)
    print_bits_findings(bits_dl)

    if args.output:
        export_csv(certutil_dl, bits_dl, args.output)

    print()


if __name__ == "__main__":
    main()
