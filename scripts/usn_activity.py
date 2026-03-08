#!/usr/bin/env python3
"""
ResidentReaper USN Activity Analyzer

Analyzes USN Journal CSV output for activity patterns: reason summaries,
activity heatmaps, and directory hotspots.

Usage:
    python usn_activity.py -f usn.csv
    python usn_activity.py -f usn.csv --top-dirs 30
    python usn_activity.py -f usn.csv -o export.csv
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime


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


def load_usn_records(usn_path):
    """Load all USN records from CSV."""
    records = []
    with open(usn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_timestamp(row.get("UpdateTimestamp", ""))
            records.append({
                "Name": row.get("Name", ""),
                "Extension": row.get("Extension", ""),
                "EntryNumber": row.get("EntryNumber", ""),
                "SequenceNumber": row.get("SequenceNumber", ""),
                "ParentPath": row.get("ParentPath", ""),
                "UpdateReasons": row.get("UpdateReasons", ""),
                "FileAttributes": row.get("FileAttributes", ""),
                "Timestamp": ts,
            })
    return records


def activity_summary(records):
    """Print summary of USN activity by reason flags."""
    print(f"\n{'='*70}")
    print(f"  USN Activity Summary")
    print(f"{'='*70}")
    print(f"  Total records: {len(records):,}\n")

    # Count individual reasons (they're pipe-separated)
    reason_counts = Counter()
    for r in records:
        reasons = r["UpdateReasons"]
        if reasons:
            for reason in reasons.split("|"):
                reason = reason.strip()
                if reason:
                    reason_counts[reason] += 1

    print(f"  Activity by Reason:")
    print(f"  {'-'*50}")
    for reason, count in reason_counts.most_common():
        bar = "#" * min(count * 40 // reason_counts.most_common(1)[0][1], 40)
        print(f"  {reason:35s} {count:>8,}  {bar}")

    # Extension breakdown
    ext_counts = Counter()
    for r in records:
        ext = r["Extension"].lower() if r["Extension"] else "(none)"
        ext_counts[ext] += 1

    print(f"\n  Top Extensions:")
    print(f"  {'-'*50}")
    for ext, count in ext_counts.most_common(15):
        print(f"  {ext:20s} {count:>8,}")

    # Time range
    timestamps = [r["Timestamp"] for r in records if r["Timestamp"]]
    if timestamps:
        earliest = min(timestamps)
        latest = max(timestamps)
        duration = latest - earliest
        print(f"\n  Time Range:")
        print(f"    Earliest: {earliest.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Latest:   {latest.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Duration: {duration.days} days, {duration.seconds // 3600} hours")


def activity_heatmap(records):
    """Show activity distribution by hour."""
    print(f"\n{'='*70}")
    print(f"  Activity Heatmap (by Hour)")
    print(f"{'='*70}")

    hourly = Counter()
    date_counts = Counter()

    for r in records:
        ts = r["Timestamp"]
        if not ts:
            continue
        hourly[ts.hour] += 1
        date_counts[ts.strftime("%Y-%m-%d")] += 1

    print(f"\n  By Hour:")
    max_hourly = max(hourly.values()) if hourly else 1
    for hour in range(24):
        count = hourly.get(hour, 0)
        bar = "#" * (count * 40 // max_hourly) if max_hourly > 0 else ""
        print(f"  {hour:02d}:00  {count:>8,}  {bar}")

    # Busiest dates
    print(f"\n  Top 10 Busiest Dates:")
    print(f"  {'-'*50}")
    for date, count in date_counts.most_common(10):
        print(f"  {date}  {count:>8,}")


def directory_hotspots(records, top_n=20):
    """Show most active directories."""
    print(f"\n{'='*70}")
    print(f"  Directory Hotspots (Top {top_n})")
    print(f"{'='*70}")

    dir_counts = Counter()
    dir_reasons = defaultdict(Counter)

    for r in records:
        parent = r["ParentPath"] if r["ParentPath"] else "."
        dir_counts[parent] += 1
        reasons = r["UpdateReasons"]
        if reasons:
            for reason in reasons.split("|"):
                reason = reason.strip()
                if reason:
                    dir_reasons[parent][reason] += 1

    print()
    for path, count in dir_counts.most_common(top_n):
        top_reasons = dir_reasons[path].most_common(3)
        reasons_str = ", ".join(f"{r}({c})" for r, c in top_reasons)
        print(f"  {count:>8,}  {path}")
        print(f"           {reasons_str}")


def export_csv(records, output_path):
    """Export records to CSV."""
    headers = ["Timestamp", "EntryNumber", "Name", "Extension", "ParentPath", "UpdateReasons", "FileAttributes"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in records:
            row = {h: r.get(h, "") for h in headers}
            if r["Timestamp"]:
                row["Timestamp"] = r["Timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")
            writer.writerow(row)

    print(f"Exported to {output_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="ResidentReaper USN Activity Analyzer — Analyze USN Journal patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python usn_activity.py -f usn.csv
  python usn_activity.py -f usn.csv --top-dirs 30
  python usn_activity.py -f usn.csv -o export.csv
""",
    )
    parser.add_argument("-f", "--file", required=True, help="Path to USN Journal CSV file")
    parser.add_argument("-o", "--output", help="Export records to CSV")
    parser.add_argument("--top-dirs", type=int, default=20, help="Number of top directories to show (default: 20)")

    args = parser.parse_args()

    print(f"Loading: {args.file}", file=sys.stderr)
    records = load_usn_records(args.file)
    print(f"Loaded {len(records):,} USN records", file=sys.stderr)

    if args.output:
        export_csv(records, args.output)

    activity_summary(records)
    activity_heatmap(records)
    directory_hotspots(records, args.top_dirs)

    print()


if __name__ == "__main__":
    main()
