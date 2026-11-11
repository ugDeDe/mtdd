#!/usr/bin/env python3
"""Merge mtdd suspect tables from several servers.

Each source is either a JSON file saved from `mtdd-ctl suspects json`
(or GET /v1/suspects), or `ssh:HOST` to fetch it over SSH as root.

    tools/suspects_merge.py ssh:203.0.113.10 ssh:198.51.100.7 old.json
    tools/suspects_merge.py --json ssh:203.0.113.10 > merged.json

An address seen on several servers with the same behaviour is the strongest
evidence, so rows sort by number of servers, then distinct signals, then score.
"""
import argparse
import json
import subprocess
import sys

CODES = {"probe_session": "A", "secret_text": "B", "raw_obfuscated2": "C", "multi_mode": "D",
         "wrong_secret": "E", "port_check": "F", "repeat_visits": "G", "junk": "H", "canary": "K"}


def load(source):
    if source.startswith("ssh:"):
        host = source[4:]
        text = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=15", "root@" + host, "mtdd-ctl suspects json"],
            check=True, capture_output=True, text=True, timeout=120).stdout
        name = host
    else:
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        name = source
    doc = json.loads(text)
    data = doc.get("data", doc)
    return name, data.get("suspects", [])


def merge(sources):
    merged = {}
    for name, rows in sources:
        for row in rows:
            ip = row.get("ip")
            if not ip:
                continue
            entry = merged.setdefault(ip, {
                "ip": ip, "servers": [], "signals": {}, "score": 0.0, "hits": 0,
                "first_seen": row.get("first_seen"), "last_seen": row.get("last_seen"),
                "users": set(), "platforms": set(), "syn": row.get("syn"),
            })
            entry["servers"].append(name)
            for signal, count in (row.get("signals") or {}).items():
                entry["signals"][signal] = entry["signals"].get(signal, 0) + int(count)
            entry["score"] = max(entry["score"], float(row.get("score", 0)))
            entry["hits"] += int(row.get("hits", 0))
            for key, pick in (("first_seen", min), ("last_seen", max)):
                if row.get(key):
                    entry[key] = pick(filter(None, (entry[key], row[key])))
            if row.get("user"):
                entry["users"].add(row["user"])
            if row.get("platform"):
                entry["platforms"].add(row["platform"])
    out = []
    for entry in merged.values():
        entry["matches"] = len(entry["signals"])
        entry["users"] = sorted(entry["users"])
        entry["platforms"] = sorted(entry["platforms"])
        out.append(entry)
    out.sort(key=lambda e: (len(e["servers"]), e["matches"], e["score"], e["last_seen"] or ""),
             reverse=True)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="+", help="JSON file or ssh:HOST")
    parser.add_argument("--json", action="store_true", help="print merged JSON")
    parser.add_argument("--min-servers", type=int, default=1)
    args = parser.parse_args()
    sources = []
    for source in args.sources:
        try:
            sources.append(load(source))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print("skip {}: {}".format(source, error), file=sys.stderr)
    rows = [row for row in merge(sources) if len(row["servers"]) >= args.min_servers]
    if args.json:
        json.dump(rows, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return
    print("{:>3} {:>3} {:>5}  {:<39} {:<14} {:<20} {}".format(
        "Срв", "Сов", "Score", "IP", "Признаки", "Платформа", "Пользователи"))
    for row in rows:
        marks = "".join(CODES.get(s, "?") for s in sorted(row["signals"], key=lambda s: CODES.get(s, "Z")))
        print("{:>3} {:>3} {:>5}  {:<39} {:<14} {:<20} {}".format(
            len(row["servers"]), row["matches"], round(row["score"]), row["ip"], marks,
            ",".join(row["platforms"]) or "-", ",".join(row["users"]) or "-"))


if __name__ == "__main__":
    main()
