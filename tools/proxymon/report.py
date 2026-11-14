#!/usr/bin/env python3
"""proxymon report: pull samples from nodes and compare them fairly.

  report.py pull   NAME=user@host ...          copy the nodes' JSONL into the cache
  report.py summary [--hours H] [NAME ...]     totals over a window, per node
  report.py bins    [--hours H] [--by relay|ips]   comparison at equal load
  report.py live    NAME=user@host ...          last sample of every node, refreshed

Ratios are computed from summed counters (CPU seconds / gigabits over the whole
window), never as an average of per-sample ratios, so idle samples cannot
inflate them. "relay" throughput is (NIC rx + tx) / 2: each relayed byte enters
and leaves the host once.

ssh auth: keys, or SSHPASS in the environment (sshpass is then used).
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

CACHE = Path(os.environ.get("PROXYMON_CACHE", Path.home() / ".cache" / "proxymon"))
REMOTE_DIR = "/var/lib/proxymon"


def ssh_cmd(target, command):
    base = ["ssh", "-o", "BatchMode=no", "-o", "ConnectTimeout=15", target, command]
    if os.environ.get("SSHPASS"):
        base = ["sshpass", "-e"] + base
    return subprocess.run(base, capture_output=True, text=True, timeout=120)


def parse_nodes(items):
    nodes = []
    for item in items:
        name, _, target = item.partition("=")
        if not target:
            sys.exit(f"node must be NAME=user@host: {item}")
        nodes.append((name, target))
    return nodes


def pull(args):
    for name, target in parse_nodes(args.nodes):
        res = ssh_cmd(target, f"cat {REMOTE_DIR}/*.jsonl")
        if res.returncode != 0:
            print(f"{name}: pull failed: {res.stderr.strip()}", file=sys.stderr)
            continue
        out = CACHE / f"{name}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(res.stdout)
        print(f"{name}: {res.stdout.count(chr(10))} samples -> {out}")


def load(name, hours):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    rows = []
    with open(CACHE / f"{name}.jsonl") as f:
        for line in f:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r["ts"] >= cutoff:
                rows.append(r)
    return rows


def cached_names(selected):
    if selected:
        return selected
    return sorted(p.stem for p in CACHE.glob("*.jsonl"))


def pct(values, q):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def agg(rows):
    """Window totals. Only samples with a valid proxy CPU delta are counted."""
    rows = [r for r in rows if "d_proc_cpu_s" in r]
    if not rows:
        return None
    secs = sum(r["dt"] for r in rows)
    gbits = sum((r["d_rx_bytes"] + r["d_tx_bytes"]) / 2 * 8 / 1e9 for r in rows)
    gbytes = gbits / 8
    proc = sum(r["d_proc_cpu_s"] for r in rows)
    host = sum(r["d_host_busy_cpu_s"] for r in rows)
    agent = sum(r.get("d_agent_cpu_s", 0) for r in rows)
    conn_secs = sum(r["client_conns"] * r["dt"] for r in rows)
    return {
        "samples": len(rows),
        "hours": secs / 3600,
        "proxy": rows[-1].get("version") or rows[-1].get("proxy") or "?",
        "relay_mbps_avg": gbits * 1e3 / secs,
        "relay_mbps_p95": pct([r["relay_mbps"] for r in rows], 0.95),
        "conns_avg": conn_secs / secs,
        "conns_p95": pct([r["client_conns"] for r in rows], 0.95),
        "ips_avg": sum(r["client_ips"] * r["dt"] for r in rows) / secs,
        "ips_p95": pct([r["client_ips"] for r in rows], 0.95),
        "me_conns_avg": sum(r["me_conns"] * r["dt"] for r in rows) / secs,
        "proc_cores_avg": proc / secs,
        "proc_cores_p95": pct([r["proc_cpu_cores"] for r in rows], 0.95),
        "host_cores_avg": host / secs,
        "softirq_cores_avg": sum(r["host_softirq_cores"] * r["dt"] for r in rows) / secs,
        "steal_cores_avg": sum(r["host_steal_cores"] * r["dt"] for r in rows) / secs,
        "agent_cores_avg": agent / secs,
        "proc_cores_per_gbit": proc / gbits if gbits > 0 else None,
        "host_cores_per_gbit": host / gbits if gbits > 0 else None,
        "proc_cpu_s_per_gb": proc / gbytes if gbytes > 0 else None,
        "proc_cpu_ms_per_conn_hour": proc * 1000 / (conn_secs / 3600) if conn_secs > 0 else None,
        "rss_p50": pct([r.get("proc_rss_mib") for r in rows], 0.5),
        "rss_max": max((r.get("proc_rss_mib") or 0) for r in rows),
        "pss_p50": pct([r.get("proc_pss_mib") for r in rows], 0.5),
        "kib_per_conn": (pct([r.get("proc_rss_mib") for r in rows], 0.5) or 0) * 1024
        / max(1.0, pct([r["client_conns"] for r in rows], 0.5) or 1.0),
        "tcp_mem_p50": pct([r.get("tcp_mem_mib") for r in rows], 0.5),
        "retrans_p50": pct([r.get("retrans_pct") for r in rows], 0.5),
        "restarts": sum(1 for r in rows if r.get("proc_restarted")),
    }


ROWS = [
    ("прокси", "proxy", "{}"),
    ("часов в окне", "hours", "{:.1f}"),
    ("трафик relay, Мбит/с ср.", "relay_mbps_avg", "{:.1f}"),
    ("трафик relay, Мбит/с p95", "relay_mbps_p95", "{:.1f}"),
    ("соединений ср. / p95", ("conns_avg", "conns_p95"), "{:.0f} / {:.0f}"),
    ("клиентских IP ср. / p95", ("ips_avg", "ips_p95"), "{:.0f} / {:.0f}"),
    ("соединений к ME ср.", "me_conns_avg", "{:.1f}"),
    ("CPU прокси, ядер ср. / p95", ("proc_cores_avg", "proc_cores_p95"), "{:.3f} / {:.3f}"),
    ("CPU хоста (без steal), ядер ср.", "host_cores_avg", "{:.3f}"),
    ("  из них softirq, ядер", "softirq_cores_avg", "{:.3f}"),
    ("  агент пула, ядер", "agent_cores_avg", "{:.3f}"),
    ("steal, ядер ср.", "steal_cores_avg", "{:.3f}"),
    ("ядер прокси на 1 Гбит/с", "proc_cores_per_gbit", "{:.3f}"),
    ("ядер хоста на 1 Гбит/с", "host_cores_per_gbit", "{:.3f}"),
    ("CPU-с прокси на 1 ГБ", "proc_cpu_s_per_gb", "{:.2f}"),
    ("CPU-мс прокси на соед.-час", "proc_cpu_ms_per_conn_hour", "{:.1f}"),
    ("RSS прокси, МиБ p50 / max", ("rss_p50", "rss_max"), "{:.1f} / {:.1f}"),
    ("PSS прокси, МиБ p50", "pss_p50", "{:.1f}"),
    ("RSS на соединение, КиБ (p50/p50)", "kib_per_conn", "{:.1f}"),
    ("память TCP ядра, МиБ p50", "tcp_mem_p50", "{:.1f}"),
    ("ретрансмиты, % p50", "retrans_p50", "{:.3f}"),
    ("перезапусков прокси", "restarts", "{}"),
]


def fmt(stats, key, pattern):
    keys = key if isinstance(key, tuple) else (key,)
    values = [stats.get(k) for k in keys]
    if any(v is None for v in values):
        return "—"
    return pattern.format(*values)


def print_table(names, stats_list):
    width = max(len(r[0]) for r in ROWS) + 2
    colw = max(22, *(len(s["proxy"]) + 2 for s in stats_list if s))
    print("".ljust(width) + "".join(n.ljust(colw) for n in names))
    for label, key, pattern in ROWS:
        cells = [fmt(s, key, pattern) if s else "нет данных" for s in stats_list]
        print(label.ljust(width) + "".join(c.ljust(colw) for c in cells))


def summary(args):
    names = cached_names(args.names)
    stats = [agg(load(n, args.hours)) for n in names]
    print_table(names, stats)
    for n, s in zip(names, stats):
        if s and s["steal_cores_avg"] > 0.05:
            print(f"! {n}: steal {s['steal_cores_avg']:.3f} ядра — соседи по хосту искажают замер")
        if s and s["relay_mbps_avg"] < 20:
            print(f"! {n}: средний трафик < 20 Мбит/с — «ядер на Гбит» здесь в основном фоновая цена простоя")


BIN_EDGES = {
    "relay": [0, 25, 50, 100, 200, 400, 800, 1e9],
    "ips": [0, 50, 100, 200, 400, 800, 1600, 1e9],
}


def bins(args):
    names = cached_names(args.names)
    key = "relay_mbps" if args.by == "relay" else "client_ips"
    edges = BIN_EDGES[args.by]
    data = {n: load(n, args.hours) for n in names}
    unit = "Мбит/с" if args.by == "relay" else "IP"
    print(f"Сравнение при равной нагрузке, корзины по {'трафику' if args.by == 'relay' else 'числу клиентских IP'} ({unit}).")
    print("В ячейке: ядер прокси на 1 Гбит/с | CPU прокси, ядер | RSS p50, МиБ | соединений p50 | n замеров")
    print("корзина".ljust(14) + "".join(n.ljust(52) for n in names))
    for lo, hi in zip(edges, edges[1:]):
        cells = []
        for n in names:
            sel = [r for r in data[n] if "d_proc_cpu_s" in r and lo <= r[key] < hi]
            if len(sel) < args.min_samples:
                cells.append(f"мало данных (n={len(sel)})")
                continue
            s = agg(sel)
            cpg = "—" if s["proc_cores_per_gbit"] is None else f"{s['proc_cores_per_gbit']:.3f}"
            cells.append(f"{cpg} | {s['proc_cores_avg']:.3f} | {s['rss_p50']:.1f} | "
                         f"{pct([r['client_conns'] for r in sel], 0.5):.0f} | {len(sel)}")
        label = f"{lo:g}–{hi:g}" if hi < 1e9 else f"{lo:g}+"
        print(label.ljust(14) + "".join(c.ljust(52) for c in cells))


def live(args):
    nodes = parse_nodes(args.nodes)
    while True:
        lines = []
        for name, target in nodes:
            res = ssh_cmd(target, f"tail -n 1 {REMOTE_DIR}/$(date -u +%F).jsonl")
            try:
                r = json.loads(res.stdout)
            except json.JSONDecodeError:
                lines.append(f"{name:<10} нет данных: {res.stderr.strip()[:80]}")
                continue
            gbit = r["relay_mbps"] / 1000
            cpg = r.get("proc_cpu_cores", 0) / gbit if gbit > 0.005 else float("nan")
            lines.append(
                f"{name:<10} {r['ts'][11:19]} {r.get('proxy') or '?':<6} "
                f"IP {r['client_ips']:>5} conn {r['client_conns']:>5} ME {r['me_conns']:>3} | "
                f"relay {r['relay_mbps']:>7.1f} Мбит/с | proc {r.get('proc_cpu_cores', 0):.3f} ядра "
                f"({cpg:.2f}/Гбит) host {r['host_busy_cores']:.3f} sirq {r['host_softirq_cores']:.3f} "
                f"steal {r['host_steal_cores']:.3f} | RSS {r.get('proc_rss_mib', 0):.1f} PSS {r.get('proc_pss_mib') or 0:.1f} МиБ "
                f"tcpmem {r.get('tcp_mem_mib', 0):.1f}")
        print("\n".join(lines), flush=True)
        if args.once:
            return
        print()
        time.sleep(args.interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pull"); p.add_argument("nodes", nargs="+"); p.set_defaults(func=pull)
    s = sub.add_parser("summary"); s.add_argument("names", nargs="*")
    s.add_argument("--hours", type=float, default=24); s.set_defaults(func=summary)
    b = sub.add_parser("bins"); b.add_argument("names", nargs="*")
    b.add_argument("--hours", type=float, default=24); b.add_argument("--by", choices=("relay", "ips"), default="relay")
    b.add_argument("--min-samples", type=int, default=30); b.set_defaults(func=bins)
    l = sub.add_parser("live"); l.add_argument("nodes", nargs="+")
    l.add_argument("--interval", type=float, default=10); l.add_argument("--once", action="store_true")
    l.set_defaults(func=live)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
