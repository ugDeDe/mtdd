#!/usr/bin/env python3
"""proxymon collector: proxy-agnostic load sampling for fair mtdd/telemt comparison.

Everything is measured from the OS (/proc, NIC counters, the kernel TCP table),
never from the proxy's own metrics, so both proxies are measured by the same
definitions. One JSON line per interval goes to DIR/YYYY-MM-DD.jsonl (UTC).

Each record carries both instantaneous gauges and the exact counter deltas of
the interval (d_*), so a report can sum CPU seconds and bytes over any window
instead of averaging per-sample ratios.

No client addresses are written: only counts.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
PROXY_NAMES = ("mtdd", "telemt")
AGENT_PREFIX = "sharedd-node"  # comm is truncated to 15 chars
V4_MAPPED = "0000000000000000FFFF0000"
ME_PORT = 8888


def read(path):
    with open(path, "r") as f:
        return f.read()


def find_pid(match):
    """Lowest PID whose comm satisfies match (main process, not a thread)."""
    found = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            comm = read(f"/proc/{entry.name}/comm").strip()
        except OSError:
            continue
        if match(comm):
            found.append((int(entry.name), comm))
    return min(found) if found else (None, None)


def proc_counters(pid):
    try:
        stat = read(f"/proc/{pid}/stat").rsplit(")", 1)[1].split()
        status = {}
        for line in read(f"/proc/{pid}/status").splitlines():
            key, _, value = line.partition(":")
            if key in ("VmRSS", "VmHWM", "Threads"):
                status[key] = int(value.split()[0])
        pss = None
        try:
            for line in read(f"/proc/{pid}/smaps_rollup").splitlines():
                if line.startswith("Pss:"):
                    pss = int(line.split()[1])
                    break
        except OSError:
            pass
        try:
            fds = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            fds = None
        return {
            "start": int(stat[19]),
            "utime": int(stat[11]),
            "stime": int(stat[12]),
            "rss_kib": status.get("VmRSS", 0),
            "hwm_kib": status.get("VmHWM", 0),
            "pss_kib": pss,
            "threads": status.get("Threads", 0),
            "fds": fds,
        }
    except (OSError, IndexError, ValueError):
        return None


def host_cpu():
    # cpu  user nice system idle iowait irq softirq steal
    v = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:9]]
    return dict(zip(("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"), v))


def default_iface():
    for line in read("/proc/net/route").splitlines()[1:]:
        parts = line.split()
        if len(parts) > 2 and parts[1] == "00000000":
            return parts[0]
    return None


def nic(iface):
    base = f"/sys/class/net/{iface}/statistics"
    return {k: int(read(f"{base}/{k}")) for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")}


def tcp_table(port):
    """Counts of ESTABLISHED sockets: clients on the proxy port, ME upstreams."""
    conns = 0
    ips = set()
    me = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = read(path).splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "01":
                continue
            local_port = int(parts[1].rsplit(":", 1)[1], 16)
            raddr, rport = parts[2].rsplit(":", 1)
            if local_port == port:
                conns += 1
                if len(raddr) == 32 and raddr.startswith(V4_MAPPED):
                    raddr = raddr[24:]
                ips.add(raddr)
            elif int(rport, 16) == ME_PORT:
                me += 1
    return conns, len(ips), me


def sockstat():
    out = {}
    for line in read("/proc/net/sockstat").splitlines():
        parts = line.split()
        if parts and parts[0] == "TCP:":
            kv = dict(zip(parts[1::2], parts[2::2]))
            out = {
                "tcp_inuse": int(kv.get("inuse", 0)),
                "tcp_orphan": int(kv.get("orphan", 0)),
                "tcp_tw": int(kv.get("tw", 0)),
                "tcp_mem_mib": round(int(kv.get("mem", 0)) * PAGE / 1048576, 2),
            }
    return out


def tcp_snmp():
    rows = [l.split() for l in read("/proc/net/snmp").splitlines() if l.startswith("Tcp:")]
    if len(rows) >= 2:
        kv = dict(zip(rows[0][1:], rows[1][1:]))
        return {"out_segs": int(kv["OutSegs"]), "retrans_segs": int(kv["RetransSegs"])}
    return {"out_segs": 0, "retrans_segs": 0}


def meminfo():
    kv = {}
    for line in read("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        kv[key] = int(value.split()[0])
    return {"mem_total_mib": kv["MemTotal"] // 1024, "mem_available_mib": kv["MemAvailable"] // 1024}


def proxy_version(name):
    for binary in (f"/usr/local/bin/{name}", f"/bin/{name}", f"/usr/bin/{name}"):
        if os.path.exists(binary):
            try:
                out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5)
                return (out.stdout or out.stderr).strip().splitlines()[0]
            except (OSError, subprocess.SubprocessError, IndexError):
                return None
    return None


def snapshot(args, iface):
    pid, name = find_pid(lambda c: c in PROXY_NAMES)
    apid, _ = find_pid(lambda c: c.startswith(AGENT_PREFIX))
    return {
        "mono": time.monotonic(),
        "pid": pid,
        "name": name,
        "proc": proc_counters(pid) if pid else None,
        "agent_pid": apid,
        "agent": proc_counters(apid) if apid else None,
        "cpu": host_cpu(),
        "nic": nic(iface),
        "snmp": tcp_snmp(),
    }


def same_proc(a, b):
    return a and b and a["start"] == b["start"]


def record(args, iface, prev, cur, versions):
    dt = cur["mono"] - prev["mono"]
    r = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "dt": round(dt, 3),
         "host": socket.gethostname(), "iface": iface, "proxy": cur["name"]}
    if cur["name"]:
        # Keyed by process start time: a swapped binary is re-read after restart.
        key = (cur["name"], cur["proc"]["start"] if cur["proc"] else None)
        if key not in versions:
            versions.clear()
            versions[key] = proxy_version(cur["name"])
        r["version"] = versions[key]

    # proxy process
    p0, p1 = prev["proc"], cur["proc"]
    if p1:
        r.update(proc_rss_mib=round(p1["rss_kib"] / 1024, 2), proc_hwm_mib=round(p1["hwm_kib"] / 1024, 2),
                 proc_pss_mib=None if p1["pss_kib"] is None else round(p1["pss_kib"] / 1024, 2),
                 proc_threads=p1["threads"], proc_fds=p1["fds"])
    if same_proc(p0, p1) and prev["pid"] == cur["pid"]:
        du = (p1["utime"] - p0["utime"]) / CLK_TCK
        ds = (p1["stime"] - p0["stime"]) / CLK_TCK
        r.update(d_proc_cpu_s=round(du + ds, 4), proc_cpu_cores=round((du + ds) / dt, 4),
                 proc_user_cores=round(du / dt, 4), proc_sys_cores=round(ds / dt, 4))
    elif p1:
        r["proc_restarted"] = True

    # pool agent (same on both nodes; reported so it can be excluded or added)
    a0, a1 = prev["agent"], cur["agent"]
    if same_proc(a0, a1):
        d = (a1["utime"] + a1["stime"] - a0["utime"] - a0["stime"]) / CLK_TCK
        r.update(d_agent_cpu_s=round(d, 4), agent_rss_mib=round(a1["rss_kib"] / 1024, 2))

    # whole host CPU in cores
    c0, c1 = prev["cpu"], cur["cpu"]
    for k in c1:
        r[f"host_{k}_cores"] = round((c1[k] - c0[k]) / CLK_TCK / dt, 4)
    busy = sum(c1[k] - c0[k] for k in ("user", "nice", "system", "irq", "softirq")) / CLK_TCK
    r["d_host_busy_cpu_s"] = round(busy, 4)
    r["host_busy_cores"] = round(busy / dt, 4)

    # NIC: relay throughput is (rx+tx)/2: every relayed byte enters and leaves
    n0, n1 = prev["nic"], cur["nic"]
    drx = n1["rx_bytes"] - n0["rx_bytes"]
    dtx = n1["tx_bytes"] - n0["tx_bytes"]
    r.update(d_rx_bytes=drx, d_tx_bytes=dtx,
             rx_mbps=round(drx * 8 / dt / 1e6, 3), tx_mbps=round(dtx * 8 / dt / 1e6, 3),
             relay_mbps=round((drx + dtx) * 4 / dt / 1e6, 3),
             rx_pps=round((n1["rx_packets"] - n0["rx_packets"]) / dt, 1),
             tx_pps=round((n1["tx_packets"] - n0["tx_packets"]) / dt, 1))

    s0, s1 = prev["snmp"], cur["snmp"]
    dout = s1["out_segs"] - s0["out_segs"]
    r["retrans_pct"] = round(100 * (s1["retrans_segs"] - s0["retrans_segs"]) / dout, 3) if dout > 0 else 0.0

    conns, ips, me = tcp_table(args.port)
    r.update(client_conns=conns, client_ips=ips, me_conns=me)
    r.update(sockstat())
    r.update(meminfo())
    r["load1"] = float(read("/proc/loadavg").split()[0])
    return r


def prune(directory, keep_days):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime("%Y-%m-%d")
    for f in directory.glob("*.jsonl"):
        if f.stem < cutoff:
            f.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--dir", default="/var/lib/proxymon")
    ap.add_argument("--port", type=int, default=443, help="proxy listen port (clients)")
    ap.add_argument("--iface", default=None, help="default: interface of the default route")
    ap.add_argument("--keep-days", type=int, default=30)
    ap.add_argument("--once", action="store_true", help="print one record to stdout and exit")
    args = ap.parse_args()

    directory = Path(args.dir)
    directory.mkdir(parents=True, exist_ok=True)
    iface = args.iface or default_iface()
    if not iface:
        sys.exit("proxymon: no default-route interface; pass --iface")

    versions = {}
    prev = snapshot(args, iface)
    next_tick = time.monotonic() + args.interval
    last_prune = 0.0
    while True:
        time.sleep(max(0.0, next_tick - time.monotonic()))
        next_tick += args.interval
        cur = snapshot(args, iface)
        rec = record(args, iface, prev, cur, versions)
        prev = cur
        line = json.dumps(rec, separators=(",", ":"))
        if args.once:
            print(line)
            return
        day = rec["ts"][:10]
        with open(directory / f"{day}.jsonl", "a") as f:
            f.write(line + "\n")
        if time.monotonic() - last_prune > 3600:
            prune(directory, args.keep_days)
            last_prune = time.monotonic()


if __name__ == "__main__":
    main()
