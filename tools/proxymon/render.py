#!/usr/bin/env python3
"""Render a min/avg/max comparison table (PNG) from cached proxymon samples.

  render.py OUT.png NAME:IP:LABEL[:VERSION] ...

VERSION, when given, keeps only samples recorded with that exact proxy version.
Only samples with more than 500 client connections are used.
"""

import json
import os
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

CACHE = Path(os.environ.get("PROXYMON_CACHE", Path.home() / ".cache" / "proxymon"))
plt.rcParams["font.family"] = "Noto Sans"

PROTOCOL = os.environ.get("PROXYMON_PROTOCOL", "")


def load(name, version):
    rows = [json.loads(l) for l in open(CACHE / f"{name}.jsonl")]
    return [r for r in rows if "d_proc_cpu_s" in r and r["client_conns"] > 500
            and (not version or r.get("version") == version)]


def stats(rows):
    s = sum(r["dt"] for r in rows)
    gb = sum((r["d_rx_bytes"] + r["d_tx_bytes"]) / 2 * 8 / 1e9 for r in rows)
    cpu = sum(r["d_proc_cpu_s"] for r in rows)
    host = sum(r["d_host_busy_cpu_s"] for r in rows)
    cs = sum(r["client_conns"] * r["dt"] for r in rows)

    def wavg(k):
        return sum(r[k] * r["dt"] for r in rows) / s

    def busy(r):
        return r["relay_mbps"] >= 50

    out = {}

    def row(name, f, avg, fmt, filt=None):
        v = [f(r) for r in rows if filt is None or filt(r)]
        out[name] = tuple(fmt.format(x) for x in (min(v), avg, max(v))) if v else ("—", "—", "—")

    row("Клиентских IP", lambda r: r["client_ips"], wavg("client_ips"), "{:.0f}")
    row("Соединений", lambda r: r["client_conns"], cs / s, "{:.0f}")
    row("Трафик relay, Мбит/с", lambda r: r["relay_mbps"], gb * 1e3 / s, "{:.0f}")
    row("Мбит/с на 1000 соед.", lambda r: r["relay_mbps"] / r["client_conns"] * 1000,
        gb * 1e3 / s / (cs / s) * 1000, "{:.1f}")
    row("CPU прокси, ядер", lambda r: r["proc_cpu_cores"], cpu / s, "{:.2f}")
    row("CPU прокси на 1 Гбит/с *", lambda r: r["proc_cpu_cores"] / (r["relay_mbps"] / 1000),
        cpu / gb, "{:.2f}", busy)
    row("CPU хоста, ядер", lambda r: r["host_busy_cores"], host / s, "{:.2f}")
    row("CPU хоста на 1 Гбит/с *", lambda r: r["host_busy_cores"] / (r["relay_mbps"] / 1000),
        host / gb, "{:.2f}", busy)
    row("   из них softirq, ядер", lambda r: r["host_softirq_cores"], wavg("host_softirq_cores"), "{:.2f}")
    row("CPU-мс прокси на соед.-час", lambda r: r["proc_cpu_cores"] * 3600e3 / r["client_conns"],
        cpu * 1e3 / (cs / 3600), "{:.0f}")
    row("RSS прокси, МиБ", lambda r: r["proc_rss_mib"], wavg("proc_rss_mib"), "{:.0f}")
    row("RSS на 1000 соед., МиБ", lambda r: r["proc_rss_mib"] / r["client_conns"] * 1000,
        wavg("proc_rss_mib") / (cs / s) * 1000, "{:.1f}")
    row("Память TCP ядра, МиБ", lambda r: r["tcp_mem_mib"], wavg("tcp_mem_mib"), "{:.0f}")
    row("Ретрансмиты, %", lambda r: r["retrans_pct"], wavg("retrans_pct"), "{:.2f}")
    row("steal, ядер", lambda r: r["host_steal_cores"], wavg("host_steal_cores"), "{:.3f}")
    return out, s / 60, len(rows)


KEY_ROWS = {"Мбит/с на 1000 соед.", "CPU прокси на 1 Гбит/с *", "RSS на 1000 соед., МиБ"}


def main():
    out = sys.argv[1]
    nodes = []
    for spec in sys.argv[2:]:
        parts = spec.split(":")
        name, ip, label = parts[:3]
        version = parts[3] if len(parts) > 3 else ""
        nodes.append((name, ip, label, version))
    data = {n: load(n, v) for n, _, _, v in nodes}
    first = min(data[n][0]["ts"] for n, *_ in nodes)
    last = max(data[n][-1]["ts"] for n, *_ in nodes)
    S = {n: stats(data[n]) for n, *_ in nodes}
    metrics = list(S[nodes[0][0]][0])

    cell = [[m] + ["  /  ".join(S[n][0][m]) for n, *_ in nodes] for m in metrics]
    cell.append(["Длительность / замеров"] + [f"{S[n][1]:.0f} мин / {S[n][2]}" for n, *_ in nodes])
    cols = ["Параметр\n(мин / среднее / макс)"] + [f"{n}\n{lab}" + (f"\n{ip}" if ip not in ("", "-") else "") for n, ip, lab, _ in nodes]

    n_rows = len(cell) + 1
    fig = plt.figure(figsize=(20, 0.5 * n_rows + 4.6), dpi=110)
    fig.patch.set_facecolor("white")
    fig.text(0.012, 0.985, "mtdd против telemt: нагрузочное сравнение на одинаковых нодах",
             fontsize=21, weight="bold", va="top")
    fig.text(0.012, 0.955, f"Окно: {first[:16].replace('T', ' ')} – {last[11:16]} UTC  ·  "
             "в каждой ячейке: минимум / среднее / максимум  ·  ключевые строки выделены",
             fontsize=12.5, color="#444", va="top")
    ax = fig.add_axes([0.012, 0.40, 0.976, 0.52])
    ax.axis("off")
    t = ax.table(cellText=cell, colLabels=cols, loc="upper center", cellLoc="center",
                 colWidths=[0.2] + [0.8 / len(nodes)] * len(nodes))
    t.auto_set_font_size(False)
    t.set_fontsize(12.5)
    t.scale(1, 2.0)
    is_mtdd = {i + 1: lab.startswith("mtdd") for i, (_, _, lab, _) in enumerate(nodes)}
    for (r, c), x in t.get_celld().items():
        x.set_edgecolor("#bbbbbb")
        if r == 0:
            x.set_height(x.get_height() * 2.3)
            x.set_facecolor("#333333" if c == 0 else ("#2b4a6f" if is_mtdd[c] else "#8a4b14"))
            x.get_text().set_color("white")
            x.get_text().set_weight("bold")
            continue
        name = cell[r - 1][0]
        key = name in KEY_ROWS
        if c == 0:
            x.set_facecolor("#e3e3e3" if key else "#f4f4f4")
            x.get_text().set_ha("left")
            x.PAD = 0.03
        else:
            if is_mtdd[c]:
                x.set_facecolor("#cfe3f7" if key else "#eaf2fb")
            else:
                x.set_facecolor("#f9d9bf" if key else "#fdf1e7")
        if key:
            x.get_text().set_weight("bold")
    if PROTOCOL:
        fig.text(0.012, 0.012, PROTOCOL, fontsize=11.3, va="bottom", linespacing=1.5,
                 bbox=dict(facecolor="#fafafa", edgecolor="#cccccc", boxstyle="round,pad=0.8"))
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    print(out)


if __name__ == "__main__":
    main()
