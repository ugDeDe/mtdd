#!/usr/bin/env python3
"""Offline executable IP accounting/history persistence acceptance."""

import argparse
import importlib.util
import json
import os
import secrets
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(binary):
    path = Path(__file__).resolve().parents[2] / "tools" / "faketls_probe.py"
    spec = importlib.util.spec_from_file_location("client", path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    with tempfile.TemporaryDirectory(prefix="mtdd-ipstats-") as directory:
        root = Path(directory)
        proxy_port, api_port, missing_me = (unused_port() for _ in range(3))
        token = secrets.token_hex(32)
        (root / "me.conf").write_text(f"default 2;\nproxy_for 2 127.0.0.1:{missing_me};\n")
        (root / "me.secret").write_bytes(secrets.token_bytes(128))
        config = {
            "tls_domain": "example.org", "ad_tag": secrets.token_hex(16),
            "proxy_port": proxy_port, "control_port": api_port,
            "users_path": "users.json", "unique_ip_stats_path": "unique-ips.json",
            "me_config_path": "me.conf", "me_secret_path": "me.secret",
            "max_connections": 16, "max_handshakes": 8,
            "handshake_timeout_seconds": 60, "shutdown_timeout_seconds": 1,
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config))
        child = None
        streams = []
        secret = None

        def request(route, method="GET", body=None):
            headers = {"Authorization": "Bearer " + token}
            data = None
            if body is not None:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(f"http://127.0.0.1:{api_port}" + route,
                                         data, headers, method=method)
            with urllib.request.urlopen(req, timeout=4) as response:
                return response.status, json.load(response)

        def wait_for(predicate):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise AssertionError("mtdd exited unexpectedly")
                try:
                    result = predicate()
                    if result:
                        return result
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.03)
            raise AssertionError("IP statistics observable-state timeout")

        def status():
            return request("/v1/status")[1]["data"]

        def stop():
            if child is not None and child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
                    raise AssertionError("bounded process shutdown failed")
                assert child.returncode == 0, "unclean mtdd exit"

        def open_authenticated(source):
            stream = socket.socket()
            streams.append(stream)
            stream.settimeout(4)
            stream.bind((source, 0))
            stream.connect(("127.0.0.1", proxy_port))
            hello, _ = client.client_hello("example.org", secret, False)
            stream.sendall(hello)
            for kind in (0x16, 0x14, 0x17):
                header, _ = client.read_record(stream)
                assert header[0] == kind, "unexpected FakeTLS authentication response"

        with (root / "process.log").open("ab", buffering=0) as log:
            def start():
                return subprocess.Popen([str(binary), "--config", str(config_path)],
                                        env={**os.environ, "MTDD_API_TOKEN": token},
                                        stdout=log, stderr=log)

            try:
                child = start()
                wait_for(lambda: request("/v1/health")[0] == 200)
                code, created = request("/v1/users", "POST", {"name": "ip_probe"})
                assert code == 201
                secret = bytes.fromhex(created["data"]["secret"])
                open_authenticated("127.0.0.1")
                open_authenticated("127.0.0.1")
                same = wait_for(lambda: (s if (s := status())["connections_active"] == 2
                                        and s["unique_ips_seen"] == 1 else None))
                assert same["unique_ip_history"]["timezone"] == "UTC"
                assert same["unique_ip_history"]["approximate"] is True
                for period in ("hour", "day", "week"):
                    assert same["unique_ip_history"][period]["estimate"] == 1
                # Handshake-only clients are "seen" but not "active" (default 1 MiB threshold).
                assert same["unique_ips_active"] == 0
                assert same["unique_ip_history"]["min_bytes"] == 1048576
                for period in ("hour_active", "day_active", "week_active"):
                    assert same["unique_ip_history"][period]["estimate"] == 0
                open_authenticated("127.0.0.2")
                wait_for(lambda: status()["unique_ips_seen"] == 2)
                for stream in streams:
                    stream.close()
                streams.clear()
                before = wait_for(lambda: (s if (s := status())["connections_active"] == 0
                                          and s["unique_ips_seen"] == 0 and s["unique_ips_active"] == 0 else None))
                history = before["unique_ip_history"]
                assert history["persistence_enabled"]
                assert history["persistence_failures"] == history["observation_failures"] == 0
                stop()
                checkpoint = root / "unique-ips.json"
                assert checkpoint.is_file() and checkpoint.stat().st_size < 65536
                assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600
                child = start()
                wait_for(lambda: request("/v1/health")[0] == 200)
                after = status()
                assert after["unique_ips_active"] == after["unique_ips_seen"] == 0
                restored = after["unique_ip_history"]
                assert restored["collection_started_at"] == history["collection_started_at"]
                for period in ("hour", "day", "week"):
                    if restored[period]["started_at"] == history[period]["started_at"]:
                        assert restored[period]["estimate"] == history[period]["estimate"]
                print("IP statistics smoke: passed; exact authenticated online dedup, calendar HLL, private checkpoint, restart retention")
            finally:
                for stream in streams:
                    stream.close()
                stop()
                logs = (root / "process.log").read_bytes()
                assert token.encode() not in logs, "API token leaked to logs"
                if secret is not None:
                    assert secret.hex().encode() not in logs, "proxy secret leaked to logs"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve())
