#!/usr/bin/env python3
"""Native control-plane contract against a real mtdd child, no Internet needed."""

import argparse
import contextlib
import json
import os
import secrets
import signal
import socket
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


def run(binary, parse_metrics=False):
    with tempfile.TemporaryDirectory(prefix="mtdd-control-") as directory:
        root = Path(directory)
        api_port, proxy_port, unavailable_me_port, metrics_port = (unused_port() for _ in range(4))
        token = secrets.token_hex(32)
        read_token = secrets.token_hex(32)
        metrics_token = secrets.token_hex(32)
        (root / "me.conf").write_text(
            f"default 2;\nproxy_for 2 127.0.0.1:{unavailable_me_port};\n"
        )
        (root / "me.secret").write_bytes(secrets.token_bytes(128))
        config = {
            "tls_domain": "example.org",
            "ad_tag": secrets.token_hex(16),
            "proxy_port": proxy_port,
            "control_port": api_port,
            "metrics_port": metrics_port,
            "api_read_token_env": "MTDD_API_READ_TOKEN",
            "metrics_token_env": "MTDD_METRICS_TOKEN",
            "users_path": "users.json",
            "me_config_path": "me.conf",
            "me_secret_path": "me.secret",
            "max_connections": 16,
            "max_handshakes": 8,
            "shutdown_timeout_seconds": 1,
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config))
        environment = {
            **os.environ,
            "MTDD_API_TOKEN": token,
            "MTDD_API_READ_TOKEN": read_token,
            "MTDD_METRICS_TOKEN": metrics_token,
        }
        base = f"http://127.0.0.1:{api_port}"
        metrics_base = f"http://127.0.0.1:{metrics_port}"

        def request(path, method="GET", body=None, authenticated=True, headers=None,
                    bearer=None, origin=None):
            request_headers = dict(headers or {})
            if authenticated:
                request_headers["Authorization"] = f"Bearer {bearer or token}"
            data = None if body is None else json.dumps(body).encode()
            if data is not None:
                request_headers["Content-Type"] = "application/json"
            req = urllib.request.Request((origin or base) + path, data, request_headers, method=method)
            try:
                response = urllib.request.urlopen(req, timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                payload = response.read()
                return response.status, response.headers, payload

        with (root / "process.log").open("wb") as log:
            child = subprocess.Popen(
                [str(binary), "--config", str(config_path)],
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    if child.poll() is not None:
                        raise AssertionError("mtdd exited before control became available")
                    try:
                        status, _, _ = request("/v1/health")
                        if status == 200:
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.monotonic() >= deadline:
                        raise AssertionError("control did not become available within 10s")
                    time.sleep(0.02)

                assert request("/v1/users", authenticated=False)[0] == 401
                assert request("/metrics", authenticated=False)[0] == 401
                assert request("/v1/users", "POST", {"name": "intruder"}, False)[0] == 401

                status, _, payload = request("/v1/users", "POST", {"name": "alice"})
                assert status == 201, ("create was not acknowledged by runtime", status)
                created = json.loads(payload)
                secret = created["data"]["secret"]
                assert len(secret) == 32
                status, headers, payload = request("/v1/users/alice")
                assert status == 200
                assert secret.encode() not in payload
                assert b'"secret"' not in payload
                assert headers.get("ETag"), "user response has no ETag"
                assert request("/v1/users", "POST", {"name": "alice"})[0] == 409
                assert request("/v1/users", "POST", {"name": "bad/name"})[0] == 400
                assert request("/v1/users/alice", "PATCH", {"quota": 100})[0] == 400
                assert request(
                    "/v1/users/alice", "PATCH", {"enabled": False},
                    headers={"If-Match": '"stale-revision"'},
                )[0] == 412

                assert request("/v1/users/alice", "PATCH", {"enabled": False})[0] == 200
                assert request("/v1/users/alice", "PATCH", {"enabled": True})[0] == 200
                assert request("/v1/users/alice", bearer=read_token)[0] == 200
                assert request("/v1/users/alice/links", bearer=read_token)[0] == 403
                assert request("/v1/users/alice", "DELETE", bearer=read_token)[0] == 403
                assert request("/v1/users", bearer=metrics_token)[0] == 401
                status, headers, scraped = request("/metrics", bearer=metrics_token, origin=metrics_base)
                assert status == 200 and b"mtdd_uptime_seconds" in scraped
                assert headers.get("Deprecation") is None
                assert request("/metrics", authenticated=False, origin=metrics_base)[0] == 401
                assert request("/metrics", origin=metrics_base)[0] == 401, "admin token must not scrape"
                assert request("/v1/users", bearer=metrics_token, origin=metrics_base)[0] == 404
                status, _, rotated = request("/v1/users/alice/rotate-secret", "POST", {})
                assert status == 200
                assert json.loads(rotated)["data"]["secret"] != secret
                assert request("/v1/ready")[0] == 503, "unavailable ME must not report ready"
                status, headers, metrics = request("/metrics")
                assert status == 200
                assert headers.get("Deprecation") == "true"
                assert b"mtdd_uptime_seconds" in metrics
                assert token.encode() not in metrics and secret.encode() not in metrics
                if parse_metrics:
                    from prometheus_client.parser import text_string_to_metric_families

                    families = list(text_string_to_metric_families(metrics.decode()))
                    samples = [sample for family in families for sample in family.samples]
                    assert samples and all(sample.name.startswith("mtdd_") for sample in samples)
                    identities = {(sample.name, tuple(sorted(sample.labels.items()))) for sample in samples}
                    assert len(identities) == len(samples), "duplicate Prometheus sample"
                    print(f"HTTP Prometheus parser: {len(families)} families, {len(samples)} unique samples")
                # v2 surface against the real binary: envelope, views, stats, actions, audit.
                status, headers, payload = request("/v1/system/info", bearer=read_token)
                info = json.loads(payload)
                assert status == 200 and info["ok"] is True
                assert headers.get("X-Request-Id") == str(info["request_id"])
                assert info["data"]["security"]["api"]["read_token"] is True
                status, _, payload = request("/v1/config", bearer=read_token)
                assert status == 200
                for credential in (token, read_token, metrics_token):
                    assert credential.encode() not in payload, "config view leaked a credential"
                status, _, payload = request("/v1/stats/summary", bearer=read_token)
                assert status == 200 and "seen" in json.loads(payload)["data"]["unique_ips"]["day"]
                assert request("/v1/stats/users?sort=traffic&limit=5", bearer=read_token)[0] == 200
                assert request("/v1/stats/users?bogus=1", bearer=read_token)[0] == 400
                assert request("/v1/users/alice", "PATCH", {"note": "smoke", "max_unique_ips": 2})[0] == 200
                status, _, payload = request("/v1/users/alice/disable", "POST")
                assert status == 200 and json.loads(payload)["data"]["user"]["enabled"] is False
                assert request("/v1/users/alice/enable", "POST", bearer=read_token)[0] == 403
                assert request("/v1/users/alice/enable", "POST")[0] == 200
                status, _, payload = request("/v1/events", bearer=read_token)
                assert status == 200
                actions = [event["action"] for event in json.loads(payload)["data"]["events"]]
                assert actions[-3:] == ["user.update", "user.disable", "user.enable"], actions
                assert secret.encode() not in payload
                assert request("/v1/users/alice", "DELETE")[0] == 200
                assert request("/v1/users/alice")[0] == 404
                print("control smoke: passed; token scopes, metrics listener, authentication, CRUD, ETag, redaction, metrics, ME readiness, v2 views/stats/actions/audit")
            finally:
                child.send_signal(signal.SIGTERM) if child.poll() is None else None
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
                    raise AssertionError("mtdd failed to stop within 10s")
                # Never print logs verbatim: an implementation under test may leak credentials.
                with contextlib.suppress(OSError):
                    log_bytes = (root / "process.log").read_bytes()
                    for credential in (token, read_token, metrics_token):
                        assert credential.encode() not in log_bytes, "API credential leaked to logs"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--parse-metrics", action="store_true", help="require prometheus-client and parse HTTP metrics")
    args = parser.parse_args()
    run(args.binary.resolve(), args.parse_metrics)
