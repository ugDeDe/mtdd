#!/usr/bin/env python3
"""Exercise the download path without root, systemd, or external network."""

import hashlib
import http.server
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import unicodedata
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.branch = self.root / "channel-dev"
        self.branch.mkdir()
        self.binary = b"#!/bin/sh\necho mtdd-test\n"
        (self.branch / "mtdd-linux-x86_64").write_bytes(self.binary)
        self.checksum(hashlib.sha256(self.binary).hexdigest())
        handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
            *args, directory=str(self.root), **kwargs
        )
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def checksum(self, digest):
        (self.branch / "SHA256SUMS").write_text(f"{digest}  mtdd-linux-x86_64\n")

    def run_installer(self, *args):
        return subprocess.run(
            ["bash", str(INSTALLER), "--binary-only",
             "--repo", "example/mtdd", "--branch", "dev", "--base-url",
             f"http://127.0.0.1:{self.server.server_port}", "--output",
             str(self.root / "installed"), *args],
            text=True, capture_output=True, timeout=20,
        )

    def test_installs_selected_branch_and_checks_hash(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "installed").read_bytes(), self.binary)
        self.assertTrue((self.root / "installed").stat().st_mode & 0o111)
        self.assertIn("mtdd", result.stdout)
        self.assertIn("dev", result.stdout)
        self.assertIn("SHA-256", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_bad_checksum_preserves_existing_binary(self):
        (self.root / "installed").write_bytes(b"previous")
        self.checksum("0" * 64)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "installed").read_bytes(), b"previous")

    def test_invalid_branch_is_rejected(self):
        result = self.run_installer("--branch", "other")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "installed").exists())

    def test_help_describes_interactive_and_automation_options(self):
        result = subprocess.run(["bash", str(INSTALLER), "--help"],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        for option in ("--branch", "--domain", "--ad-tag", "--public-host",
                       "--public-port", "--binary-only"):
            self.assertIn(option, result.stdout)

    def test_help_describes_management_commands(self):
        result = subprocess.run(["bash", str(INSTALLER), "--help"],
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        for token in ("status", "users add", "users remove", "users rotate",
                      "metrics", "uninstall", "menu", "mtdd-ctl", "logs",
                      "check-config", "host"):
            self.assertIn(token, result.stdout)

    def test_unknown_command_is_rejected(self):
        result = subprocess.run(["bash", str(INSTALLER), "bogus"],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Неизвестная команда", result.stderr)

    def test_management_commands_are_incompatible_with_binary_only(self):
        result = subprocess.run(["bash", str(INSTALLER), "status", "--binary-only"],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--binary-only", result.stderr)

    def test_management_commands_fail_cleanly_without_installation(self):
        for command in (["status"], ["users", "list"], ["menu"], ["check-config"]):
            result = subprocess.run(["bash", str(INSTALLER), *command],
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, command)
            self.assertRegex(result.stderr + result.stdout, "root|установ")

    def test_terminal_colors_respect_no_color(self):
        if not shutil.which("script"):
            self.skipTest("script is required for a pseudo-terminal")
        args = ["bash", str(INSTALLER), "--binary-only",
                "--branch", "dev", "--base-url", f"http://127.0.0.1:{self.server.server_port}",
                "--output", str(self.root / "installed")]
        env = os.environ.copy()
        env["TERM"] = "xterm"
        env.pop("NO_COLOR", None)
        for disabled in (False, True):
            if disabled:
                env["NO_COLOR"] = "1"
            result = subprocess.run(["script", "-q", "-e", "-c", shlex.join(args), "/dev/null"],
                                    env=env, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual("\x1b[" in result.stdout, not disabled)

    def test_interactive_install_accepts_answers_through_a_pipe(self):
        binary_path = os.environ.get("MTDD_INSTALLER_INTEGRATION_BINARY")
        if not binary_path or not shutil.which("unshare") or not shutil.which("script"):
            self.skipTest("integration binary, unshare and script are required")
        if subprocess.run(["unshare", "-Ur", "-m", "true"], capture_output=True).returncode:
            self.skipTest("unprivileged mount namespaces unavailable")
        binary = pathlib.Path(binary_path).resolve().read_bytes()
        (self.branch / "mtdd-linux-x86_64").write_bytes(binary)
        self.checksum(hashlib.sha256(binary).hexdigest())
        sandbox = self.root / "interactive"
        for name in ("etc", "etc/sysctl.d", "varlib", "bin", "run/systemd/system", "commands"):
            (sandbox / name).mkdir(parents=True)
        (sandbox / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nmtdd:x:0:0:mtdd:/var/lib/mtdd:/usr/sbin/nologin\n")
        (sandbox / "etc/group").write_text("root:x:0:\nmtdd:x:0:\n")
        for name, content in {
            "systemctl": "#!/bin/sh\nexit 0\n",
            "curl": "#!/bin/sh\ncase \"$*\" in *api.ipify.org*) printf '8.8.8.8';; *) exec /usr/bin/curl \"$@\";; esac\n",
        }.items():
            command = sandbox / "commands" / name
            command.write_text(content)
            command.chmod(0o755)
        env = os.environ.copy()
        env.update(MTDD_TEST_SANDBOX=str(sandbox), MTDD_TEST_INSTALLER=str(INSTALLER),
                   MTDD_TEST_URL=f"http://127.0.0.1:{self.server.server_port}",
                   PATH=f"{sandbox / 'commands'}:/usr/bin:/bin", TERM="dumb")
        command = r'''
set -eu
mount --bind "$MTDD_TEST_SANDBOX/etc" /etc
mount --bind "$MTDD_TEST_SANDBOX/varlib" /var/lib
mount --bind "$MTDD_TEST_SANDBOX/bin" /usr/local/bin
mount --bind "$MTDD_TEST_SANDBOX/run" /run
script -q -e -c 'bash "$MTDD_TEST_INSTALLER" --branch dev --base-url "$MTDD_TEST_URL" --domain bob.example.org --ad-tag 00112233445566778899aabbccddeeff --port 14443 --user bob --public-host proxy.example.org --public-port 443' /dev/null
python3 -c 'from pathlib import Path; [Path(p).unlink() for p in ("/etc/mtdd/config.json", "/etc/mtdd/credentials.env", "/var/lib/mtdd/users.json")]'
printf 'dev\nexample.org\n00112233445566778899aabbccddeeff\n14443\nalice\n' |
  script -q -e -c 'bash "$MTDD_TEST_INSTALLER" --base-url "$MTDD_TEST_URL" --public-port 443' /dev/null
'''
        result = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", command],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads((sandbox / "etc/mtdd/config.json").read_text())
        self.assertEqual(config["proxy_port"], 14443)
        self.assertEqual(config["public_host"], "8.8.8.8")
        self.assertIn("alice: https://t.me/proxy?", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_system_install_and_update_in_isolated_mount_namespace(self):
        binary_path = os.environ.get("MTDD_INSTALLER_INTEGRATION_BINARY")
        if not binary_path or not shutil.which("unshare"):
            self.skipTest("set MTDD_INSTALLER_INTEGRATION_BINARY and install unshare")
        probe = subprocess.run(["unshare", "-Ur", "-m", "true"], capture_output=True)
        if probe.returncode:
            self.skipTest("unprivileged mount namespaces unavailable")
        binary = pathlib.Path(binary_path).resolve().read_bytes()
        (self.branch / "mtdd-linux-x86_64").write_bytes(binary)
        self.checksum(hashlib.sha256(binary).hexdigest())
        sandbox = self.root / "sandbox"
        for name in ("etc", "etc/sysctl.d", "varlib", "bin", "run/systemd/system", "commands"):
            (sandbox / name).mkdir(parents=True)
        (sandbox / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nmtdd:x:0:0:mtdd:/var/lib/mtdd:/usr/sbin/nologin\n"
        )
        (sandbox / "etc/group").write_text("root:x:0:\nmtdd:x:0:\n")
        systemctl = sandbox / "commands/systemctl"
        systemctl.write_text("#!/bin/sh\nexit 0\n")
        systemctl.chmod(0o755)
        curl = sandbox / "commands/curl"
        curl.write_text("#!/bin/sh\ncase \"$*\" in *api.ipify.org*) printf '8.8.8.8';; *) exec /usr/bin/curl \"$@\";; esac\n")
        curl.chmod(0o755)
        env = os.environ.copy()
        env["MTDD_TEST_SANDBOX"] = str(sandbox)
        env["MTDD_TEST_INSTALLER"] = str(INSTALLER)
        env["MTDD_TEST_URL"] = f"http://127.0.0.1:{self.server.server_port}"
        env["PATH"] = f"{sandbox / 'commands'}:/usr/bin:/bin"
        script = r'''
set -eu
mount --bind "$MTDD_TEST_SANDBOX/etc" /etc
mount --bind "$MTDD_TEST_SANDBOX/varlib" /var/lib
mount --bind "$MTDD_TEST_SANDBOX/bin" /usr/local/bin
mount --bind "$MTDD_TEST_SANDBOX/run" /run
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL" --domain example.org \
  --ad-tag 00112233445566778899aabbccddeeff --port 14443 --user alice \
  --public-host proxy.example.org --public-port 443
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL" --domain ignored.example --port 14444
python3 -c 'import json; p="/etc/mtdd/config.json"; d=json.load(open(p)); del d["public_host"]; d["me_connections_per_dc"]=20; open(p,"w").write(json.dumps(d))'
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL"
'''
        result = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", script],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads((sandbox / "etc/mtdd/config.json").read_text())
        users = json.loads((sandbox / "varlib/mtdd/users.json").read_text())
        self.assertEqual(config["proxy_port"], 14443)
        self.assertEqual(config["tls_domain"], "example.org")
        self.assertEqual(config["public_host"], "8.8.8.8")
        self.assertEqual(config["public_port"], 443)
        self.assertEqual(users["users"][0]["name"], "alice")
        self.assertEqual(len(users["users"][0]["secret"]), 32)
        link = ("https://t.me/proxy?server=proxy.example.org&port=443&secret=ee"
                + users["users"][0]["secret"] + "example.org".encode().hex())
        self.assertEqual(result.stdout.count(link), 2)
        self.assertIn(link.replace("proxy.example.org", "8.8.8.8"), result.stdout)
        self.assertIn("Telegram", result.stdout)
        self.assertIn("systemctl status mtdd", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)
        self.assertEqual((sandbox / "etc/mtdd/credentials.env").stat().st_mode & 0o777, 0o600)
        self.assertTrue((sandbox / "etc/systemd/system/mtdd.service").exists())
        # Capacity defaults: filled when absent, never overriding an operator.
        self.assertGreaterEqual(config["global_buffer_bytes"], 64 << 20)
        self.assertLessEqual(config["global_buffer_bytes"], 1 << 30)
        self.assertEqual(config["me_connections_per_dc"], 20,
                         "an operator's explicit value must survive the update")
        unit = (sandbox / "etc/systemd/system/mtdd.service").read_text()
        self.assertIn("LimitNOFILE=1048576", unit)
        self.assertIn("ExecReload=/bin/kill -HUP $MAINPID", unit)
        nettune_unit = (sandbox / "etc/systemd/system/mtdd-nettune.service").read_text()
        self.assertIn("ExecStart=/usr/local/bin/mtdd-nettune start", nettune_unit)
        self.assertIn("ExecStop=/usr/local/bin/mtdd-nettune stop", nettune_unit)
        self.assertTrue(os.access(sandbox / "bin/mtdd-nettune", os.X_OK))
        sysctl = (sandbox / "etc/sysctl.d/99-mtdd-load.conf").read_text()
        self.assertIn("net.core.somaxconn = ", sysctl)
        self.assertIn("net.ipv4.tcp_orphan_retries = ", sysctl)
        bad_candidate = b"#!/bin/sh\nexit 1\n"
        (self.branch / "mtdd-linux-x86_64").write_bytes(bad_candidate)
        self.checksum(hashlib.sha256(bad_candidate).hexdigest())
        failed = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", script],
                                env=env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual((sandbox / "bin/mtdd").read_bytes(), binary)

    def test_management_subcommands_in_isolated_mount_namespace(self):
        binary_path = os.environ.get("MTDD_INSTALLER_INTEGRATION_BINARY")
        if not binary_path or not shutil.which("unshare") or not shutil.which("script"):
            self.skipTest("integration binary, unshare and script are required")
        if subprocess.run(["unshare", "-Ur", "-m", "true"], capture_output=True).returncode:
            self.skipTest("unprivileged mount namespaces unavailable")
        binary = pathlib.Path(binary_path).resolve().read_bytes()
        (self.branch / "mtdd-linux-x86_64").write_bytes(binary)
        self.checksum(hashlib.sha256(binary).hexdigest())
        sandbox = self.root / "manage"
        for name in ("etc", "etc/sysctl.d", "varlib", "bin", "run/systemd/system", "commands"):
            (sandbox / name).mkdir(parents=True)
        (sandbox / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nmtdd:x:0:0:mtdd:/var/lib/mtdd:/usr/sbin/nologin\n")
        (sandbox / "etc/group").write_text("root:x:0:\nmtdd:x:0:\n")
        for name, content in {
            "systemctl": "#!/bin/sh\nexit 0\n",
            "curl": "#!/bin/sh\ncase \"$*\" in *api.ipify.org*) printf '8.8.8.8';; *) exec /usr/bin/curl \"$@\";; esac\n",
        }.items():
            command = sandbox / "commands" / name
            command.write_text(content)
            command.chmod(0o755)
        env = os.environ.copy()
        env.update(MTDD_TEST_SANDBOX=str(sandbox), MTDD_TEST_INSTALLER=str(INSTALLER),
                   MTDD_TEST_URL=f"http://127.0.0.1:{self.server.server_port}",
                   PATH=f"{sandbox / 'commands'}:/usr/bin:/bin", TERM="dumb")
        script = r'''
set -eu
mount --bind "$MTDD_TEST_SANDBOX/etc" /etc
mount --bind "$MTDD_TEST_SANDBOX/varlib" /var/lib
mount --bind "$MTDD_TEST_SANDBOX/bin" /usr/local/bin
mount --bind "$MTDD_TEST_SANDBOX/run" /run
bash "$MTDD_TEST_INSTALLER" --repo example/mtdd --branch dev \
  --base-url "$MTDD_TEST_URL" --domain example.org \
  --ad-tag 00112233445566778899aabbccddeeff --port 14443 --user alice \
  --public-host proxy.example.org --public-port 443 >/dev/null
test -x /usr/local/bin/mtdd-ctl
bash "$MTDD_TEST_INSTALLER" check-config
if bash "$MTDD_TEST_INSTALLER" status >"$MTDD_TEST_SANDBOX/status.out" 2>&1; then
  echo "status must fail while the API is down" >&2
  exit 1
fi
grep -q "не отвечает" "$MTDD_TEST_SANDBOX/status.out"
if bash "$MTDD_TEST_INSTALLER" users list >"$MTDD_TEST_SANDBOX/users.out" 2>&1; then
  echo "users list must fail while the API is down" >&2
  exit 1
fi
printf '0\n' | script -q -e -c 'bash "$MTDD_TEST_INSTALLER" menu' /dev/null
'''
        result = subprocess.run(["unshare", "-Ur", "-m", "bash", "-c", script],
                                env=env, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Конфигурация корректна", result.stdout)
        self.assertIn("управление прокси", result.stdout)
        self.assertIn("Готово", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_metrics_dashboard_renders_without_api(self):
        """The metrics renderer works from a status JSON snapshot alone."""
        functions = self.root / "functions.sh"
        status = self.root / "status.json"
        history = self.root / "history.tsv"

        truncated = subprocess.run(
            ["bash", "-c", "sed '/^# Диспетчер/,$d' \"$1\"", "_", str(INSTALLER)],
            text=True, capture_output=True, check=True,
        )
        functions.write_text(truncated.stdout.replace(
            'readonly MTDD_METRICS_HISTORY="$MTDD_STATE/metrics-history.tsv"',
            'readonly MTDD_METRICS_HISTORY="{}"'.format(history),
        ))

        dc = {
            "dc": "2", "connected": True, "connections": 2, "ready_connections": 2,
            "pool_target": 2, "bound_clients": 1, "ping_rtt_us": 42000,
            "ready_queue_depth": 1, "ready_queue_clients": 1, "frames_queued_bytes": 0,
            "out_queued_bytes": 0, "rx_bytes_total": 1024, "tx_bytes_total": 2048,
            "creation_failures_total": 0, "proxy_ans_received_total": 0,
        }
        status.write_text(json.dumps({"data": {
            "ready": True, "revision": 3, "uptime_seconds": 900,
            "users_total": 2, "users_enabled": 2,
            "connections_active": 4, "connections_accepted_total": 12,
            "connections_rejected_total": 1, "unique_ips_active": 3,
            "handshakes_total": 12, "replay_cache_entries": 0,
            "buffer_bytes": {"queued": 0, "pending_write": 2048, "relay": 4096},
            "backpressure_events_total": {"c2s": 1, "s2c": 0},
            "unique_ip_history": {
                "hour": {"estimate": 5, "started_at": 0},
                "day": {"estimate": 7}, "week": {"estimate": 9},
                "relative_standard_error": 0.0325,
            },
            "build": {"version": "0.1.0"},
            "me": {"connected_dcs": 1, "pending_buffer_bytes": 0,
                   "requests_total": 5, "reconnects_total": 2, "dcs": [dc]},
        }}))
        with history.open("w", encoding="utf-8") as handle:
            for offset in range(3):
                handle.write("{}\t4\t3\t4096\t42.0\t1\t1\t12\n".format(1000000 + offset * 60))

        result = subprocess.run(
            ["bash", "-c", 'f=$1; s=$2; set --; source "$f"; metrics_render "$s" ""',
             "_", str(functions), str(status)],
            text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for marker in ("Метрики", "Соединения", "Буферы и очереди", "ME / DC",
                       "RTT", "Уникальные IP", "Динамика"):
            self.assertIn(marker, result.stdout)
        self.assertNotIn("\x1b[", result.stdout)


class LauncherTest(unittest.TestCase):
    """Launcher (mtdd-ctl) and credentials logic, tested without root or systemd."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.ctl = self.bin / "mtdd-ctl"
        # Copy of the installer whose launcher path points into the temp dir.
        self.script = self.root / "install-copy.sh"
        self.script.write_text(INSTALLER.read_text().replace(
            "/usr/local/bin/mtdd-ctl", str(self.ctl)))
        www = self.root / "www"
        www.mkdir()
        self.www = www
        handler = lambda *a, **k: QuietHandler(*a, directory=str(www), **k)  # noqa: E731
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/install.sh"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def sh(self, body, script=None, pipe=False, **env):
        full = os.environ.copy()
        full.update(MTDD_INSTALLER_SOURCE_ONLY="1", **env)
        path = script or self.script
        src = f'<(cat "{path}")' if pipe else f'"{path}"'
        prog = (f'set -Eeuo pipefail; source {src}; '
                "ensure_sudo_visibility() { :; }; " + body)
        return subprocess.run(["bash", "-c", prog], text=True, capture_output=True,
                              env=full, timeout=60)

    def test_launcher_url_follows_channel_and_repo(self):
        for channel in ("main", "dev"):
            r = self.sh(f'repo=a/b channel={channel}; launcher_source_url')
            self.assertEqual(r.stdout, f"https://raw.githubusercontent.com/a/b/{channel}/install.sh")
        r = self.sh('repo=a/b channel=dev; launcher_manual_command')
        self.assertIn("sudo curl -fsSLo", r.stdout)
        self.assertIn("a/b/dev/install.sh", r.stdout)
        self.assertIn("chmod 755", r.stdout)

    def test_fetch_validates_shebang_and_marker(self):
        dest = self.root / "fetched"
        (self.www / "install.sh").write_text("#!/usr/bin/env bash\n# install_launcher_copy\n")
        r = self.sh(f'fetch_launcher_source "{dest}"', MTDD_LAUNCHER_URL=self.url)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(dest.exists())
        (self.www / "install.sh").write_text("#!/usr/bin/env bash\necho unrelated\n")
        r = self.sh(f'fetch_launcher_source "{dest}"', MTDD_LAUNCHER_URL=self.url)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(dest.exists())
        (self.www / "install.sh").write_text("<html>install_launcher_copy</html>\n")
        r = self.sh(f'fetch_launcher_source "{dest}"', MTDD_LAUNCHER_URL=self.url)
        self.assertNotEqual(r.returncode, 0)

    def test_installs_regular_file_atomically(self):
        self.ctl.write_text("old")
        old_inode = self.ctl.stat().st_ino
        r = self.sh(f'work="{self.root}"; launcher_installed=0; install_launcher_copy; '
                    'echo "flag=$launcher_installed"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("flag=1", r.stdout)
        self.assertEqual(self.ctl.read_text(), self.script.read_text())
        self.assertEqual(self.ctl.stat().st_mode & 0o777, 0o755)
        self.assertNotEqual(self.ctl.stat().st_ino, old_inode)
        self.assertEqual([p.name for p in self.bin.iterdir()], ["mtdd-ctl"])

    def test_update_from_launcher_refreshes_it(self):
        shutil.copy(self.script, self.ctl)
        self.ctl.chmod(0o755)
        fresh = "#!/usr/bin/env bash\n# install_launcher_copy fresh\n"
        (self.www / "install.sh").write_text(fresh)
        r = self.sh(f'work="{self.root}"; launcher_installed=0; install_launcher_copy; '
                    'echo "flag=$launcher_installed"', script=self.ctl,
                    MTDD_LAUNCHER_URL=self.url)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.ctl.read_text(), fresh)
        self.assertEqual(self.ctl.stat().st_mode & 0o777, 0o755)
        self.assertIn("flag=1", r.stdout)

    def test_failed_refresh_keeps_existing_launcher_and_warns(self):
        shutil.copy(self.script, self.ctl)
        self.ctl.chmod(0o755)
        before = self.ctl.read_text()
        (self.www / "install.sh").write_text("garbage\n")
        r = self.sh(f'work="{self.root}"; launcher_installed=0; install_launcher_copy; '
                    'echo "flag=$launcher_installed"', script=self.ctl,
                    MTDD_LAUNCHER_URL=self.url)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.ctl.read_text(), before)
        self.assertIn("flag=1", r.stdout)
        self.assertIn("sudo curl -fsSLo", r.stdout)

    def test_pipe_mode_failure_prints_manual_command(self):
        (self.www / "install.sh").write_text("garbage\n")
        r = self.sh(f'work="{self.root}"; launcher_installed=0; repo=x/y channel=dev; '
                    'install_launcher_copy; echo "flag=$launcher_installed"',
                    pipe=True, MTDD_LAUNCHER_URL=self.url)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("НЕ УСТАНОВЛЕН", r.stdout)
        self.assertIn("x/y/dev/install.sh", r.stdout)
        self.assertIn("flag=0", r.stdout)
        self.assertFalse(self.ctl.exists())

    def test_path_has_dir(self):
        ok = self.sh('path_has_dir /sbin:/usr/local/bin:/bin /usr/local/bin')
        self.assertEqual(ok.returncode, 0)
        no = self.sh('path_has_dir /sbin:/bin:/usr/sbin /usr/local/bin')
        self.assertEqual(no.returncode, 1)
        no = self.sh('path_has_dir /usr/local/binx /usr/local/bin')
        self.assertEqual(no.returncode, 1)

    def test_launcher_installed_before_service_start(self):
        text = INSTALLER.read_text()
        body = text[text.index("\nrun_install() {"):]
        self.assertLess(body.index("install_launcher_copy"),
                        body.index('systemctl enable --now "$MTDD_SERVICE"'))
        self.assertLess(body.index("install_launcher_copy"), body.index("install -m 0644 /dev/stdin"))
        self.assertEqual(body.count("install_launcher_copy"), 1)

    def test_uninstall_removes_symlink_helper(self):
        text = INSTALLER.read_text()
        uninstall = text[text.index("cmd_uninstall() {"):]
        self.assertLess(uninstall.index("remove_ctl_links"), uninstall.index('rm -f -- "$MTDD_BIN"'))

    def test_fresh_install_generates_three_tokens(self):
        text = INSTALLER.read_text()
        for name in ("MTDD_API_TOKEN", "MTDD_API_READ_TOKEN", "MTDD_METRICS_TOKEN"):
            self.assertIn(f"'{name}'", text)
        self.assertIn("secrets.token_hex(32)", text)

    def test_config_references_scoped_tokens_with_old_binary_fallback(self):
        text = INSTALLER.read_text()
        body = text[text.index("\nrun_install() {"):]
        self.assertIn("for scoped in 1 0; do", body)
        self.assertIn("'api_read_token_env': 'MTDD_API_READ_TOKEN'", body)
        self.assertIn("'metrics_token_env': 'MTDD_METRICS_TOKEN'", body)
        self.assertIn("'usage_state_path': '/var/lib/mtdd/usage.json'", body)
        self.assertLess(body.index("for scoped in 1 0; do"), body.index('mv -f -- "$config_candidate" "$MTDD_CONF"'))

    def update_snippet(self):
        text = INSTALLER.read_text()
        start = text.index("python3 - \"$MTDD_CREDS\" <<'PY'\n") + len("python3 - \"$MTDD_CREDS\" <<'PY'\n")
        return text[start:text.index("\nPY\n", start)]

    def test_update_appends_only_missing_tokens_and_keeps_mode(self):
        creds = self.root / "credentials.env"
        creds.write_text("MTDD_API_TOKEN=" + "a" * 64)  # no trailing newline
        creds.chmod(0o600)
        ino = creds.stat().st_ino
        for _ in range(2):
            subprocess.run(["python3", "-c", self.update_snippet(), str(creds)], check=True)
        lines = creds.read_text().splitlines()
        self.assertEqual(lines[0], "MTDD_API_TOKEN=" + "a" * 64)
        values = dict(line.split("=", 1) for line in lines)
        self.assertEqual(set(values), {"MTDD_API_TOKEN", "MTDD_API_READ_TOKEN", "MTDD_METRICS_TOKEN"})
        self.assertEqual(len(lines), 3)
        for name in ("MTDD_API_READ_TOKEN", "MTDD_METRICS_TOKEN"):
            self.assertRegex(values[name], r"^[A-Za-z0-9]{32,512}$")
        self.assertEqual(creds.stat().st_mode & 0o777, 0o600)
        self.assertEqual(creds.stat().st_ino, ino)

    def test_update_preserves_existing_new_tokens(self):
        creds = self.root / "credentials.env"
        creds.write_text("MTDD_API_TOKEN=x\nMTDD_API_READ_TOKEN=r\nMTDD_METRICS_TOKEN=m\n")
        subprocess.run(["python3", "-c", self.update_snippet(), str(creds)], check=True)
        self.assertEqual(creds.read_text(), "MTDD_API_TOKEN=x\nMTDD_API_READ_TOKEN=r\nMTDD_METRICS_TOKEN=m\n")



def display_width(line):
    """Ширина строки в колонках терминала без ANSI-последовательностей."""
    plain = re.sub(r"\x1b\[[0-9;]*m", "", line)
    return sum(0 if unicodedata.combining(ch)
               else 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
               for ch in plain)


class MetricsDashboardTest(unittest.TestCase):
    """Дашборд метрик и metrics_fetch: без root, systemd и сети."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        # Копия установщика, где пути конфигурации указывают во временный каталог.
        self.conf = self.root / "config.json"
        self.creds = self.root / "credentials.env"
        self.script = self.root / "install-copy.sh"
        self.script.write_text(INSTALLER.read_text()
                               .replace("/etc/mtdd/config.json", str(self.conf))
                               .replace("/etc/mtdd/credentials.env", str(self.creds)))
        self.dashboard = self.root / "dashboard.py"
        result = self.sh("metrics_python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.dashboard.write_text(result.stdout)
        self.status = self.root / "status.json"
        self.history = self.root / "history.tsv"
        self.prom = self.root / "metrics.txt"
        self.write_fixture()

    def tearDown(self):
        self.tmp.cleanup()

    def sh(self, body, **env):
        full = os.environ.copy()
        full.update(MTDD_INSTALLER_SOURCE_ONLY="1", **env)
        return subprocess.run(
            ["bash", "-c", f'set -Eeuo pipefail; source "{self.script}"; ' + body],
            text=True, capture_output=True, env=full, timeout=60)

    def dc(self, number, up=True):
        return {"dc": str(number), "connected": up, "connections": 4,
                "ready_connections": 4 if up else 0, "pool_target": 4, "bound_clients": 31,
                "ping_rtt_us": 95000 if up else 0, "ready_queue_depth": 2,
                "ready_queue_clients": 1, "frames_queued_bytes": 2048, "out_queued_bytes": 512,
                "rx_bytes_total": 7_300_000_000, "tx_bytes_total": 2_100_000_000,
                "creation_failures_total": 1}

    def data(self, active_fields=True):
        history = {"hour": {"estimate": 410, "started_at": 1_700_000_000},
                   "day": {"estimate": 2210}, "week": {"estimate": 8120},
                   "relative_standard_error": 0.0325}
        data = {"ready": True, "revision": 17, "uptime_seconds": 273000,
                "users_total": 12, "users_enabled": 11, "connections_active": 142,
                "connections_accepted_total": 123456, "connections_rejected_total": 321,
                "unique_ips_active": 131, "handshakes_total": 124000,
                "replay_cache_entries": 5400,
                "buffer_bytes": {"queued": 4096, "pending_write": 20480, "relay": 1500000},
                "backpressure_events_total": {"c2s": 31, "s2c": 4},
                "unique_ip_history": history, "build": {"version": "0.9.0"},
                "me": {"connected_dcs": 2, "pending_buffer_bytes": 1024,
                       "requests_total": 55000, "reconnects_total": 3,
                       "dcs": [self.dc(1), self.dc(2), self.dc(4, up=False)]}}
        if active_fields:
            data["unique_ips_active"] = 118
            data["unique_ips_seen"] = 131
            history.update(hour_active={"estimate": 352}, day_active={"estimate": 1730},
                           week_active={"estimate": 6400}, min_bytes=4096)
        return data

    def write_fixture(self, points=60, active_fields=True):
        self.status.write_text(json.dumps({"data": self.data(active_fields)}))
        self.prom.write_text('mtdd_handshakes_total{result="success"} 123000\n'
                             'mtdd_connections_rejected_total{reason="limit"} 300\n'
                             "mtdd_handshakes_pending 3\n")
        now = time.time()
        with self.history.open("w", encoding="utf-8") as handle:
            for i in range(points):
                handle.write("{:.0f}\t{}\t{}\t{}\t{:.1f}\t3\t{}\t{}\n".format(
                    now - (points - i) * 25, 100 + i, 80 + i, i * 90_000_000,
                    40 + i % 30, 300 + i // 5, 120000 + i * 20))

    def render(self, columns, color=False):
        env = os.environ.copy()
        for name in ("NO_COLOR", "MTDD_LIVE"):
            env.pop(name, None)
        env.update(COLUMNS=str(columns), MTDD_JSON=str(self.status),
                   MTDD_METRICS_TXT=str(self.prom), MTDD_HISTORY_FILE=str(self.history),
                   MTDD_METRICS_INTERVAL="100000", MTDD_COLOR="1" if color else "0")
        if color:
            env.update(MTDD_C_RESET="\033[0m", MTDD_C_BOLD="\033[1m", MTDD_C_DIM="\033[2m",
                       MTDD_C_GRAY="\033[38;5;245m", MTDD_C_ACCENT="\033[38;5;45m",
                       MTDD_C_VIOLET="\033[38;5;141m", MTDD_C_GREEN="\033[38;5;114m",
                       MTDD_C_YELLOW="\033[38;5;221m", MTDD_C_RED="\033[38;5;203m")
        result = subprocess.run(["python3", str(self.dashboard)], text=True,
                                capture_output=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_render_never_exceeds_terminal_width(self):
        for columns in (60, 80, 120, 200):
            for color in (False, True):
                out = self.render(columns, color)
                widest = max(display_width(line) for line in out.splitlines())
                self.assertLess(widest, columns, f"{columns} cols, color={color}")

    def test_cards_adapt_to_width(self):
        wide = self.render(120)
        narrow = self.render(60)
        # Широкий терминал: все четыре карточки в одном ряду.
        row = next(line for line in wide.splitlines() if "Соединения" in line and "╭" in line)
        for title in ("Уникальные IP", "Трафик в секунду", "ME RTT"):
            self.assertIn(title, row)
        row = next(line for line in narrow.splitlines() if "Соединения" in line and "╭" in line)
        self.assertNotIn("ME RTT", row)

    def test_graphs_are_three_rows_and_separated(self):
        lines = self.render(80).splitlines()
        titles = [i for i, line in enumerate(lines) if "Активные соединения" in line and "сейчас" in line]
        self.assertEqual(len(titles), 1)
        top = titles[0]
        self.assertIn("┤", lines[top + 1])
        self.assertIn("│", lines[top + 2])
        self.assertIn("┤", lines[top + 3])
        self.assertEqual(lines[top + 4], "")
        self.assertTrue(any(ch in lines[top + 1] + lines[top + 2] + lines[top + 3]
                            for ch in "▁▂▃▄▅▆▇█"))

    def test_no_color_uses_symbols_and_no_escape_codes(self):
        out = self.render(80, color=False)
        self.assertNotIn("\x1b", out)
        for symbol in ("✓", "!", "✗"):
            self.assertIn(symbol, out)

    def test_color_mode_keeps_symbols(self):
        out = self.render(80, color=True)
        self.assertIn("\x1b[", out)
        for symbol in ("✓", "!", "✗"):
            self.assertIn(symbol, out)

    def test_active_and_seen_ips_are_shown_with_hint(self):
        out = self.render(80)
        self.assertIn("118 / 131", out)
        self.assertIn("≈352 / ≈410", out)
        self.assertIn("акт. — IP, передавшие", out)
        self.assertIn("4.0 KiB", out)

    def test_old_status_without_active_fields_renders(self):
        self.write_fixture(active_fields=False)
        out = self.render(80)
        self.assertIn("131 сейчас", out)
        self.assertIn("≈410", out)
        self.assertNotIn("акт. — IP", out)

    def test_short_history_shows_collecting_message(self):
        for points in (0, 1):
            self.write_fixture(points=points)
            out = self.render(80)
            self.assertIn("собираю историю…", out)
            self.assertNotIn("┤", out)

    def test_old_history_rows_still_parse(self):
        with self.history.open("a", encoding="utf-8") as handle:
            handle.write("broken line\n1\t2\t3\n")
        out = self.render(80)
        self.assertIn("Динамика · 60 точек", out)

    def serve(self, status=200):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                seen.append((handler.path, handler.headers.get("Authorization")))
                body = (b"mtdd_uptime_seconds 5\n" if status == 200 else b"nope\n")
                handler.send_response(status)
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(handler, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))
        return server.server_port, seen

    def free_port(self):
        import socket
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def configure(self, **config):
        self.conf.write_text(json.dumps(config))
        self.creds.write_text("MTDD_API_TOKEN=" + "a" * 40 + "\nMTDD_METRICS_TOKEN=" + "m" * 40 + "\n")

    def test_metrics_fetch_falls_back_to_api_port_without_metrics_port(self):
        api_port, api_seen = self.serve()
        self.configure(control_host="127.0.0.1", control_port=api_port)
        result = self.sh("metrics_fetch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mtdd_uptime_seconds", result.stdout)
        self.assertEqual(api_seen, [("/metrics", "Bearer " + "a" * 40)])

    def test_metrics_fetch_falls_back_when_metrics_listener_is_down(self):
        api_port, api_seen = self.serve()
        self.configure(control_host="127.0.0.1", control_port=api_port,
                       metrics_host="127.0.0.1", metrics_port=self.free_port())
        result = self.sh("metrics_fetch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mtdd_uptime_seconds", result.stdout)
        self.assertEqual(len(api_seen), 1)

    def test_metrics_fetch_falls_back_when_metrics_listener_rejects(self):
        api_port, api_seen = self.serve()
        metrics_port, metrics_seen = self.serve(status=401)
        self.configure(control_port=api_port, metrics_port=metrics_port)
        result = self.sh("metrics_fetch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(metrics_seen), 1)
        self.assertEqual(len(api_seen), 1)

    def test_metrics_fetch_prefers_metrics_port_with_its_token(self):
        api_port, api_seen = self.serve()
        metrics_port, metrics_seen = self.serve()
        self.configure(control_port=api_port, metrics_port=metrics_port,
                       metrics_token_env="MTDD_METRICS_TOKEN")
        result = self.sh("metrics_fetch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(metrics_seen, [("/metrics", "Bearer " + "m" * 40)])
        self.assertEqual(api_seen, [])
        self.assertNotIn("m" * 40, result.stdout + result.stderr)

    def test_metrics_fetch_without_token_env_sends_no_authorization(self):
        api_port, api_seen = self.serve()
        metrics_port, metrics_seen = self.serve()
        self.configure(control_port=api_port, metrics_port=metrics_port)
        self.assertEqual(self.sh("metrics_fetch").returncode, 0)
        self.assertEqual(metrics_seen, [("/metrics", None)])
        self.assertEqual(api_seen, [])

    def test_metrics_port_zero_means_legacy_endpoint(self):
        api_port, api_seen = self.serve()
        self.configure(control_port=api_port, metrics_port=0)
        self.assertEqual(self.sh("metrics_fetch").returncode, 0)
        self.assertEqual(len(api_seen), 1)


class PolicyShellCase(unittest.TestCase):
    """Общая основа: копия установщика с путями во временном каталоге, без root."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.conf = self.root / "config.json"
        self.creds = self.root / "credentials.env"
        self.script = self.root / "install-copy.sh"
        self.script.write_text(INSTALLER.read_text()
                               .replace("/etc/mtdd/config.json", str(self.conf))
                               .replace("/etc/mtdd/credentials.env", str(self.creds)))

    def sh(self, body, *args):
        # Аргументы идут через окружение ($T1, $T2…): позиционные разбирал бы сам установщик.
        env = os.environ.copy()
        env["MTDD_INSTALLER_SOURCE_ONLY"] = "1"
        env.update({f"T{i}": value for i, value in enumerate(args, 1)})
        return subprocess.run(
            ["bash", "-c", f'set -Eeuo pipefail; source "{self.script}"; ' + body],
            text=True, capture_output=True, env=env, timeout=60)


class UserPolicyTest(PolicyShellCase):
    """Помощники политик пользователей в лаунчере: разбор ввода и JSON."""

    def body(self, field, value):
        return self.sh('policy_body "$T1" "$T2"', field, value)

    def assertBody(self, field, value, expected):
        result = self.body(field, value)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {field: expected})

    def assertRejected(self, field, value, text=None):
        result = self.body(field, value)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stdout, "")
        if text:
            self.assertIn(text, result.stderr)

    def test_quota_accepts_binary_human_sizes(self):
        for raw, expected in (("10G", 10 * 1024 ** 3), ("500M", 500 * 1024 ** 2),
                              ("1T", 1024 ** 4), ("2k", 2048), ("1.5G", 1610612736),
                              ("10GiB", 10 * 1024 ** 3), ("12345", 12345), ("1", 1)):
            with self.subTest(raw=raw):
                self.assertBody("data_quota_bytes", raw, expected)

    def test_quota_clear_and_rejects_garbage(self):
        for raw in ("", "none", "NONE", "null", "-"):
            self.assertBody("data_quota_bytes", raw, None)
        for raw in ("0", "abc", "-5", "10X", "1e3", "0.0001K", "99999999999999999999T"):
            with self.subTest(raw=raw):
                self.assertRejected("data_quota_bytes", raw)

    def test_rate_limits_reject_below_one_kib(self):
        self.assertBody("rate_limit_up_bytes_per_sec", "2M", 2 * 1024 ** 2)
        self.assertBody("rate_limit_down_bytes_per_sec", "1K", 1024)
        self.assertBody("rate_limit_down_bytes_per_sec", "1024", 1024)
        self.assertBody("rate_limit_up_bytes_per_sec", "none", None)
        self.assertRejected("rate_limit_up_bytes_per_sec", "1023", "1K")
        self.assertRejected("rate_limit_down_bytes_per_sec", "0.5K", "1K")

    def test_unique_ip_limit_bounds(self):
        self.assertBody("max_unique_ips", "3", 3)
        self.assertBody("max_unique_ips", "4294967295", 4294967295)
        self.assertBody("max_unique_ips", "", None)
        for raw in ("0", "4294967296", "-1", "1.5", "x"):
            with self.subTest(raw=raw):
                self.assertRejected("max_unique_ips", raw)

    def test_device_limit_bounds(self):
        self.assertBody("max_devices", "2", 2)
        self.assertBody("max_devices", "1000000", 1000000)
        self.assertBody("max_devices", "none", None)
        for raw in ("0", "1000001", "-1", "1.5", "x"):
            with self.subTest(raw=raw):
                self.assertRejected("max_devices", raw)

    def test_expiry_date_becomes_end_of_day_utc(self):
        self.assertBody("expires_at", "2030-01-01", "2030-01-01T23:59:59Z")
        self.assertBody("expires_at", "2028-02-29", "2028-02-29T23:59:59Z")
        self.assertBody("expires_at", "2030-01-01T00:00:00Z", "2030-01-01T00:00:00Z")
        self.assertBody("expires_at", "2030-01-01t10:00:00+03:00", "2030-01-01T10:00:00+03:00")
        self.assertBody("expires_at", "none", None)
        self.assertBody("expires_at", "", None)
        for raw in ("2030-02-30", "2029-02-29", "2030-13-01", "01.01.2030", "2030-01-01T25:00:00Z",
                    "2030-01-01T00:00:00", "tomorrow"):
            with self.subTest(raw=raw):
                self.assertRejected("expires_at", raw)

    def test_note_is_json_escaped_and_validated(self):
        tricky = 'say "hi" \\ {"enabled":false} \u00e9 \u0434\u0430'
        self.assertBody("note", tricky, tricky)
        self.assertBody("note", "", "")
        self.assertBody("note", "a" * 256, "a" * 256)
        self.assertRejected("note", "a" * 257, "256")
        self.assertRejected("note", "tab\there", "управляющие")

    def test_unknown_field_is_rejected(self):
        self.assertRejected("enabled", "true", "Неизвестное поле")

    def test_output_is_compact_json_with_single_key(self):
        result = self.body("max_unique_ips", "5")
        self.assertEqual(result.stdout.strip(), '{"max_unique_ips":5}')

    def test_users_set_validates_before_any_request(self):
        # Конфигурации нет: если бы запрос ушёл, ошибка была бы про токен, а не про размер.
        result = self.sh('cmd_users_set bob data_quota_bytes oops')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Неверный размер", result.stderr)
        self.assertNotIn("MTDD_API_TOKEN", result.stderr)
        result = self.sh('cmd_users_set "bad name" note x')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Неверное имя", result.stderr)


class UserPolicyApiTest(PolicyShellCase):
    """Запросы лаунчера к фиктивному API: тела, пути, показ данных и ошибок."""

    def start_api(self, responses):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def handle_any(handler):
                length = int(handler.headers.get("Content-Length") or 0)
                body = handler.rfile.read(length).decode() if length else ""
                seen.append((handler.command, handler.path, body,
                             handler.headers.get("Authorization")))
                status, payload = responses.get((handler.command, handler.path.split("?")[0]),
                                                (200, {"ok": True, "request_id": 1, "data": {}}))
                raw = json.dumps(payload).encode()
                handler.send_response(status)
                handler.send_header("Content-Length", str(len(raw)))
                handler.end_headers()
                handler.wfile.write(raw)

            do_GET = do_POST = do_PATCH = handle_any

            def log_message(handler, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))
        self.conf.write_text(json.dumps({"control_host": "127.0.0.1",
                                         "control_port": server.server_port}))
        self.creds.write_text("MTDD_API_TOKEN=" + "a" * 40 + "\n")
        return seen

    def test_set_sends_patch_with_escaped_json(self):
        seen = self.start_api({})
        result = self.sh('cmd_users_set bob note "$T1"', 'x","enabled":false,"y":"')
        self.assertEqual(result.returncode, 0, result.stderr)
        method, path, body, auth = seen[0]
        self.assertEqual((method, path, auth), ("PATCH", "/v1/users/bob", "Bearer " + "a" * 40))
        self.assertEqual(json.loads(body), {"note": 'x","enabled":false,"y":"'})

    def test_server_error_message_is_shown(self):
        self.start_api({("POST", "/v1/users/bob/reset-quota"): (
            500, {"ok": False, "request_id": 2,
                  "error": {"type": "internal", "message": "not wired yet"}})})
        result = self.sh("cmd_users_action bob reset-quota")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not wired yet", result.stderr)

    def test_actions_post_empty_body(self):
        seen = self.start_api({})
        for action in ("enable", "disable", "reset-quota"):
            self.assertEqual(self.sh(f"cmd_users_action bob {action}").returncode, 0)
        self.assertEqual([(m, p, b) for m, p, b, _ in seen],
                         [("POST", f"/v1/users/bob/{a}", "") for a in ("enable", "disable", "reset-quota")])

    def test_show_renders_policy_in_human_form(self):
        user = {"name": "bob", "enabled": True, "expires_at": "2030-01-01T23:59:59Z",
                "data_quota_bytes": 10 * 1024 ** 3, "quota_used_bytes": 1024 ** 3,
                "max_unique_ips": 3, "rate_limit_up_bytes_per_sec": 2 * 1024 ** 2,
                "rate_limit_down_bytes_per_sec": None, "max_connections": None,
                "note": "friend", "stats": {"active_connections": 2, "unique_ips_active": 1}}
        self.start_api({("GET", "/v1/users/bob"): (200, {"ok": True, "request_id": 3,
                                                       "data": {"user": user}})})
        result = self.sh("NO_COLOR=1; cmd_users_show bob")
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ("2030-01-01 23:59:59 UTC", "1.0 GiB / 10.0 GiB (10%)", "2.0 MiB/s",
                     "friend", "без лимита"):
            self.assertIn(text, result.stdout)

    def test_show_without_quota_used_still_works(self):
        user = {"name": "bob", "enabled": False, "data_quota_bytes": 5 * 1024 ** 2, "note": ""}
        self.start_api({("GET", "/v1/users/bob"): (200, {"ok": True, "request_id": 3,
                                                       "data": {"user": user}})})
        result = self.sh("cmd_users_show bob")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("5.0 MiB", result.stdout)
        self.assertIn("отключён", result.stdout)

    def test_audit_lists_events_with_limit(self):
        events = [{"id": 1, "at": "2030-01-01T10:00:00Z", "action": "user.update",
                   "user": "bob", "source": "127.0.0.1", "revision": 7, "request_id": 9,
                   "applied": True, "fields": ["enabled", "note"]}]
        seen = self.start_api({("GET", "/v1/events"): (200, {"ok": True, "request_id": 4,
                                                           "data": {"events": events}})})
        result = self.sh("cmd_audit")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(seen[0][1], "/v1/events?limit=20")
        for text in ("2030-01-01 10:00:00", "user.update", "bob", "enabled, note"):
            self.assertIn(text, result.stdout)
        self.assertNotEqual(self.sh("cmd_audit abc").returncode, 0)


if __name__ == "__main__":
    unittest.main()


class NetTuneScriptTest(unittest.TestCase):
    """The mtdd-nettune script embedded in install.sh, run on a fake sysfs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        text = INSTALLER.read_text()
        start = text.index("<<'NETTUNE'\n") + len("<<'NETTUNE'\n")
        end = text.index("\nNETTUNE\n", start)
        self.script = self.root / "mtdd-nettune"
        self.script.write_text(text[start:end] + "\n")
        self.script.chmod(0o755)
        self.sysfs = self.root / "sys"
        bindir = self.root / "bin"
        bindir.mkdir()
        # Fake `ip`: two default routes (v4 on eth0, v6 on eth1) plus a
        # non-default route on eth2 that must be ignored.
        ip = bindir / "ip"
        ip.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  -4) echo 'default via 10.0.0.1 dev eth0 proto dhcp' ;;\n"
            "  -6) echo 'default via fe80::1 dev eth1 metric 1024' ;;\n"
            "esac\n")
        ip.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bindir}:/usr/bin:/bin",
                        MTDD_NETTUNE_SYSFS=str(self.sysfs),
                        MTDD_NETTUNE_STATE=str(self.root / "state"))

    def tearDown(self):
        self.tmp.cleanup()

    def knob(self, dev, name, value=None):
        path = self.sysfs / "class/net" / dev / name
        if value is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value + "\n")
        return path.read_text().strip()

    def run_script(self, action):
        result = subprocess.run([str(self.script), action], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_applies_defaults_only_and_restores_its_own_changes(self):
        self.knob("eth0", "napi_defer_hard_irqs", "0")
        self.knob("eth0", "gro_flush_timeout", "0")
        # Operator-tuned interface: left untouched.
        self.knob("eth1", "napi_defer_hard_irqs", "5")
        self.knob("eth1", "gro_flush_timeout", "0")
        # Not a default-route interface.
        self.knob("eth2", "napi_defer_hard_irqs", "0")
        self.run_script("start")
        self.assertEqual(self.knob("eth0", "napi_defer_hard_irqs"), "2")
        self.assertEqual(self.knob("eth0", "gro_flush_timeout"), "1000000")
        self.assertEqual(self.knob("eth1", "napi_defer_hard_irqs"), "5")
        self.assertEqual(self.knob("eth1", "gro_flush_timeout"), "1000000")
        self.assertEqual(self.knob("eth2", "napi_defer_hard_irqs"), "0")
        # A later operator change survives stop; our own values are reverted.
        self.knob("eth0", "gro_flush_timeout", "50000")
        self.run_script("stop")
        self.assertEqual(self.knob("eth0", "napi_defer_hard_irqs"), "0")
        self.assertEqual(self.knob("eth1", "napi_defer_hard_irqs"), "5")
        self.assertEqual(self.knob("eth1", "gro_flush_timeout"), "0")
        self.assertEqual(self.knob("eth0", "gro_flush_timeout"), "50000")
        # A second stop is a no-op.
        self.run_script("stop")

    def test_missing_knobs_and_interfaces_are_skipped(self):
        # Old kernel: the interface exists but has no NAPI deferral files.
        (self.sysfs / "class/net/eth0").mkdir(parents=True)
        self.run_script("start")
        self.assertFalse((self.sysfs / "class/net/eth0/napi_defer_hard_irqs").exists())
        self.run_script("stop")
