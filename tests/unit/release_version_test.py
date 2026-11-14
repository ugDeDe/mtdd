"""tools/release-version.sh: every CI build gets a new, increasing version."""

import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "release-version.sh"


def run(*args, cwd=None, stdin=""):
    return subprocess.run(
        ["bash", str(SCRIPT), *args], input=stdin, text=True, capture_output=True,
        cwd=cwd, timeout=20,
    )


class NextVersionTest(unittest.TestCase):
    def next(self, base, tags):
        result = run("next", base, stdin="".join(f"{tag}\n" for tag in tags))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_first_release_is_the_base_version(self):
        self.assertEqual(self.next("0.1.0", []), "0.1.0")
        self.assertEqual(self.next("0.1.0", ["channel-main", "dev-1a2b3c4"]), "0.1.0")

    def test_patch_grows_from_the_highest_release(self):
        self.assertEqual(self.next("0.1.0", ["v0.1.0"]), "0.1.1")
        self.assertEqual(self.next("1.2.0", ["v1.2.9", "v1.2.10", "v1.1.40"]), "1.2.11")
        self.assertEqual(self.next("0.2.0", ["v0.3.4"]), "0.3.5")  # VERSION left behind

    def test_manual_bump_in_version_file_wins(self):
        self.assertEqual(self.next("0.2.0", ["v0.1.9"]), "0.2.0")
        self.assertEqual(self.next("1.0.0", ["v0.9.9"]), "1.0.0")

    def test_malformed_tags_are_ignored(self):
        self.assertEqual(self.next("0.1.0", ["v0.1", "v9.9.9-rc1", "vX.Y.Z", "v0.1.3"]), "0.1.4")

    def test_malformed_base_is_refused(self):
        for base in ("1.2", "v1.2.3", "1.2.3-dev", ""):
            with self.subTest(base=base):
                self.assertNotEqual(run("next", base).returncode, 0)


class GitTagsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.tmp.name)
        self.git("init", "-q", "-b", "main")
        (self.repo / "VERSION").write_text("0.1.0\n")
        self.commit("first")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
            cwd=self.repo, check=True, text=True, capture_output=True,
        ).stdout.strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def release(self, channel):
        result = run(channel, cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_main_increments_and_rerun_reuses_the_tag(self):
        self.assertEqual(self.release("main"),
                         {"version": "0.1.0", "tag": "v0.1.0", "existing": "0", "previous": ""})
        self.git("tag", "v0.1.0")
        # A re-run on the released commit publishes nothing.
        self.assertEqual(self.release("main")["existing"], "1")
        self.commit("second")
        self.assertEqual(self.release("main"),
                         {"version": "0.1.1", "tag": "v0.1.1", "existing": "0",
                          "previous": "v0.1.0"})
        self.git("tag", "v0.1.1")
        rerun = self.release("main")
        self.assertEqual((rerun["tag"], rerun["existing"], rerun["previous"]),
                         ("v0.1.1", "1", "v0.1.0"))
        (self.repo / "VERSION").write_text("0.2.0\n")
        self.commit("minor bump")
        self.assertEqual(self.release("main")["tag"], "v0.2.0")

    def test_dev_goes_to_the_channel_with_the_commit_as_version(self):
        sha = self.git("rev-parse", "--short=7", "HEAD")
        self.assertEqual(self.release("dev"), {"version": f"dev-{sha}", "tag": "channel-dev",
                                               "existing": "0", "previous": ""})
        # Version tags never stop a dev build.
        self.git("tag", "v0.1.0")
        self.assertEqual(self.release("dev")["existing"], "0")


if __name__ == "__main__":
    unittest.main()
