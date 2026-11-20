"""Tests for ghost-release-cover. Stdlib only (`python3 -m unittest`)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "ghost_release_cover.py"
sys.path.insert(0, str(ROOT / "bin"))
import ghost_release_cover as g  # noqa: E402

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _clean_fixture():
    versions = {
        "app": {
            "version": "1.0.0",
            "patches": {"Linux-x86_64": {
                "from": "0.9.0", "file": "patch-Linux-x86_64-0.9.0-to-1.0.0.hdiff",
                "sha256": SHA_A, "size": 100}},
            "full": {"Linux-x86_64": {
                "file": "app-1.0.0-Linux-x86_64.zip", "sha256": SHA_B, "size": 200}},
        },
        "packs": {},
    }
    release = {"tag": "v1.0.0", "assets": [
        {"name": "app-1.0.0-Linux-x86_64.zip", "size": 200, "digest": "sha256:" + SHA_B},
        {"name": "patch-Linux-x86_64-0.9.0-to-1.0.0.hdiff", "size": 100, "digest": "sha256:" + SHA_A},
    ]}
    releases = {"tags": ["v1.0.0", "v0.9.0"]}
    return versions, release, releases


class TestParsers(unittest.TestCase):
    def test_platform_windows_x64(self):
        self.assertEqual(g.parse_platform("Ghost-Downloader-v4.5.10-Windows-x86_64.zip"),
                         "Windows-x86_64")

    def test_platform_linux_arm64(self):
        self.assertEqual(g.parse_platform("Ghost-Downloader-v4.5.10-Linux-arm64.AppImage"),
                         "Linux-arm64")

    def test_platform_android(self):
        self.assertEqual(g.parse_platform("Ghost-Downloader-v4.5.10-Android-arm64-v8a.apk"),
                         "Android-arm64")

    def test_platform_none_without_arch(self):
        self.assertIsNone(g.parse_platform("checksums.txt"))

    def test_digest_hex_strips_prefix(self):
        self.assertEqual(g._digest_hex("sha256:" + SHA_A), SHA_A)

    def test_digest_hex_rejects_garbage(self):
        self.assertIsNone(g._digest_hex("sha256:nothex"))

    def test_version_tuple_ordering(self):
        self.assertGreater(g._version_tuple("4.5.10"), g._version_tuple("4.5.8"))
        self.assertEqual(g._version_tuple("v4.5.0"), g._version_tuple("4.5"))


class TestAudit(unittest.TestCase):
    def test_clean_fixture_has_no_findings(self):
        v, r, h = _clean_fixture()
        rep = g.audit(v, r, h, None)
        self.assertEqual(rep["summary"]["findings"], 0)
        self.assertEqual(rep["summary"]["status"], "clean")

    def test_untracked_artifact_flagged(self):
        v, r, h = _clean_fixture()
        r["assets"].append({"name": "app-1.0.0-Linux-x86_64.AppImage",
                            "size": 5, "digest": "sha256:" + SHA_C})
        rep = g.audit(v, r, h, None)
        ids = {f["id"] for f in rep["findings"]}
        self.assertIn("ARTIFACT_UNTRACKED", ids)

    def test_uncovered_platform_flagged(self):
        v, r, h = _clean_fixture()
        r["assets"].append({"name": "app-1.0.0-Android-arm64-v8a.apk",
                            "size": 5, "digest": "sha256:" + SHA_C})
        rep = g.audit(v, r, h, None)
        self.assertIn("Android-arm64", rep["coverage"]["platforms_uncovered"])

    def test_integrity_mismatch_is_error(self):
        v, r, h = _clean_fixture()
        r["assets"][0]["digest"] = "sha256:" + SHA_C  # wrong digest for the full asset
        rep = g.audit(v, r, h, None)
        self.assertEqual(rep["summary"]["errors"], 1)
        self.assertIn("app-1.0.0-Linux-x86_64.zip", rep["integrity"]["mismatches"])

    def test_missing_tracked_asset_is_error(self):
        v, r, h = _clean_fixture()
        r["assets"] = [a for a in r["assets"] if not a["name"].endswith(".hdiff")]
        rep = g.audit(v, r, h, None)
        self.assertEqual(rep["summary"]["errors"], 1)
        self.assertIn("patch-Linux-x86_64-0.9.0-to-1.0.0.hdiff", rep["integrity"]["missing"])

    def test_pack_integrity_mismatch(self):
        v, r, h = _clean_fixture()
        v["packs"] = {"demo_pack": {"version": "1.0.0", "file": "demo_pack.zip",
                                    "sha256": SHA_A, "gdMinVersion": "1.0.0"}}
        packs = {"packs": [{"name": "demo_pack", "file": "demo_pack.zip",
                            "sha256": SHA_C, "size": 10}]}
        rep = g.audit(v, r, h, packs)
        self.assertIn("demo_pack", rep["packs"]["mismatches"])
        self.assertIn("PACK_INTEGRITY_MISMATCH", {f["id"] for f in rep["findings"]})

    def test_pack_requires_newer_app_is_error(self):
        v, r, h = _clean_fixture()
        v["packs"] = {"demo_pack": {"version": "1.0.0", "file": "demo_pack.zip",
                                    "sha256": SHA_A, "gdMinVersion": "2.0.0"}}
        packs = {"packs": [{"name": "demo_pack", "file": "demo_pack.zip",
                            "sha256": SHA_A, "size": 10}]}
        rep = g.audit(v, r, h, packs)
        self.assertIn("PACK_MIN_VERSION_EXCEEDS_APP", {f["id"] for f in rep["findings"]})

    def test_patch_reachability_counts(self):
        v, r, h = _clean_fixture()
        h["tags"] = ["v1.0.0", "v0.9.0", "v0.8.0"]
        rep = g.audit(v, r, h, None)
        self.assertEqual(rep["patch_reachability"]["prior_versions"], 2)
        self.assertEqual(rep["patch_reachability"]["prior_without_patch"], 1)


class TestCLI(unittest.TestCase):
    def _write(self, d, v, r, h):
        for name, obj in (("versions.json", v), ("release.json", r), ("releases.json", h)):
            (Path(d) / name).write_text(json.dumps(obj), encoding="utf-8")

    def _run(self, d, *extra):
        return subprocess.run([sys.executable, str(BIN),
                               "--versions", str(Path(d) / "versions.json"),
                               "--release", str(Path(d) / "release.json"),
                               "--releases", str(Path(d) / "releases.json"), *extra],
                              capture_output=True, text=True)

    def test_exit_1_on_warnings(self):
        v, r, h = _clean_fixture()
        r["assets"].append({"name": "app-1.0.0-Linux-x86_64.AppImage",
                            "size": 5, "digest": "sha256:" + SHA_C})
        with tempfile.TemporaryDirectory() as d:
            self._write(d, v, r, h)
            p = self._run(d)  # default --fail-on warning
            self.assertEqual(p.returncode, 1, p.stderr)

    def test_exit_0_when_clean(self):
        v, r, h = _clean_fixture()
        with tempfile.TemporaryDirectory() as d:
            self._write(d, v, r, h)
            p = self._run(d)
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_json_output_is_parseable(self):
        v, r, h = _clean_fixture()
        with tempfile.TemporaryDirectory() as d:
            self._write(d, v, r, h)
            p = self._run(d, "--json")
            data = json.loads(p.stdout)
            self.assertEqual(data["tool"], "ghost-release-cover")
            self.assertIn("summary", data)

    def test_fail_on_never_forces_zero(self):
        v, r, h = _clean_fixture()
        r["assets"].append({"name": "app-1.0.0-Linux-x86_64.AppImage",
                            "size": 5, "digest": "sha256:" + SHA_C})
        with tempfile.TemporaryDirectory() as d:
            self._write(d, v, r, h)
            p = self._run(d, "--fail-on", "never")
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_usage_error_exit_2(self):
        p = subprocess.run([sys.executable, str(BIN)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)

    def test_real_examples_exit_1_and_json(self):
        p = subprocess.run(
            [sys.executable, str(BIN),
             "--versions", str(ROOT / "examples/in/versions.json"),
             "--release", str(ROOT / "examples/in/release.json"),
             "--releases", str(ROOT / "examples/in/releases.json"),
             "--packs", str(ROOT / "examples/in/packs.json"), "--json"],
            capture_output=True, text=True)
        self.assertEqual(p.returncode, 1, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["coverage"]["artifacts_total"], 17)
        self.assertEqual(data["coverage"]["artifacts_tracked"], 8)
        self.assertEqual(data["integrity"]["mismatches"], [])


if __name__ == "__main__":
    unittest.main()
