#!/usr/bin/env python3
"""ghost-release-cover — audit Ghost-Downloader-3's versions.json release manifest.

Reconciles three offline sources:
  * versions.json  : the upstream self-update manifest (app.patches / app.full / packs)
  * release.json   : the real asset inventory of one release tag (name/size/digest)
  * releases.json  : the release history (list of tags)

It reports coverage gaps (artifacts / platforms shipped but untracked by the
manifest), delta-patch reachability (prior versions that have no patch path) and
integrity (does each declared sha256/size match the real release asset).

Zero third-party dependencies. Core logic is fully offline; no network calls.
Exit codes: 0 = clean, 1 = problems found, 2 = usage / input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TOOL = "ghost-release-cover"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# OS-arch tokens we recognise inside a release asset filename.
_OS_TOKENS = [
    ("Windows", ["windows"]),
    ("macOS", ["macos", "darwin", "mac"]),
    ("Linux", ["linux"]),
    ("Android", ["android"]),
]
_ARCH_TOKENS = [
    ("x86_64", ["x86_64", "amd64", "x64"]),
    ("arm64", ["arm64", "aarch64"]),
]


def _die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.stderr.write(f"{TOOL}: error: {msg}\n")
    raise SystemExit(2)


def load_json(path: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        _die(f"file not found: {path}")
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON in {path}: {exc}")


def parse_platform(name: str) -> str | None:
    """Return 'OS-arch' platform key inferred from an asset filename, or None."""
    lower = name.lower()
    os_name = None
    for canon, kws in _OS_TOKENS:
        if any(kw in lower for kw in kws):
            os_name = canon
            break
    if os_name is None:
        return None
    arch = None
    for canon, kws in _ARCH_TOKENS:
        if any(kw in lower for kw in kws):
            arch = canon
            break
    if arch is None:
        return None
    # Windows Setup.exe / zip share the plain OS-arch key; Android suffixes are
    # collapsed onto the base arch so the whole ABI family maps to one platform.
    return f"{os_name}-{arch}"


def _digest_hex(digest: str) -> str | None:
    if not isinstance(digest, str):
        return None
    d = digest.strip()
    if d.startswith("sha256:"):
        d = d[len("sha256:"):]
    return d.lower() if SHA256_RE.match(d) else None


def _version_tuple(s: str) -> tuple:
    """Loose version parse matching upstream app.update.parseVersion semantics."""
    seg, acc, has = [], 0, False
    for ch in s.lstrip("vV"):
        if ch.isdigit():
            acc = acc * 10 + int(ch)
            has = True
        elif ch == "." and has:
            seg.append(acc)
            acc, has = 0, False
        else:
            break
    if has:
        seg.append(acc)
    while seg and seg[-1] == 0:
        seg.pop()
    return tuple(seg)


def audit(versions: dict, release: dict, releases: dict, packs: dict | None) -> dict:
    findings: list[dict] = []

    def add(fid: str, level: str, message: str, detail=None):
        findings.append({"id": fid, "level": level, "message": message,
                         "detail": detail or {}})

    app = versions.get("app", {}) if isinstance(versions, dict) else {}
    app_version = str(app.get("version", ""))
    patches = app.get("patches", {}) or {}
    full = app.get("full", {}) or {}
    pack_map = versions.get("packs", {}) or {}

    # ---- structural sanity of declared sha256 values -------------------
    declared = []  # (label, file, obj, kind)
    for plat, info in patches.items():
        declared.append((f"patch:{plat}", info.get("file", ""), info, "patch"))
    for plat, info in full.items():
        declared.append((f"full:{plat}", info.get("file", ""), info, "full"))
    for label, _f, info, _k in declared:
        sha = info.get("sha256", "")
        if not SHA256_RE.match(str(sha or "")):
            add("INVALID_SHA", "error",
                f"{label} has a malformed sha256", {"file": _f, "sha256": sha})
        size = info.get("size")
        if not isinstance(size, int) or size <= 0:
            add("INVALID_SIZE", "error",
                f"{label} has a missing/zero size", {"file": _f, "size": size})

    # ---- release asset inventory ---------------------------------------
    assets = release.get("assets", []) if isinstance(release, dict) else []
    release_tag = release.get("tag") if isinstance(release, dict) else None
    by_name = {}
    for a in assets:
        n = a.get("name")
        if n:
            by_name[n] = a

    tracked_files = {info.get("file") for _l, _f, info, _k in declared if info.get("file")}

    # ---- coverage: artifacts shipped but not tracked by the manifest ----
    untracked = [a["name"] for a in assets
                 if a.get("name") and a["name"] not in tracked_files]
    if untracked:
        add("ARTIFACT_UNTRACKED", "warning",
            f"{len(untracked)} release artifact(s) are not tracked by the manifest",
            {"assets": untracked})

    shipped_platforms = sorted({p for p in (parse_platform(a.get("name", ""))
                                            for a in assets) if p})
    manifest_platforms = sorted(full.keys())
    uncovered = [p for p in shipped_platforms if p not in manifest_platforms]
    for p in uncovered:
        add("PLATFORM_UNCOVERED", "warning",
            f"{p} is shipped in the release but has no app.full entry "
            f"(in-app update on this platform ends in 'no update available')",
            {"platform": p})

    # ---- delta-patch reachability across release history ----------------
    tags = releases.get("tags", []) if isinstance(releases, dict) else []
    prior_versions = []
    for t in tags:
        v = str(t).lstrip("vV")
        if v and v != app_version:
            prior_versions.append(v)
    patch_from = sorted({str(i.get("from", "")).lstrip("vV")
                         for i in patches.values() if i.get("from")})
    prior_with = [v for v in prior_versions if v in patch_from]
    prior_without = [v for v in prior_versions if v not in patch_from]
    if prior_without:
        add("PATCH_MISSING_FOR_PRIOR", "warning",
            f"{len(prior_without)} prior release(s) have no delta patch → forced full download",
            {"versions": prior_without})

    # ---- integrity: declared digest/size vs real release asset ----------
    integrity_checked = 0
    integrity_mismatch = []
    integrity_missing = []
    for label, fname, info, _kind in declared:
        asset = by_name.get(fname)
        if asset is None:
            integrity_missing.append(fname)
            add("MISSING_TRACKED_ASSET", "error",
                f"{label} references a file absent from the release assets",
                {"file": fname})
            continue
        integrity_checked += 1
        want_sha = str(info.get("sha256", "")).lower()
        got_sha = _digest_hex(asset.get("digest", ""))
        size_ok = (info.get("size") == asset.get("size"))
        sha_ok = (got_sha is None) or (want_sha == got_sha)
        if not (size_ok and sha_ok):
            integrity_mismatch.append(fname)
            add("INTEGRITY_MISMATCH", "error",
                f"{label} declared size/sha256 disagrees with the real asset",
                {"file": fname, "declared_size": info.get("size"),
                 "actual_size": asset.get("size"), "declared_sha": want_sha,
                 "actual_sha": got_sha, "size_ok": size_ok, "sha_ok": sha_ok})

    # ---- packs ----------------------------------------------------------
    packs_checked = 0
    packs_mismatch = []
    packs_missing = []
    pack_inventory = (packs or {}).get("packs", []) if isinstance(packs, dict) else []
    inv_by_name = {p.get("name"): p for p in pack_inventory if p.get("name")}
    for pname, pinfo in pack_map.items():
        want = str(pinfo.get("sha256", "")).lower()
        got = inv_by_name.get(pname)
        if got is None:
            packs_missing.append(pname)
            add("PACK_MISSING", "warning",
                f"pack {pname} is in the manifest but absent from the pack inventory",
                {"pack": pname})
            continue
        packs_checked += 1
        if str(got.get("sha256", "")).lower() != want:
            packs_mismatch.append(pname)
            add("PACK_INTEGRITY_MISMATCH", "error",
                f"pack {pname} sha256 disagrees with the shipped file",
                {"pack": pname, "declared_sha": want, "actual_sha": got.get("sha256")})
        gdmin = str(pinfo.get("gdMinVersion", "")).lstrip("vV")
        if gdmin and app_version and _version_tuple(gdmin) > _version_tuple(app_version):
            add("PACK_MIN_VERSION_EXCEEDS_APP", "error",
                f"pack {pname} needs GD ≥ {gdmin} but manifest app is {app_version}",
                {"pack": pname, "gdMinVersion": gdmin, "app_version": app_version})

    # ---- assemble -------------------------------------------------------
    errors = sum(1 for f in findings if f["level"] == "error")
    warnings = sum(1 for f in findings if f["level"] == "warning")
    return {
        "tool": TOOL,
        "app_version": app_version,
        "release_tag": release_tag,
        "coverage": {
            "artifacts_total": len(assets),
            "artifacts_tracked": len([a for a in assets
                                      if a.get("name") in tracked_files]),
            "artifacts_untracked": sorted(untracked),
            "platforms_shipped": shipped_platforms,
            "platforms_in_manifest": manifest_platforms,
            "platforms_uncovered": uncovered,
        },
        "patch_reachability": {
            "patch_from": patch_from,
            "prior_versions": len(prior_versions),
            "prior_with_patch": sorted(prior_with),
            "prior_without_patch": len(prior_without),
            "forced_full_versions": len(prior_without),
        },
        "integrity": {
            "checked": integrity_checked,
            "mismatches": integrity_mismatch,
            "missing": integrity_missing,
        },
        "packs": {
            "checked": packs_checked,
            "mismatches": packs_mismatch,
            "missing": packs_missing,
        },
        "summary": {
            "findings": len(findings),
            "errors": errors,
            "warnings": warnings,
            "status": "problems" if findings else "clean",
        },
        "findings": findings,
    }


def render_text(report: dict) -> str:
    lines = []
    c = report["coverage"]
    p = report["patch_reachability"]
    s = report["summary"]
    lines.append(f"{TOOL} — Ghost Downloader release-manifest audit")
    lines.append(f"app_version={report['app_version']}  release_tag={report['release_tag']}")
    lines.append("")
    lines.append(f"Coverage   : {c['artifacts_tracked']}/{c['artifacts_total']} artifacts tracked; "
                 f"platforms {len(c['platforms_in_manifest'])}/{len(c['platforms_shipped'])} covered")
    if c["platforms_uncovered"]:
        lines.append(f"  uncovered: {', '.join(c['platforms_uncovered'])}")
    lines.append(f"Patch reach: from {p['patch_from']}; "
                 f"{p['prior_without_patch']}/{p['prior_versions']} prior releases forced to full download")
    lines.append(f"Integrity  : {report['integrity']['checked']} app artifacts checked, "
                 f"{len(report['integrity']['mismatches'])} mismatch, "
                 f"{len(report['integrity']['missing'])} missing")
    lines.append(f"Packs      : {report['packs']['checked']} checked, "
                 f"{len(report['packs']['mismatches'])} mismatch, "
                 f"{len(report['packs']['missing'])} missing")
    lines.append("")
    status = "PASS (no findings)" if s["findings"] == 0 else f"PROBLEMS: {s['errors']} error(s), {s['warnings']} warning(s)"
    lines.append(f"Result     : {status}")
    for f in report["findings"]:
        lines.append(f"  [{f['level']:7s}] {f['id']}: {f['message']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description="Audit Ghost-Downloader-3 versions.json against real release assets.")
    ap.add_argument("--versions", required=True, help="path to upstream versions.json")
    ap.add_argument("--release", required=True, help="path to one release asset inventory JSON")
    ap.add_argument("--releases", required=True, help="path to release history JSON ({tags:[...]})")
    ap.add_argument("--packs", help="optional pack inventory JSON ({packs:[{name,file,sha256,size}]})")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--fail-on", choices=["warning", "error", "never"], default="warning",
                    help="lowest finding level that makes exit code 1 (default: warning)")
    args = ap.parse_args(argv)

    versions = load_json(args.versions)
    release = load_json(args.release)
    releases = load_json(args.releases)
    packs = load_json(args.packs) if args.packs else None

    if not isinstance(versions, dict) or "app" not in versions:
        _die("versions file is not a versions.json object (missing 'app')")

    report = audit(versions, release, releases, packs)

    if args.json:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print(render_text(report))

    s = report["summary"]
    if args.fail_on == "never":
        return 0
    if args.fail_on == "error":
        return 1 if s["errors"] > 0 else 0
    return 1 if (s["errors"] > 0 or s["warnings"] > 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
