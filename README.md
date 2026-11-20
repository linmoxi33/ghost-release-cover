# ghost-release-cover

Audit [Ghost Downloader 3](https://github.com/XiaoYouChR/Ghost-Downloader-3)'s self-update
manifest against the artifacts the project *actually* releases — and see, in one command,
which platforms and which upgrade paths the manifest forgot. **Why now:** Ghost Downloader
ships 17 build artifacts per release (Windows / macOS / Linux / Android, several formats)
but its `versions.json` self-update manifest is hand-maintained; a missing entry silently
turns "one-click in-app update" into "current platform has no update available".

Upstream: https://github.com/XiaoYouChR/Ghost-Downloader-3

## Upstream and the gap it leaves

Ghost Downloader 3 is a desktop download manager (12.9k★, GPL-3.0). On launch it fetches
[`versions.json`](https://github.com/XiaoYouChR/Ghost-Downloader-3/blob/main/versions.json)
and, on the "update" button, picks `app.patches[platformKey]` or `app.full[platformKey]`
from that file. Two real problems are visible in the public data:

- **The manifest covers 4 platforms; the release ships 7.** `app.full` / `app.patches` only
  contain `Windows-x86_64`, `Windows-arm64`, `macOS-arm64`, `macOS-x86_64`. But the
  [`v4.5.10` release](https://github.com/XiaoYouChR/Ghost-Downloader-3/releases/tag/v4.5.10)
  publishes 17 assets including Linux `AppImage`/`deb`/`tar.xz` (x86_64 + arm64) and an
  Android `apk`. The README (line ~51) lists **Linux as a supported platform**.
- **On Linux the in-app updater always fails.** For Linux, `platformKey` is
  `Linux-x86_64`/`Linux-arm64`; `app.full` has no such key, so
  [`update_service.py` L233-L239](https://github.com/XiaoYouChR/Ghost-Downloader-3/blob/main/app/services/update_service.py#L233-L239)
  hits `if not full:` and emits `FAILED: 当前平台无可用更新`. Delta patches are also
  gated to the exact installed version (`patch.get("from") == VERSION`, L211-214), so even
  on Windows/macOS only one prior version gets a delta — 28 of the last 29 releases have no
  patch path and force a full download.

Nothing in the repo checks the manifest against the release inventory. `ghost-release-cover`
does exactly that, offline.

## What it does / does not do

It reconciles three **local** files — the manifest, one release's asset inventory, and the
release-history tag list — and reports:

1. **Coverage** — release artifacts not tracked by the manifest, and platform-arch targets
   shipped but with no `app.full` entry.
2. **Delta-patch reachability** — how many prior versions have no patch → forced full
   download.
3. **Integrity** — every declared `sha256`/`size` is compared against the real asset digest
   and size; every pack's `sha256` against the shipped pack file.

It does **not**: download binaries, call any network API at runtime, modify `versions.json`,
or decide whether Linux *should* self-update. Core logic is pure offline file analysis.

## Install

No dependencies. Python 3.9+ only.

```bash
git clone git@github-linmoxi33:linmoxi33/ghost-release-cover.git
cd ghost-release-cover
python3 -m unittest discover -s tests -v          # 21 tests
```

## Usage

Capture the two inventories once with `gh` (read-only), then audit offline:

```bash
# 1) release asset inventory for the current tag (name / size / sha256 digest)
gh api repos/XiaoYouChR/Ghost-Downloader-3/releases/tags/v4.5.10 \
  --jq '{tag:.tag_name, assets:[.assets[]|{name,size,digest}]}' > examples/in/release.json

# 2) release history
gh api 'repos/XiaoYouChR/Ghost-Downloader-3/releases?per_page=30' \
  --jq '{tags:[.[]|.tag_name]}' > examples/in/releases.json

# 3) audit
python3 bin/ghost_release_cover.py \
  --versions examples/in/versions.json \
  --release  examples/in/release.json \
  --releases examples/in/releases.json \
  --packs    examples/in/packs.json
```

Human output on the real `v4.5.10` data:

```
Coverage   : 8/17 artifacts tracked; platforms 4/7 covered
  uncovered: Android-arm64, Linux-arm64, Linux-x86_64
Patch reach: from ['4.5.8']; 28/29 prior releases forced to full download
Integrity  : 8 app artifacts checked, 0 mismatch, 0 missing
Packs      : 13 checked, 0 mismatch, 0 missing
Result     : PROBLEMS: 0 error(s), 5 warning(s)
```

`--json` emits the full report (see `examples/out/report.json`):

```bash
python3 bin/ghost_release_cover.py --versions examples/in/versions.json \
  --release examples/in/release.json --releases examples/in/releases.json \
  --packs examples/in/packs.json --json | python3 -c "import json,sys;print(json.load(sys.stdin)['coverage'])"
```

### Exit codes

| code | meaning |
| --- | --- |
| `0` | clean — no finding at or above the `--fail-on` level |
| `1` | problems found (default `--fail-on warning`) |
| `2` | usage error or unreadable / invalid input JSON |

`--fail-on {warning,error,never}` selects the lowest level that makes the exit code `1`.
`--packs` is optional; without it the pack section reports `checked: 0`.

## 与同类项目的差异

Searched `gh search repos "release manifest audit"` / `"updater manifest sha256"` /
`"ghost downloader update"` on 2026-11-20 (commands in `/tmp/similar.md` when run live).
No project audits a **HDiff-patch self-update manifest against the real multi-platform
release inventory**. The only near hit was `AnandMNambiar/release-manifest-audit` (0★,
generic SHA3-512 prototype, no coverage/patch-reachability model). This tool is specific to
the manifest→release→release-history reconciliation and ships runnable examples from real
upstream data.

## 本轮创新

首次把「自更新清单」从逐字段静态校验推进到**清单 × 真实 release 资产 × 发布历史的三方对账**：
在同一份 `versions.json` 上量化出「清单只覆盖 4/7 平台-架构、Linux/Android 完全没有条目、
11 个历史版本里只有 1 个有增量补丁」，并用真实 release digest 证明清单已声明的 8 个条目
0 完整性缺陷。台账里没有一条以发布/分发清单为被测对象的运行时数据对账。

## 局限

- It audits *declared metadata*, not binary contents (it trusts the release `digest` as the
  ground truth rather than re-hashing a 46-90 MB download).
- Platform inference is filename-based; a release asset whose name omits OS/arch is skipped.
- It does not model *which* Linux format the updater should use — that is a product decision
  for upstream, not something this tool guesses.
- The `--packs` inventory must be captured separately from `dist/packs/` (see `examples/in/packs.json`).

MIT licensed. Upstream is GPL-3.0; this tool is an independent analyzer that only reads
public data files and ships no upstream code.
