# ProxGram v2.0 Production Verification Report

**Date:** 2026-10-01 · **Question:** Is v2.0 behavior actually live in production?

## Verdict: **v1 behavior is still running in production.**

The v2.0 code exists **only as uncommitted local changes** on this machine. GitHub
Actions deploys from `origin/main` via `git checkout` of the default branch — and
`origin/main` contains **zero** v2.0 commits. Every production run therefore
executes the old pipeline: TCP-connect-only probing, no SNI whitelist, and a
5-proxy target that is padded via "known-good reuse". This was confirmed by
runtime evidence (the `chore: update history` commit stream) and by executing
both codebases side-by-side under identical live conditions.

---

## Step 1 — Production execution path

| Item | Finding | Evidence |
|---|---|---|
| Platform | GitHub Actions cron (no VPS/Docker/crontab files in repo; no deploy configs) | [.github/workflows/auto_post.yml](.github/workflows/auto_post.yml#L3-L4): `cron: '*/5 * * * *'` |
| Entrypoint | `python main.py` after a test step (`python -m unittest test_main -v`) and `python verify_chat.py` | [auto_post.yml](.github/workflows/auto_post.yml#L31-L46) |
| Deploy source | `actions/checkout@v4` of the repo's default branch → **whatever is on `origin/main`** | [auto_post.yml](.github/workflows/auto_post.yml#L15-L19) |
| Actual cadence | Runs execute, but **~17–28 min apart** (GitHub cron slots), not every 5 min. 1,377 total runs; latest: run #1377 at 2026-10-01T07:01:05Z, completed 07:01:30Z (25 s wall) | GitHub API `GET /actions/runs?per_page=8` (public repo, unauthenticated 200 OK) |
| Single runner | Only one workflow exists on the remote (`Auto Post Proxies`, state `active`); `git ls-remote --heads` shows only `refs/heads/main`; repo is **public, not a fork** | GitHub API `GET /actions/workflows` |

## Step 2 — Configuration / deployment state: v2.0 was never pushed

- Local branch is **0 ahead / 1236 behind** `origin/main` (after `git fetch`).
- Last local commit touching `main.py/prober.py/fetcher.py`: `a01a0f6` (2026-09-17) — v1.
- `git status`: `main.py`, `fetcher.py`, `prober.py`, `test_main.py`, `README.md` all **modified but uncommitted** (1,024 insertions of v2.0 work).
- `git diff --stat` on the working tree is exactly the v2.0 feature set (SNI gate, handshake probe, dynamic batch).
- **Conclusion:** GitHub Actions cannot see v2.0. There is no silent config fallback — the *code itself* on `origin/main` is the old architecture. All v2.0 constants (`MIN_BATCH_SIZE`, `SNI_ALLOWED_DOMAINS`, `EXPANSION_SOURCES`) live in code, not env vars; the only env vars are the Telegram secrets.

## Step 3 — SNI gate

**v2.0 code (local working tree — NOT deployed):**
- Extraction: `extract_sni_domain()` — [fetcher.py:128](fetcher.py#L128); server fallback `effective_sni()` — [fetcher.py:176](fetcher.py#L176)
- Whitelist: `SNI_ALLOWED_DOMAINS = SNI_TIER1_DOMAINS + SNI_TIER2_DOMAINS` — [fetcher.py:111](fetcher.py#L111); check `sni_is_allowed()` — [fetcher.py:200](fetcher.py#L200); rejected in `validate()` — [fetcher.py:334-347](fetcher.py#L334-L347) (`bad_sni` counter)

**Deployed v1 code (origin/main):** exactly **one** hit for "sni" in `main.py` (a docstring); `fetcher.py` has **zero** SNI logic; `validate()` only checks `bad_secret` / `bad_port` / `duplicate`.

**Live run traces (my controlled runs today, real feeds, Telegram stubbed):**

v2 (workspace code):
```
PROXIES_FETCHED_COUNT: 179 | PROXIES_VALIDATED_COUNT: 10
(rejected: 22 bad secret, 45 bad port, 102 bad SNI, 0 duplicate)
```
- Rejected by whitelist (example): `79.137.196.223` (bare IP → invalid SNI), `mrak.store`, `welcome.kisex.top` (domains not on the allow list)
- Accepted and probed (example): `direct.mtaccess.win` (SNI `cloudflare.com`), plus 9 others with allowed SNIs

v1 (extracted from `origin/main`, same feed data, same minute):
```
PROXIES_FETCHED_COUNT: 179 | PROXIES_VALIDATED_COUNT: 112
(rejected: 22 bad secret, 45 bad port, 0 duplicate)
```
→ **102 candidates that v2 discards as bad-SNI sail through in v1**, including bare IPs.

## Step 4 — Fake-TLS handshake is the deciding factor

**v2.0 code:** `build_client_hello()` — [prober.py:145](prober.py#L145); `faketls_ping()` (connect → ClientHello with the secret's SNI → require valid ServerHello `16 03… 02`) — [prober.py:221](prober.py#L221); `probe()` — [prober.py:444](prober.py#L444). A successful TCP connect alone returns no latency; verification requires a ServerHello.

**Deployed v1 code (origin/main):** `probe()` submits **`tcp_ping` only** into the thread pool (read from `git show origin/main:prober.py`, lines 229–275). No ClientHello exists anywhere in the deployed tree. TCP-connect success alone marks a proxy "valid".

**Live probe traces (same controlled runs):**

v2:
```
handshake trace: 10 probed | 1 verified | 9 failed
VERIFIED  direct.mtaccess.win:443  sni=cloudflare.com  1051 ms
FAILED    79.137.196.223:443   sni=www.cloudflare.com   ← TCP-reachable, no TLS ServerHello
FAILED    79.137.196.223:8443  sni=www.cloudflare.com
FAILED    79.137.196.223:2053  sni=www.cloudflare.com
FAILED    87.58.149.247:443    sni=www.cloudflare.com   (…+5 more)
```
(Hosts that appear repeatedly on multiple ports are precisely the "TCP-accepts-everything" servers that v1's probe passes and v2 correctly rejects.)

v1, same pool: `PROBES: tested 8 → 8 valid` — zero handshakes performed; 5 bare-IP servers selected and posted:
```
Selected #1 server=154.86.119.143 latency=104 ms
Selected #2 server=31.76.77.201  latency=117 ms   … (5 total, all bare IPs)
```

Production-side corroboration: `history.json` on `origin/main` marks bare IPs `45.146.164.117:443`, `212.67.15.226:443` as `alive: True` — impossible under v2's SNI gate (bare IPs are rejected before probing).

## Step 5 — Dynamic batch (1..5) + no padding

**v2.0 code:** `MIN_BATCH_SIZE = 1` — [main.py:71](main.py#L71); log "Dynamic batch: publishing %d verified proxy(ies)" — [main.py:1104-1107](main.py#L1104-L1107); `pick_batch()` returns *up to* the size, never padding. Verified live: my v2 run posted **n=1** (`send -> {"n_proxies": 1, "servers": ["direct.mtaccess.win"]}`).

**Deployed v1 code:** `BATCH_SIZE = 5` (origin/main `main.py:66`) with a **padding fallback**: when fresh picks are short, `_reuse_known_good(reachable, last_posted, BATCH_SIZE)` — origin/main `main.py:853, 1036` — refills the batch toward 5 from previously-posted TCP-healthy proxies. This is how the channel keeps "looking like v1".

**Telegram channel history (from `history.txt` on origin/main — the runtime record of every dispatch, 452 post-events):**
```
10-01 01:00Z n=5 (4 bare IPs)   10-01 02:10Z n=5 (4 bare IPs)
10-01 02:28Z n=5 (5 bare IPs)   10-01 03:01Z n=5 (5 bare IPs)
10-01 04:57Z n=1 (1 bare IP)    10-01 06:42Z n=5 (4 bare IPs)
10-01 07:01Z n=5 (3 bare IPs)   ← latest post: exactly 5, three bare IPs
distribution over ALL 452 events: {5: 386, 1: 62, 2: 4}
```
386/452 posts are exactly 5 and recent posts carry 3–5 bare-IP servers — v2's gate would reject bare IPs outright, so **the channel provably is not running v2.0**. (The n=1/n=2 events are the deployed mid-version's partial-batch/reuse edge cases, not v2 dynamic dispatch.)

## Step 6 — Zero-post suppression

**v2.0 code:** suppression when 0 verified — [main.py:1097-1101](main.py#L1097-L1101) with `_silent_skip()` — [main.py:927](main.py#L927) and the exit path at [main.py:999](main.py#L999).

**Live forced test (feeds stubbed empty → 0 candidates), v2:**
```
Silent skip: 0 verified proxies found, skipping post - nothing will be posted this cycle…
POST DECISION: {will_post=no | reason='0 verified proxies found, skipping post' | …}
exit: 0 | send attempts: 0
```

**Hardest case (candidate exists → handshake fails → extended search → still 0 verified), v2:**
```
Only 0 valid proxies after probing; Refresh Cycle… → Still 0 valid; extended search via expansion feeds
0 verified proxies found, skipping post
POST DECISION: {will_post=no | reason='0 verified proxies found, skipping post' | chat_id=skipped | text_len=0}
exit: 0 | send attempts: 0
```

**Deployed v1** skips only when there are **0 candidates** (`reason='no valid candidates from sources'`); it has no "0 verified after probing" suppression and pads toward 5 via reuse instead.

Production-side corroboration: the run history shows zero "skip" evidence of the v2 string and uninterrupted 5-proxy posting; if v2 were live, bare-IP posts would be impossible.

## Step 7 — Two runners / wrong channel / stale deployment

- **Multiple workflows:** none — GitHub API lists exactly one workflow (`auto_post.yml`, active); no other YAML in `.github/workflows/`.
- **Multiple branches:** `git ls-remote --heads origin` → only `main`.
- **Fork:** repo is public, `fork: false`.
- **Hardcoded chat/bot:** none — `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHANNEL_ID` come only from GitHub Secrets (referenced in [auto_post.yml](.github/workflows/auto_post.yml#L37-L46) and read via `os.environ` in main.py); `t.me` strings in code are dead-link examples (`t.me/proxy` placeholder), not destinations.
- **Old runner still posting?** No — the channel's "v1 look" is fully explained by the stale deployment itself.
- **Diagnosis: stale deployment.** The v2.0 changes were completed and tested locally (166/166 tests) but were **never committed or pushed**. Every scheduled run checks out v1 code.
- **Credential note (task contingency):** no Telegram credentials exist in this sandbox (posting was stubbed; the live channel was never touched). GitHub Actions log/artifact downloads returned `403 Must have admin rights` unauthenticated — with a `GITHUB_TOKEN`/admin access, `GET /repos/…/actions/runs/{id}/logs` (or the `proxgram-log-*` artifacts) would provide the per-run CI logs referenced above. The runtime trace I used instead is the `chore: update history` commit stream, which is written by production runs themselves.

## Step 8 — Final verdict table

| Req | Verdict | Evidence |
|---|---|---|
| **A** Only handshake-verified proxies posted | **FAIL in production** (PASS in local v2) | v1 `probe()` = `tcp_ping` only (origin/main prober.py:229-275); v2 `faketls_ping` [prober.py:221](prober.py#L221). Live: v2 rejected 9/10 incl. TCP-reachable hosts; v1 passed all TCP-reachable. Production `history.json` marks bare IPs `alive`. |
| **B** Dynamic batch 1..5, no padding | **FAIL in production** (PASS in local v2) | 386/452 posts exactly 5 (history.txt); v1 pads via `_reuse_known_good(...BATCH_SIZE)` (origin/main main.py:853,1036); v2 `MIN_BATCH_SIZE=1` [main.py:71](main.py#L71) demonstrated live with n=1. |
| **C** Zero-post suppression | **FAIL in production** (PASS in local v2) | v2: `will_post=no`, 0 sends, exact skip string (forced tests above). v1 lacks it; pads instead. |
| **D** SNI extraction + Iran whitelist gate active | **FAIL in production** (PASS in local v2) | v1 has zero SNI logic; v2 live: `102 bad SNI` rejections of 179 fetched. Production posts contain 3–5 bare-IP servers per post → gate provably not running. |

## Conclusion

**"v1 behavior still running."** Exact reason: **the v2.0 implementation was never committed to `origin/main`** — it exists only as local uncommitted changes. The single GitHub Actions workflow correctly runs `python main.py` on a schedule, but it checks out a codebase whose prober is TCP-only, whose validator has no SNI gate, and whose dispatcher pads toward 5. There is no second runner, no wrong channel, and no config fallback to fix — the fix is deployment.

**Minimal fix (1 action):** commit and push the five modified files (`main.py`, `fetcher.py`, `prober.py`, `test_main.py`, `README.md`) to `origin/main`. The next scheduled run executes v2.0 automatically; verify with the run log funnel (`PROXIES_FETCHED_COUNT → bad SNI rejections → handshake-verified → Dynamic batch: publishing N`) and watch `history.txt` for posts with <5 proxies and no bare IPs. Optional hardening afterward: gate the commit step on state-file changes only, and watch whether the `mtpro.xyz` expansion feed actually answers from Actions' vantage.
