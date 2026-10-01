# ProxGram — System Documentation

**Version:** 2.0 · **Generated:** 2026-09-27 · **Scope:** full codebase (`main.py`, `fetcher.py`, `prober.py`, `rates.py`, `verify_chat.py`, `test_main.py`, `.github/workflows/auto_post.yml`, state files)

ProxGram is a fully automated, GitHub Actions–driven publisher that posts **one Telegram message** containing **1–5 handshake-verified, censorship-resistant MTProto proxies** (Fake-TLS `ee` secrets, HTTPS-compatible ports, curated Iranian-DPI fronting domains) plus a **real-time Iranian gold & currency market board** — **only when at least one proxy passes a real Fake-TLS TLS handshake**. If nothing verifies, nothing is posted.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Directory Structure & File Map](#2-directory-structure--file-map)
3. [Step-by-Step Workflow](#3-step-by-step-workflow)
4. [Validation & Filtering Logic](#4-validation--filtering-logic)
5. [CI/CD & Automation](#5-cicd--automation)
6. [Known Bottlenecks & Limitations for Iranian ISPs](#6-known-bottlenecks--limitations-for-iranian-isps)
7. [Local Setup & Testing Guide](#7-local-setup--testing-guide)

---

## 1. System Overview

### 1.1 Core Purpose

ProxGram solves a single operational problem for an Iranian-audience Telegram channel: **reliably publishing working, anti-censorship MTProto proxies without human intervention — and never publishing a dead one.** Each run is adversarial by design: upstream feeds are noisy (mixed protocols, dead servers, plain-socks spam), Iranian DPI actively kills non-camouflaged MTProto traffic, and the 5-minute schedule tempts the pipeline into posting unverified fillers. The design enforces four invariants:

1. **Never post an unverified proxy.** A proxy is published only after passing secret-format validation, port allow-listing, the SNI fronting-domain gate, **and a real Fake-TLS ClientHello handshake** that requires a valid TLS ServerHello response.
2. **Never post a duplicate.** Every published proxy is recorded (link-based, timestamped) in `history.txt`, committed back to the repository so dedup state persists across runs.
3. **Never post on a rigid schedule with dead proxies.** Batch size is **dynamic (1–5)** and driven entirely by how many proxies genuinely verify. Zero verified proxies means **zero Telegram traffic** — the run exits cleanly with a "0 verified proxies found, skipping post" status.
4. **Never fail the run on partial data.** Any single source, rate endpoint, or Telegram formatting mode failing degrades gracefully instead of aborting the pipeline.

### 1.2 Architecture

ProxGram is a **serverless, scheduled search-and-publish pipeline** — there is no always-on server. GitHub Actions acts as the scheduler *and* the persistence layer (state files are committed back into the repo). The 5-minute cron is now merely the *search cadence*: each run is an escalating search that ends in a dispatch only if the search succeeds.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     GitHub Actions (ubuntu-latest)                       │
│  cron */5 * * * *  →  checkout → tests → verify_chat → main.py           │
│                                                 │                        │
│  ┌─────────────────────┐   ┌─────────────────┐  │  ┌──────────┐          │
│  │     fetcher.py      │   │    prober.py    │  │  │ rates.py │          │
│  │ 7 primary feeds     │   │ faketls_ping:   │  │  │ TGJU /   │          │
│  │ + mtpro.xyz         │──►│ ClientHello(SNI)│─ ►│  │ Nobitex  │          │
│  │ expansion (extended)│   │ → ServerHello?  │  │  │ 3s budget│          │
│  │ SNI gate + tiering  │   │ 60 workers      │  │  └──────────┘          │
│  └─────────────────────┘   └─────────────────┘  │                        │
│              │  SNI-gated, tier-sorted      verified pool             │
│              ▼                                ▼                         │
│        selection (dynamic 1-5, history/cooldown, distinct hosts)         │
│                              │                                           │
│                 0 verified ─┤(suppressed)├─ 1-5 verified                 │
│                              ▼                        ▼                 │
│                        NO POST, exit 0      Telegram Bot API             │
│                                             sendMessage (HTML + KB)      │
│                                                          │               │
│                 history.txt / history.json / last_rates.json │           │
│                              git commit + rebase + push back to repo        │
└──────────────────────────────────────────────────────────────────────────┘
```

**Module roles:**

| Module | Responsibility | Key additions in v2 |
| --- | --- | --- |
| `main.py` | Orchestrator: config constants, `Proxy` model, secret validation (now 3 wire formats), history dedup, message formatting, Telegram dispatch, `main()` dynamic search pipeline | `MIN_BATCH_SIZE=1`, extended search wiring, zero-post suppression, dotted-domain secret branch |
| `fetcher.py` | Multi-source parallel acquisition + **SNI module**: `extract_sni_domain()` (3 secret formats), `effective_sni()`, `sni_is_allowed()`, `sni_tier()`, curated Iran-DPI domain lists, `EXPANSION_SOURCES`, SNI-aware `validate()` | `extract_sni` functions; Iran-DPI gate & scoring; expansion feeds |
| `prober.py` | Strict quality gate: **`faketls_ping()` handshake probe** (`build_client_hello()` + `is_tls_server_hello()`), 60-way parallelism, 2500 ms cap, two-strike TTL health map (`history.json`) | `perform-handshake` module: real Fake-TLS ClientHello, ServerHello required |
| `rates.py` | Market data: TGJU bulk JSON (primary) + Nobitex USDT (fallback), rial→toman normalization, Jalali date rendering, `last_rates.json` cache | unchanged |
| `verify_chat.py` | Pre-flight `getChat` diagnostic; workflow fail-fast step | unchanged |

The circular-import hazard (`main` ↔ `fetcher`/`prober`) is deliberately managed: `main` imports the three modules eagerly at startup, while `fetcher` and `prober` reference `main` only inside function bodies (`from main import Proxy` lazily; `prober._const()` reads constants lazily; `prober._sni_for()` imports `fetcher` lazily) — importing any single module is always safe.

### 1.3 Overall Data Flow

```
7 primary feeds (+ mtpro.xyz on extended search) ──parallel fetch (5s/URL)──► raw text/JSON
        │
        ▼  normalize: keep only t.me/proxy | tg://proxy lines (socks5/vless/vmess discarded)
        ▼  merge + raw dedup by (server, port, secret)          ← PROXIES_FETCHED_COUNT
        ▼  SNI GATE: extract_sni_domain → sni_is_allowed
        │     bare-IP / unknown / blocked fronting → discarded  ← bad_sni stat
        ▼  SNI TIER SORT: global-CDN camouflage probed first
        ▼  cap at MAX_TO_TEST (90)                              ← PROXIES_VALIDATED_COUNT
        ▼
   Fake-TLS HANDSHAKE PROBE (60 workers, 2.0 s deadline, ≤2500 ms):
        TCP connect → ClientHello(SNI=fronting domain) → require TLS ServerHello
        two-strike ban list from history.json; early stop at 8 valid
        │
        ├─ 0 verified → Refresh Cycle (+30 cap) → still 0 → EXTENDED search
        │              (expansion feeds) → still 0 → ZERO-POST SUPPRESSION
        ▼
   Selection: exclude 24 h-cooldown history, prefer distinct hostnames,
              latency-sorted, dynamic batch 1-5 (0 → known-good reuse → no post)
        ▼
   Rates stage (≤3 s): TGJU bulk → cache fill → Nobitex USD → render board
        ▼
   sendMessage: HTML + inline keyboard → plaintext + keyboard → plaintext
        ▼  only if `ok:true`
   append history.txt (timestamped v2) → compact to 2000 entries
        ▼
   workflow: git add history.txt/history.json/last_rates.json → commit → rebase → push
```

**Live reference run** (2026-09-27, from CI-like vantage): 186 fetched → 9 survived the SNI gate (108 unknown-SNI discards) → **2 handshake-verified** (`moonmy.world:443` 279 ms, `direct.mtaccess.win:443` 307 ms, both fronting `cloudflare.com`) → a dynamic batch of 2 would be dispatched.

---

## 2. Directory Structure & File Map

```
ProxGram/
├── main.py                          # Orchestrator & entrypoint (see §2.1)
├── fetcher.py                       # Acquisition + SNI extraction/gating module
├── prober.py                        # Fake-TLS handshake probe + two-strike health
├── rates.py                         # Gold/currency rates: fetch, cache, board
├── verify_chat.py                   # getChat pre-flight diagnostic
├── test_main.py                     # Full unit-test suite (unittest, stdlib only)
├── requirements.txt                 # Runtime deps: requests>=2.31.0
├── README.md                        # User-facing overview & ops runbook
├── SYSTEM_DOCUMENTATION.md          # This document
│
├── .github/
│   └── workflows/
│       └── auto_post.yml            # Scheduled CI/CD pipeline (see §5)
│
├── history.txt                      # STATE: posted-proxy dedup log (v2 timestamped)
├── history.json                     # STATE: TTL health map (strikes/latency/purged)
├── last_rates.json                  # STATE: last successful market-rates cache
├── proxgram.log                     # Run log file (gitignored)
├── news_history.txt                 # Legacy artifact from a removed news module (unreferenced)
├── .gitignore                       # Ignores proxgram.log, __pycache__, venvs
└── __pycache__/                     # Python bytecode cache
```

### 2.1 `main.py` — Orchestrator (entrypoint)

| Region (in file order) | Contents |
| --- | --- |
| Configuration | All tunable constants (§4.5); env-var reads for `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHANNEL_ID`, `TELEGRAM_CHANNEL_TAG`; `_DOMAIN_SUFFIX_RE` for the dotted-domain secret branch |
| Logging | `setup_logging()` — dual console (follows `sys.stdout`, so GitHub annotations interleave correctly) + file (`proxgram.log`) handlers |
| Telemetry | `gh_annotation()` emits `::error::`/`::warning::`/`::notice::` Actions annotations; `mask_token()` prevents token leaks; `TG_ERROR_HINTS` maps 400/401/403/404/429 to actionable fix text; `validate_credentials()` validates token shape (`^\d{6,12}:[A-Za-z0-9_-]{30,}$`) and channel-id shape |
| Proxy model | `Proxy` class — `server`, `port`, `secret`, optional `latency_ms`; properties `combo` (full identity tuple), `key` (`host:port` legacy id used by history), `link` (`https://t.me/proxy?...`), `tg_link` (`tg://proxy?...`) |
| Secret validation | `is_valid_faketls_secret()` — now **three** wire formats (§4.2); `is_allowed_port()` |
| Data collection | `fetch_text()`, `parse_qs_last()` (last-value-wins for mangled params), `parse_json_source()`, `parse_plaintext_source()`, `apply_filters()`, `collect_candidates(extra, extended)` — delegating to `fetcher` (extended → expansion feeds) |
| History | `_extract_ident()`, `_history_entries()` (v2 + legacy migration via `RECOVERY_TS`), `load_history()`, `load_history_timestamps()`, `compact_history()` (newest 2000), `append_history()` |
| Message formatting | `format_message()` / `format_message_minimal()` (rates prepended, headline only — **no raw proxy links in the body**), `format_batch_message()`, `build_inline_keyboard()` (2-column grid sized to the dynamic batch + full-width join row), `send_message()` (3-attempt degradation + single 429 backoff retry) |
| Selection | `rank_reachable()` (delegates to `prober.probe`, early-stop at 8 valid), `pick_batch()` (dynamic, §3 stage 3) |
| Main pipeline | `main()` — six stages with per-stage timing; escalation ladder (refresh cycle → extended expansion search); zero-post suppression at every exit; fallbacks `_reuse_known_good()` and `_silent_skip()`; `get_chat_info()`; `_post_decision()` verdict line |

### 2.2 `fetcher.py` — Acquisition + SNI Module

- **`SOURCES`** — ordered `(url, kind)` pairs; JSON feeds first (handshake-verified upstream, win dedup collisions):
  1. `dubblebyte/free-mtproto-proxies/main/proxies.json` *(json)*
  2. `hookzof/socks5_list/master/proxy.txt` *(text)*
  3. `TheSpeedX/SOCKS-List/master/mtproto.txt` *(text)*
  4. `jetkai/proxy-list/main/online-proxies/proto.txt` *(text)*
  5. `roosterkid/openproxylist/main/MTPROTO_RAW.txt` *(text)*
  6. `SoliSpirit/mtproto/master/all_proxies.txt` *(text)*
  7. `Grim1313/mtproto-for-telegram/master/all_proxies.txt` *(text)*
- **`EXPANSION_SOURCES`** — polled **only** by the extended search (`fetch_candidates(extended=True)`): `https://mtpro.xyz/api/?type=mtproto` (canonical MTProto JSON aggregator; `parse_json_feed` accepts both `server` and `host` keys). A dead expansion feed is skipped with a log, never crashing the run.
- **SNI extraction & Iran-DPI gate:**
  - `extract_sni_domain(secret)` — parses all three Fake-TLS wire formats (§4.3).
  - `effective_sni(server, secret)` — the SNI a client would actually send: the secret's embedded domain, else the server hostname; a bare IPv4/IPv6 address yields `None` (TLS forbids IP SNI; IP-fronting is trivially blocked).
  - `sni_is_allowed(domain)` — hard gate: syntactically valid (RFC-style domain regex) **and** on the curated allow list (subdomains included); blocked list (`t.me`, `telegram.org`, `example.com`, …) discards first.
  - `sni_tier(domain)` — probe-priority rank: 2 = global CDN (best camouflage), 1 = popular Iranian service, 0 = other.
  - `SNI_TIER1_DOMAINS` / `SNI_TIER2_DOMAINS` / `SNI_BLOCKED_DOMAINS` — the curated lists (§4.4).
- **`fetch_all()`** — `ThreadPoolExecutor(max_workers=len(sources))`; wall time ≈ slowest single fetch; per-URL failures contained (returned as `None`) and logged.
- **`parse_text_feed()`** — strict marker filter (`t.me/proxy` / `tg://proxy` only); caps at `MAX_PER_SOURCE` (60) per source.
- **`validate()`** — secret format + port allow-list + **SNI gate** + combo dedup, with `bad_secret`/`bad_port`/`bad_sni`/`duplicate` statistics. Bad-SNI proxies are discarded immediately — never probed, never posted.
- **`fetch_candidates(extended=False)`** — full pipeline; **SNI-tier sorts** the survivors (strongest camouflage first; stable within tiers); logs `PROXIES_FETCHED_COUNT` and `PROXIES_VALIDATED_COUNT` incl. SNI rejections; caps at `MAX_TO_TEST` (90).

### 2.3 `prober.py` — Handshake Quality-Gate Module

- **`build_client_hello(sni, random32=None)`** — a minimal, **RFC 8446-correct** Fake-TLS ClientHello: TLS 1.3 record layer, SNI extension carrying the fronting domain, x25519 key share, TLS 1.3/1.2 supported versions. Framing details that real servers enforce: every extension is `type(2) len(2) data` with **byte-count** list lengths, `supported_versions` uses a **one-byte** list length (`versions<2..254>`), and the key share is **x25519-only** (any 32 bytes is a valid share — a random secp256r1 point almost never lies on the curve and servers answering `decode_error` to it are common). Verified live: cloudflare.com, google.com, speedtest.net, and digikala.com all answer a valid ServerHello to this exact byte string.
- **`is_tls_server_hello(data)`** — acceptance rule: content type `0x16` (handshake), TLS major version `3`, sane record length, and first handshake message type `0x02` (ServerHello). Anything else — HTTP error page, RST echo, garbage, empty, alert — is `False`.
- **`faketls_ping(host, port, sni, timeout)`** — non-blocking TCP connect (same select-based, shared-deadline machinery as `tcp_ping`, covering DNS + both address families) → sends the ClientHello with the fronting domain as SNI → waits for a response within the deadline:
  - valid TLS ServerHello → **alive**, returns connect-to-response latency in ms;
  - empty read / connection reset / garbage / silent timeout → **dead** (`None`).
  The socket is closed immediately after the response; no MTProto data is exchanged and no full TLS session is established.
- **`tcp_ping()`** — the original TCP-connect-only probe, retained for diagnostics and tests; the pipeline itself now uses `faketls_ping`.
- **`load_health()` / `save_health()` / `banned_keys()` / `update_health()`** — `history.json` two-strike TTL mechanics (§4.6); handshake failures feed the same purge path (a failed handshake is a failed check).
- **`_sni_for(proxy)`** — resolves the probe's SNI per candidate (lazy `fetcher` import: `effective_sni`), so the ClientHello impersonates exactly the domain the user's client will.
- **`probe()`** — parallel handshake test with **early stop** (once `enough` = 8 valid results exist, pending futures are cancelled); banned proxies skipped without probing; outcomes update `history.json`; returns `(Proxy, latency)` sorted latency-ascending.

### 2.4 `rates.py` — Market Data Layer (unchanged in v2)

- TGJU bulk JSON primary + Nobitex USDT fallback; rial→toman normalization at parse time; computed bubble/intrinsic fields cached but **never rendered**; plausibility windows with loud rejection (a rial-scale cache is rejected wholesale); `last_rates.json` cache; pure-Python Jalali calendar; 3 s per request / 3 s stage budget; missing fields drop their line cleanly (never dashes or placeholders).

### 2.5 `verify_chat.py` — Pre-flight Diagnostic (unchanged)

One-shot `getChat` call using the env credentials; exit 0 = chat resolved, 1 = failed. Workflow fail-fast step.

### 2.6 `test_main.py` — Test Suite (166 tests, stdlib `unittest` only)

`requests` is stubbed at module top (`sys.modules["requests"]`) so the suite runs with no packages installed and no network (except two intentionally live `TcpPingTests`). Test classes (v2 additions bolded):

| Class | Covers |
| --- | --- |
| `SecretValidationTests` | `ee` prefix, hex key-only rejection, base64url acceptance, **dotted b64url+domain acceptance & digit-tail garbage rejection**, regression fixture, mangled params |
| **`SniDomainTests`** | **3-format SNI extraction (hex / b64url / b64url+dotted), key-only → None, bare-IP effective-SNI → None, allow-list membership, unknown/blocked/invalid rejection, tier scoring, `bad_sni` discards, expansion-source config, extended-feed wiring, `host`-key JSON feeds, tier sorting** |
| `PortTests` | Allow-list membership; rejection of 80/1080/7799/9999/65535 |
| `SourceParsingTests` | JSON feed parsing, plaintext strict filter, filter-chain stats |
| `BatchSelectionTests` | Latency ordering, duplicate combos, history exclusion (v2 + legacy), cooldown reuse/blocking, distinct-hostname preference, short pools, latency cap |
| `MessageAndKeyboardTests` | No links in body, deep-link shape, keyboard layout, exactly ONE sendMessage request, parse-entity fallback |
| `HistoryTests` | Append-on-success, v2 format, compaction, legacy migration, `_extract_ident` |
| `WorkflowConfigTests` | Cron, dispatch, concurrency, permissions, checkout config, tests-before-post ordering, history-commit ordering, YAML syntax |
| `JalaliDateTests` / `RatesParsingTests` / `RatesCacheTests` / `RatesFetchTests` / `RatesBoardTests` / `RatesValidationTests` / `RatesCaptionTests` / `WorkflowRatesConfigTests` | Market-data coverage (unchanged) |
| `EndToEndRatesFlowTests` | Full `main()` runs: history only on confirmed send, partial batches post, known-good reuse, rates failure never blocks |
| `CredentialValidationTests` / `TelegramErrorHandlingTests` / `ReliabilityHardeningTests` | Credentials, 4xx hints, 429 retry, POST DECISION, maintenance removal |
| `TimeoutAndTelemetryConfigTests` | Strict timeout constants, 4xx hint coverage |
| `TcpPingTests` | Legacy TCP probe (live host, dead host, invalid inputs) |
| `MultiSourceFetcherTests` | Strict MTProto filter, parallel skip-on-failure, telemetry + dedup, source backbone, delegation (now asserting `extended=False` default) |
| **`FakeTlsHandshakeTests`** | **ClientHello structure & SNI embedding, deterministic prefix, ServerHello validator matrix (valid/truncated/HTTP/alert/non-ServerHello), local TLS-behaving socket servers: valid ServerHello accepted, immediate FIN rejected, garbage rejected, closed port rejected, invalid inputs** |
| `StrictProberTests` | Two-strike purge, strike reset, banned skip (now via `faketls_ping` mock), latency cap, **SNI passed correctly to the handshake**, `history.json` compaction, delegation |
| **`ZeroPostSuppressionTests`** | **0 verified → no dispatch & exit 0; exactly 1 verified → 1-button post; 2-3 verified → dynamic batch; 5 verified → full batch; extended search recovers before suppression; `MIN_BATCH_SIZE == 1`** |
| **`TlsProbeHealthIntegrationTests`** | **Handshake failure feeds the two-strike purge** |
| `ResiliencePipelineTests` | Refresh cycle, low-pool suppression, no-dead-proxies guarantee, **extended search triggers on empty primary pool, suppression holds even when extended search also fails** |

### 2.7 State Files

| File | Producer | Consumer | Persisted? |
| --- | --- | --- | --- |
| `history.txt` | `main.append_history()` | `load_history()` / `load_history_timestamps()` | ✅ Committed by workflow — cross-run dedup |
| `history.json` | `prober.save_health()` | `prober.load_health()`, `_reuse_known_good()` | ✅ Committed by workflow — cross-run ban list |
| `last_rates.json` | `rates.save_cached_rates()` | `rates.load_cached_rates()` | ✅ Committed by workflow — rate fallback |
| `proxgram.log` | `setup_logging()` file handler | humans / uploaded as CI artifact | ❌ `.gitignore`d; 7-day artifact retention in CI |
| `news_history.txt` | (removed news module) | — | Legacy leftover, unreferenced by code or workflow |

---

## 3. Step-by-Step Workflow

`main()` enforces a **global deadline of 90 s** and logs a `[stage] name: result in N s` line plus a final always-printed `POST DECISION: {will_post | reason | fresh_count | selected_count | chat_id | parse_mode | text_len}` verdict for every run. **The run is a search, not a fixed poll**: the schedule merely starts a search; a dispatch happens only if the search finds verified proxies.

### From fixed polling to the dynamic search pipeline

Previously the run assumed five candidates would survive a TCP-only probe every five minutes and posted "exactly five or none," with TCP reachability as the only health signal. The pipeline is now a four-phase dynamic search — **Acquisition+Gate → Handshake Verification → Dynamic Selection → Dispatch** — where every phase can escalate (refresh cycle, extended expansion feeds) and the run ends in a dispatch *only* when at least one proxy is protocol-verified:

```
┌─ PHASE 1: ACQUISITION + SNI GATE (fetcher.py) ─────────────────────────┐
│ 7 primary feeds ──parallel 5s──► MTProto-link filter ──► merge/dedup    │
│ (empty? → +30 cap refresh)      (still empty? → EXTENDED: +mtpro.xyz)   │
│        ▼ extract_sni_domain(secret) → effective_sni(server, secret)     │
│        ▼ sni_is_allowed?  NO → discard immediately (bad_sni)            │
│        ▼ sni_tier sort: global-CDN camouflage first ──► cap 90          │
├─ PHASE 2: HANDSHAKE VERIFICATION (prober.py) ───────────────────────────┤
│ faketls_ping: TCP connect → ClientHello(SNI) → REQUIRE ServerHello      │
│ 60 workers · 2.0 s shared deadline · ≤2500 ms · two-strike history.json │
│ early stop at 8 valid                                                   │
│ (0 valid? → refresh cycle → still 0? → EXTENDED search → probe)         │
├─ PHASE 3: DYNAMIC SELECTION (main.py) ──────────────────────────────────┤
│ history + 24 h cooldown → distinct-host preference → latency order      │
│ picks 1-5 verified (never forced to 5, never padded)                    │
│ 0 picks → known-good reuse (re-probed healthy only) → still 0 → NO POST │
├─ PHASE 4: DISPATCH ─────────────────────────────────────────────────────┤
│ rates board (never blocks) → ONE sendMessage (HTML+KB → plain+KB → plain)│
│ history write ONLY on confirmed send → git persistence                  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Stage 0 — Credential verification (exit code 2 on failure)

1. Read `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHANNEL_ID` from the environment.
2. `validate_credentials()` checks token and channel-id shape; problems are logged **and** emitted as GitHub error annotations; the run exits `2`.
3. `get_chat_info()` performs a soft (non-fatal) `getChat` to resolve and log the destination chat — the wrong-chat guard.

### Stage 1 — Acquisition + SNI Gate (with escalation)

1. `collect_candidates()` → `fetcher.fetch_candidates(cap=90)`: all 7 primary sources fetched in parallel (5 s per-URL timeout, failing sources skipped); text feeds normalized to MTProto links only; raw merge with combo dedup (`PROXIES_FETCHED_COUNT`); then the strict filter — Fake-TLS secret format, port allow-list, **SNI gate**, dedup (`PROXIES_VALIDATED_COUNT`) — and the survivors are **SNI-tier sorted** so global-CDN-camouflaged proxies are probed first.
2. **Escalation on empty:** zero candidates → Refresh Cycle (`cap = min(90+30, 200)`) → still zero → **extended search** (`collect_candidates(extra=30, extended=True)`), which additionally polls `EXPANSION_SOURCES` (mtpro.xyz).
3. If still zero candidates → GitHub warning annotation → **`_silent_skip("0 verified proxies found, skipping post")`** — nothing is posted, exit 0.

### Stage 2 — Handshake Verification (with escalation)

1. `rank_reachable(candidates, enough=8)` → `prober.probe`: `history.json` ban list consulted (two-strike/purged keys skipped without probing); up to 90 candidates tested by `faketls_ping` across 60 workers; a proxy is **alive** only if it answers the ClientHello (SNI = its own fronting domain) with a valid TLS ServerHello within the 2.0 s shared deadline and 2500 ms cap; early stop once 8 valid; every outcome updates the health map (a handshake failure counts as a failed check toward the two-strike purge).
2. **Escalation on < 1 valid:** Refresh Cycle re-fetch (+30 cap) and re-probe → still < 1 → **extended search**: expansion-feed candidates (deduplicated against already-verified combos) are probed and merged.
3. Distinct reachable hostnames are logged, and the `[stage] probe: N valid / M tested (extended search used)` line records whether escalation fired.
4. With **zero** verified proxies a warning annotation is emitted; the run continues into Stage 3 solely so the known-good reuse fallback gets its chance — the floor is `MIN_BATCH_SIZE = 1`, and nothing below it can ever be posted.

### Stage 3 — Dynamic Selection (1–5, never padded)

1. `history.txt` is touched; identity set + last-posted stamps are loaded; candidates not in history (or last posted ≥ 24 h ago) remain eligible.
2. `pick_batch(reachable, history, size=BATCH_SIZE)` selects in three ordered passes (latency cap 2500 ms → history/cooldown → combo uniqueness → distinct-host preference, then same-host fallback only if the pool cannot fill).
3. **Zero fresh picks → Fallback 1:** `_reuse_known_good()` re-posts up to `min(BATCH_SIZE, len(reachable))` proxies that are in the *current run's* verified pool (they just passed the handshake) ranked by health record — never a blind repost.
4. **Still zero → Zero-post suppression:** `_silent_skip("0 verified proxies found, skipping post")` — no Telegram traffic at all, exit 0.
5. 1–4 picks are published normally: `Dynamic batch: publishing N verified proxy(ies)` — a short batch is *correct* output, not a failure. Each selection is logged (`Selected #N server=… port=… latency=… ms`).

### Stage 4 — Market rates section (never blocks the post)

`rates.get_rates()` in its own try/except: TGJU bulk → cache fill → Nobitex USD fallback (§2.4); board rendered in HTML + plaintext; any crash means "post without rates."

### Stage 5 — Telegram dispatch (exactly ONE logical message)

1. `format_batch_message()` builds the HTML body (rates board + headline; no proxy links in the body; 4096-limit checked) with plaintext fallback.
2. `send_message()` attempts: HTML + keyboard (2-column `tg://proxy` grid sized to the dynamic batch + full-width join row) → plaintext + keyboard → plaintext; a single 429 backoff retry; `"parse entities"` errors advance attempts; other failures produce actionable hints as log + annotation. The keyboard (carrying every deep link) survives attempts 1–2.
3. Network failure → `False`; history is **not** updated.

### Stage 6 — History persistence (only after confirmed send)

`append_history()` writes `ISO-timestamp|host:port` v2 lines and compacts to the newest 2000; the workflow then commits `history.txt` / `history.json` / `last_rates.json` (each only if changed), rebases over concurrent runs, and pushes.

---

## 4. Validation & Filtering Logic

### 4.1 Layered Defense Model

Validation happens at **five independent layers**; a proxy must pass all of them to reach a user:

| # | Layer | Module | Rejection reason |
| --- | --- | --- | --- |
| 1 | Protocol normalization | `fetcher.parse_text_feed` | Non-MTProto link (socks5/http/vless/vmess/junk) |
| 2 | Format validation | `main.apply_filters` / `fetcher.validate` | Bad secret, bad port, duplicate combo |
| 3 | **SNI fronting-domain gate** | `fetcher.validate` → `sni_is_allowed` | Bare-IP, unknown, or blocked fronting domain — discarded **immediately, at zero probe cost** |
| 4 | **Fake-TLS handshake probe** | `prober.probe` → `faketls_ping` | TCP failure, no/garbage/alert response, latency > 2500 ms, banned (2 strikes) |
| 5 | Selection policy | `main.pick_batch` | History/cooldown, combo repeat in batch, host saturation |

### 4.2 Secrets — Fake-TLS `ee` Prefix (three wire formats)

`is_valid_faketls_secret()` accepts a secret only when it starts with the Fake-TLS magic `ee` (byte `0xEE`) **and** carries a usable fronting domain:

| Format | Layout | Acceptance rule |
| --- | --- | --- |
| **Hex** | `ee` + 32-hex key + hex-encoded ASCII domain | Strictly longer than 34 chars; the tail beyond the key is the hex-encoded SNI domain (a bare key-only secret is **rejected**) |
| **Base64url** | `ee` + b64url key (≥ 22 chars) | Length ≥ 22; every char in the b64url alphabet |
| **Base64url + dotted domain** | `ee` + 22-char b64url key + **verbatim dotted domain** (e.g. `...dCQdigikala.com`) | `len > 24`, key part all-b64url, domain part matches `_DOMAIN_SUFFIX_RE` — letter-TLD-ending dotted labels (rejects digit-tail garbage like `0.000000000000000`) |

The dotted-domain branch matters because `.` sits outside the b64url alphabet: the older two-branch validator silently rejected exactly the secrets that carry human-readable SNI domains — now the most informative format. Mixed/unknown alphabets are still rejected outright. The base64url branch exists because the de-facto spec example secret (`eeNEgYdJvXrFGRMCIMJdCQ`) is base64url — hex-only validation would wrongly reject working proxies (pinned by the regression fixture in `SecretValidationTests`).

### 4.3 SNI Extraction (`extract_sni_domain`)

Parses the fronting (SNI) domain out of a secret per format:

- **Hex:** decodes everything after the 32-hex key from hex to ASCII; accepts it **only if the decoding is a syntactically valid domain** (garbage decodings mean "no SNI", not "SNI").
- **Base64url / b64url+dotted:** the key/domain boundary is ambiguous (keys of 20 and 22 chars both occur in the wild, and domain letters overlap the b64url alphabet), so the domain is resolved as the **longest suffix that is a syntactically valid domain AND on the curated allow list** — precisely the SNI the Iran-DPI gate will require anyway; anything else returns `None`.
- Key-only secrets (both hex 34-char and b64url 22-char) return `None`.

`effective_sni(server, secret)` then computes the SNI a client would actually send: the extracted domain if present, else the server hostname — **unless the server is a bare IPv4/IPv6 address**, which yields `None` (TLS forbids IP SNI; IP-fronting is trivially fingerprintable and blocked). This `None` is what makes the fetcher drop key-only secrets on IP servers at the gate.

### 4.4 Iranian ISP Whitelist Scoring (`sni_is_allowed` / `sni_tier`)

The allow list encodes the fronting domains empirically known to pass Iranian DPI (MCI, Irancell, TCI) as ordinary HTTPS:

- **Tier 2 — global CDN / infrastructure** (best camouflage, probed first): `cloudflare.com`, `speedtest.net`, `ooklaserver.org`, `google.com`, `yahoo.com`, `jsdelivr.net`, `cloudfront.net`, `fastly.net`, `akamaized.net`, `microsoft.com`, `bing.com`.
- **Tier 1 — popular Iranian services** (domestically trusted names): `digikala.com`, `snapp.ir`, `snappfood.ir`, `varzesh3.com`, `aparat.com`, `telewebion.com`, `bale.ai`, `shad.ir`, `irancell.ir`, `mci.ir`, `divar.ir`, `torob.com`, `alibaba.ir`, `snapptrip.ir`.
- **Blocked list** (instant discard before the allow-list check): `telegram.org`, `telegram.me`, `t.me`, `core.telegram.org`, `example.com/org/net`, `test.com`, `localhost` — self-fronting and placeholder domains that DPI specifically watches.
- Matching is suffix-based (`cdn.cloudflare.com` matches `cloudflare.com`; the domain is normalized by stripping a leading `www.`), and a syntactic domain regex runs first — invalid shapes never reach the list check.
- **Scoring:** `sni_tier()` returns 2/1/0, and `fetch_candidates` stable-sorts candidates by descending tier — probe budget is spent on the strongest camouflage first, so early-stop triggers on the best class of proxies.

**Why it matters:** Fake-TLS survives DPI only while the SNI domain the handshake impersonates is (a) syntactically real, (b) reachable, and (c) not itself flagged. The gate enforces (a) and curates (c) at ingestion; the handshake probe in §4.5 then verifies (b) for the *actual endpoint* end-to-end.

### 4.5 The Fake-TLS ClientHello Handshake Probe (`faketls_ping`)

The probe is a **protocol-level liveness test**, replacing the old TCP-connect-only check:

1. **Connect:** non-blocking TCP connect with a shared per-attempt deadline (2.0 s default) covering DNS resolution plus the first two resolved addresses (v4 then v6) — same select-based machinery as the retained `tcp_ping`.
2. **Speak:** send `build_client_hello(sni)` — an RFC 8446-correct TLS 1.3 ClientHello whose SNI extension carries the proxy's fronting domain (exactly what the user's client will do). Framing requirements that real servers enforce (each found by live ground-truth testing, then fixed):
   - all list lengths are **byte counts** (cipher suites: `u16(8)` for 4 suites, not 4);
   - `supported_versions` uses a **one-byte** list length per §4.2.1 (`04 0304 0303`);
   - the key share is **x25519-only** — any 32 bytes is a valid share, whereas a random secp256r1 point almost never lies on the curve and servers respond with fatal `decode_error`.
3. **Require:** read until a valid response appears, then apply `is_tls_server_hello()`: content type `0x16`, TLS major version `3`, sane record length, first handshake message type `0x02`. **Only then is the proxy alive**, with connect-to-response latency recorded.
4. **Everything else is dead:** clean FIN before a ServerHello, TCP RST (on send or receive), HTTP error pages, TLS alerts (`0x15`), garbage bytes, or a silent timeout → `None` → a failed check.
5. The socket closes immediately after the response; no MTProto data is exchanged and no full TLS session is established — the probe costs one round trip.

**Ground-truth validation** (live, 2026-09-27): `cloudflare.com:443` → 243 ms, `www.google.com:443` → 221 ms, `speedtest.net:443` → 221 ms, `digikala.com:443` → 43 ms all **pass**; an HTTP-only server on port 80 and a closed port both **fail** — the exact discrimination TCP-only probing could never make. In the unit suite, the same behavior is pinned by local TLS-behaving socket servers (accept/reject matrix) plus a validator test matrix, so CI needs no internet.

**Health integration:** handshake outcomes feed `update_health()` unchanged — success (ServerHello within cap) resets strikes and records latency; failure increments strikes; `STRIKE_LIMIT` (2) sets the persistent `purged` flag in `history.json`, and `probe()` skips banned keys without spending probe budget.

### 4.6 Constants

| Constant | Value | Meaning |
| --- | --- | --- |
| `FAKETLS_PREFIX` | `"ee"` | Fake-TLS secret magic |
| `MIN_B64URL_SECRET_LEN` | 22 | 16-byte b64 key + domain chars |
| `MIN_HEX_SECRET_LEN` | 34 | `ee` + 32 hex; **more** required (domain) |
| `SNI_TIER1/TIER2/BLOCKED_DOMAINS` | 11 / 14 / 9 entries | Iran-DPI allow/scoring/blocked lists (§4.4) |
| `EXPANSION_SOURCES` | `mtpro.xyz` JSON API | Polled only by the extended search |
| `PING_TIMEOUT` | 2.0 s | Per-attempt deadline (connect + ClientHello + response) |
| `MAX_LATENCY_MS` | 2500 | Hard latency ceiling (probe *and* source-supplied) |
| `MAX_WORKERS` | 60 | Parallel handshake probes |
| `MIN_BATCH_SIZE` / `BATCH_SIZE` | 1 / 5 | Dynamic post floor / maximum (never forced) |
| `REUSE_COOLDOWN` | 86 400 s (24 h) | Min age before a posted proxy is eligible again |
| `MAX_HISTORY_ENTRIES` | 2000 | `history.txt` compaction cap |
| `GLOBAL_DEADLINE` | 90 s | Hard budget for the entire run |
| `STRIKE_LIMIT` | 2 | Consecutive handshake failures before purge |
| `MAX_TO_TEST` / `MAX_PER_SOURCE` | 90 / 60 | Probe cap / per-source cap |
| `REFRESH_EXTRA` | 30 | Extra candidates admitted by each escalation step |
| `HTTP_TIMEOUT` / `TELEGRAM_TIMEOUT` | 10 s / 10 s | Caps per API call |
| `FETCH_TIMEOUT` / `RATE_TIMEOUT` / `RATES_STAGE_BUDGET` | 5 s / 3 s / 3 s | Fetcher per-URL / rates request / rates stage |
| `MAX_HEALTH_ENTRIES` | 1000 | `history.json` compaction cap |
| `MAX_MESSAGE_LENGTH` | 4096 | Telegram hard limit |

### 4.7 History Tracking & Duplicate Prevention (`history.txt`) — unchanged in v2

Identity = `host:port`; v2 format `ISO-timestamp|host:port`; legacy lines migrate with `RECOVERY_TS` (always cooldown-eligible); write-once guarantee (history only after Telegram `ok: true`); compaction to newest 2000; cooldown reuse after 24 h (max stamp per identity; unstamped entries stay excluded).

### 4.8 Rates Validation — unchanged in v2

Plausibility windows per field with loud per-field rejection; wholesale rejection of rial-scale caches; clean omission of unavailable fields; no bubble/intrinsic metrics ever rendered.

---

## 5. CI/CD & Automation

### 5.1 Pipeline Definition (`.github/workflows/auto_post.yml`) — unchanged in v2

| Property | Value |
| --- | --- |
| **Name** | `Auto Post Proxies` |
| **Triggers** | `schedule: cron '*/5 * * * *'` (UTC) + `workflow_dispatch` (manual) — the *search* cadence, not a posting guarantee |
| **Concurrency** | group `proxgram`, `cancel-in-progress: true` |
| **Permissions** | `contents: write` |
| **Runner** | `ubuntu-latest` |

### 5.2 Step Order (matters — enforced by tests)

1. **Checkout** — `actions/checkout@v4`, `fetch-depth: 0`, `persist-credentials: true`.
2. **Set up Python** — `actions/setup-python@v5`, Python `3.11`.
3. **Install Dependencies** — `pip install -r requirements.txt` (only `requests`).
4. **Run unit tests** — `python -m unittest test_main -v` (166 tests incl. the handshake and SNI suites). **A failing test blocks posting.**
5. **Verify destination chat** — `python verify_chat.py`.
6. **Run Proxy Publisher** — `python main.py` (the dynamic search pipeline of §3).
7. **Commit and Push History** — `github-actions[bot]` identity; stages `history.txt` / `history.json` / `last_rates.json` only if changed; skips when nothing staged; otherwise `git commit -m "chore: update history [skip ci]"` → `git pull --rebase origin main` → `git push origin HEAD:main`.
8. **Upload run log artifact** — `if: always()`; `proxgram.log` as `proxgram-log-<run_id>`, 7-day retention.

### 5.3 Required Secrets — unchanged

`TELEGRAM_BOT_TOKEN` (regex-validated `<bot_id>:<secret>`), `TELEGRAM_CHANNEL_ID` (`@username` or `-100…`), optional `TELEGRAM_CHANNEL_TAG`. Set under **Settings → Secrets and variables → Actions**; the bot must be a channel **administrator** with *Post messages* permission.

### 5.4 Environment Variables — unchanged

`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHANNEL_ID`, optional `TELEGRAM_CHANNEL_TAG`; `GITHUB_EVENT_NAME` (set by Actions) is logged as the run trigger.

### 5.5 Persistence Strategy — unchanged

The repository is the persistence layer: `history.txt` (dedup, 2000-entry cap), `history.json` (health + persistent two-strike bans), `last_rates.json` (rates fallback) are committed back each run so ephemeral VMs inherit full state; `git pull --rebase` + the `proxgram` concurrency group make the loop loss-free. Operational caveat: GitHub disables schedules after ~60 days of repo inactivity (re-enable in the Actions tab), and `*/5` cron is best-effort — **by design this now only delays the next search, never publishes a filler post.**

---

## 6. Known Bottlenecks & Limitations for Iranian ISPs

### 6.1 What the Handshake Probe + SNI Gate Resolve (v1 → v2)

The v1 pipeline verified reachability with a bare TCP three-way handshake from a foreign runner and trusted upstream secret formatting. Both gaps are now closed at the protocol level:

| v1 blind spot (invisible to a TCP-only probe) | v2 resolution |
| --- | --- |
| Broken/obsolete MTProto or TLS stack behind an open TCP port | **`faketls_ping` performs the real handshake**: a proxy that cannot produce a TLS ServerHello to a well-formed ClientHello is dead and never posted |
| Garbage/RST/HTTP-error responders counted as "alive" | Response must parse as `0x16 03 … 02` (ServerHello); HTTP pages, alerts, resets, and silent drops all fail |
| SNI domain never checked: key-only secrets, bare-IP servers, self-fronting (`t.me`) and placeholder domains passed validation | **SNI gate discards them at ingestion** (bare-IP effective-SNI → `None`; blocked list; syntactic regex) before any probe budget is spent |
| Fronting domain reachability unverified — a proxy whose front domain was dead or hijacked still passed | The ClientHello is sent **to the actual endpoint carrying the actual SNI**; only endpoints that complete the camouflage handshake for their own fronting domain survive |
| Probe budget wasted on weak-camouflage candidates first | **Tier scoring** sorts global-CDN fronting first; the early-stop (8 valid) then biases the published pool toward the strongest class |
| Fake-TLS-only policy enforced structurally but untested | The `ee` requirement is now exercised *end-to-end*: the handshake only makes sense for Fake-TLS proxies, and the SNI the probe uses is parsed from the same secret the user's client will use |

Net effect: every published proxy has demonstrated — in the same run that posts it — that it accepts a TCP connection **and** completes a TLS handshake impersonating a curated, DPI-trusted fronting domain. The class of "TCP-open but protocol-dead" false positives that dominated v1 complaints is eliminated by construction, and the dynamic batch (1–5) plus zero-post suppression guarantee the channel never carries a dead button after a bad cycle.

### 6.2 Residual Limitations (honest assessment)

The handshake probe moves verification one full protocol layer closer to the user's experience, but it cannot see through geography:

1. **The vantage is still foreign.** The run executes from GitHub's Azure IP space. Iran-side filtering evaluates traffic **from inside Iranian networks on Iranian transit**; a handshake that succeeds from a US/EU datacenter does not prove the same `server:port` completes a handshake from an MCI/Irancell/TCI subscriber. Iran-side IP/port blocks and cross-border TCP drops remain invisible in both directions.
2. **Allow-listed ≠ never-flagged.** `cloudflare.com` and friends are the *strongest known* camouflage domains, but Iranian authorities periodically throttle or flag even major CDN SNI ranges. The gate encodes a curated prior, not live Iranian ground truth; a domain can degrade between the list's last review and a given run.
3. **Post-handshake quality is unmeasured.** The probe costs one round trip: throughput, stability under load, and MTProto-layer behavior after the ServerHello (user quota, upstream saturation) are still untested. A proxy can handshake cleanly and still be unusable at peak.
4. **Sources are public and pre-targeted.** All eight feeds (7 primary + mtpro.xyz) are popular public aggregators watched by censors and abuse bots alike; "fresh" proxies can be flagged or saturated before ProxGram republishes them.
5. **Latency numbers are runner-relative.** Logged latencies reflect Azure→proxy; Persian users typically face higher real latencies, and ISP-specific peering differences are unobservable.
6. **Schedule drift & expansion-feed availability.** `*/5` cron is best-effort, and `mtpro.xyz` (the sole expansion feed) has shown intermittent availability — both only delay or skip searches, never degrade post quality, but they can thin the published pool during source droughts.

### 6.3 Mitigations Built Into the Design

- **Protocol-level verification** — the Fake-TLS handshake is the strongest remote check available without an in-Iran vantage.
- **Curated fronting domains + tiering** — the SNI gate encodes the best-known DPI evasion prior and spends probe budget on it first.
- **Redundancy without padding** — up to five independent, individually verified endpoints per post; fewer when fewer verify; none when none do.
- **Two-strike persistent purge** — any proxy failing the handshake twice (across runs, via committed `history.json`) leaves rotation permanently.
- **Source-level handshake verification upstream** — the primary JSON feed is handshake-verified by its maintainer, layered under ProxGram's own probe.
- **Zero-post suppression** — source droughts produce silence, not dead buttons.

### 6.4 The Fundamental Frontier

The remaining failure modes — Iran-side IP/port blocking, ISP-specific SNI throttling, and post-handshake quality — are architecturally invisible to any probe running outside Iran. Closing them requires measuring from inside Iran (residential vantage probes or user feedback signals), which is a different architecture. Within the current one, the pipeline now guarantees: **every posted proxy completed a Fake-TLS handshake on its own curated fronting domain, in the same run that posted it.**

---

## 7. Local Setup & Testing Guide

### 7.1 Prerequisites

- **Python 3.11** (CI pins 3.11; `X | None` unions need ≥ 3.10).
- **pip** and (optionally) a virtual environment; the single runtime dep is `requests>=2.31.0` (`python -m pip install -r requirements.txt`).
- A Telegram bot token from @BotFather and a channel where the bot is **administrator** — required only for live posting runs, not for tests.
- Network access for live runs: outbound HTTPS to GitHub raw feeds, `mtpro.xyz`, `api.telegram.org`, `call1.tgju.org`, `api.nobitex.ir`, plus outbound TCP to proxy endpoints on ports 443/8443/2053/2083/8880.
- No other system dependencies — the test suite stubs `requests` and needs zero packages.

### 7.2 Installation

```bash
git clone <your-fork-url> && cd <repo-dir>
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

### 7.3 Running the Unit Tests

```bash
python -m unittest test_main -v        # full suite (166 tests), exactly as CI runs it
python -m unittest test_main -k Sni    # filter: SNI gate tests
python -m unittest test_main -k FakeTls  # filter: handshake tests
python -m unittest test_main -k ZeroPost # filter: suppression tests
```

- The suite runs **fully offline** — `requests` is stubbed; the handshake tests use local TLS-behaving socket servers (positive and negative), so the ClientHello/ServerHello logic is verified without internet.
- Live-network exceptions: `TcpPingTests` (legacy probe) touches `1.1.1.1:443` and a TEST-NET address; fast and safe.
- `test_yaml_syntax_valid` silently skips without PyYAML; structural assertions still run.
- A green suite is the CI gate: the workflow refuses to post when tests fail.

### 7.4 Manual Probes & One-Off Diagnostics

**Full posting run (sends a real message — dynamic batch, may post nothing):**

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC-your-token"
export TELEGRAM_CHANNEL_ID="@yourchannel"        # or -1001234567890
export TELEGRAM_CHANNEL_TAG="@yourchannel"       # optional
python main.py
```

Follow the `[stage]` lines and the final `POST DECISION: {...}` verdict; a suppressed run logs `0 verified proxies found, skipping post`. Exit codes: `0` = completed (posted or suppressed), `2` = credential failure. Tail `proxgram.log` for the file-side trail.

**Verify the destination chat without posting anything:**

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC-your-token"
export TELEGRAM_CHANNEL_ID="@yourchannel"
python verify_chat.py    # exit 0 = resolved, 1 = failed
```

**Interactive one-liners:**

```python
# Validate a secret / extract + check its SNI / render its deep link
python -c "
import fetcher, main
s = 'eeNEgYdJvXrFGRMCIMJdCQdigikala.com'
print(main.is_valid_faketls_secret(s))                 # True (dotted format)
print(fetcher.extract_sni_domain(s))                   # digikala.com
print(fetcher.sni_is_allowed(fetcher.extract_sni_domain(s)))  # True
print(fetcher.sni_tier('cloudflare.com'))              # 2 (global CDN)
"

# Handshake-probe a single endpoint with a chosen SNI (needs network)
python -c "
import prober
print(prober.faketls_ping('cloudflare.com', 443, 'cloudflare.com'))  # ms or None
print(prober.build_client_hello('digikala.com')[:5].hex())           # record header
"

# Full acquisition: fetch -> SNI gate -> tier sort (no probing, no posting)
python -c "
import logging, fetcher
logging.basicConfig(level=logging.INFO)
cands = fetcher.fetch_candidates(cap=20)
print(f'{len(cands)} SNI-valid candidates')
for p in cands[:5]:
    print(p.key, fetcher.effective_sni(p.server, p.secret), p.link)
"

# Render the market board (live TGJU, falls back to last_rates.json)
python -c "
import logging, rates
logging.basicConfig(level=logging.INFO)
print(rates.format_board(rates.get_rates() or {}, 'plain'))
"

# Inspect state files
python -c "
import prober, main
h = prober.load_health()
print(f'{len(h)} health entries, {len(prober.banned_keys(h))} banned')
print(f'{len(main.load_history())} posted identities in history.txt')
"
```

**Manual workflow trigger:** on GitHub, open the repository → **Actions → Auto Post Proxies → Run workflow** (`workflow_dispatch`). Every run's `proxgram.log` is downloadable as an artifact for 7 days.

### 7.5 Operational Checklist

- [ ] Secrets `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHANNEL_ID` set in repo settings.
- [ ] Bot is an **admin** of the target channel (Post messages).
- [ ] First run via *Run workflow* — confirm the `[stage] probe: N valid / M tested` line and the `POST DECISION: will_post=...` verdict; **`will_post=no` with reason `0 verified proxies found, skipping post` is healthy suppression, not a bug.**
- [ ] Watch `::warning::` annotations (`Only N verified proxies…`, `No valid Fake-TLS candidates…`) — they indicate upstream-feed droughts, not code faults.
- [ ] If the schedule auto-disables after 60 days of inactivity, re-enable it in the Actions tab.
