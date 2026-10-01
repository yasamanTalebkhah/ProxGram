# ProxGram 🚀

Posts **1–5 handshake-verified, censorship-resistant Telegram MTProto proxies**
(Fake-TLS `ee` secrets, HTTPS-compatible ports) to a Telegram channel in ONE
message, each behind its own one-tap connect button — **only when at least one
proxy passes a real Fake-TLS handshake**. The workflow fires every five
minutes, but it is a *search*, not a poll: a run that verifies nothing posts
nothing.

## How it works (v2.0)

Each run is a dynamic search pipeline. v1 published a fixed batch of five
proxies validated only by a TCP connect check; v2 verifies protocol behavior
end-to-end and scales the batch to reality.

1. **Fetch** candidates in parallel (5 s per-URL timeout) from 7 primary
   feeds — handshake-verified JSON (`dubblebyte/free-mtproto-proxies`) plus
   plaintext MTProto lists (hookzof, TheSpeedX, jetkai, roosterkid,
   SoliSpirit, Grim1313). An empty pool escalates: a refresh cycle with a
   wider cap, then an extended search that additionally polls the
   `mtpro.xyz` MTProto API.
2. **SNI gate (Iran-DPI filter).** The Fake-TLS secret's fronting (SNI)
   domain is extracted — hex-encoded, base64url, and base64url+dotted
   secret formats are all parsed — and checked against a curated whitelist
   of domains known to pass Iranian DPI: global CDNs (`cloudflare.com`,
   `speedtest.net`, `google.com`, …) and popular Iranian services
   (`digikala.com`, `snapp.ir`, `varzesh3.com`, …). Bare-IP servers,
   syntactically invalid domains, and self-fronting/placeholder domains
   (`t.me`, `example.com`, …) are discarded immediately; survivors are
   tier-sorted so the strongest camouflage is probed first.
3. **Fake-TLS handshake probe.** Every candidate receives a real
   Fake-TLS ClientHello carrying *its own fronting domain* as SNI. A proxy
   is alive only if it answers with a valid TLS ServerHello (2.0 s shared
   deadline, ≤ 2500 ms cap). TCP RST/FIN, HTTP error pages, TLS alerts,
   garbage, and silent drops are all dead. Two consecutive handshake
   failures permanently purge a proxy via `history.json`.
4. **Select** 1–5 fresh verified proxies — not posted within the 24 h
   cooldown, unique `server + port + secret`, preferring distinct
   hostnames, fastest first. The batch is never padded to five.
5. **Dispatch** one message: a short clean body (plus a live Iranian
   gold/currency market board from TGJU with a Nobitex USD fallback), with
   every deep link living only in the inline keyboard buttons and a
   channel-join row. **Zero verified proxies → zero Telegram traffic**
   (logged as `0 verified proxies found, skipping post`): no dead buttons,
   no placeholder, clean exit.
6. **Record** the posted links in `history.txt` only after Telegram
   confirms the send, then commit/push (`history.txt`, `history.json`,
   `last_rates.json`) so the next ephemeral run inherits full dedup and
   health state.

> **The v1 caveat is retired.** The old warning — "the TCP test is an
> availability check only" — no longer applies: every published proxy has
> completed a TLS handshake on a curated fronting domain *in the same run
> that posted it*. What remains unverifiable from a foreign runner is
> Iran-side IP/port blocking and per-ISP throttling; five individually
> verified proxies per post keep that residual risk redundant. See
> `SYSTEM_DOCUMENTATION.md` §6 for the full analysis.

## Dispatch rules

| Situation | Behavior |
| --- | --- |
| 1–5 proxies verify | Post exactly those, one message, dynamic batch |
| 0 proxies verify (all feeds + expansion searched) | **No post.** Silent skip, exit 0 |
| < 5 fresh but ≥ 1 verified | Publish the short batch — never pad with unverified |
| All previously posted (within 24 h cooldown) | Re-post only known-good proxies that re-verified this run |

## Required repository secrets

Set in **Settings → Secrets and variables → Actions**:

| Secret | Value |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHANNEL_ID` | `@yourchannel` (public) or `-100…` numeric ID |

Optional: `TELEGRAM_CHANNEL_TAG` overrides the display tag (defaults to
`TELEGRAM_CHANNEL_ID`). The join button is only added when a public username
is available.

## Channel administrator requirements (manual, one-time)

1. **Add the bot as an administrator** of the channel — otherwise Telegram
   rejects posts with "bot is not a member" / "not enough rights".
2. **Native emoji reactions** (👍🔥❤ on the post) are a **channel-admin
   setting** (Manage channel → Reactions), not a bot feature. ProxGram
   deliberately adds no feedback/callback buttons.

## Workflow (`.github/workflows/auto_post.yml`)

- Schedule: `*/5 * * * *` (UTC) — the *search* cadence — plus manual
  `workflow_dispatch`. A suppressed run is a normal, healthy outcome.
- Concurrency: group `proxgram`, `cancel-in-progress: true`; permissions:
  `contents: write` (history commits).
- The **166-test suite runs before every post** (SNI gate, handshake probe,
  dynamic dispatch, zero-post suppression); a failing test blocks posting.
- History commits use `git pull --rebase` first so overlapping runs never
  lose each other's entries; `proxgram.log` is uploaded as a 7-day artifact.
- Scheduled workflows need recent repository activity; if GitHub disables
  the schedule after 60 days of inactivity, re-enable it in the **Actions**
  tab.

## Local usage

Requirements: **Python 3.11** (≥ 3.10 works) and the single runtime
dependency `requests>=2.31.0`.

```bash
python -m pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_CHANNEL_ID="@yourchannel"

python -m unittest test_main -v      # 166 tests, fully offline
python main.py                       # one search-and-post run (may post nothing)
python verify_chat.py                # pre-flight: destination chat check
```

Quick manual probes (no credentials needed):

```bash
python -c "import prober; print(prober.faketls_ping('cloudflare.com', 443, 'cloudflare.com'))"
python -c "import fetcher; print(fetcher.extract_sni_domain('eeNEgYdJvXrFGRMCIMJdCQdigikala.com'))"
python -c "import logging, fetcher; logging.basicConfig(level='INFO'); print(len(fetcher.fetch_candidates(cap=20)))"
```

`history.txt` stays local when you run manually; in CI it is committed by the
workflow to persist dedup state. `proxgram.log` is gitignored.

For the deep dive — architecture diagrams, the five-layer validation model,
the SNI whitelist tables, and the Iranian-ISP bottleneck analysis — read
[`SYSTEM_DOCUMENTATION.md`](SYSTEM_DOCUMENTATION.md).
