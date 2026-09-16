# ProxGram 🚀

Posts **five fast, censorship-resistant Telegram MTProto proxies** (Fake-TLS `ee`
secrets, HTTPS-compatible ports) to a Telegram channel **every five minutes** —
all five in one message, each behind its own one-tap connect button.

## How it works

1. **Fetch** candidates from:
   - Primary (handshake-verified): `dubblebyte/free-mtproto-proxies` `proxies.json`
   - Fallbacks (plaintext): `SoliSpirit/mtproto`, `Grim1313/mtproto-for-telegram`
2. **Validate**: MTProto-only links; Fake-TLS secrets must start with `ee`
   (hex secrets need an SNI domain beyond the 16-byte key; base64url secrets
   need ≥ 22 chars); ports restricted to `443, 8443, 2053, 2083, 8880`.
3. **Latency-test**: strict 2.0 s TCP connect; keep ≤ 2500 ms.
4. **Select** the best five fresh proxies (never posted before, unique
   `server + port + secret`, preferring five different hostnames).
5. **Post** one message whose body is short and clean — all five proxy deep
   links live only in the inline keyboard buttons, plus a channel button.
6. **Record** all five links in `history.txt` only after Telegram confirms the
   send, then commit/push so the next run never reposts them.

> ⚠️ The TCP test is an **availability check only**. It does not prove a proxy
> works on every Iranian operator: filtering happens at the DPI layer. The
> handshake-verified source feed and the Fake-TLS/secret validation are the
> main quality defenses; five concurrent proxies give users redundancy because
> individual proxies may still be blocked or unstable.

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
   setting**, not a bot feature: open the channel → **Manage channel →
   Reactions** and enable the emoji set you want. A bot cannot reliably enable
   or configure native channel reactions for every channel through the Bot
   API, so ProxGram deliberately does not add feedback/callback buttons —
   reactions must be enabled from the channel settings by the owner/admin.

## Workflow (`.github/workflows/auto_post.yml`)

- Schedule: `*/5 * * * *` (UTC) + manual `workflow_dispatch`.
- Concurrency: group `proxgram`, `cancel-in-progress: true` — overlapping runs
  cannot double-post or race the history update.
- Permissions: `contents: write` so the bot can commit `history.txt`.
- Runs unit tests before every post; a failing test blocks posting.
- History commits use `git pull --rebase` first so a just-finished run's
  entries are never overwritten.
- Trigger type (`schedule` / `workflow_dispatch`) is logged on every run.

> Scheduled workflows need recent repository activity; if GitHub disables the
> schedule due to 60 days of inactivity, re-enable it in the **Actions** tab.
> Runs may start a few minutes late under load — that is normal.

## Local usage

```bash
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_CHANNEL_ID="@yourchannel"
python -m unittest test_main -v   # tests
python main.py                    # one posting run
```

`history.txt` and `proxgram.log` stay local; `history.txt` is committed by the
workflow to persist dedup state across runs.
