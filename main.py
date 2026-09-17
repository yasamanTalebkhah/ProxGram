#!/usr/bin/env python3
"""ProxGram — post five fast, censorship-resistant Telegram MTProto proxies
(Fake-TLS `ee` secrets, HTTPS-compatible ports) in ONE Telegram message.

Sources:
  1. Primary: handshake-verified JSON feed (dubblebyte/free-mtproto-proxies).
  2. Fallbacks: plaintext MTProto feeds (SoliSpirit, Grim1313).

Pipeline per run:
  fetch -> parse (JSON + plaintext) -> Fake-TLS/secret + port filters ->
  dedupe by (server, port, secret) -> TCP latency test (2.0s, <= 2500ms) ->
  exclude history.txt -> prefer distinct hostnames -> pick best five ->
  send ONE message with five connect buttons -> record links in history.txt.

The TCP test is an availability check only. Source-level verification
(handshake-verified feed) and Fake-TLS/secret validation remain the main
Iran-DPI defenses; five concurrent proxies give users redundancy because
individual proxies may still be blocked or unstable on Iranian networks.

Credentials are read from environment variables:
    TELEGRAM_BOT_TOKEN   - bot token from @BotFather
    TELEGRAM_CHANNEL_ID  - target channel (e.g. @mychannel or -1001234567890)
    TELEGRAM_CHANNEL_TAG - optional display tag for the post signature
                           (defaults to TELEGRAM_CHANNEL_ID)

history.txt (repo root) stores the full deep link of every posted proxy so
duplicates are never re-posted across workflow runs. last_rates.json
(rates.py) caches the last successfully fetched market rates.
"""

import json
import logging
import os
import re
import socket
import string
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import requests

import rates as rates_module
import fetcher as fetcher_module
import prober as prober_module

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Multi-source backbone (parallel fetch in fetcher.py; listed here as
# readable aliases for diagnostics and tests).
JSON_SOURCES = [url for url, kind in fetcher_module.SOURCES if kind == "json"]
PLAINTEXT_SOURCES = [url for url, kind in fetcher_module.SOURCES if kind == "text"]

MAX_PER_SOURCE = fetcher_module.MAX_PER_SOURCE
MAX_TO_TEST = fetcher_module.MAX_TO_TEST      # probe cap
FETCH_TIMEOUT = fetcher_module.FETCH_TIMEOUT  # 5s per URL (parallel)
REFRESH_EXTRA = 30   # extra candidates admitted by the refresh cycle
STRIKE_LIMIT = prober_module.STRIKE_LIMIT     # 2 consecutive fails -> purge
PING_TIMEOUT = 2.0    # seconds - strict TCP connect timeout
MAX_LATENCY_MS = 2500  # discard anything slower than this
MAX_WORKERS = 60      # parallel TCP tests (total wall time ~= one timeout)
BATCH_SIZE = 5        # proxies posted per run (exactly five or none)
REUSE_COOLDOWN = 24 * 3600.0  # seconds before a posted proxy may be reused
MAX_HISTORY_ENTRIES = 2000    # history compaction cap
GLOBAL_DEADLINE = 90          # seconds - hard budget for the entire run
# Placeholder timestamp for legacy plain history lines (always eligible for
# cooldown reuse so old entries can never block the pipeline forever).
RECOVERY_TS = "2000-01-01T00:00:00"

ALLOWED_PORTS = {443, 8443, 2053, 2083, 8880}

HEX_SET = set(string.hexdigits)
B64URL_SET = set(string.ascii_letters + string.digits + "-_")
FAKETLS_PREFIX = "ee"       # Fake-TLS secrets start with 0xEE
MIN_B64URL_SECRET_LEN = 22  # 16-byte key (b64) + at least ~10 chars of domain
MIN_HEX_SECRET_LEN = 34     # ee + 32 hex (key only) is NOT enough - domain required

HISTORY_FILE = Path(__file__).resolve().parent / "history.txt"
HISTORY_JSON_FILE = prober_module.HISTORY_JSON_FILE  # TTL health map
LOG_FILE = Path(__file__).resolve().parent / "proxgram.log"

HTTP_TIMEOUT = 10     # seconds - strict cap for every source/feed fetch
TELEGRAM_TIMEOUT = 10  # seconds - hard cap per Telegram API call
USER_AGENT = "v2rayN/6.23"  # standard client UA - aggregators treat unknown UAs differently
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/{method}"
MAX_MESSAGE_LENGTH = 4096

# Public module-level exports (readable for diagnostics one-liners):
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHANNEL_ID = os.environ.get("TELEGRAM_CHANNEL_ID", "@ChannelID")
_channel_id = TELEGRAM_CHANNEL_ID
CHANNEL_TAG = os.environ.get("TELEGRAM_CHANNEL_TAG") or _channel_id

PROXY_BUTTON_EMOJIS = ("🚀", "⚡️", "🛡", "🌐", "🔥")  # one emoji per button row
FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

logger = logging.getLogger("proxgram")


def fa_num(n: int) -> str:
    """Latin digits -> Persian digits for user-facing labels."""
    return str(n).translate(FA_DIGITS)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """Configure console + file logging."""
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    class _ConsoleHandler(logging.StreamHandler):
        """Console handler that follows the current sys.stdout, so log
        lines and GitHub annotations stay interleaved (and testable)."""

        def emit(self, record):
            self.stream = sys.stdout
            super().emit(record)

    console = _ConsoleHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    try:
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Could not open log file %s: %s", LOG_FILE, exc)

    return logger


# ---------------------------------------------------------------------------
# Telemetry + GitHub Actions annotations + credential verification
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")

TG_ERROR_HINTS = {
    400: ("Bad Request: 'chat not found' means TELEGRAM_CHANNEL_ID is wrong "
          "or the bot is not in that channel; 'parse entities' errors are "
          "already handled by the plaintext fallback."),
    401: ("Unauthorized: the bot token is invalid or revoked. Regenerate it "
          "with @BotFather and update the TELEGRAM_BOT_TOKEN secret."),
    403: ("Forbidden: the bot must be an ADMIN of the target channel with "
          "'Post messages' permission (or it has been blocked)."),
    404: ("Not Found: chat not found - check TELEGRAM_CHANNEL_ID and add "
          "the bot to the channel."),
    429: ("Too Many Requests: rate-limited by Telegram; the next scheduled "
          "run will retry automatically."),
}


def mask_token(token: str | None) -> str:
    """Token form safe for logs: bot id + first 2 secret chars only."""
    if not token:
        return "<missing>"
    bot_id, sep, secret = token.partition(":")
    if sep and secret:
        return f"{bot_id}:{secret[:2]}***"
    return token[:4] + "***"


def gh_annotation(level: str, message: str) -> None:
    """Emit a GitHub Actions annotation (::error:: / ::warning:: / ::notice::).

    Printed bare to stdout so Actions renders it on the run summary; locally
    it is simply a visible marker line.
    """
    prefix = {"error": "::error::", "warning": "::warning::"}.get(
        level, "::notice::"
    )
    print(f"{prefix}{message}")


def validate_credentials(token: str | None,
                         channel_id: str | None) -> list[str]:
    """Actionable credential problems; empty list means OK to proceed."""
    problems: list[str] = []
    if not token:
        problems.append(
            "TELEGRAM_BOT_TOKEN is missing. Add it under Settings > Secrets "
            "and variables > Actions (get the token from @BotFather)."
        )
    elif not _TOKEN_RE.match(token.strip()):
        problems.append(
            "TELEGRAM_BOT_TOKEN is malformed (expected '<bot_id>:<secret>', "
            "e.g. '123456789:AA...'). Regenerate it with @BotFather and "
            "update the secret."
        )
    if not channel_id:
        problems.append(
            "TELEGRAM_CHANNEL_ID is missing. Use '@channelusername' or a "
            "'-100...' numeric channel id."
        )
    else:
        cid = channel_id.strip()
        valid = (cid.startswith("@") and len(cid) > 1) or (
            cid.startswith("-100") and len(cid) > 4
        )
        if not valid:
            problems.append(
                "TELEGRAM_CHANNEL_ID must start with '@' (public username) "
                "or '-100' (numeric channel/supergroup id)."
            )
    return problems


# ---------------------------------------------------------------------------
# Proxy model
# ---------------------------------------------------------------------------

class Proxy:
    """A parsed Fake-TLS MTProto proxy with a standard deep link."""

    def __init__(self, server: str, port: int, secret: str,
                 latency_ms: float | None = None):
        self.server = str(server).strip().strip(".")
        self.port = int(port)
        self.secret = str(secret).strip()
        self.latency_ms = latency_ms  # optional value from a verified source

    @property
    def protocol(self) -> str:
        return "MTProto"

    @property
    def combo(self) -> tuple[str, int, str]:
        """Full identity: server + port + secret."""
        return (self.server.lower(), self.port, self.secret)

    @property
    def key(self) -> str:
        """Legacy host:port identifier (still honored by history.txt)."""
        return f"{self.server.lower()}:{self.port}"

    @property
    def link(self) -> str:
        """Standard https deep link (used for history dedup + storage)."""
        return (
            "https://t.me/proxy"
            f"?server={quote(self.server, safe='')}"
            f"&port={self.port}"
            f"&secret={quote(self.secret, safe='')}"
        )

    @property
    def tg_link(self) -> str:
        """Native tg:// deep link - opens the proxy dialog in installed
        Telegram apps without the intermediate t.me web hop."""
        return (
            "tg://proxy"
            f"?server={quote(self.server, safe='')}"
            f"&port={self.port}"
            f"&secret={quote(self.secret, safe='')}"
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Proxy MTProto {self.server}:{self.port}>"


# ---------------------------------------------------------------------------
# Secret validation (Fake-TLS only)
# ---------------------------------------------------------------------------

def is_valid_faketls_secret(secret: str) -> bool:
    """True when the secret is a usable Fake-TLS (ee) secret.

    Two legitimate Telegram MTProto Fake-TLS alphabets exist in the wild:
      - hex-encoded: `ee` + 32 hex key + hex-encoded SNI domain; a bare
        `ee` + 32 hex (34 chars, no domain) is REJECTED.
      - base64url:   `ee` + 22-char b64 key + domain; accepted at >= 22
        chars so the key is present, with the domain following.
    (The spec example secret eeNEgYdJvXrFGRMCIMJdCQ is base64url, which is
    why hex-only validation would wrongly reject working proxies.)
    """
    s = (secret or "").strip()
    if not s or not s.lower().startswith(FAKETLS_PREFIX):
        return False

    if all(c in HEX_SET for c in s):
        return len(s) > MIN_HEX_SECRET_LEN  # strictly longer than key-only 34

    if all(c in B64URL_SET for c in s):
        return len(s) >= MIN_B64URL_SECRET_LEN

    return False


def is_allowed_port(port: int) -> bool:
    """HTTPS-compatible ports that typically bypass DPI port blocking."""
    return port in ALLOWED_PORTS


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def fetch_text(url: str) -> str | None:
    """Download a payload (delegates to the parallel fetcher)."""
    return fetcher_module.fetch_url(url)


def parse_qs_last(query: str) -> dict[str, str]:
    """parse_qs keeping the LAST value of duplicated keys.

    Tolerates mangled links like ...&secret=X&port=8880&secret=Y by using
    the final value of each parameter (Telegram/client behavior).
    """
    return {k: v[-1] for k, v in parse_qs(query).items() if v}


def parse_json_source(text: str) -> list[Proxy]:
    """Parse the handshake-verified JSON feed into Proxy objects."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        logger.warning("JSON source is invalid: %s", exc)
        return []
    if not isinstance(data, list):
        logger.warning("JSON source has unexpected top-level type")
        return []

    proxies = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        server = str(entry.get("server") or "").strip()
        secret = str(entry.get("secret") or "").strip()
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if not server or not secret:
            continue
        latency = entry.get("latency_ms")
        try:
            latency = float(latency) if latency is not None else None
        except (TypeError, ValueError):
            latency = None
        proxies.append(Proxy(server, port, secret, latency_ms=latency))
    return proxies


def parse_plaintext_source(text: str) -> list[Proxy]:
    """Parse plaintext feeds of t.me/proxy / tg://proxy links."""
    proxies = []
    for line in text.splitlines():
        stripped = line.strip()
        if "t.me/proxy" not in stripped and not stripped.startswith("tg://proxy"):
            continue  # socks5/vless/vmess/unknown formats never enter the model
        try:
            parsed = urlparse(stripped)
            qs = parse_qs_last(parsed.query)
            server = (qs.get("server") or "").strip().strip(".")
            port = int(qs.get("port", "").strip())
            secret = qs.get("secret", "").strip()
        except ValueError:
            continue
        if not server or not secret:
            continue
        proxies.append(Proxy(server, port, secret))
    return proxies


def apply_filters(proxies: list[Proxy]) -> tuple[list[Proxy], dict]:
    """Fake-TLS secret validation + allowed-port filter, keeping feed order."""
    kept: list[Proxy] = []
    stats = {"bad_secret": 0, "bad_port": 0}
    seen: set[tuple[str, int, str]] = set()
    for proxy in proxies:
        if not is_valid_faketls_secret(proxy.secret):
            stats["bad_secret"] += 1
            continue
        if not is_allowed_port(proxy.port):
            stats["bad_port"] += 1
            continue
        if proxy.combo in seen:
            continue
        seen.add(proxy.combo)
        kept.append(proxy)
    return kept, stats


def collect_candidates(extra: int = 0) -> list[Proxy]:
    """Parallel multi-source fetch via fetcher.py (dedup + strict filter).

    `extra` raises the probe cap temporarily (refresh cycle). The returned
    list is ordered JSON-feed-first so handshake-verified entries win.
    """
    cap = min(MAX_TO_TEST + max(0, extra), 200)
    return fetcher_module.fetch_candidates(cap=cap)


# ---------------------------------------------------------------------------
# Health check (TCP connect + latency)
# ---------------------------------------------------------------------------

def tcp_ping(host: str, port: int, timeout: float = PING_TIMEOUT) -> float | None:
    """Non-blocking TCP connect test (delegates to the strict prober)."""
    return prober_module.tcp_ping(host, port, timeout)


# ---------------------------------------------------------------------------
# History (duplicate prevention, link-based)
# ---------------------------------------------------------------------------

def _extract_ident(line: str) -> str:
    """Canonical identity of a history entry: host:port of a deep link.

    Accepts full t.me/proxy deep links (server+port+secret combos share a
    host:port) and legacy bare host:port lines; unmappable lines return
    themselves so nothing is silently dropped.
    """
    line = (line or "").strip()
    if not line:
        return ""
    if line.startswith("http") or line.startswith("tg://"):
        try:
            qs = parse_qs_last(urlparse(line).query)
            host = (qs.get("server") or "").strip().strip(".").lower()
            port = int((qs.get("port") or "0").strip())
            if host and port:
                return f"{host}:{port}"
        except (ValueError, AttributeError):
            pass
        return line
    return line


def _history_entries() -> list[tuple[str, str]]:
    """(timestamp_iso, ident) pairs from history.txt.

    Plain lines (legacy format) get RECOVERY_TS so they are eligible for
    cooldown reuse rather than blocking the pipeline forever.
    """
    if not HISTORY_FILE.exists():
        return []
    try:
        entries: list[tuple[str, str]] = []
        for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if len(stripped) > 19 and stripped[4] == "-" and stripped[10] in " T" and stripped[13] == ":":
                ts, sep, rest = stripped.partition("|")
                if sep and rest.strip():
                    entries.append((ts.strip(), _extract_ident(rest)))
                    continue
            entries.append((RECOVERY_TS, _extract_ident(stripped)))
        return [e for e in entries if e[1]]
    except OSError as exc:
        logger.error("Could not read history file %s: %s", HISTORY_FILE, exc)
        return []


def load_history() -> set[str]:
    """Identities of previously posted proxies (legacy + v2 formats)."""
    return {ident for _ts, ident in _history_entries()}


def load_history_timestamps() -> dict[str, float]:
    """ident -> last-posted epoch seconds (used for cooldown reuse)."""
    stamps: dict[str, float] = {}
    for ts, ident in _history_entries():
        try:
            when = datetime.fromisoformat(ts)
        except ValueError:
            when = datetime(2000, 1, 1)  # unmappable -> ancient
        if when.tzinfo is not None:
            when = when.astimezone().replace(tzinfo=None)
        epoch = when.timestamp()
        stamps[ident] = max(epoch, stamps.get(ident, 0.0))
    return stamps


def compact_history() -> int:
    """Rewrite history.txt keeping only the newest MAX_HISTORY_ENTRIES.

    Legacy plain lines are upgraded to the timestamped v2 format in the
    process. Returns the number of retained entries.
    """
    entries = _history_entries()
    try:
        parsed = sorted(
            ((datetime.fromisoformat(ts), ts, ident) for ts, ident in entries),
            key=lambda item: item[0],
        )
        kept = [(ts, ident) for _dt, ts, ident in parsed[-MAX_HISTORY_ENTRIES:]]
    except ValueError:
        # Any unmappable timestamp: keep original order, still cap.
        kept = entries[-MAX_HISTORY_ENTRIES:]
    try:
        with HISTORY_FILE.open("w", encoding="utf-8") as fh:
            for ts, ident in kept:
                fh.write(f"{ts}|{ident}\n")
        return len(kept)
    except OSError as exc:
        logger.error("Could not compact history file %s: %s", HISTORY_FILE, exc)
        return -1


def append_history(proxies: list[Proxy]) -> bool:
    """Record posted proxies (timestamped v2) and compact to the cap."""
    try:
        now_iso = datetime.now().isoformat(timespec="seconds")
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            for proxy in proxies:
                fh.write(f"{now_iso}|{_extract_ident(proxy.link)}\n")
        retained = compact_history()
        if retained >= 0:
            logger.info("History compacted: %d entries retained", retained)
            return True
        return False
    except OSError as exc:
        logger.error("Could not update history file %s: %s", HISTORY_FILE, exc)
        return False


# ---------------------------------------------------------------------------
# Message formatting (HTML parse mode)
# ---------------------------------------------------------------------------

def channel_username() -> str | None:
    """Return the channel username (without @) when the tag is a username.

    Numeric channel IDs cannot be turned into t.me links, so callers use
    this to omit the join button that Telegram would reject.
    """
    tag = CHANNEL_TAG.strip()
    if tag.startswith("@") and len(tag) > 1 and all(
        c.isalnum() or c == "_" for c in tag[1:]
    ):
        return tag[1:]
    return None


NEWS_HEADER = "📰 <b>خبر فوری:</b>"
NEWS_HEADER_PLAIN = "📰 خبر فوری:"
POST_HEADLINE = "⚡️ <b>پروکسی‌های فعال و پرسرعت</b>"
POST_HEADLINE_PLAIN = "⚡️ پروکسی‌های فعال و پرسرعت"


def format_message(proxies: list[Proxy], latencies: list[float],
                   rates_section: str | None = None) -> str:
    """Build the Persian post body (HTML entities pre-escaped).

    Compact: the rates board (when available) leads, then the proxy
    headline. No raw proxy links — deep links live ONLY in the
    inline-keyboard buttons.
    """
    parts: list[str] = []
    if rates_section:
        parts.append(rates_section)
    parts.append(POST_HEADLINE)
    return "\n\n".join(parts)


def format_message_minimal(proxies: list[Proxy], latencies: list[float],
                           rates_section: str | None = None) -> str:
    """Safe plaintext twin of the body (still link-free; the inline
    keyboard carries the deep links)."""
    parts: list[str] = []
    if rates_section:
        parts.append(rates_section)
    parts.append(POST_HEADLINE_PLAIN)
    return "\n\n".join(parts)


def format_batch_message(proxies: list[Proxy], latencies: list[float],
                         rates_section: str | None = None,
                         rates_section_plain: str | None = None) -> str:
    """Format with HTML; on any failure return the plaintext fallback."""
    try:
        message = format_message(proxies, latencies, rates_section)
        if len(message) > MAX_MESSAGE_LENGTH:
            raise ValueError("message exceeds Telegram limit")
        return message
    except Exception:
        logger.exception("HTML formatting failed; using plaintext fallback")
        return format_message_minimal(proxies, latencies, rates_section_plain)


def html_escape(text: str) -> str:
    """Escape the five HTML-critical characters for parse_mode=HTML."""
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


JOIN_BUTTON_TEXT = "📢 عضویت در کانال"


def _join_button() -> dict | None:
    """Join-channel button, or None when the channel id is numeric
    (it cannot be turned into a t.me link Telegram would accept)."""
    username = channel_username()
    return {"text": JOIN_BUTTON_TEXT, "url": f"https://t.me/{username}"} \
        if username else None


def build_inline_keyboard(proxies: list[Proxy],
                          latencies: list[float]) -> list[list[dict]]:
    """Compact 2-column proxy grid + one full-width channel row.

    Proxy connect buttons sit side-by-side (2 per row, minimal height);
    the final row spans the full width with the join-channel button.
    Deep links use the native tg:// scheme. There is no help/feedback
    button and no callback data.
    """
    buttons = [
        {
            "text": f"{PROXY_BUTTON_EMOJIS[(i - 1) % len(PROXY_BUTTON_EMOJIS)]} "
                    f"پروکسی {fa_num(i)}",
            "url": proxy.tg_link,
        }
        for i, proxy in enumerate(proxies, start=1)
    ]
    rows = [buttons[i:i + 2] for i in range(0, len(buttons), 2)]
    join = _join_button()
    if join is not None:
        rows.append([join])  # full-width channel row at the very bottom
    return rows


def send_message(token: str, chat_id: str, text: str,
                 proxies: list[Proxy] | None = None,
                 latencies: list[float] | None = None,
                 rates_section_plain: str | None = None) -> bool:
    """ONE logical sendMessage (first successful HTTP request wins) with
    graceful degradation: HTML+keyboard -> plaintext+keyboard -> plaintext.
    The deep links always reach users via the keyboard buttons and the
    market-rates section (when any) survives the formatting fallback; only
    the text formatting changes between attempts. True on any success.
    """
    url = TELEGRAM_API_URL.format(token=token, method="sendMessage")
    keyboard = (
        {"inline_keyboard": build_inline_keyboard(proxies, latencies)}
        if proxies and latencies else None
    )
    attempts: list[dict] = [{"text": text, "parse_mode": "HTML"}]
    attempts.append({"text": format_message_minimal(proxies, latencies,
                                                    rates_section_plain)
                     if proxies and latencies else text})
    if keyboard:
        attempts[0]["reply_markup"] = keyboard
        attempts[1]["reply_markup"] = keyboard
    attempts.append({"text": attempts[1]["text"]})  # last resort: no markup

    last_desc = ""
    rate_limited_once = False
    i = 0
    while i < len(attempts):
        payload_base = attempts[i]
        payload = {"chat_id": chat_id, "disable_web_page_preview": False, **payload_base}
        logger.info(
            "Telegram dispatch attempt %d/%d: chat_id=%s parse_mode=%s "
            "text_len=%d keyboard_rows=%d token=%s",
            i + 1, len(attempts), chat_id,
            payload.get("parse_mode", "<plain>"),
            len(payload.get("text", "")),
            len(payload.get("reply_markup", {}).get("inline_keyboard", [])),
            mask_token(token),
        )
        try:
            resp = requests.post(url, json=payload, timeout=TELEGRAM_TIMEOUT)
            status = getattr(resp, "status_code", None)
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("Telegram request failed (timeout <= %ds): %s",
                         TELEGRAM_TIMEOUT, exc)
            gh_annotation("error", f"Telegram request failed: {exc}")
            return False
        except ValueError as exc:
            logger.error("Telegram returned non-JSON response: %s", exc)
            gh_annotation("error", f"Telegram returned non-JSON response: {exc}")
            return False

        if data.get("ok"):
            logger.info(
                "Posted to Telegram (message_id=%s)",
                data.get("result", {}).get("message_id", "?"),
            )
            return True

        last_desc = str(data.get("description", data))
        error_code = data.get("error_code", status)
        logger.error(
            "Telegram API error (attempt %d): HTTP status=%s body=%s",
            i + 1, status, data,
        )
        # 429 rate limit: wait out retry_after once, then re-attempt the
        # SAME payload (dispatch failure here must not lose the batch).
        if error_code == 429 and not rate_limited_once:
            retry_after = 1.0
            params = data.get("parameters") or {}
            try:
                retry_after = min(30.0, max(1.0, float(params.get("retry_after", 1.0))))
            except (TypeError, ValueError):
                pass
            logger.warning("Rate-limited; backing off %.0f s then retrying once", retry_after)
            time.sleep(retry_after)
            rate_limited_once = True
            continue  # retry the same attempt index
        if "parse" in last_desc.lower() and i + 1 < len(attempts):
            i += 1  # formatting error - the plaintext attempt follows
            continue
        # Non-formatting (or final) failure: surface an actionable hint.
        hint = TG_ERROR_HINTS.get(error_code) or TG_ERROR_HINTS.get(status)
        message = f"Telegram API error {error_code or status or '?'}: {last_desc}"
        if hint:
            message = f"{message} -> {hint}"
        logger.error(message)
        gh_annotation("error", message)
        return False
    logger.error("Telegram rejected all formatting attempts: %s", last_desc)
    return False


# ---------------------------------------------------------------------------
# Selection: five distinct, fresh, fastest proxies
# ---------------------------------------------------------------------------

def rank_reachable(proxies: list[Proxy],
                   enough: int | None = None) -> list[tuple[Proxy, float]]:
    """Strict parallel probe via prober.py (latency cap + TTL health).

    `enough` enables early stop: probing halts once that many valid
    proxies exist (deadline-safe; in-flight probes are cancelled).
    """
    if not proxies:
        return []
    return prober_module.probe(proxies, enough=enough or (BATCH_SIZE + 3))


def pick_batch(reachable: list[tuple[Proxy, float]],
               history: set[str], size: int = BATCH_SIZE,
               last_posted: dict[str, float] | None = None) -> list[tuple[Proxy, float]]:
    """Select `size` fresh, fastest proxies, preferring distinct hostnames.

    Rules applied in order: latency cap, history exclusion with cooldown
    reuse (a proxy last posted > REUSE_COOLDOWN ago becomes eligible again),
    duplicate (server, port, secret) suppression, and at most one proxy per
    server hostname unless fewer than `size` distinct servers are reachable.
    Returns fewer than `size` only when the candidate pool is genuinely
    exhausted within the cooldown window.
    """
    picked: list[tuple[Proxy, float]] = []
    picked_combos: set[tuple[str, int, str]] = set()
    picked_hosts: set[str] = set()
    now = time.time()
    last_posted = last_posted or {}

    def try_take(proxy: Proxy, latency: float) -> bool:
        if proxy.latency_ms is not None and proxy.latency_ms > MAX_LATENCY_MS:
            return False
        if latency > MAX_LATENCY_MS:
            return False
        if proxy.key in history:
            if last_posted is None:
                return False  # no cooldown data: stay conservative (old behavior)
            stamp = last_posted.get(proxy.key)
            if stamp is None or (now - stamp) < REUSE_COOLDOWN:
                return False  # posted recently (or unstamped) - still cooling down
        if proxy.combo in picked_combos:
            return False
        picked.append((proxy, latency))
        picked_combos.add(proxy.combo)
        picked_hosts.add(proxy.server.lower())
        return True

    def fill(pool_items: list[tuple[Proxy, float]]) -> None:
        for proxy, latency in pool_items:
            if len(picked) >= size:
                return
            try_take(proxy, latency)

    # Pass 1: one proxy per server hostname (best latency per host first).
    best_per_host: dict[str, tuple[Proxy, float]] = {}
    for proxy, latency in reachable:
        host = proxy.server.lower()
        if host not in best_per_host:
            best_per_host[host] = (proxy, latency)
    fill(list(best_per_host.values()))

    # Pass 2: allow a second/third proxy from already-picked servers only if
    # the distinct-server pool cannot fill the batch.
    if len(picked) < size:
        rest = [(p, l) for p, l in reachable
                if p.server.lower() not in picked_hosts]
        fill(rest)
    if len(picked) < size:
        fill(reachable)

    return picked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

MIN_BATCH_SIZE = 1     # post 1-4 proxies rather than skip the run entirely


def get_chat_info(token: str, chat_id: str) -> dict | None:
    """Resolve the destination chat (title/username/id) for the log trail."""
    url = TELEGRAM_API_URL.format(token=token, method="getChat")
    try:
        resp = requests.post(url, json={"chat_id": chat_id},
                             timeout=TELEGRAM_TIMEOUT)
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("getChat check failed: %s", exc)
        return None
    if data.get("ok"):
        result = data.get("result") or {}
        logger.info(
            "Destination chat verified: id=%s username=%s title=%s",
            result.get("id"), result.get("username") or "<none>",
            result.get("title") or "<none>",
        )
        return result
    logger.warning("getChat failed: %s", data.get("description", data))
    return None


def _post_decision(will_post: bool, reason: str, fresh_count: int,
                   selected_count: int, chat_id: str,
                   parse_mode: str, text_len: int) -> None:
    """One always-printed line summarizing the posting decision."""
    logger.info(
        "POST DECISION: {will_post=%s | reason='%s' | fresh_count=%d | "
        "selected_count=%d | chat_id=%s | parse_mode=%s | text_len=%d}",
        "yes" if will_post else "no", reason, fresh_count,
        selected_count, chat_id, parse_mode, text_len,
    )


def _reuse_known_good(reachable: list[tuple[Proxy, float]],
                      last_posted: dict[str, float],
                      count: int) -> list[tuple[Proxy, float]]:
    """Fallback 1: reuse previously posted proxies that re-probed healthy.

    Every candidate here comes from the CURRENT run's validated pool, so
    each returned proxy just passed the strict TCP probe (< 2500 ms). Among
    those, proxies with a proven history.json health record (alive, low
    recorded ping) rank first, then the oldest last-posted stamp; distinct
    server hostnames are preferred exactly like pick_batch.
    """
    if count <= 0 or not reachable:
        return []
    health = prober_module.load_health()

    def rank(item: tuple[Proxy, float]):
        proxy, latency = item
        entry = health.get(proxy.key) or {}
        alive = 1 if entry.get("alive") else 0
        recorded = float(entry.get("latency_ms") or latency)
        stamp = last_posted.get(proxy.key, 0.0)
        return (-alive, recorded, stamp)

    ordered = sorted(reachable, key=rank)
    picked: list[tuple[Proxy, float]] = []
    seen_hosts: set[str] = set()
    for proxy, latency in ordered:  # pass 1: distinct hostnames
        if len(picked) >= count:
            break
        host = proxy.server.lower()
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        picked.append((proxy, latency))
    for proxy, latency in ordered:  # pass 2: distinct hosts exhausted
        if len(picked) >= count:
            break
        if all(p.combo != proxy.combo for p, _ in picked):
            picked.append((proxy, latency))
    if picked:
        logger.info(
            "Known-good reuse: returning %d previously-posted proxies with "
            "verified health records", len(picked),
        )
    return picked


def _silent_skip(run_started: float, reason: str, fresh_count: int) -> int:
    """Fallback 2: post nothing this cycle (silent wait until the next
    scheduled run). No placeholder, maintenance, or dummy post is ever
    sent; dead proxies are never published to fill space."""
    logger.warning(
        "Silent skip: %s - nothing will be posted this cycle; the next "
        "scheduled run will retry.", reason,
    )
    _post_decision(False, reason, fresh_count, 0, "skipped", "-", 0)
    logger.info("=== ProxGram run finished (silent skip) in %.1f s ===",
                time.monotonic() - run_started)
    return 0


def main() -> int:
    run_started = time.monotonic()
    deadline = run_started + GLOBAL_DEADLINE
    setup_logging()
    trigger = os.environ.get("GITHUB_EVENT_NAME", "manual/local")
    logger.info("=== ProxGram run started (trigger: %s) ===", trigger)

    # 0. Credentials are required for any posting to happen.
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    channel_id = os.environ.get("TELEGRAM_CHANNEL_ID")
    cred_problems = validate_credentials(token, channel_id)
    if cred_problems:
        for problem in cred_problems:
            logger.error("Credential problem: %s", problem)
            gh_annotation("error", problem)
        _post_decision(False, "missing/malformed credentials", 0, 0,
                       channel_id or "<none>", "-", 0)
        return 2  # unrecoverable: nothing can be posted without them
    logger.info(
        "Credentials OK (token=%s channel_id=%s)",
        mask_token(token), channel_id,
    )
    # Resolve and log the real destination chat (wrong-chat guard).
    try:
        get_chat_info(token, channel_id)
    except Exception:
        logger.exception("getChat verification crashed (non-fatal)")

    # 1. Collect + filter candidates (parallel multi-source fetcher) with a
    # one-shot Refresh Cycle when the pool comes back empty.
    stage_started = time.monotonic()
    candidates: list[Proxy] = []
    try:
        candidates = collect_candidates()
        if not candidates:
            logger.warning(
                "Fetch yielded 0 candidates; triggering Refresh Cycle "
                "(+%d probe budget)", REFRESH_EXTRA,
            )
            candidates = collect_candidates(extra=REFRESH_EXTRA)
    except Exception:
        logger.exception("Unexpected error while collecting proxies")
        gh_annotation("error", "Proxy source collection crashed - see logs")
        return 0  # transient infrastructure issue - don't fail the workflow
    logger.info("[stage] fetch+validate: %d candidates in %.1f s",
                len(candidates), time.monotonic() - stage_started)
    if not candidates:
        logger.error("No valid Fake-TLS candidates from any source.")
        gh_annotation("warning",
                      "No valid Fake-TLS candidates from any source")
        return _silent_skip(run_started, "no valid candidates from sources", 0)

    # 2. Strict probe (latency cap + TTL health) with a Refresh Cycle when
    # fewer than BATCH_SIZE valid proxies survive.
    stage_started = time.monotonic()
    reachable: list[tuple[Proxy, float]] = []
    try:
        reachable = rank_reachable(candidates, enough=BATCH_SIZE + 3)
        if len(reachable) < BATCH_SIZE:
            logger.warning(
                "Only %d valid proxies after probing; Refresh Cycle with a "
                "broader candidate pool (+%d)", len(reachable), REFRESH_EXTRA,
            )
            refreshed = collect_candidates(extra=REFRESH_EXTRA)
            if refreshed:
                reachable = rank_reachable(
                    refreshed, enough=BATCH_SIZE + 3,
                )
    except Exception:
        logger.exception("Unexpected error during latency tests")
        return 0
    logger.info(
        "[stage] probe: %d valid / %d tested in %.1f s",
        len(reachable), len(candidates), time.monotonic() - stage_started,
    )
    logger.info(
        "Distinct server hostnames available: %d",
        len({p.server.lower() for p, _ in reachable}),
    )
    # Never post dead proxies just to fill space: below the hard floor of
    # BATCH_SIZE - 2 valid proxies, selection falls back to known-good
    # reuse and, if that finds nothing, a silent skip (no notice post).
    if len(reachable) < BATCH_SIZE - 2:
        logger.warning(
            "Valid pool below floor (%d < %d); known-good reuse will fill "
            "the batch if the fresh selection comes up short",
            len(reachable), BATCH_SIZE - 2,
        )
        gh_annotation(
            "warning",
            f"Only {len(reachable)} valid proxies available; "
            "falling back to known-good reuse",
        )

    # 3. Pick fresh proxies (cooldown-aware reuse; never pad unverified).
    stage_started = time.monotonic()
    try:
        HISTORY_FILE.touch(exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create history file %s: %s", HISTORY_FILE, exc)
    history = load_history()
    last_posted = load_history_timestamps()
    after_history = [p for p, _ in reachable
                     if p.key not in history
                     or (time.time() - last_posted.get(p.key, 0.0)) >= REUSE_COOLDOWN]
    logger.info(
        "After history filtering: %d candidates remain (history size %d, "
        "cooldown %.0fh)",
        len(after_history), len(history), REUSE_COOLDOWN / 3600.0,
    )
    picks = pick_batch(reachable, history, last_posted=last_posted)
    logger.info("[stage] selection: %d fresh proxies in %.1f s",
                len(picks), time.monotonic() - stage_started)
    if not picks:
        # Fallback 1: the pool is exhausted within the cooldown window ->
        # re-post known-good proxies that just re-probed healthy (proven
        # latency records), never unverified or dead fillers.
        logger.warning(
            "No fresh proxies within the %.0fh cooldown window; reusing "
            "known-good proxies with verified health records.",
            REUSE_COOLDOWN / 3600.0,
        )
        picks = _reuse_known_good(reachable, last_posted, BATCH_SIZE)
    if not picks:
        # Fallback 2: nothing viable at all -> silent wait, no placeholder.
        return _silent_skip(run_started, "no viable proxies this cycle",
                            len(after_history))
    if len(picks) < BATCH_SIZE:
        logger.warning(
            "Partial batch: only %d/%d fresh valid proxies available; "
            "publishing what is available rather than skipping.",
            len(picks), BATCH_SIZE,
        )
        gh_annotation(
            "warning",
            f"Partial batch: only {len(picks)}/{BATCH_SIZE} fresh proxies "
            "available; publishing them anyway",
        )

    proxies = [p for p, _ in picks]
    latencies = [l for _, l in picks]
    for i, (proxy, latency) in enumerate(zip(proxies, latencies), start=1):
        logger.info("Selected #%d server=%s port=%d latency=%.0f ms",
                    i, proxy.server, proxy.port, latency)

    # 4. Market rates section (never blocks the proxy post on failure).
    stage_started = time.monotonic()
    rates_html = rates_plain = None
    try:
        rates_data = rates_module.get_rates()
    except Exception:
        logger.exception("Unexpected rates error; posting without rates")
        rates_data = None
    if rates_data:
        try:
            rates_html = rates_module.format_board(rates_data, "html")
            rates_plain = rates_module.format_board(rates_data, "plain")
            omitted = [f for f, v in rates_data.items() if v is None]
            logger.info(
                "Rates board rendered: %d/%d fields, omitted: %s",
                len(rates_data) - len(omitted), len(rates_data),
                omitted or "none",
            )
        except Exception:
            logger.exception("Failed to render rates section; posting without it")
            rates_html = rates_plain = None
    rates_elapsed = time.monotonic() - stage_started
    if rates_html:
        logger.info("[stage] rates: section rendered in %.1f s", rates_elapsed)
    else:
        logger.info(
            "[stage] rates: unavailable after %.1f s; posting without rates",
            rates_elapsed,
        )

    # 5. Send exactly ONE message; deep links live only in the buttons.
    stage_started = time.monotonic()
    message = format_batch_message(proxies, latencies,
                                   rates_section=rates_html,
                                   rates_section_plain=rates_plain)
    if time.monotonic() > deadline:
        logger.warning("Global deadline exceeded before dispatch; dispatching anyway.")
    try:
        success = send_message(token, channel_id, message,
                               proxies=proxies, latencies=latencies,
                               rates_section_plain=rates_plain)
    except Exception:
        logger.exception("Unexpected error while posting the batch")
        gh_annotation("error", "Unexpected crash while posting the batch")
        _post_decision(False, "dispatch crashed", len(after_history),
                       len(proxies), channel_id, "-", len(message))
        return 0
    logger.info(
        "[stage] dispatch: success=%s in %.1f s",
        success, time.monotonic() - stage_started,
    )
    _post_decision(success, "batch dispatched" if success else "telegram rejected",
                   len(after_history), len(proxies), channel_id,
                   "HTML", len(message))

    if not success:
        logger.error("History NOT updated for this batch.")
        return 0

    # 6. Only after a confirmed send, record the posted proxy links.
    if append_history(proxies):
        logger.info("All %d links written to %s.", len(proxies), HISTORY_FILE.name)
    logger.info("=== ProxGram run finished OK in %.1f s ===",
                time.monotonic() - run_started)
    return 0


if __name__ == "__main__":
    sys.exit(main())
