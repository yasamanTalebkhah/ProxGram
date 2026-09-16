#!/usr/bin/env python3
"""ProxGram — post fast, censorship-resistant Telegram MTProto proxies
(Fake-TLS `ee` secrets, HTTPS-compatible ports) to a Telegram channel.

Sources:
  1. Primary: handshake-verified JSON feed (dubblebyte/free-mtproto-proxies).
  2. Fallbacks: plaintext MTProto feeds (SoliSpirit, Grim1313).

Every candidate must pass strict Fake-TLS validation:
  - secret starts with `ee` (Fake-TLS; plain/dd rejected)
  - hex-only secrets must be long enough to carry key + SNI domain
    (bare `ee` + 32 hex = key with no domain is rejected)
  - base64url Fake-TLS secrets must be >= 22 chars (16-byte key + domain)
  - port in the HTTPS-compatible allow-list (443, 8443, 2053, 2083, 8880)

Candidates are TCP-tested (2.0s strict timeout), filtered to latency
<= 2500 ms, sorted by latency, and the best ones (up to MAX_POSTS) that are
not in history.txt are posted to the channel with a one-tap connect button.

Credentials are read from environment variables:
    TELEGRAM_BOT_TOKEN   - bot token from @BotFather
    TELEGRAM_CHANNEL_ID  - target channel (e.g. @mychannel or -1001234567890)
    TELEGRAM_CHANNEL_TAG - optional display tag for the post signature
                           (defaults to TELEGRAM_CHANNEL_ID)

history.txt (repo root) stores the full deep link of every posted proxy so
duplicates are never re-posted across workflow runs.
"""

import concurrent.futures
import html
import json
import logging
import os
import select
import socket
import string
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Handshake-verified feed first; plaintext feeds as fallbacks.
JSON_SOURCES = [
    "https://raw.githubusercontent.com/dubblebyte/free-mtproto-proxies/main/proxies.json",
]
PLAINTEXT_SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
]

MAX_PER_SOURCE = 40   # cap parsed proxies per source feed
MAX_TO_TEST = 60      # cap total candidates sent through the health check
PING_TIMEOUT = 2.0    # seconds - strict TCP connect timeout
MAX_LATENCY_MS = 2500  # discard anything slower than this
MAX_WORKERS = 60      # parallel TCP tests (total wall time ~= one timeout)
MAX_POSTS = 2         # post the best 1..N proxies per run

ALLOWED_PORTS = {443, 8443, 2053, 2083, 8880}

HEX_SET = set(string.hexdigits)
B64URL_SET = set(string.ascii_letters + string.digits + "-_")
FAKETLS_PREFIX = "ee"      # Fake-TLS secrets start with 0xEE
MIN_B64URL_SECRET_LEN = 22  # 16-byte key (b64) + at least ~10 chars of domain
MIN_HEX_SECRET_LEN = 34     # ee + 32 hex (key only) is NOT enough - domain required

HISTORY_FILE = Path(__file__).resolve().parent / "history.txt"
LOG_FILE = Path(__file__).resolve().parent / "proxgram.log"

HTTP_TIMEOUT = 15  # seconds
USER_AGENT = "v2rayN/6.23"  # standard client UA - aggregators treat unknown UAs differently
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/{method}"
MAX_MESSAGE_LENGTH = 4096

_channel_id = os.environ.get("TELEGRAM_CHANNEL_ID", "@ChannelID")
CHANNEL_TAG = os.environ.get("TELEGRAM_CHANNEL_TAG") or _channel_id

CONNECT_BUTTON_TEXT = "⚡️ اتصال مستقیم به پروکسی"
JOIN_BUTTON_TEXT = "📢 عضویت در کانال"

logger = logging.getLogger("proxgram")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """Configure console + file logging."""
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console = logging.StreamHandler(sys.stdout)
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
    def link(self) -> str:
        """Standard deep link that opens Telegram's proxy dialog on tap."""
        return (
            "https://t.me/proxy"
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

    Two alphabets exist in the wild:
      - hex-encoded: `ee` + 32 hex key + hex-encoded SNI domain; a bare
        `ee` + 32 hex (34 chars, no domain) is REJECTED.
      - base64url:   `ee` + 22-char b64 key + domain; accepted at >= 22
        chars so the key is present, with the domain following.
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
    """Download a text payload; return None on any network/HTTP error."""
    try:
        resp = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


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
            qs = parse_qs(parsed.query)
            server = (qs.get("server") or [""])[0].strip().strip(".")
            port = int((qs.get("port") or [""])[0].strip())
            secret = (qs.get("secret") or [""])[0].strip()
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
    seen: set[str] = set()
    for proxy in proxies:
        if not is_valid_faketls_secret(proxy.secret):
            stats["bad_secret"] += 1
            continue
        if not is_allowed_port(proxy.port):
            stats["bad_port"] += 1
            continue
        if proxy.link in seen:
            continue
        seen.add(proxy.link)
        kept.append(proxy)
    return kept, stats


def collect_candidates() -> list[Proxy]:
    """Fetch all sources, parse, filter, dedupe, and cap the test list."""
    candidates: list[Proxy] = []
    seen: set[str] = set()

    def add_many(parsed: list[Proxy], source_name: str) -> None:
        fetched = len(parsed)
        kept, stats = apply_filters(parsed)
        for proxy in kept:
            if proxy.link in seen:
                continue
            seen.add(proxy.link)
            candidates.append(proxy)
        logger.info(
            "%s: fetched %d, after Fake-TLS/port filtering %d "
            "(rejected: %d bad secret, %d bad port)",
            source_name, fetched, len(kept), stats["bad_secret"], stats["bad_port"],
        )

    for url in JSON_SOURCES:
        raw = fetch_text(url)
        if raw is None:
            continue
        add_many(parse_json_source(raw), f"JSON feed {url.split('/main/')[-1]}")

    plaintext_budget = max(MAX_TO_TEST - len(candidates), 0)
    for url in PLAINTEXT_SOURCES:
        if plaintext_budget <= 0:
            break
        raw = fetch_text(url)
        if raw is None:
            continue
        parsed = parse_plaintext_source(raw)
        add_many(parsed[:plaintext_budget * 3], f"plaintext {url.split('/')[-1]}")
        plaintext_budget = max(MAX_TO_TEST - len(candidates), 0)

    logger.info("Total unique candidates after filtering: %d", len(candidates))
    return candidates[:MAX_TO_TEST]


# ---------------------------------------------------------------------------
# Health check (TCP connect + latency)
# ---------------------------------------------------------------------------

def tcp_ping(host: str, port: int, timeout: float = PING_TIMEOUT) -> float | None:
    """Non-blocking TCP connect test. Returns latency in ms, or None.

    The socket is set non-blocking so a dead host burns exactly `timeout`
    seconds, never more, and a shared per-attempt deadline covers DNS
    resolution plus all resolved addresses.
    """
    host = str(host).strip().strip(".")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not host or not (0 < port < 65536):
        return None

    deadline = time.monotonic() + timeout
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None  # unresolvable host

    # Codes meaning "connection in progress" on Linux/macOS/Windows:
    in_progress_codes = {
        code for code in (
            getattr(socket, "EINPROGRESS", None),
            getattr(socket, "EWOULDBLOCK", None),
            getattr(socket, "WSAEWOULDBLOCK", None),
            10035, 115, 36,
        )
        if code is not None
    }

    for af, socktype, proto, _canonical, sockaddr in infos[:2]:  # v4 then v6
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        started = time.monotonic()
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.setblocking(False)  # non-blocking: connect wins/loses fast
            err = sock.connect_ex(sockaddr)
            if err == 0:
                return (time.monotonic() - started) * 1000.0
            if err not in in_progress_codes:
                continue  # refused/unreachable outright - try next address
            # Wait for writability without blocking past the deadline.
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None  # timed out
                _, writable, _ = select.select([], [sock], [], left)
                if not writable:
                    continue  # loop re-checks the deadline
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    return (time.monotonic() - started) * 1000.0
                return None  # handshake failed (refused / unreachable)
        except OSError:
            continue  # try next address
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return None


# ---------------------------------------------------------------------------
# History (duplicate prevention, link-based)
# ---------------------------------------------------------------------------

def load_history() -> set[str]:
    """Load previously posted proxy links from history.txt."""
    if not HISTORY_FILE.exists():
        return set()
    try:
        return {
            line.strip()
            for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    except OSError as exc:
        logger.error("Could not read history file %s: %s", HISTORY_FILE, exc)
        return set()


def append_history(proxy: Proxy) -> None:
    """Record a posted proxy link in history.txt (created on first write)."""
    try:
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(proxy.link + "\n")
    except OSError as exc:
        logger.error("Could not update history file %s: %s", HISTORY_FILE, exc)


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


def format_message(proxy: Proxy, ping_ms: float) -> str:
    """Build the Persian channel post (HTML entities pre-escaped)."""
    ping = max(1, round(ping_ms))
    link = html.escape(proxy.link, quote=True)
    server = html.escape(proxy.server, quote=True)
    tag = html.escape(CHANNEL_TAG.strip(), quote=True)
    return (
        "🚀 <b>پروکسی ضدفیلتر تلگرام (Fake-TLS)</b>\n\n"
        f"⚡️ <b>پینگ:</b> <code>{ping} ms</code>\n"
        f"🌐 <b>سرور:</b> <code>{server}</code>\n"
        f"🚪 <b>پورت:</b> <code>{proxy.port}</code>\n\n"
        "🔗 <b>لینک پروکسی (جهت کپی دستی):</b>\n"
        f"<code>{link}</code>\n\n"
        f"🆔 {tag}"
    )


def format_message_minimal(proxy: Proxy, ping_ms: float) -> str:
    """Last-resort plaintext message used when HTML formatting fails."""
    return (
        "پروکسی ضدفیلتر تلگرام\n"
        f"پینگ: {max(1, round(ping_ms))} ms | سرور: {proxy.server} "
        f"| پورت: {proxy.port}\n"
        f"لینک: {proxy.link}"
    )


def build_inline_keyboard(proxy: Proxy) -> list[list[dict]]:
    """One-tap connect button + join-channel button (when a username exists)."""
    rows = [[{"text": CONNECT_BUTTON_TEXT, "url": proxy.link}]]
    username = channel_username()
    if username:
        rows.append([{"text": JOIN_BUTTON_TEXT, "url": f"https://t.me/{username}"}])
    return rows


def send_message(token: str, chat_id: str, text: str,
                 proxy: Proxy | None = None, ping_ms: float = 0) -> bool:
    """sendMessage with graceful degradation:
    HTML+keyboard -> HTML only -> minimal plaintext. True on any success.
    """
    url = TELEGRAM_API_URL.format(token=token, method="sendMessage")
    attempts: list[dict] = []
    if proxy is not None:
        attempts.append({
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {"inline_keyboard": build_inline_keyboard(proxy)},
        })
    attempts.append({"text": text, "parse_mode": "HTML"})
    fallback_text = format_message_minimal(proxy, ping_ms) if proxy else text
    attempts.append({"text": fallback_text})

    last_desc = ""
    for i, payload_base in enumerate(attempts):
        payload = {"chat_id": chat_id, "disable_web_page_preview": False, **payload_base}
        try:
            resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("Telegram request failed: %s", exc)
            return False
        except ValueError as exc:
            logger.error("Telegram returned non-JSON response: %s", exc)
            return False

        if data.get("ok"):
            logger.info(
                "Posted to Telegram (message_id=%s)",
                data.get("result", {}).get("message_id", "?"),
            )
            return True

        last_desc = str(data.get("description", data))
        logger.warning("Telegram API error (attempt %d): %s", i + 1, last_desc)
        if "parse" not in last_desc.lower():
            return False  # non-formatting error - retrying won't help
    logger.error("Telegram rejected all formatting attempts: %s", last_desc)
    return False


def post_to_telegram(token: str, channel_id: str, proxy: Proxy,
                     ping_ms: float) -> bool:
    """Format the message and send it; falls back to plaintext on errors."""
    try:
        message = format_message(proxy, ping_ms)
        if len(message) > MAX_MESSAGE_LENGTH:
            raise ValueError("message too long")
    except Exception:
        logger.exception("HTML formatting failed; using minimal plaintext")
        return send_message(token, channel_id, "", proxy=proxy, ping_ms=ping_ms)
    return send_message(token, channel_id, message, proxy=proxy, ping_ms=ping_ms)


# ---------------------------------------------------------------------------
# Selection: fastest reachable, not-yet-posted proxies
# ---------------------------------------------------------------------------

def rank_reachable(proxies: list[Proxy]) -> list[tuple[Proxy, float]]:
    """TCP-test candidates in parallel; return reachable ones sorted by ping."""
    if not proxies:
        return []
    results: list[tuple[int, Proxy, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(tcp_ping, p.server, p.port): (i, p)
            for i, p in enumerate(proxies)
        }
        for future in concurrent.futures.as_completed(futures):
            index, proxy = futures[future]
            try:
                latency = future.result()
            except Exception as exc:  # defensive: a worker must never kill the run
                logger.debug("Health check crashed for %s: %s", proxy.server, exc)
                continue
            if latency is not None:
                results.append((index, proxy, latency))

    results.sort(key=lambda item: (item[2], item[0]))  # lowest ping first, ties by feed order
    reachable = [(proxy, latency) for _i, proxy, latency in results]
    logger.info(
        "Latency test: %d/%d proxies reachable, best %.0f ms "
        "(timeout %.1fs, max %d ms)",
        len(reachable), len(proxies),
        reachable[0][1] if reachable else float("inf"),
        PING_TIMEOUT, MAX_LATENCY_MS,
    )
    return reachable


def pick_best_proxies(reachable: list[tuple[Proxy, float]],
                      history: set[str], limit: int = MAX_POSTS
                      ) -> list[tuple[Proxy, float]]:
    """Up to `limit` lowest-latency reachable proxies never posted before.

    History entries may be full deep links (current format) or legacy
    host:port keys from earlier versions; both are honored.
    """
    picked = []
    for proxy, latency in reachable:
        if latency > MAX_LATENCY_MS:
            continue
        if proxy.link in history or proxy.key in history:
            continue
        picked.append((proxy, latency))
        if len(picked) >= limit:
            break
    return picked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    setup_logging()
    logger.info("=== ProxGram run started ===")

    # 0. Credentials are required for any posting to happen.
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    channel_id = os.environ.get("TELEGRAM_CHANNEL_ID")
    if not token or not channel_id:
        logger.error(
            "Missing credentials. Set TELEGRAM_BOT_TOKEN and "
            "TELEGRAM_CHANNEL_ID environment variables."
        )
        return 2  # unrecoverable

    # 1. Collect + filter candidates.
    try:
        candidates = collect_candidates()
    except Exception:
        logger.exception("Unexpected error while collecting proxies")
        return 0  # transient infrastructure issue - don't fail the workflow

    if not candidates:
        logger.error("No valid Fake-TLS candidates from any source.")
        return 0

    # 2. Latency-test and rank.
    try:
        reachable = rank_reachable(candidates)
    except Exception:
        logger.exception("Unexpected error during latency tests")
        return 0

    if not reachable:
        logger.error("None of the %d candidates are reachable.", len(candidates))
        return 0

    # 3. Pick the best ones not posted before; make sure history.txt exists.
    try:
        HISTORY_FILE.touch(exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create history file %s: %s", HISTORY_FILE, exc)
    history = load_history()
    picks = pick_best_proxies(reachable, history)
    if not picks:
        logger.info("All fast reachable proxies were already posted. Nothing to do.")
        return 0

    # 4. Post each pick; record only successful posts.
    posted = 0
    for proxy, ping_ms in picks:
        logger.info("Selected %s (%.0f ms)", proxy.link, ping_ms)
        try:
            success = post_to_telegram(token, channel_id, proxy, ping_ms)
        except Exception:
            logger.exception("Unexpected error while posting %s", proxy.link)
            continue
        if success:
            append_history(proxy)
            posted += 1

    logger.info("Run finished: %d/%d posts succeeded.", posted, len(picks))
    return 0 if posted > 0 else 0  # transient Telegram failure is not fatal in CI


if __name__ == "__main__":
    sys.exit(main())
