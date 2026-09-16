#!/usr/bin/env python3
"""ProxGram — fetch fresh Telegram MTProto / Socks5 proxies from public
aggregators, health-check them with a quick TCP connect test, and post the
single best (lowest-latency, never-posted-before) proxy to a Telegram channel
with a one-tap connect button.

Credentials are read from environment variables:
    TELEGRAM_BOT_TOKEN   - bot token from @BotFather
    TELEGRAM_CHANNEL_ID  - target channel (e.g. @mychannel or -1001234567890)
    TELEGRAM_CHANNEL_TAG - optional display tag for the post signature
                           (defaults to TELEGRAM_CHANNEL_ID)

A local history.txt file next to this script tracks already-posted proxies
(by host:port) so duplicates are never sent twice.
"""

import concurrent.futures
import html
import logging
import os
import select
import socket
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# MTProto proxy feeds (t.me/proxy?server=..&port=..&secret=.. lines).
MTPROTO_SOURCES = [
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
]

# Socks5 feeds (host:port lines).
SOCKS5_SOURCES = [
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
]

MAX_PER_SOURCE = 40   # cap parsed proxies per source feed
MTPROTO_CAP = 40      # guaranteed slots for MTProto candidates (priority)
MAX_TO_TEST = 80      # cap total candidates sent through the health check
PING_TIMEOUT = 3.0    # seconds - strict TCP connect timeout
MAX_WORKERS = 60      # parallel TCP tests (total wall time ~= one timeout)

HISTORY_FILE = Path(__file__).resolve().parent / "history.txt"
LOG_FILE = Path(__file__).resolve().parent / "proxgram.log"

HTTP_TIMEOUT = 15  # seconds
USER_AGENT = "v2rayN/6.23"  # standard client UA - aggregators treat unknown UAs differently
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/{method}"
MAX_MESSAGE_LENGTH = 4096

_channel_id = os.environ.get("TELEGRAM_CHANNEL_ID", "@ChannelID")
CHANNEL_TAG = os.environ.get("TELEGRAM_CHANNEL_TAG") or _channel_id

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
# Proxy model + Telegram deep links
# ---------------------------------------------------------------------------

class Proxy:
    """A parsed proxy with helpers for standard Telegram deep links."""

    def __init__(self, protocol: str, server: str, port: int,
                 secret: str | None = None, link: str | None = None):
        self.protocol = protocol
        self.server = str(server).strip().strip(".")
        self.port = int(port)
        self.secret = secret
        self.raw_link = link

    @property
    def key(self) -> str:
        """Stable identity used for deduplication and history."""
        return f"{self.server.lower()}:{self.port}"

    @property
    def tg_link(self) -> str:
        """Standard deep link that opens Telegram's proxy dialog on tap."""
        if self.protocol == "MTProto":
            return (
                "https://t.me/proxy"
                f"?server={quote(self.server, safe='')}"
                f"&port={self.port}"
                f"&secret={quote(self.secret or '', safe='')}"
            )
        if self.protocol == "Socks5":
            return f"https://t.me/socks?server={quote(self.server, safe='')}&port={self.port}"
        return self.raw_link or ""

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Proxy {self.protocol} {self.key}>"


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


def parse_mtproto_link(line: str) -> Proxy | None:
    """Parse a t.me/proxy or tg://proxy link. Returns None if unusable."""
    stripped = line.strip()
    if "t.me/proxy" not in stripped and not stripped.startswith("tg://proxy"):
        return None
    try:
        parsed = urlparse(stripped)
        qs = parse_qs(parsed.query)
        server = (qs.get("server") or [""])[0].strip().strip(".")
        port = int((qs.get("port") or [""])[0].strip())
        secret = (qs.get("secret") or [""])[0].strip()
        if not server or not (0 < port < 65536) or not secret:
            return None
    except (ValueError, IndexError):
        return None
    return Proxy("MTProto", server, port, secret=secret, link=stripped)


def parse_socks5_line(line: str) -> Proxy | None:
    """Parse a bare host:port line into a Socks5 proxy."""
    stripped = line.strip()
    if ":" not in stripped or "/" in stripped or "?" in stripped:
        return None
    host, _, port_raw = stripped.rpartition(":")
    host = host.strip("[]")  # tolerate [ipv6]:port
    try:
        port = int(port_raw)
    except ValueError:
        return None
    if not host or not (0 < port < 65536):
        return None
    return Proxy("Socks5", host, port)


def collect_proxies() -> list[Proxy]:
    """Fetch every source feed and parse links, deduped by host:port.

    MTProto feeds are processed first and get a guaranteed quota
    (MTPROTO_CAP) so they are always prioritized over Socks5.
    """
    proxies: list[Proxy] = []
    seen: set[str] = set()
    mtproto_count = 0

    def add(proxy: Proxy) -> None:
        nonlocal mtproto_count
        if proxy.key in seen:
            return
        seen.add(proxy.key)
        proxies.append(proxy)
        if proxy.protocol == "MTProto":
            mtproto_count += 1

    for url in MTPROTO_SOURCES:
        raw = fetch_text(url)
        if raw is None:
            continue
        count = 0
        for line in raw.splitlines():
            if count >= MTPROTO_CAP:
                break
            proxy = parse_mtproto_link(line)
            if proxy is None:
                continue
            add(proxy)
            count += 1
        logger.info("Parsed %d MTProto proxies from %s", count, url)

    socks5_budget = max(MAX_TO_TEST - len(proxies), 0)
    for url in SOCKS5_SOURCES:
        raw = fetch_text(url)
        if raw is None:
            continue
        count = 0
        for line in raw.splitlines():
            if count >= MAX_PER_SOURCE or len(proxies) >= MAX_TO_TEST:
                break
            if count >= socks5_budget:
                break
            proxy = parse_socks5_line(line)
            if proxy is None:
                continue
            add(proxy)
            count += 1
        logger.info("Parsed %d Socks5 proxies from %s", count, url)

    logger.info(
        "Total unique proxy candidates: %d (MTProto: %d, Socks5: %d)",
        len(proxies), mtproto_count, len(proxies) - mtproto_count,
    )
    return proxies


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
            sock.setblocking(False)  # non-blocking: connect returns immediately
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
# History (duplicate prevention)
# ---------------------------------------------------------------------------

def load_history() -> set[str]:
    """Load previously posted host:port keys from history.txt."""
    if not HISTORY_FILE.exists():
        return set()
    try:
        return {
            line.strip().lower()
            for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    except OSError as exc:
        logger.error("Could not read history file %s: %s", HISTORY_FILE, exc)
        return set()


def append_history(proxy: Proxy) -> None:
    """Record a posted proxy key in history.txt (created on first write)."""
    try:
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(proxy.key + "\n")
    except OSError as exc:
        logger.error("Could not update history file %s: %s", HISTORY_FILE, exc)


# ---------------------------------------------------------------------------
# Message formatting (HTML parse mode)
# ---------------------------------------------------------------------------

CONNECT_BUTTON_TEXT = "⚡️ اتصال به پروکسی | Connect"


def channel_username() -> str | None:
    """Return the channel username (without @) when the tag is a username.

    Numeric channel IDs cannot be turned into t.me links, so callers use
    this to omit channel buttons/lines that Telegram would reject.
    """
    tag = CHANNEL_TAG.strip()
    if tag.startswith("@") and len(tag) > 1 and all(
        c.isalnum() or c == "_" for c in tag[1:]
    ):
        return tag[1:]
    return None


def format_message(proxy: Proxy, ping_ms: float) -> str:
    """Build the Persian channel post (HTML entities pre-escaped)."""
    server = html.escape(proxy.server, quote=True)
    protocol = html.escape(proxy.protocol, quote=True)
    link = html.escape(proxy.tg_link, quote=True)
    channel_line = ""
    username = channel_username()
    if username:
        channel_line = f"\n\n📢 <b>کانال ما:</b> @{username}"
    return (
        "🚀 <b>پروکسی پرسرعت تلگرام</b>\n"
        "━━━━━━━━━━━━━━\n\n"
        f"⚡️ پینگ: <b>{max(1, round(ping_ms))}</b> ms\n"
        f"🛡️ پروتکل: <b>{protocol}</b>\n"
        f"🌐 سرور: <code>{server}</code>\n\n"
        "🔗 <b>لینک اتصال:</b>\n"
        f"<code>{link}</code>"
        f"{channel_line}"
    )


def build_inline_keyboard(proxy: Proxy) -> list[list[dict]]:
    """One-tap connect button + a button back to the channel (if linked)."""
    rows = [[{"text": CONNECT_BUTTON_TEXT, "url": proxy.tg_link}]]
    username = channel_username()
    if username:
        rows.append([{"text": f"📢 @{username}", "url": f"https://t.me/{username}"}])
    return rows


def post_to_telegram(token: str, channel_id: str, proxy: Proxy,
                     message: str) -> bool:
    """Send the message via the Telegram Bot API. Returns True on success.

    Tries HTML formatting first; if Telegram rejects the formatting
    (HTTP 400 'can't parse entities'), retries once as plain text with no
    buttons. raise_for_status() is intentionally NOT used here - error
    responses still carry a JSON body with the description we need.
    """
    for parse_mode, markup in (("HTML", {"inline_keyboard": build_inline_keyboard(proxy)}), (None, None)):
        payload: dict = {
            "chat_id": channel_id,
            "text": message,
            "disable_web_page_preview": False,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if markup:
            payload["reply_markup"] = markup
        label = parse_mode or "plain"
        try:
            resp = requests.post(
                TELEGRAM_API_URL.format(token=token, method="sendMessage"),
                json=payload,
                timeout=HTTP_TIMEOUT,
            )
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("Telegram request failed (parse_mode=%s): %s", label, exc)
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

        description = str(data.get("description", data))
        logger.error("Telegram API error (parse_mode=%s): %s", label, description)
        if "parse" not in description.lower():
            return False  # non-formatting error (auth, chat not found...) - retry won't help
    return False


# ---------------------------------------------------------------------------
# Selection: first reachable, lowest-latency, not-yet-posted proxy
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
        "Health check: %d/%d proxies reachable (best %.0f ms)",
        len(reachable), len(proxies),
        reachable[0][1] if reachable else float("inf"),
    )
    return reachable


def pick_best_proxy(reachable: list[tuple[Proxy, float]],
                    history: set[str]) -> tuple[Proxy, float] | None:
    """First lowest-latency reachable proxy whose key was never posted."""
    for proxy, latency in reachable:
        if proxy.key not in history:
            return proxy, latency
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    setup_logging()
    logger.info("=== ProxGram run started ===")

    # 1. Collect proxy candidates from all sources.
    try:
        proxies = collect_proxies()
    except Exception:
        logger.exception("Unexpected error while collecting proxies")
        return 1

    if not proxies:
        logger.error("No proxies could be collected from any source URL.")
        return 1

    # 2. Health-check them and rank by latency.
    try:
        reachable = rank_reachable(proxies)
    except Exception:
        logger.exception("Unexpected error during health checks")
        return 1

    if not reachable:
        logger.error("None of the %d candidate proxies are reachable.", len(proxies))
        return 1

    # 3. Pick the best one not posted before; make sure history.txt exists.
    try:
        HISTORY_FILE.touch(exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create history file %s: %s", HISTORY_FILE, exc)
    history = load_history()
    picked = pick_best_proxy(reachable, history)
    if picked is None:
        logger.info("All reachable proxies were already posted. Nothing to do.")
        return 0
    proxy, ping_ms = picked
    fresh = sum(1 for p, _ in reachable if p.key not in history) - 1
    logger.info(
        "Selected %s proxy %s (%.0f ms); %d fresh candidates remaining",
        proxy.protocol, proxy.key, ping_ms, fresh,
    )

    # 4. Read credentials from environment.
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    channel_id = os.environ.get("TELEGRAM_CHANNEL_ID")
    if not token or not channel_id:
        logger.error(
            "Missing credentials. Set TELEGRAM_BOT_TOKEN and "
            "TELEGRAM_CHANNEL_ID environment variables."
        )
        return 2

    # 5. Format and post.
    message = format_message(proxy, ping_ms)
    if len(message) > MAX_MESSAGE_LENGTH:
        logger.error("Formatted message exceeds Telegram limit; skipping.")
        return 1

    try:
        success = post_to_telegram(token, channel_id, proxy, message)
    except Exception:
        logger.exception("Unexpected error while posting to Telegram")
        return 1

    if success:
        # 6. Only record in history after a successful post.
        append_history(proxy)
        logger.info("Success. History updated (%s).", HISTORY_FILE.name)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
