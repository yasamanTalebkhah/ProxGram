#!/usr/bin/env python3
"""ProxGram — fetch fresh Telegram MTProto / Socks5 proxies from public
aggregators, health-check them with a quick TCP connect test, and post the
single best (lowest-latency, never-posted-before) proxy to a Telegram channel.

Credentials are read from environment variables:
    TELEGRAM_BOT_TOKEN   - bot token from @BotFather
    TELEGRAM_CHANNEL_ID  - target channel (e.g. @mychannel or -1001234567890)
    TELEGRAM_CHANNEL_TAG - optional signature shown in the post (default @ChannelID)

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
from urllib.parse import parse_qs, urlparse

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
MAX_TO_TEST = 80      # cap total candidates sent through the health check
PING_TIMEOUT = 3.0    # seconds - strict TCP connect timeout
MAX_WORKERS = 60      # parallel TCP tests (total wall time ~= one timeout)

HISTORY_FILE = Path(__file__).resolve().parent / "history.txt"
LOG_FILE = Path(__file__).resolve().parent / "proxgram.log"

HTTP_TIMEOUT = 15  # seconds
USER_AGENT = "v2rayN/6.23"  # standard client UA - aggregators treat unknown UAs differently
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"
MAX_MESSAGE_LENGTH = 4096

CHANNEL_SIGNATURE = os.environ.get("TELEGRAM_CHANNEL_TAG") or "@ChannelID"

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


def parse_mtproto_link(line: str) -> dict | None:
    """Parse a t.me/proxy or tg://proxy link into a proxy dict.

    Returns None when the line is not a usable MTProto link. The returned
    link is normalized to the https://t.me/proxy?... form so it is clickable
    from every Telegram client.
    """
    stripped = line.strip()
    if "t.me/proxy" not in stripped and not stripped.startswith("tg://proxy"):
        return None
    try:
        parsed = urlparse(stripped)
        qs = parse_qs(parsed.query)
        server = (qs.get("server") or [""])[0].strip().strip(".")
        port_raw = (qs.get("port") or [""])[0].strip()
        secret = (qs.get("secret") or [""])[0].strip()
        port = int(port_raw)
        if not server or not (0 < port < 65536) or not secret:
            return None
    except (ValueError, IndexError):
        return None
    return {
        "protocol": "MTProto",
        "server": server,
        "port": port,
        "secret": secret,
        "link": f"https://t.me/proxy?server={server}&port={port}&secret={secret}",
    }


def parse_socks5_line(line: str) -> dict | None:
    """Parse a bare host:port line into a Socks5 proxy dict."""
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
    return {
        "protocol": "Socks5",
        "server": host,
        "port": port,
        "secret": None,
        "link": f"socks5://{host}:{port}",
    }


def collect_proxies() -> list[dict]:
    """Fetch every source feed, parse links, dedupe by host:port.

    MTProto sources are collected first so they win dedup ties and get
    priority when the candidate cap truncates the list.
    """
    proxies: list[dict] = []
    seen: set[str] = set()

    jobs = [(MTPROTO_SOURCES, parse_mtproto_link), (SOCKS5_SOURCES, parse_socks5_line)]
    for urls, parser in jobs:
        for url in urls:
            raw = fetch_text(url)
            if raw is None:
                continue
            count = 0
            for line in raw.splitlines():
                if count >= MAX_PER_SOURCE:
                    break
                proxy = parser(line)
                if proxy is None:
                    continue
                key = f"{proxy['server'].lower()}:{proxy['port']}"
                if key in seen:
                    continue
                seen.add(key)
                proxies.append(proxy)
                count += 1
            logger.info("Parsed %d proxies from %s", count, url)

    logger.info("Total unique proxy candidates: %d", len(proxies))
    return proxies[:MAX_TO_TEST]


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


def append_history(proxy: dict) -> None:
    """Record a posted proxy key in history.txt (created on first write)."""
    key = f"{proxy['server'].lower()}:{proxy['port']}"
    try:
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(key + "\n")
    except OSError as exc:
        logger.error("Could not update history file %s: %s", HISTORY_FILE, exc)


# ---------------------------------------------------------------------------
# Posting
# ---------------------------------------------------------------------------

def format_message(proxy: dict, ping_ms: float) -> str:
    """Build the Persian channel post with ping, protocol and connect link."""
    link = html.escape(proxy["link"], quote=True)
    return (
        "🚀 <b>پراکسی جدید تلگرام</b>\n\n"
        f"⚡ پینگ: {max(1, round(ping_ms))} میلی‌ثانیه\n"
        f"🛡️ پروتکل: {proxy['protocol']}\n\n"
        "🔗 <b>جهت اتصال کلیک کنید:</b>\n"
        f"{link}\n\n"
        f"🆔 {CHANNEL_SIGNATURE}"
    )


def post_to_telegram(token: str, channel_id: str, message: str) -> bool:
    """Send the message via the Telegram Bot API. Returns True on success.

    Tries HTML formatting first; if Telegram rejects the formatting
    (HTTP 400 'can't parse entities'), retries once as plain text so a post
    is never lost. raise_for_status() is intentionally NOT used here - error
    responses still carry a JSON body with the description we need.
    """
    url = TELEGRAM_API_URL.format(token=token)
    for parse_mode in ("HTML", None):
        payload = {
            "chat_id": channel_id,
            "text": message,
            "disable_web_page_preview": False,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        label = parse_mode or "plain"
        try:
            resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
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

def rank_reachable(proxies: list[dict]) -> list[tuple[dict, float]]:
    """TCP-test candidates in parallel; return reachable ones sorted by ping."""
    if not proxies:
        return []
    results: list[tuple[int, dict, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(tcp_ping, p["server"], p["port"]): (i, p)
            for i, p in enumerate(proxies)
        }
        for future in concurrent.futures.as_completed(futures):
            index, proxy = futures[future]
            try:
                latency = future.result()
            except Exception as exc:  # defensive: a worker must never kill the run
                logger.debug("Health check crashed for %s: %s", proxy["server"], exc)
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


def pick_best_proxy(reachable: list[tuple[dict, float]], history: set[str]) -> tuple[dict, float] | None:
    """First lowest-latency reachable proxy whose host:port was never posted."""
    for proxy, latency in reachable:
        key = f"{proxy['server'].lower()}:{proxy['port']}"
        if key not in history:
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
    logger.info(
        "Selected %s proxy %s:%d (%.0f ms); %d fresh candidates remaining",
        proxy["protocol"], proxy["server"], proxy["port"], ping_ms,
        sum(1 for p, _ in reachable
            if f"{p['server'].lower()}:{p['port']}" not in history) - 1,
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
        success = post_to_telegram(token, channel_id, message)
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
