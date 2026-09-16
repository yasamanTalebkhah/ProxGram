#!/usr/bin/env python3
"""ProxGram — fetch fresh proxy configs from public aggregators and post
one unique (never-posted-before) config to a Telegram channel.

Credentials are read from environment variables:
    TELEGRAM_BOT_TOKEN   - bot token from @BotFather
    TELEGRAM_CHANNEL_ID  - target channel (e.g. @mychannel or -1001234567890)

A local history.txt file next to this script tracks already-posted configs
so duplicates are never sent twice.
"""

import base64
import html
import logging
import os
import random
import re
import sys
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Primary sources (as specified for this project)
SOURCE_URLS = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/main/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
]

# Fallbacks used only when a primary URL fails (branch renamed / repo blocked):
# the mahdibland repo's default branch is "master", and Epodonios/v2ray-configs
# hosts an identical All_Configs_Sub.txt mirror.
FALLBACK_URLS = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
]

PROTOCOLS = ("vmess://", "vless://", "trojan://", "ss://")

HISTORY_FILE = Path(__file__).resolve().parent / "history.txt"
LOG_FILE = Path(__file__).resolve().parent / "proxgram.log"

HTTP_TIMEOUT = 30  # seconds
USER_AGENT = "ProxGram/1.0 (+https://github.com/yasamanTalebkhah/ProxGram)"
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"
MAX_MESSAGE_LENGTH = 4096      # Telegram hard limit
MAX_CONFIG_LENGTH = 3500       # leave room for the friendly message

B64_LINE_RE = re.compile(r"^[A-Za-z0-9+/\-_]+={0,2}$")

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


def try_decode_base64(line: str) -> str | None:
    """If the line is a base64-encoded block of links, decode it.

    Returns the decoded text, or None when the line is not base64 (e.g. it is
    already a plain vmess:// link — those contain ':' and are skipped).
    """
    stripped = line.strip()
    if len(stripped) < 16 or not B64_LINE_RE.match(stripped):
        return None
    # Support both standard and URL-safe alphabets, add missing padding.
    normalized = stripped.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if "://" in decoded else None


def decode_payload(text: str) -> str:
    """Decode base64 content if needed; pass plain text through unchanged."""
    out_lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        decoded = try_decode_base64(line)
        out_lines.append(decoded if decoded is not None else line)
    return "\n".join(out_lines)


def extract_configs(text: str) -> list[str]:
    """Extract valid vmess/vless/trojan/ss links (deduplicated, order kept)."""
    configs = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(PROTOCOLS) and line not in seen:
            seen.add(line)
            configs.append(line)
    return configs


def collect_configs() -> list[str]:
    """Fetch every source URL, decode, and merge all configs into one list."""
    all_configs: list[str] = []
    seen = set()

    for url in SOURCE_URLS + FALLBACK_URLS:
        raw = fetch_text(url)
        if raw is None:
            continue
        decoded = decode_payload(raw)
        configs = extract_configs(decoded)
        logger.info("Fetched %3d configs from %s", len(configs), url)
        for cfg in configs:
            if cfg not in seen:
                seen.add(cfg)
                all_configs.append(cfg)

    logger.info("Total unique configs collected: %d", len(all_configs))
    return all_configs


# ---------------------------------------------------------------------------
# History (duplicate prevention)
# ---------------------------------------------------------------------------

def load_history() -> set[str]:
    """Load previously posted configs from history.txt."""
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


def append_history(config: str) -> None:
    """Record a posted config in history.txt."""
    try:
        with HISTORY_FILE.open("a", encoding="utf-8") as fh:
            fh.write(config + "\n")
    except OSError as exc:
        logger.error("Could not update history file %s: %s", HISTORY_FILE, exc)


# ---------------------------------------------------------------------------
# Posting
# ---------------------------------------------------------------------------

PROTOCOL_LABELS = {
    "vmess://": "VMess",
    "vless://": "VLESS",
    "trojan://": "Trojan",
    "ss://": "Shadowsocks",
}


def format_message(config: str) -> str:
    """Build a neat, friendly Telegram message around the config."""
    protocol = next(
        (label for prefix, label in PROTOCOL_LABELS.items() if config.startswith(prefix)),
        "Proxy",
    )
    tag = protocol.lower().replace(" ", "")
    return (
        "🚀 <b>Fresh free proxy config, served daily!</b>\n\n"
        f"🔐 Protocol: <b>{protocol}</b>\n"
        "📡 Config below — copy &amp; import into your client 👇\n\n"
        f"<code>{html.escape(config)}</code>\n\n"
        f"#proxy #{tag} #v2ray #vpn #free #ProxGram"
    )


def post_to_telegram(token: str, channel_id: str, message: str) -> bool:
    """Send the message via the Telegram Bot API. Returns True on success."""
    url = TELEGRAM_API_URL.format(token=token)
    payload = {
        "chat_id": channel_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error("Telegram request failed: %s", exc)
        return False
    except ValueError as exc:
        logger.error("Telegram returned non-JSON response: %s", exc)
        return False

    if not data.get("ok"):
        logger.error("Telegram API error: %s", data.get("description", data))
        return False

    logger.info(
        "Posted to Telegram (message_id=%s)",
        data.get("result", {}).get("message_id", "?"),
    )
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def pick_new_config(configs: list[str], history: set[str]) -> str | None:
    """Pick ONE config not posted before (random pick among the fresh ones)."""
    candidates = [
        c for c in configs
        if c not in history and len(c) <= MAX_CONFIG_LENGTH
    ]
    if not candidates:
        return None
    return random.choice(candidates)


def main() -> int:
    setup_logging()
    logger.info("=== ProxGram run started ===")

    # 1. Collect configs from all sources.
    try:
        configs = collect_configs()
    except Exception:
        logger.exception("Unexpected error while collecting configs")
        return 1

    if not configs:
        logger.error("No configs could be collected from any source URL.")
        return 1

    # 2. Filter out already-posted configs and select one.
    history = load_history()
    config = pick_new_config(configs, history)
    if config is None:
        logger.info("No new (unposted) configs available. Nothing to do.")
        return 0

    logger.info(
        "Selected a fresh %s config (%d/%d new ones remaining)",
        PROTOCOL_LABELS.get(config.split("://")[0] + "://", "proxy"),
        sum(1 for c in configs if c not in history) - 1,
        len(configs),
    )

    # 3. Read credentials from environment.
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    channel_id = os.environ.get("TELEGRAM_CHANNEL_ID")
    if not token or not channel_id:
        logger.error(
            "Missing credentials. Set TELEGRAM_BOT_TOKEN and "
            "TELEGRAM_CHANNEL_ID environment variables."
        )
        return 2

    # 4. Format and post.
    message = format_message(config)
    if len(message) > MAX_MESSAGE_LENGTH:
        logger.error("Formatted message exceeds Telegram limit; skipping.")
        return 1

    try:
        success = post_to_telegram(token, channel_id, message)
    except Exception:
        logger.exception("Unexpected error while posting to Telegram")
        return 1

    if success:
        # 5. Only record in history after a successful post.
        append_history(config)
        logger.info("Success. History updated (%s).", HISTORY_FILE.name)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
