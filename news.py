#!/usr/bin/env python3
"""news.py — breaking Persian news headlines for ProxGram posts.

Fetches RSS feeds from leading Persian international outlets in priority
order, picks the freshest entry that has not been published before, and
returns a sanitized, <= 140-character headline.

Resilience contract: if every feed fails (network error, timeout, parse
error) or nothing new is available, `get_news()` returns None and the
caller publishes the proxy post WITHOUT the news section. News problems
must never block or break a proxy post.

Persistence: NEWS_HISTORY_FILE (news_history.txt, repo root) stores the
unique identifier (entry link, falling back to entry id/guid) of the last
MAX_NEWS_HISTORY published items. The selected item's ID is appended ONLY
after the Telegram post succeeds (caller's responsibility via
`append_news_history()`).
"""

import html
import logging
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import feedparser

import requests

logger = logging.getLogger("proxgram.news")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NEWS_FEEDS = [
    # Primary: BBC News Persian
    ("BBC Persian", "https://feeds.bbci.co.uk/persian/rss.xml"),
    # Alternate 1: Voice of America Persian
    ("VOA Persian", "https://ir.voanews.com/api/z$g-m_eq_m"),
    # Alternate 2: Iran International (all sections)
    ("Iran International", "https://www.iranintl.com/rss/all"),
]

NEWS_TIMEOUT = 10          # seconds - per-feed HTTP fetch timeout
NEWS_USER_AGENT = "Mozilla/5.0 (compatible; ProxGram/1.0; RSS reader)"
MAX_NEWS_TEXT_LEN = 140    # headline (title+summary) hard limit, then "..."
MAX_NEWS_HISTORY = 200     # unique IDs kept in news_history.txt
MIN_PUBLISHED_TS = 0.0     # entries older than epoch sanity checks are ignored

NEWS_HISTORY_FILE = Path(__file__).resolve().parent / "news_history.txt"

_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Text sanitization
# ---------------------------------------------------------------------------

def sanitize_news_text(title: str | None, summary: str | None) -> str | None:
    """Strip HTML tags, URLs and excessive whitespace; collapse to one text.

    - HTML entities are unescaped AFTER tags are removed so `&lt;b&gt;`
      never re-introduces markup.
    - If the summary is unavailable or merely duplicates the title, the
      title alone is used.
    - Returns None when nothing usable remains.
    """
    clean_parts: list[str] = []
    for raw in (title, summary):
        if not raw:
            continue
        text = _TAG_RE.sub(" ", str(raw))
        text = _URL_RE.sub(" ", text)
        text = html.unescape(text)
        # Unescaping can surface escaped entities that decode to tags.
        text = _TAG_RE.sub(" ", text)
        text = _WS_RE.sub(" ", text).strip()
        if text:
            clean_parts.append(text)
    if not clean_parts:
        return None
    # Drop a summary that adds nothing beyond the title.
    if len(clean_parts) == 2 and clean_parts[1] == clean_parts[0]:
        clean_parts = clean_parts[:1]
    return " — ".join(clean_parts)


def truncate_news_text(text: str, limit: int = MAX_NEWS_TEXT_LEN) -> str:
    """Trim to `limit` characters, appending `...` when truncated."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


# ---------------------------------------------------------------------------
# History (published-news dedup, last MAX_NEWS_HISTORY IDs)
# ---------------------------------------------------------------------------

def load_news_history() -> set[str]:
    """Load unique IDs of previously published news items."""
    if not NEWS_HISTORY_FILE.exists():
        return set()
    try:
        return {
            line.strip()
            for line in NEWS_HISTORY_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    except OSError as exc:
        logger.error("Could not read news history file %s: %s",
                     NEWS_HISTORY_FILE, exc)
        return set()


def append_news_history(entry_id: str) -> bool:
    """Record one published news ID, keeping only the newest MAX_NEWS_HISTORY."""
    entry_id = (entry_id or "").strip()
    if not entry_id:
        return False
    try:
        existing: list[str] = []
        if NEWS_HISTORY_FILE.exists():
            existing = [
                line.strip()
                for line in
                NEWS_HISTORY_FILE.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        if entry_id in existing:
            existing.remove(entry_id)
        existing.append(entry_id)
        existing = existing[-MAX_NEWS_HISTORY:]
        NEWS_HISTORY_FILE.write_text(
            "\n".join(existing) + "\n", encoding="utf-8"
        )
        return True
    except OSError as exc:
        logger.error("Could not update news history file %s: %s",
                     NEWS_HISTORY_FILE, exc)
        return False


# ---------------------------------------------------------------------------
# Fetching + selection
# ---------------------------------------------------------------------------

def _fetch_feed(url: str) -> str | None:
    """Download raw feed bytes; return None on any network/HTTP error."""
    try:
        resp = requests.get(
            url,
            timeout=NEWS_TIMEOUT,
            headers={"User-Agent": NEWS_USER_AGENT},
        )
        resp.raise_for_status()
        resp.encoding = resp.apparent_encoding or resp.encoding
        return resp.text
    except (requests.RequestException, OSError) as exc:
        # OSError also covers socket-level failures from non-requests backends
        # so the remaining feeds (and the post itself) are never skipped.
        logger.warning("News feed fetch failed %s: %s", url, exc)
        return None


def _entry_published_ts(entry) -> float:
    """Best-effort publication timestamp (0.0 when unknown)."""
    for attr in ("published_parsed", "updated_parsed"):
        ts = entry.get(attr)
        if ts:
            try:
                return max(0.0, float(time.mktime(ts)))
            except (TypeError, ValueError, OverflowError):
                continue
    return 0.0


def _entry_identifier(entry) -> str:
    """Stable unique ID: entry link, falling back to id/guid, then title."""
    for attr in ("link", "id", "guid"):
        value = (entry.get(attr) or "").strip()
        if value:
            return value
    return (entry.get("title") or "").strip()


def _entry_display_text(entry) -> str | None:
    """Sanitized title(+summary) for an entry, or None if unusable."""
    title = entry.get("title")
    summary = entry.get("summary") or entry.get("description")
    return sanitize_news_text(title, summary)


def _is_acceptable_link(entry) -> bool:
    """Entries must carry an http(s) link or id we can dedupe on."""
    ident = _entry_identifier(entry)
    if not ident:
        return False
    if ident.startswith("http"):
        parsed = urlparse(ident)
        return bool(parsed.netloc)
    return True  # non-URL ids (guids) are fine for dedup purposes


def get_news(feeds: list[tuple[str, str]] | None = None,
             history: set[str] | None = None) -> tuple[str | None, str | None]:
    """Return (news_text <= 140 chars, entry_id) or (None, None).

    Feeds are tried in priority order. Within a feed, entries are sorted by
    publication date descending and the freshest entry that is not in
    `history` wins. All feeds failing or yielding nothing new -> (None, None).
    """
    feeds = feeds if feeds is not None else NEWS_FEEDS
    history = history if history is not None else load_news_history()

    for name, url in feeds:
        raw = _fetch_feed(url)
        if raw is None:
            continue
        try:
            parsed_feed = feedparser.parse(raw)
        except Exception as exc:  # feedparser rarely raises; be defensive
            logger.warning("News feed parse failed %s: %s", name, exc)
            continue
        entries = list(parsed_feed.get("entries") or [])
        if not entries:
            logger.info("News feed %s: no entries", name)
            continue
        entries.sort(key=_entry_published_ts, reverse=True)
        for entry in entries:
            entry_id = _entry_identifier(entry)
            if not entry_id or entry_id in history:
                continue
            if not _is_acceptable_link(entry):
                continue
            text = _entry_display_text(entry)
            if not text:
                continue  # title+summary unusable; try the next entry
            news_text = truncate_news_text(text)
            published = _entry_published_ts(entry)
            logger.info(
                "News selected from %s (published ts=%s): %s",
                name, int(published) or "unknown", news_text[:60],
            )
            return news_text, entry_id
        logger.info("News feed %s: no fresh usable entries", name)

    logger.info("No new news available from any feed; posting without news.")
    return None, None
