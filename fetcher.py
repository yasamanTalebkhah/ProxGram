#!/usr/bin/env python3
"""fetcher.py — multi-source, parallelized proxy acquisition for ProxGram.

Backbone feeds (fetched concurrently; a failing URL is skipped with a log,
never crashing the run):

  JSON (handshake-verified, preferred):
    - dubblebyte/free-mtproto-proxies  proxies.json
  Plaintext tg://proxy | https://t.me/proxy link lists:
    - hookzof/socks5_list              proxy.txt
    - TheSpeedX/SOCKS-List             mtproto.txt
    - jetkai/proxy-list                proto.txt
    - roosterkid/openproxylist         MTPROTO_RAW.txt
    - SoliSpirit/mtproto               all_proxies.txt
    - Grim1313/mtproto-for-telegram    all_proxies.txt

Pipeline: parallel fetch (FETCH_TIMEOUT=5s per URL) -> normalize (strip,
MTProto-link filter: socks5/http/vless/vmess lines never enter the model)
-> strict validation (Fake-TLS `ee` secret + HTTPS-compatible port allow
list) -> dedup by server+port+secret -> cap at MAX_TO_TEST probes.

Telemetry: every run logs PROXIES_FETCHED_COUNT (raw unique MTProto links
merged from all sources) and PROXIES_VALIDATED_COUNT (after strict filter).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import requests

if TYPE_CHECKING:  # main imports this module; never import main at load time
    from main import Proxy

logger = logging.getLogger("proxgram.fetcher")

# (url, kind) — kind selects the parser. JSON feeds are handshake-verified
# upstream and are listed first so their entries win dedup collisions.
SOURCES: list[tuple[str, str]] = [
    ("https://raw.githubusercontent.com/dubblebyte/free-mtproto-proxies/main/proxies.json",
     "json"),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "text"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/mtproto.txt", "text"),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/proto.txt",
     "text"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/MTPROTO_RAW.txt",
     "text"),
    ("https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
     "text"),
    ("https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt",
     "text"),
]

FETCH_TIMEOUT = 5.0   # seconds - hard per-URL timeout (parallel, not summed)
MAX_PER_SOURCE = 60   # parsed links kept per source before merging
MAX_TO_TEST = 90      # cap on candidates handed to the prober

USER_AGENT = "v2rayN/6.23"

_MTPROTO_MARKERS = ("t.me/proxy", "tg://proxy")


def fetch_url(url: str, timeout: float = FETCH_TIMEOUT) -> str | None:
    """Download one source; None on any network/HTTP error (logged, silent)."""
    started = time.monotonic()
    try:
        resp = requests.get(
            url, timeout=timeout, headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        logger.info(
            "Source fetched: %s (%d chars, %.0f ms)",
            url.rsplit("/", 1)[-1], len(resp.text),
            (time.monotonic() - started) * 1000.0,
        )
        return resp.text
    except (requests.RequestException, OSError) as exc:
        logger.warning(
            "Source failed (skipped): %s after %.0f ms: %s",
            url, (time.monotonic() - started) * 1000.0, exc,
        )
        return None


def fetch_all(sources: list[tuple[str, str]] | None = None,
              timeout: float = FETCH_TIMEOUT) -> dict[str, str | None]:
    """Fetch every source concurrently. Returns {url: text-or-None}.

    Wall time ~= slowest single fetch, never the sum. Any exception inside
    a worker is contained and reported as None for that URL.
    """
    sources = sources if sources is not None else SOURCES
    results: dict[str, str | None] = {url: None for url, _kind in sources}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, len(sources))
    ) as pool:
        futures = {
            pool.submit(fetch_url, url, timeout): url for url, _kind in sources
        }
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                results[url] = future.result()
            except Exception as exc:  # defensive: one worker must not kill all
                logger.warning("Source worker crashed for %s: %s", url, exc)
                results[url] = None
    return results


def parse_json_feed(text: str) -> list[Proxy]:
    """Parse a handshake-verified JSON feed ([{server, port, secret, ...}])."""
    from main import Proxy  # lazy: avoids a circular import at load time
    try:
        data = json.loads(text)
    except ValueError as exc:
        logger.warning("JSON source is invalid: %s", exc)
        return []
    if not isinstance(data, list):
        logger.warning("JSON source has unexpected top-level type")
        return []
    proxies: list[Proxy] = []
    for entry in data[: MAX_PER_SOURCE * 2]:
        if not isinstance(entry, dict):
            continue
        server = str(entry.get("server") or "").strip().strip(".")
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


def parse_text_feed(text: str) -> list[Proxy]:
    """Extract MTProto proxies from a plaintext feed; everything else
    (socks5://, http://, vless://, vmess://, junk) is discarded by the
    strict tg://proxy | t.me/proxy marker filter."""
    from main import Proxy  # lazy: avoids a circular import at load time
    proxies: list[Proxy] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not any(m in stripped for m in _MTPROTO_MARKERS):
            continue  # socks5/http/vless/vmess/unknown formats never enter
        try:
            parsed = urlparse(stripped)
            qs = {k: v[-1] for k, v in parse_qs(parsed.query).items() if v}
            server = (qs.get("server") or "").strip().strip(".")
            port = int(qs.get("port", "").strip())
            secret = (qs.get("secret") or "").strip()
        except ValueError:
            continue
        if not server or not secret:
            continue
        proxies.append(Proxy(server, port, secret))
        if len(proxies) >= MAX_PER_SOURCE:
            break
    return proxies


def validate(proxies: list[Proxy]) -> tuple[list[Proxy], dict[str, int]]:
    """Strict quality filter: Fake-TLS secret + allowed port + dedup."""
    from main import (  # lazy: avoids a circular import at load time
        is_allowed_port, is_valid_faketls_secret,
    )
    kept: list[Proxy] = []
    stats = {"bad_secret": 0, "bad_port": 0, "duplicate": 0}
    seen: set[tuple[str, int, str]] = set()
    for proxy in proxies:
        if not is_valid_faketls_secret(proxy.secret):
            stats["bad_secret"] += 1
            continue
        if not is_allowed_port(proxy.port):
            stats["bad_port"] += 1
            continue
        if proxy.combo in seen:
            stats["duplicate"] += 1
            continue
        seen.add(proxy.combo)
        kept.append(proxy)
    return kept, stats


def fetch_candidates(sources: list[tuple[str, str]] | None = None,
                     timeout: float = FETCH_TIMEOUT,
                     cap: int = MAX_TO_TEST) -> list[Proxy]:
    """Full acquisition pipeline; returns validated, deduped candidates.

    Telemetry: logs PROXIES_FETCHED_COUNT (unique MTProto links merged
    across sources, pre-strict-filter) and PROXIES_VALIDATED_COUNT (what
    the prober will actually test).
    """
    started = time.monotonic()
    results = fetch_all(sources, timeout)

    merged: list[Proxy] = []
    seen_raw: set[tuple[str, int, str]] = set()
    fetched_count = 0
    for url, kind in (sources if sources is not None else SOURCES):
        text = results.get(url)
        if not text:
            continue
        parsed = (parse_json_feed(text) if kind == "json"
                  else parse_text_feed(text))
        for proxy in parsed:
            if proxy.combo in seen_raw:
                continue
            seen_raw.add(proxy.combo)
            merged.append(proxy)
    fetched_count = len(merged)

    kept, stats = validate(merged)
    logger.info(
        "PROXIES_FETCHED_COUNT: %d | PROXIES_VALIDATED_COUNT: %d "
        "(rejected: %d bad secret, %d bad port, %d duplicate) in %.1f s",
        fetched_count, len(kept), stats["bad_secret"], stats["bad_port"],
        stats["duplicate"], time.monotonic() - started,
    )
    return kept[:cap]
