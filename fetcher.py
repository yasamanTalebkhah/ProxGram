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
list + SNI fronting-domain gate) -> dedup by server+port+secret ->
cap at MAX_TO_TEST probes.

SNI / Iran-DPI gate: the Fake-TLS secret must carry (or the server hostname
must provide) a fronting domain from the curated allow list of domains
known to camouflage TLS through Iranian DPI (MCI/Irancell/TCI): global
CDNs (cloudflare.com, speedtest.net, ...) and popular Iranian services
(digikala.com, snapp.ir, ...). Proxies with unknown, invalid, bare-IP or
blocked SNIs are discarded immediately; known-good domains are ranked
(global-CDN tier first) so the prober tests the strongest camouflage
first.

Expansion feeds: when the primary backbone yields zero validated
candidates, fetch_candidates(extended=True) additionally polls
EXPANSION_SOURCES (mtpro.xyz JSON API) once per run.

Telemetry: every run logs PROXIES_FETCHED_COUNT (raw unique MTProto links
merged from all sources) and PROXIES_VALIDATED_COUNT (after strict filter).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import string
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

# Expansion sources: polled ONLY by the extended search when the primary
# backbone yields zero validated candidates. The mtpro.xyz JSON API is the
# canonical MTProto aggregator (keys: host/port/secret; parse_json_feed
# accepts both "server" and "host"). A dead expansion feed is skipped with
# a log, never crashing the run.
EXPANSION_SOURCES: list[tuple[str, str]] = [
    ("https://mtpro.xyz/api/?type=mtproto", "json"),
]

# ---------------------------------------------------------------------------
# SNI extraction & Iran-DPI fronting-domain gate
# ---------------------------------------------------------------------------

# Fake-TLS secrets carry the TLS server_name they impersonate. That
# fronting domain decides whether Iranian DPI (MCI, Irancell, TCI) waves
# the connection through as ordinary HTTPS or kills it. These curated
# lists drive both the hard gate (require) and the probe order
# (prioritize).
SNI_TIER1_DOMAINS = (  # global CDN / infrastructure - battle-tested camouflage
    "cloudflare.com", "speedtest.net", "ooklaserver.org", "google.com",
    "yahoo.com", "jsdelivr.net", "cloudfront.net", "fastly.net",
    "akamaized.net", "microsoft.com", "bing.com",
)
SNI_TIER2_DOMAINS = (  # popular Iranian services - domestically trusted names
    "digikala.com", "snapp.ir", "snappfood.ir", "varzesh3.com",
    "aparat.com", "telewebion.com", "bale.ai", "shad.ir", "irancell.ir",
    "mci.ir", "divar.ir", "torob.com", "alibaba.ir", "snapptrip.ir",
)
SNI_ALLOWED_DOMAINS = SNI_TIER1_DOMAINS + SNI_TIER2_DOMAINS
SNI_BLOCKED_DOMAINS = (  # instant-discard: self-fronting/placeholder domains
    "telegram.org", "telegram.me", "t.me", "core.telegram.org",
    "example.com", "example.org", "example.net", "test.com", "localhost",
)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_HEX_KEY_LEN = 32      # 16-byte faketls key, hex-encoded (after "ee")
_B64_KEY_LEN = 22      # 16-byte faketls key, unpadded urlsafe-b64

HEX_SET = set(string.hexdigits)
B64URL_SET = set(string.ascii_letters + string.digits + "-_")


def extract_sni_domain(secret: str) -> str | None:
    """Extract the fronting (SNI) domain embedded in a Fake-TLS secret.

    Two wire formats exist in the wild:
      - hex:      ee + 32-hex-char key + hex-encoded ASCII domain
      - base64url: ee + key (20 or 22 chars both occur) + plaintext domain
        appended (the domain chars, e.g. '.', sit outside the b64url
        alphabet, but the key/domain boundary is ambiguous, so the domain
        is resolved as the longest suffix that is a syntactically valid
        domain AND on the curated allow list - exactly the SNI the
        Iran-DPI gate will require anyway)
    Returns None when no domain is embedded (key-only secret) or the
    encoding is invalid. (A b64url key consisting solely of hex digits
    is ambiguous with the hex format; the hex branch wins, matching
    is_valid_faketls_secret's long-standing behavior.)
    """
    s = (secret or "").strip()
    if len(s) < 4 or not s[:2].lower() == "ee":
        return None
    body = s[2:]
    if all(c in HEX_SET for c in s):
        if len(body) <= _HEX_KEY_LEN or (len(body) - _HEX_KEY_LEN) % 2:
            return None
        try:
            domain = bytes.fromhex(body[_HEX_KEY_LEN:]).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return None
        domain = domain.strip().strip(".").lower()
        # Only accept decodings that ARE a syntactically valid domain;
        # garbage decodings (random hex tails) mean there is no SNI.
        if domain and _DOMAIN_RE.match(domain):
            return domain
        return None
    key = body[:_B64_KEY_LEN]
    if len(key) == _B64_KEY_LEN and all(c in B64URL_SET for c in key):
        # Ambiguous key/domain boundary -> longest allow-listed valid
        # domain suffix (first match scanning from the left is longest).
        lower = body.lower()
        for i in range(len(body)):
            cand = lower[i:]
            if "." in cand and _DOMAIN_RE.match(cand) \
                    and _matches_any(cand, SNI_ALLOWED_DOMAINS) \
                    and not _matches_any(cand, SNI_BLOCKED_DOMAINS):
                return cand
        return None  # no recognizable fronting domain embedded
    return None


def effective_sni(server: str, secret: str) -> str | None:
    """SNI a client would actually send: the secret's embedded domain,
    else the server hostname. A bare IP (v4 or v6) yields None - TLS
    forbids IP SNI and IP-fronting is trivially blocked by DPI."""
    embedded = extract_sni_domain(secret)
    if embedded:
        return embedded.lower()
    s = (server or "").strip().strip(".").lower()
    if not s or _IPV4_RE.match(s) or ":" in s:
        return None
    return s


def _normalize_domain(domain: str) -> str:
    d = (domain or "").strip().strip(".").lower()
    if d.startswith("www."):
        d = d[4:]
    return d.split("/")[0]


def _matches_any(domain: str, domains) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in domains)


def sni_is_allowed(domain: str) -> bool:
    """True when `domain` is syntactically valid AND on the curated
    Iran-bypass allow list (subdomains included)."""
    d = _normalize_domain(domain)
    if not d or not _DOMAIN_RE.match(d):
        return False
    if _matches_any(d, SNI_BLOCKED_DOMAINS):
        return False
    return _matches_any(d, SNI_ALLOWED_DOMAINS)


def sni_tier(domain: str) -> int:
    """Rank for probe ordering: 2 = global CDN (best camouflage),
    1 = popular Iranian service, 0 = anything else."""
    d = _normalize_domain(domain)
    if _matches_any(d, SNI_TIER1_DOMAINS):
        return 2
    if _matches_any(d, SNI_TIER2_DOMAINS):
        return 1
    return 0


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
        server = str(entry.get("server") or entry.get("host") or "").strip().strip(".")
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
    """Strict quality filter: Fake-TLS secret + allowed port + SNI gate +
    dedup."""
    from main import (  # lazy: avoids a circular import at load time
        is_allowed_port, is_valid_faketls_secret,
    )
    kept: list[Proxy] = []
    stats = {"bad_secret": 0, "bad_port": 0, "bad_sni": 0, "duplicate": 0}
    seen: set[tuple[str, int, str]] = set()
    for proxy in proxies:
        if not is_valid_faketls_secret(proxy.secret):
            stats["bad_secret"] += 1
            continue
        if not is_allowed_port(proxy.port):
            stats["bad_port"] += 1
            continue
        sni = effective_sni(proxy.server, proxy.secret)
        if not sni or not sni_is_allowed(sni):
            # Unknown/invalid/bare-IP fronting domain: useless against
            # Iranian DPI - discard immediately (never probed, never posted).
            stats["bad_sni"] += 1
            continue
        if proxy.combo in seen:
            stats["duplicate"] += 1
            continue
        seen.add(proxy.combo)
        kept.append(proxy)
    return kept, stats


def fetch_candidates(sources: list[tuple[str, str]] | None = None,
                     timeout: float = FETCH_TIMEOUT,
                     cap: int = MAX_TO_TEST,
                     extended: bool = False) -> list[Proxy]:
    """Full acquisition pipeline; returns validated, deduped candidates.

    extended=True additionally polls EXPANSION_SOURCES (used by the
    caller's extended search when the primary backbone yields nothing).

    Telemetry: logs PROXIES_FETCHED_COUNT (unique MTProto links merged
    across sources, pre-strict-filter) and PROXIES_VALIDATED_COUNT (what
    the prober will actually test), including SNI rejections.
    """
    started = time.monotonic()
    active = list(sources) if sources is not None else list(SOURCES)
    if sources is None and extended:
        active += list(EXPANSION_SOURCES)
    results = fetch_all(active, timeout)

    merged: list[Proxy] = []
    seen_raw: set[tuple[str, int, str]] = set()
    for url, kind in active:
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
    # Iran-DPI prioritization: strongest camouflage (global-CDN fronting
    # domains) is probed first; stable sort keeps feed order within tiers.
    kept.sort(key=lambda p: -sni_tier(effective_sni(p.server, p.secret) or ""))
    logger.info(
        "PROXIES_FETCHED_COUNT: %d | PROXIES_VALIDATED_COUNT: %d "
        "(rejected: %d bad secret, %d bad port, %d bad SNI, %d duplicate) "
        "in %.1f s",
        fetched_count, len(kept), stats["bad_secret"], stats["bad_port"],
        stats["bad_sni"], stats["duplicate"], time.monotonic() - started,
    )
    return kept[:cap]
