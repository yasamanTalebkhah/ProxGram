#!/usr/bin/env python3
"""prober.py — strict quality enforcement for ProxGram candidates.

Quality rules enforced here:

  - Real connection check: non-blocking TCP connect (the MTProto handshake
    itself needs the protocol stack; the connect+latency probe is the
    practical availability signal, and source-level handshake verification
    from the JSON feed stays the protocol-level guarantee).
  - Latency threshold: only proxies answering within MAX_LATENCY_MS (2500ms)
    are returned as valid.
  - TTL / two-strike rule: every probe outcome is recorded in history.json.
    A proxy that fails 2 consecutive checks is purged from the active list
    immediately and is never probed or posted again.
  - Protocol filter: only MTProto candidates handed over by the fetcher are
    accepted; socks5/http entries can never reach this module.

Telemetry: logs PROXIES_VALIDATED_COUNT (post-probe valid pool) against the
number probed, plus purged-proxy details.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import select
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # main imports this module; never import main at load time
    from main import MAX_LATENCY_MS, MAX_WORKERS, PING_TIMEOUT, Proxy

logger = logging.getLogger("proxgram.prober")

STRIKE_LIMIT = 2        # consecutive failures before a proxy is purged
HISTORY_JSON_FILE = Path(__file__).resolve().parent / "history.json"
MAX_HEALTH_ENTRIES = 1000  # compaction cap (newest by last_seen)

# Runtime constants mirrored from main (read lazily so no import cycle).
def _const(name: str, default):
    import main
    return getattr(main, name, default)


PING_TIMEOUT = _const("PING_TIMEOUT", 2.0)
MAX_LATENCY_MS = _const("MAX_LATENCY_MS", 2500)
MAX_WORKERS = _const("MAX_WORKERS", 60)


# ---------------------------------------------------------------------------
# Connection / latency check
# ---------------------------------------------------------------------------

def tcp_ping(host: str, port: int, timeout: float | None = None) -> float | None:
    """Non-blocking TCP connect test. Returns latency in ms, or None.

    The socket is set non-blocking so a dead host burns exactly `timeout`
    seconds, never more, and a shared per-attempt deadline covers DNS
    resolution plus all resolved addresses.
    """
    timeout = PING_TIMEOUT if timeout is None else timeout
    host = str(host).strip().strip(".")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not host or not (0 < port < 65536):
        return None

    started = time.monotonic()
    deadline = started + timeout
    try:
        infos = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
    except OSError:
        return None

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

    for family, _type, _proto, _canonname, sa in infos[:2]:  # v4 then v6
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)  # non-blocking: connect wins/loses fast
        try:
            err = sock.connect_ex(sa)
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
            try:
                sock.close()
            except OSError:
                pass
    return None


# ---------------------------------------------------------------------------
# history.json — TTL health tracking (two-strike purge)
# ---------------------------------------------------------------------------

def load_health() -> dict[str, dict]:
    """Load {key: {alive, strikes, latency_ms, last_seen}} from history.json."""
    if not HISTORY_JSON_FILE.exists():
        return {}
    try:
        payload = json.loads(HISTORY_JSON_FILE.read_text(encoding="utf-8"))
        health = payload.get("health") if isinstance(payload, dict) else None
        return health if isinstance(health, dict) else {}
    except (OSError, ValueError) as exc:
        logger.warning("Could not read %s: %s", HISTORY_JSON_FILE, exc)
        return {}


def save_health(health: dict[str, dict]) -> bool:
    """Persist health map, compacted to the newest MAX_HEALTH_ENTRIES."""
    try:
        entries = sorted(
            health.items(),
            key=lambda kv: kv[1].get("last_seen", 0.0),
            reverse=True,
        )[:MAX_HEALTH_ENTRIES]
        payload = {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "health": dict(entries),
        }
        HISTORY_JSON_FILE.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8",
        )
        return True
    except OSError as exc:
        logger.error("Could not update %s: %s", HISTORY_JSON_FILE, exc)
        return False


def banned_keys(health: dict[str, dict] | None = None) -> set[str]:
    """Keys currently banned from the active list (2+ consecutive fails).

    Purged entries stay in history.json flagged `purged: true` so the ban
    persists across runs (deleting them would reset their strike counter
    and let dead proxies back into rotation).
    """
    health = load_health() if health is None else health
    return {
        key for key, entry in health.items()
        if entry.get("purged")
        or int(entry.get("strikes", 0)) >= STRIKE_LIMIT
    }


def is_banned(key: str) -> bool:
    """Convenience single-key check (loads history.json)."""
    return key in banned_keys()


def update_health(results: dict[str, float | None],
                  latency_cap: float = MAX_LATENCY_MS) -> list[str]:
    """Record probe outcomes; return the keys purged by the two-strike rule.

    A successful connect resets strikes and stores latency_ms; a failure
    (or a connect slower than `latency_cap`) counts as a failed check and
    increments strikes. Reaching STRIKE_LIMIT flags the entry `purged` -
    the proxy leaves the active list immediately and stays banned (the
    flag persists in history.json so the ban survives across runs).
    """
    health = load_health()
    now = time.time()
    purged: list[str] = []
    for key, latency in results.items():
        entry = dict(health.get(key) or {})
        failed = latency is None or latency > latency_cap
        if failed:
            entry["strikes"] = int(entry.get("strikes", 0)) + 1
            entry["alive"] = False
            entry["last_seen"] = now
            entry.pop("latency_ms", None)
            if entry["strikes"] >= STRIKE_LIMIT:
                purged.append(key)
                entry["purged"] = True  # persistent ban marker
        else:
            entry["strikes"] = 0
            entry["alive"] = True
            entry["latency_ms"] = round(float(latency), 1)
            entry["last_seen"] = now
        health[key] = entry
    save_health(health)
    if purged:
        logger.info(
            "Purged %d proxies after %d consecutive failed checks: %s",
            len(purged), STRIKE_LIMIT, ", ".join(sorted(purged)[:8]),
        )
    return purged


# ---------------------------------------------------------------------------
# Parallel probe with early stop
# ---------------------------------------------------------------------------

def probe(candidates: list[Proxy],
          enough: int = 8,
          timeout: float | None = None,
          max_latency: float = MAX_LATENCY_MS,
          update_health_file: bool = True) -> list[tuple[Proxy, float]]:
    """TCP-test candidates concurrently; return reachable ones under
    `max_latency`, sorted by latency ascending.

    Early stop: once `enough` valid results exist, remaining probes are
    cancelled. Banned (two-strike) proxies are skipped without probing.
    Outcomes update history.json unless update_health_file=False.
    """
    timeout = PING_TIMEOUT if timeout is None else timeout
    if not candidates:
        return []
    health = load_health()
    banned = banned_keys(health)
    to_test = [p for p in candidates if p.key not in banned]
    if len(to_test) < len(candidates):
        logger.info(
            "Skipped %d banned proxies (2+ consecutive failures)",
            len(candidates) - len(to_test),
        )
    if not to_test:
        return []

    started = time.monotonic()
    results: dict[str, float | None] = {}
    key_to_proxy: dict[str, Proxy] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(tcp_ping, p.server, p.port, timeout): p for p in to_test
        }
        pending = set(futures)
        while pending:
            done, pending = concurrent.futures.wait(
                pending, timeout=0.1,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                proxy = futures[future]
                try:
                    latency = future.result()
                except Exception as exc:  # defensive: worker must not kill run
                    logger.debug("Probe crashed for %s: %s", proxy.server, exc)
                    latency = None
                results[proxy.key] = latency
                key_to_proxy[proxy.key] = proxy
            valid_now = sum(
                1 for v in results.values()
                if v is not None and v <= max_latency
            )
            if enough and valid_now >= enough:
                for future in pending:
                    future.cancel()
                break

    tested = {key: v for key, v in results.items()}
    if update_health_file and tested:
        update_health(tested, latency_cap=max_latency)

    valid = [
        (key_to_proxy[key], latency)
        for key, latency in tested.items()
        if latency is not None and latency <= max_latency
    ]
    valid.sort(key=lambda item: item[1])
    logger.info(
        "PROBES: tested %d (%d banned skipped) -> PROXIES_VALIDATED_COUNT: %d "
        "within %.0f ms cap in %.1f s",
        len(tested), len(candidates) - len(to_test), len(valid), max_latency,
        time.monotonic() - started,
    )
    return valid
