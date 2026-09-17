#!/usr/bin/env python3
"""rates.py — real-time Iranian gold & currency market rates for ProxGram.

Primary source: TGJU bulk market JSON (call1.tgju.org/ajax.json) — one HTTP
request covering currencies, coins, gold, melted gold, and global ounce
benchmarks. Secondary reference: Nobitex USDT-RLS midpoint as a USD
fallback when TGJU is unreachable.

Resilience contract: a strict 3-second timeout per request; if live
fetching fails entirely, the last successful rates are served from
`last_rates.json` so the Telegram post is never delayed. When some fields
are missing live, they are filled from the cache; fields missing everywhere
are dropped from the board cleanly (never dashes, zeros or placeholders).
Only when nothing at all is available does `get_rates()` return None and
the caller posts without the rates section.

Units: all Iranian instruments are normalized to TOMAN at parse time
(TGJU quotes rials; divided by 10 here); global ounce benchmarks
(انس طلا) stay in US dollars. Bubble/intrinsic fields are still computed
and cached for downstream tooling, but the posted board NEVER renders
bubble or intrinsic-value metrics. Live values must pass plausibility
checks (PLAUSIBLE_RANGES); any violation is logged as a loud warning
naming the endpoint and offending field — cache fill is reported
per-field, never silently injected.
"""

import html
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path

import requests

logger = logging.getLogger("proxgram.rates")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RATE_TIMEOUT = 3.0          # seconds - hard timeout for every market request
RATES_STAGE_BUDGET = 3.0    # seconds - total budget for the whole rates stage
TGJU_BULK_URL = "https://call1.tgju.org/ajax.json"
NOBITEX_USD_URL = "https://api.nobitex.ir/market/stats?srcCurrency=usdt&dstCurrency=rls"
RATE_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

MISQAL_GRAMS = 4.6083       # one misqal = 4.6083 g
GOLD_17_PURITY = 17.0 / 24.0  # آبشده is 17-alloy melted gold (per misqal)

RATES_CACHE_FILE = Path(__file__).resolve().parent / "last_rates.json"

# Internal field -> TGJU bulk keys, first present wins.
FIELD_KEYS = {
    "usd": ["price_dollar_rl", "price_dollar_dt"],
    "eur": ["price_eur"],
    "aed": ["price_aed"],
    "usdt": ["crypto-tether-irr"],
    "gold_18": ["geram18", "tgju_gold_irg18"],
    "gold_24": ["geram24"],
    "emami": ["sekee", "retail_sekee"],
    "bahar": ["sekeb", "retail_sekeb"],
    "nim": ["nim", "retail_nim"],
    "rob": ["rob", "retail_rob"],
    "gerami": ["gerami", "retail_gerami"],
    "abshodeh": ["gold_melted_wholesale", "gold_melted_transfer"],
    "ons_gold": ["ons"],
    "ons_silver": ["silver"],
    "bubble_bahar": ["sekeb_blubber"],
    "bubble_nim": ["nim_blubber"],
    "bubble_rob": ["rob_blubber"],
    "bubble_gerami": ["gerami_blubber"],
}
COMPUTED_FIELDS = ("bubble_emami", "value_emami", "bubble_abshodeh", "value_abshodeh")
ALL_FIELDS = list(FIELD_KEYS) + list(COMPUTED_FIELDS)
USD_FIELDS = {"ons_gold", "ons_silver"}  # quoted in US dollars, not rial

_NUMBER_RE = re.compile(r"[^0-9.\-]")

# ---------------------------------------------------------------------------
# Persian (Jalali) calendar — pure python port of the jalaali algorithm
# ---------------------------------------------------------------------------

_JALALI_BREAKS = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210,
                  1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178]

# Persian weekday names, Monday (datetime.weekday() == 0) first.
JALALI_WEEKDAYS = ["دوشنبه", "سه‌شنبه", "چهارشنبه", "پنج‌شنبه",
                   "جمعه", "شنبه", "یکشنبه"]


def _div(a: float, b: float) -> int:
    """Integer division truncating toward zero (matches jalaali-js `div`)."""
    return int(a / b)


def _jal_cal(jy: int) -> tuple[int, int, int]:
    """(leap, gregorian_year, march_day) for a Jalali year."""
    bl = len(_JALALI_BREAKS)
    gy = jy + 621
    leap_j = -14
    jp = _JALALI_BREAKS[0]
    jump = 0
    for i in range(1, bl):
        jm = _JALALI_BREAKS[i]
        jump = jm - jp
        if jy < jm:
            break
        leap_j += _div(jump, 33) * 8 + _div(jump % 33, 4)
        jp = jm
    n = jy - jp
    leap_j += _div(n, 33) * 8 + _div((n % 33) + 3, 4)
    if (jump % 33) == 4 and jump - n == 4:
        leap_j += 1
    leap_g = _div(gy, 4) - _div((_div(gy, 100) + 1) * 3, 4) - 150
    march = 20 + leap_j - leap_g
    if jump - n < 6:
        n = n - jump + _div(jump + 4, 33) * 33
    leap = ((n + 1) % 33 - 1) % 4
    if leap == -1:
        leap = 4
    return leap, gy, march


def _g2d(gy: int, gm: int, gd: int) -> int:
    """Gregorian date -> Julian day number."""
    d = _div((gy + _div(gm - 8, 6) + 100100) * 1461, 4) \
        + _div(153 * ((gm + 9) % 12) + 2, 5) + gd - 34840408
    d = d - _div(_div(gy + 100100 + _div(gm - 8, 6), 100) * 3, 4) + 752
    return d


def _d2g(jdn: int) -> tuple[int, int, int]:
    """Julian day number -> Gregorian (y, m, d)."""
    j = 4 * jdn + 139361631
    j += _div(_div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908
    i = _div(j % 1461, 4) * 5 + 308
    gd = _div(i % 153, 5) + 1
    gm = (_div(i, 153) % 12) + 1
    gy = _div(j, 1461) - 100100 + _div(8 - gm, 6)
    return gy, gm, gd


def _d2j(jdn: int, gy: int) -> tuple[int, int, int]:
    """Julian day number -> Jalali (y, m, d)."""
    jy = gy - 621
    leap, _g_year, march = _jal_cal(jy)
    jdn1f = _g2d(gy, 3, march)
    k = jdn - jdn1f
    if k >= 0:
        if k <= 185:
            return jy, 1 + _div(k, 31), (k % 31) + 1
        k -= 186
    else:
        jy -= 1
        k += 179
        if leap == 1:
            k += 1
    return jy, 7 + _div(k, 30), (k % 30) + 1


def _j2d(jy: int, jm: int, jd: int) -> int:
    """Jalali date -> Julian day number."""
    _leap, gy, march = _jal_cal(jy)
    return _g2d(gy, 3, march) + (jm - 1) * 31 - _div(jm, 7) * (jm - 7) + jd - 1


def gregorian_to_jalali(dt: datetime) -> tuple[int, int, int]:
    """Convert a gregorian datetime to (jalali_year, month, day)."""
    jdn = _g2d(dt.year, dt.month, dt.day)
    return _d2j(jdn, dt.year)


def jalali_to_gregorian(jy: int, jm: int, jd: int) -> tuple[int, int, int]:
    """Convert (jalali_year, month, day) to a gregorian (y, m, d) date."""
    return _d2g(_j2d(jy, jm, jd))


def format_jalali_date(dt: datetime) -> str:
    """Zero-padded Jalali date, e.g. 2026-09-17 -> '26/06/1405'."""
    jy, jm, jd = gregorian_to_jalali(dt)
    return f"{jd:02d}/{jm:02d}/{jy}"


def persian_weekday(dt: datetime) -> str:
    """Persian weekday name for a gregorian datetime."""
    return JALALI_WEEKDAYS[dt.weekday()]


# ---------------------------------------------------------------------------
# Parsing / formatting
# ---------------------------------------------------------------------------

def _to_number(raw) -> float | None:
    """'2,340,100,000' / '<span ...>2422000</span>' / 4306 -> float."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    text = _NUMBER_RE.sub("", str(raw))
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _fmt_toman(value: float | None) -> str:
    """Toman amounts with thousands separators (e.g. 85,400,000)."""
    if value is None:
        return "—"
    return f"{int(round(value)):,}"


def _fmt_usd(value: float | None) -> str:
    """Dollar benchmarks with 2 decimals; None -> em dash."""
    if value is None:
        return "—"
    return f"{value:,.2f}"


def parse_tgju_bulk(payload: dict) -> dict[str, float | None]:
    """Extract every required field from the TGJU bulk JSON.

    TGJU quotes Iranian instruments in RIALS; every rial field is
    normalized to TOMAN (divided by 10) here so the whole pipeline
    (bubbles, cache, display) speaks one unit. USD ounce benchmarks are
    left untouched.

    Computed fields (all in toman after normalization):
      - value_emami    = sekee_real / 10 (TGJU's intrinsic coin value)
      - bubble_emami   = emami - value_emami
      - value_abshodeh = geram24 * MISQAL_GRAMS * GOLD_17_PURITY (per misqal)
      - bubble_abshodeh = abshodeh - value_abshodeh
    Missing inputs yield None for the dependent fields, never exceptions.
    """
    current = payload.get("current") or {}
    data: dict[str, float | None] = {}

    def rial_to_toman(raw) -> float | None:
        value = _to_number(raw)
        return value / 10.0 if value is not None else None

    for field, keys in FIELD_KEYS.items():
        value = None
        for key in keys:
            entry = current.get(key)
            if isinstance(entry, dict) and entry.get("p") is not None:
                value = _to_number(entry.get("p"))
                if value is not None:
                    # Global ounce benchmarks are USD: no rial->toman divide.
                    if field not in USD_FIELDS:
                        value /= 10.0
                    break
        data[field] = value

    emami = data.get("emami")
    emami_real = rial_to_toman((current.get("sekee_real") or {}).get("p"))
    data["value_emami"] = emami_real
    data["bubble_emami"] = (emami - emami_real) if (emami is not None and emami_real is not None) else None

    gold_24 = data.get("gold_24")
    abshodeh = data.get("abshodeh")
    value_abshodeh = (gold_24 * MISQAL_GRAMS * GOLD_17_PURITY) if gold_24 is not None else None
    data["value_abshodeh"] = value_abshodeh
    data["bubble_abshodeh"] = (abshodeh - value_abshodeh) if (abshodeh is not None and value_abshodeh is not None) else None

    return data


# Plausibility windows (in toman; USD fields in dollars) that live values
# must fall inside to be trusted. Catches zeroed/stale/mislabeled feeds.
PLAUSIBLE_RANGES: dict[str, tuple[float, float]] = {
    "usd": (50_000, 2_000_000),
    "eur": (50_000, 2_000_000),
    "aed": (5_000, 600_000),
    "usdt": (5_000, 2_000_000),
    "gold_18": (1_000_000, 100_000_000),
    "gold_24": (1_000_000, 150_000_000),
    "abshodeh": (5_000_000, 500_000_000),
    "emami": (10_000_000, 1_000_000_000),
    "ons_gold": (500.0, 10_000.0),
    "ons_silver": (1.0, 500.0),
}


def _plausible(field: str, value: float) -> bool:
    """True when `value` falls inside the field's plausibility window."""
    window = PLAUSIBLE_RANGES.get(field)
    return True if window is None else window[0] <= value <= window[1]

# Last error detail from each endpoint, surfaced in warnings so nothing
# fails silently.
_last_tgju_error: str | None = None


def validate_rates(data: dict[str, float | None]) -> list[str]:
    """Human-readable warnings for implausible live values (or empty)."""
    warnings: list[str] = []
    for field, (low, high) in PLAUSIBLE_RANGES.items():
        value = data.get(field)
        if value is None:
            warnings.append(
                f"field '{field}' missing from live endpoint response"
            )
        elif not (low <= value <= high):
            warnings.append(
                f"field '{field}'={value} outside plausible range "
                f"[{low}, {high}] - source response may be stale or mislabeled"
            )
    return warnings


def format_rates(data: dict[str, float | None]) -> dict[str, str]:
    """Numbers -> display strings (toman with separators; USD 2 decimals)."""
    out: dict[str, str] = {}
    for field in ALL_FIELDS:
        value = data.get(field)
        if value is None:
            out[field] = "—"
        elif field in USD_FIELDS:
            out[field] = _fmt_usd(value)
        else:
            out[field] = _fmt_toman(value)
    return out


# ---------------------------------------------------------------------------
# Fetching + caching
# ---------------------------------------------------------------------------

def fetch_tgju_bulk() -> dict | None:
    """Download the TGJU bulk JSON (3s timeout); None on any failure."""
    global _last_tgju_error
    started = time.monotonic()
    try:
        resp = requests.get(
            TGJU_BULK_URL,
            timeout=RATE_TIMEOUT,
            headers={"User-Agent": RATE_USER_AGENT},
        )
        elapsed = (time.monotonic() - started) * 1000.0
        resp.raise_for_status()
        payload = resp.json()
        # Structural validation: an unexpected/empty body must not be
        # mistaken for "live data is empty" (which would silently inject
        # stale cache values as if they were current).
        current = payload.get("current") if isinstance(payload, dict) else None
        if not isinstance(current, dict) or not current:
            _last_tgju_error = (
                f"unexpected payload structure from {TGJU_BULK_URL}: "
                "missing or empty 'current' object"
            )
            logger.warning("TGJU bulk feed unusable: %s", _last_tgju_error)
            return None
        _last_tgju_error = None
        logger.info(
            "TGJU bulk feed: HTTP %s, %d bytes in %.0f ms",
            getattr(resp, "status_code", "?"), len(resp.content or b""), elapsed,
        )
        return payload
    except (requests.RequestException, OSError, ValueError) as exc:
        _last_tgju_error = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "TGJU bulk feed failed after %.0f ms: %s",
            (time.monotonic() - started) * 1000.0, _last_tgju_error,
        )
        return None


def fetch_usd_nobitex(timeout: float | None = None) -> float | None:
    """Secondary USD reference: Nobitex USDT-RLS midpoint (3s timeout)."""
    started = time.monotonic()
    try:
        resp = requests.get(
            NOBITEX_USD_URL,
            timeout=timeout or RATE_TIMEOUT,
            headers={"User-Agent": RATE_USER_AGENT},
        )
        resp.raise_for_status()
        stats = (resp.json().get("stats") or {})
        pair = stats.get("usdt-rls") or {}
        best_sell = _to_number(pair.get("bestSell"))
        best_buy = _to_number(pair.get("bestBuy"))
        if best_sell is not None and best_buy is not None:
            midpoint_toman = (best_sell + best_buy) / 2.0 / 10.0
            logger.info(
                "Nobitex USDT-RLS midpoint %.0f toman (%.0f ms)",
                midpoint_toman, (time.monotonic() - started) * 1000.0,
            )
            return midpoint_toman
        logger.warning("Nobitex response missing usdt-rls bestSell/bestBuy keys")
    except (requests.RequestException, OSError, ValueError) as exc:
        logger.warning(
            "Nobitex USD fallback failed after %.0f ms: %s: %s",
            (time.monotonic() - started) * 1000.0, type(exc).__name__, exc,
        )
    return None


def load_cached_rates() -> dict | None:
    """Load last_rates.json ({'fetched_at', 'rates'}) or None."""
    if not RATES_CACHE_FILE.exists():
        return None
    try:
        payload = json.loads(RATES_CACHE_FILE.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("rates"), dict):
            logger.warning("last_rates.json has unexpected structure; ignoring")
            return None
        return payload
    except (OSError, ValueError) as exc:
        logger.warning("Could not read %s: %s", RATES_CACHE_FILE, exc)
        return None


def save_cached_rates(data: dict[str, float | None]) -> bool:
    """Persist successfully fetched rates to last_rates.json."""
    try:
        payload = {
            "fetched_at": datetime.now().isoformat(timespec="seconds"),
            "rates": {k: v for k, v in data.items() if v is not None},
        }
        RATES_CACHE_FILE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return True
    except OSError as exc:
        logger.error("Could not update %s: %s", RATES_CACHE_FILE, exc)
        return False


def get_rates() -> dict[str, float | None] | None:
    """Live rates merged with cache; None only when nothing is available.

    Order: TGJU bulk (live) -> cache fill for missing fields -> Nobitex
    USD fallback if the dollar is still missing. On live success the cache
    is refreshed so future failures fall back to fresh data.
    """
    stage_started = time.monotonic()
    cached_payload = load_cached_rates() or {}
    cached = cached_payload.get("rates") or {}

    # Whole-cache unit fingerprint: the cached dollar must be plausible in
    # toman. A rial-scale cache (written before normalization, or by a
    # mismatched source) is rejected wholesale and loudly, never served.
    cached_usd = _to_number(cached.get("usd"))
    if cached_usd is not None and not _plausible("usd", cached_usd):
        logger.warning(
            "Rates validation: last_rates.json (fetched_at=%s) fails unit "
            "plausibility (usd=%s toman expected; got rial-scale or corrupt "
            "value) - ignoring the ENTIRE cache as stale/mismatched data",
            cached_payload.get("fetched_at"), cached_usd,
        )
        cached = {}
    data: dict[str, float | None] = {}

    payload = fetch_tgju_bulk()
    if payload is not None:
        try:
            data = parse_tgju_bulk(payload)
        except Exception:
            logger.exception("Failed to parse TGJU bulk payload")
            data = {}
        if data:
            save_cached_rates(data)
    else:
        detail = _last_tgju_error or "no response"
        logger.warning(
            "TGJU bulk unavailable (%s at %s); falling back to last_rates.json",
            detail, TGJU_BULK_URL,
        )

    merged: dict[str, float | None] = {}
    live_count = 0
    for field in ALL_FIELDS:
        value = data.get(field)
        if value is not None:
            live_count += 1
        else:
            value = _to_number(cached.get(field))
            if value is not None:
                if _plausible(field, value):
                    logger.info(
                        "field '%s' missing live; served from last_rates.json "
                        "cache (fetched_at=%s)",
                        field, cached_payload.get("fetched_at"),
                    )
                else:
                    logger.warning(
                        "Rates validation: cached field '%s'=%s outside "
                        "plausible range %s - rejected (stale or mismatched "
                        "unit), field renders as dash",
                        field, value, PLAUSIBLE_RANGES.get(field),
                    )
                    value = None
        merged[field] = value

    if merged.get("usd") is None:
        remaining = RATES_STAGE_BUDGET - (time.monotonic() - stage_started)
        if remaining >= 0.5:
            usd = fetch_usd_nobitex(timeout=min(RATE_TIMEOUT, remaining))
            if usd is not None:
                merged["usd"] = usd
                save_cached_rates(merged)
            else:
                logger.warning(
                    "USD unavailable from both %s and %s; field omitted",
                    TGJU_BULK_URL, NOBITEX_USD_URL,
                )
        else:
            logger.warning(
                "Rates stage budget (%.1fs) exhausted; skipping Nobitex "
                "fallback - post continues without USD",
                RATES_STAGE_BUDGET,
            )

    # Loud validation: implausible live values are logged with the exact
    # offending field; nothing is silently swapped for dummy data.
    for warning in validate_rates(merged):
        logger.warning("Rates validation: %s", warning)

    available = sum(1 for v in merged.values() if v is not None)
    source = "TGJU bulk + cache" if data else "cache only"
    logger.info(
        "Rates stage done in %.2fs: source=%s, rial->toman /10 applied to "
        "Iranian fields, %d/%d fields available (%d live, %d from cache)",
        time.monotonic() - stage_started, source,
        available, len(ALL_FIELDS), live_count, available - live_count,
    )
    return merged if available > 0 else None


# ---------------------------------------------------------------------------
# Full market board (ONE ITEM PER LINE, units OUTSIDE <code>, missing
# fields dropped cleanly - NO bubble or intrinsic-value items ever)
# ---------------------------------------------------------------------------

RATES_TITLE_HTML = "📌 <b>تابلوی کامل طلا، سکه و ارز</b>"
RATES_TITLE_PLAIN = "📌 تابلوی کامل طلا، سکه و ارز"

_DIVIDER = "━━━━━━━━━━━━"

# Board segments: (label, field, unit). Only the numeric portion is
# wrapped in <code>; the unit stays outside so RTL/LTR runs never mix
# inside a single markup token. A segment whose value is missing/unreliable
# is removed entirely - never "0", "N/A", "null" or a dash placeholder.
# Deliberately absent: every bubble (حباب) and intrinsic-value (ارزش ذاتی)
# metric - those are never shown on the board.
_SEGMENTS = (
    ("💵 دلار", "usd", "تومان"),
    ("💶 یورو", "eur", "تومان"),
    ("🇦🇪 درهم", "aed", "تومان"),
    ("🪙 تتر", "usdt", "تومان"),
    ("🌍 انس جهانی", "ons_gold", "$"),
    ("🟡 طلای ۱۸ عیار", "gold_18", "تومان"),
    ("🧊 آبشده", "abshodeh", "تومان"),
    ("🪙 سکه امامی", "emami", "تومان"),
    ("🪙 تمام بهار", "bahar", "تومان"),
    ("🪙 نیم‌سکه", "nim", "تومان"),
    ("🪙 ربع‌سکه", "rob", "تومان"),
    ("🪙 سکه گرمی", "gerami", "تومان"),
)

# Layout sections: each section is a tuple of segment indexes rendered
# one item per line, with a divider between sections. A field whose value
# is missing drops only its own line; a fully-missing section drops its
# divider too (never a blank or double-divider line).
_BOARD_SECTIONS = (
    (0, 1, 2, 3),    # دلار، یورو، درهم، تتر
    (4, 5, 6),       # انس جهانی، طلای ۱۸، آبشده
    (7, 8, 9, 10, 11),  # امامی، بهار، نیم، ربع، گرمی
)


def _html_escape(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _segment_html(label: str, field: str, value: float | None,
                  unit: str) -> str | None:
    """One 'label: <code>number</code> unit' segment, or None if missing."""
    if value is None:
        return None
    number = _fmt_usd(value) if field in USD_FIELDS else _fmt_toman(value)
    return f"{label}: <code>{_html_escape(number)}</code> {unit}"


def _segment_plain(label: str, field: str, value: float | None,
                   unit: str) -> str | None:
    """Tag-free twin of _segment_html."""
    if value is None:
        return None
    number = _fmt_usd(value) if field in USD_FIELDS else _fmt_toman(value)
    return f"{label}: {number} {unit}"


def format_board(data: dict[str, float | None], mode: str = "html",
                 now: datetime | None = None) -> str:
    """Render the full market board (currencies, ounce, gold, coins).

    mode="html" produces the <code>/<b> version for parse_mode=HTML;
    mode="plain" the tag-free twin. Every market item sits on its own
    line; missing fields are dropped cleanly (only that line vanishes,
    never a blank line, dash, or placeholder), and no bubble/intrinsic
    metric is ever rendered.
    """
    now = now or datetime.now()
    if mode == "html":
        title = RATES_TITLE_HTML
        date_line = f"🗓 <i>{persian_weekday(now)} {format_jalali_date(now)}</i>"
        render = _segment_html
    else:
        title = RATES_TITLE_PLAIN
        date_line = f"🗓 {persian_weekday(now)} {format_jalali_date(now)}"
        render = _segment_plain

    segments = [render(label, field, data.get(field), unit)
                for label, field, unit in _SEGMENTS]

    # One item per line, grouped into sections separated by dividers.
    blocks: list[list[str]] = []
    for section in _BOARD_SECTIONS:
        cells = [segments[i] for i in section if segments[i] is not None]
        if cells:
            blocks.append(cells)

    if not blocks:
        return f"{title}\n{date_line}"  # nothing available: no dangling divider

    lines: list[str] = [title, date_line]
    for cells in blocks:
        lines.append(_DIVIDER)
        lines.extend(cells)
    lines.append(_DIVIDER)

    return "\n".join(lines)
