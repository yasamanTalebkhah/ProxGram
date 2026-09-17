"""Unit tests for ProxGram's five-proxy batch posting logic.

Run with:  python -m unittest test_main -v
Uses only the standard library (unittest); `requests` is stubbed so the
tests run without the package installed.
"""

import os
import re
import sys
import time
import types
import unittest
from datetime import date, datetime
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

# Stub `requests` and `feedparser` before main/news import them.
_requests = types.ModuleType("requests")


class RequestException(Exception):
    pass


_requests.RequestException = RequestException
_requests.get = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))
_requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))
sys.modules["requests"] = _requests

import main  # noqa: E402
import rates  # noqa: E402
import fetcher  # noqa: E402
import prober  # noqa: E402


def make_proxy(server="s.example", port=443, secret="ee" + "ab" * 8):
    return main.Proxy(server, port, secret)


def make_batch(n=6, prefix="h", secret="ee" + "ab" * 8, base_latency=80.0):
    """n distinct-host proxies with increasing latency."""
    return [
        (make_proxy(f"{prefix}{i}.example", 443, secret), base_latency + i * 10.0)
        for i in range(1, n + 1)
    ]


class SecretValidationTests(unittest.TestCase):
    def test_ee_prefix_required(self):
        self.assertFalse(main.is_valid_faketls_secret("dd10400103324995b07c030386e886e7f1"))
        self.assertFalse(main.is_valid_faketls_secret("00112233445566778899aabbccddeeff"))
        self.assertFalse(main.is_valid_faketls_secret(""))

    def test_hex_secret_needs_domain_beyond_ee_plus_32(self):
        key_only = "ee" + "ab" * 16            # 34 chars: ee + 32 hex, no domain
        with_domain = "ee" + "ab" * 16 + "1a"  # + 1 hex byte of domain
        self.assertFalse(main.is_valid_faketls_secret(key_only))
        self.assertTrue(main.is_valid_faketls_secret(with_domain))

    def test_base64url_faketls_secret_accepted(self):
        # Actual format used by the configured sources (ee + b64url key + domain)
        self.assertTrue(main.is_valid_faketls_secret("eeNEgYdJvXrFGRMCIMJdCQ"))

    def test_regression_fixture_working_proxy(self):
        """User-provided fixture: bale.foltmeingop.co.uk:8880 with the
        base64url Fake-TLS secret must pass the whole filter chain — no
        hex-only assumption may reject it."""
        proxy = main.parse_plaintext_source(
            "https://t.me/proxy?server=bale.foltmeingop.co.uk&port=8880"
            "&secret=eeNEgYdJvXrFGRMCIMJdCQ"
        )[0]
        self.assertEqual(proxy.server, "bale.foltmeingop.co.uk")
        self.assertEqual(proxy.port, 8880)
        kept, _ = main.apply_filters([proxy])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].link,
                         "https://t.me/proxy?server=bale.foltmeingop.co.uk&port=8880"
                         "&secret=eeNEgYdJvXrFGRMCIMJdCQ")

    def test_mangled_duplicate_params_use_last_value(self):
        qs = main.parse_qs_last("server=x.example&port=8880&secret=.co.uk&port=8880&secret=eeAB")
        self.assertEqual(qs["port"], "8880")
        self.assertEqual(qs["secret"], "eeAB")
        self.assertFalse(main.is_valid_faketls_secret("GRMCIMJdCQ"))  # orphan fragment

    def test_invalid_alphabet_rejected(self):
        self.assertFalse(main.is_valid_faketls_secret("ee" + "0" * 15 + "." + "0" * 16))
        self.assertTrue(main.is_valid_faketls_secret("ee" + "g" * 32))  # b64url letters

    def test_b64url_too_short_rejected(self):
        self.assertFalse(main.is_valid_faketls_secret("eeAbC3"))


class PortTests(unittest.TestCase):
    def test_allowed_https_ports(self):
        for port in (443, 8443, 2053, 2083, 8880):
            self.assertTrue(main.is_allowed_port(port))

    def test_other_ports_rejected(self):
        for port in (80, 1080, 7799, 9999, 65535):
            self.assertFalse(main.is_allowed_port(port))


class SourceParsingTests(unittest.TestCase):
    def test_parse_json_source(self):
        raw = """
        [
          {"server": "79.137.196.223", "port": 16443,
           "secret": "ee64cb94437cedd507cf9c4d83fbc229287777772e636c6f7564666c6172652e636f6d",
           "latency_ms": 120, "regions": [], "link": ""},
          {"server": "bad", "port": "NaN", "secret": "eeAA"},
          {"server": "", "port": 443, "secret": "eeAA"},
          {"server": "x.example", "port": 2083, "secret": "eeNEgYdJvXrFGRMCIMJdCQ"}
        ]
        """
        proxies = main.parse_json_source(raw)
        self.assertEqual(len(proxies), 2)
        self.assertEqual(proxies[0].latency_ms, 120)
        self.assertEqual(proxies[1].secret, "eeNEgYdJvXrFGRMCIMJdCQ")

    def test_parse_plaintext_sources(self):
        raw = "\n".join([
            "https://t.me/proxy?server=rain.lavazemi2.co.uk&port=2053&secret=eeNEgYdJvXrFGRMCIMJdCQ",
            "tg://proxy?server=host2.example&port=443&secret=eeAABBCCDDEEFF00112233",
            "1.2.3.4:1080",                        # socks5 - ignored
            "vless://uuid@host:443?type=ws#x",      # vless - ignored
            "vmess://eyJhZGQiOiJ4In0=",             # vmess - ignored
            "https://t.me/proxy?server=x&port=443", # no secret - dropped
        ])
        proxies = main.parse_plaintext_source(raw)
        self.assertEqual(len(proxies), 2)

    def test_filters_reject_non_mtproto_and_bad_secrets(self):
        parsed = [
            main.Proxy("a.example", 2053, "eeNEgYdJvXrFGRMCIMJdCQ"),   # keep
            main.Proxy("b.example", 7799, "eeNEgYdJvXrFGRMCIMJdCQ"),   # bad port
            main.Proxy("c.example", 443, "dd" + "ab" * 16),             # dd secret
            main.Proxy("d.example", 443, "ee" + "ab" * 16),             # key-only hex
            main.Proxy("e.example", 8880, "eeNEgYdJvXrFGRMCIMJdCQ"),   # keep
        ]
        kept, stats = main.apply_filters(parsed)
        self.assertEqual([p.server for p in kept], ["a.example", "e.example"])
        self.assertEqual(stats["bad_secret"], 2)
        self.assertEqual(stats["bad_port"], 1)


class BatchSelectionTests(unittest.TestCase):
    def test_selects_exactly_five(self):
        batch = main.pick_batch(make_batch(8), set())
        self.assertEqual(len(batch), 5)

    def test_sorted_by_latency(self):
        batch = main.pick_batch(make_batch(8, base_latency=50.0), set())
        latencies = [l for _, l in batch]
        self.assertEqual(latencies, sorted(latencies))

    def test_rejects_duplicate_combos(self):
        proxy = make_proxy("dup.example", 443, "eeAABBCCDDEEFF00112233")
        reachable = [(proxy, 100.0), (proxy, 100.0), (proxy, 100.0)]
        batch = main.pick_batch(reachable, set())
        self.assertEqual(len(batch), 1)

    def test_excludes_history_links(self):
        batch_items = make_batch(6)
        history = {p.key for p, _ in batch_items[:5]}
        picked = main.pick_batch(batch_items, history)
        self.assertEqual([p.server for p, _ in picked], ["h6.example"])

    def test_excludes_legacy_host_port_history(self):
        batch_items = make_batch(6)
        history = {f"h{i}.example:443" for i in range(1, 6)}
        picked = main.pick_batch(batch_items, history)
        self.assertEqual([p.server for p, _ in picked], ["h6.example"])

    def test_cooldown_reuse_after_24h(self):
        """A proxy posted > REUSE_COOLDOWN ago becomes eligible again."""
        batch_items = make_batch(6)
        history = {p.key for p, _ in batch_items[:5]}
        stale = time.time() - main.REUSE_COOLDOWN - 60
        last_posted = {p.key: stale for p, _ in batch_items[:5]}
        picked = main.pick_batch(batch_items, history, last_posted=last_posted)
        self.assertEqual([p.server for p, _ in picked[:5]],
                         [p.server for p, _ in batch_items[:5]],
                         "stale entries must be reusable in latency order")

    def test_cooldown_blocks_recent_entries(self):
        batch_items = make_batch(6)
        history = {p.key for p, _ in batch_items[:5]}
        recent = {p.key: time.time() - 60 for p, _ in batch_items[:5]}
        picked = main.pick_batch(batch_items, history, last_posted=recent)
        self.assertEqual([p.server for p, _ in picked], ["h6.example"],
                         "recently-posted proxies must stay excluded")

    def test_prefers_distinct_hostnames(self):
        hostA_fast = (make_proxy("hosta.example", 443, "eeAA" + "bb" * 8), 50.0)
        hostA_slow = (make_proxy("hosta.example", 8443, "eeCC" + "dd" * 8), 60.0)
        others = make_batch(8, prefix="other", base_latency=70.0)
        batch = main.pick_batch([hostA_fast, hostA_slow] + others, set())
        self.assertEqual(len(batch), 5)
        servers = [p.server for p, _ in batch]
        self.assertEqual(servers.count("hosta.example"), 1)

    def test_repeats_server_only_when_distinct_pool_below_five(self):
        hostA1 = (make_proxy("solo.example", 443, "eeAA" + "bb" * 8), 50.0)
        hostA2 = (make_proxy("solo.example", 8443, "eeCC" + "dd" * 8), 60.0)
        others = make_batch(3, prefix="other", base_latency=70.0)
        batch = main.pick_batch([hostA1, hostA2] + others, set())
        self.assertEqual(len(batch), 5)
        servers = [p.server for p, _ in batch]
        self.assertEqual(len(set(servers)), 4)
        self.assertEqual(servers.count("solo.example"), 2)

    def test_short_pool_returns_all_available(self):
        batch = main.pick_batch(make_batch(3), set())
        self.assertEqual(len(batch), 3)  # fewer than 5 -> caller must skip posting

    def test_latency_cap_applied(self):
        items = make_batch(6, base_latency=2400.0)
        items.append((make_proxy("tooslow.example", 443, "eeAA" + "bb" * 8), 2600.0))
        batch = main.pick_batch(items, set())
        self.assertTrue(all(l <= main.MAX_LATENCY_MS for _, l in batch))
        self.assertNotIn("tooslow.example", [p.server for p, _ in batch])


class MessageAndKeyboardTests(unittest.TestCase):
    def setUp(self):
        self.proxies = [p for p, _ in make_batch(5)]
        self.latencies = [100.0, 120.0, 140.0, 160.0, 180.0]
        self.msg = main.format_message(self.proxies, self.latencies)
        self.minimal = main.format_message_minimal(self.proxies, self.latencies)
        self.keyboard = main.build_inline_keyboard(self.proxies, self.latencies)

    def test_body_contains_no_proxy_links(self):
        for text in (self.msg, self.minimal):
            self.assertNotIn("https://t.me/proxy?", text)
            self.assertNotIn("t.me/socks", text)

    def test_body_is_short_with_required_lines(self):
        # exact final-template proxy block: clean headline, no guidance text
        self.assertEqual(self.msg.split("\n\n")[-1],
                         "⚡️ <b>پروکسی‌های فعال و پرسرعت</b>")
        self.assertNotIn("برای اتصال", self.msg)
        self.assertNotIn("دکمهٔ بعدی", self.msg)
        self.assertLess(len(self.msg), main.MAX_MESSAGE_LENGTH)
        self.assertNotIn("<b>", self.minimal)

    def test_body_has_no_protocol_or_cadence_metadata(self):
        for text in (self.msg, self.minimal):
            self.assertNotIn("MTProto", text)
            self.assertNotIn("Fake-TLS", text)
            self.assertNotIn("پروتکل", text)
            self.assertNotIn("به‌روزرسانی", text)
            self.assertNotIn("هر ۵ دقیقه", text)

    def test_five_valid_deep_links(self):
        for proxy in self.proxies:
            parsed = urlparse(proxy.link)
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.netloc, "t.me")
            self.assertEqual(parsed.path, "/proxy")
            self.assertIn("secret=", proxy.link)

    def test_keyboard_two_columns_with_full_width_join(self):
        """5 proxy buttons in a 2-column grid (3 rows) + one full-width
        channel-join row at the very bottom. No help button anywhere."""
        self.assertEqual(len(self.keyboard), 4)
        self.assertEqual(len(self.keyboard[0]), 2)   # proxy 1 | proxy 2
        self.assertEqual(len(self.keyboard[1]), 2)   # proxy 3 | proxy 4
        self.assertEqual(len(self.keyboard[2]), 1)   # proxy 5 alone
        self.assertEqual(len(self.keyboard[3]), 1)   # full-width join row
        flat = [btn for row in self.keyboard[:3] for btn in row]
        self.assertEqual(len(flat), 5)
        for i, btn in enumerate(flat, start=1):
            self.assertIn(f"پروکسی {main.fa_num(i)}", btn["text"])
            self.assertEqual(btn["url"], self.proxies[i - 1].tg_link)
            self.assertTrue(btn["url"].startswith("tg://proxy?"))
        join = self.keyboard[3][0]
        self.assertEqual(join["text"], main.JOIN_BUTTON_TEXT)
        self.assertEqual(join["url"], "https://t.me/ChannelID")
        for row in self.keyboard:
            for btn in row:
                self.assertNotIn("راهنما", btn["text"])
        # per-row emoji variety for visual scanning
        self.assertEqual(flat[0]["text"].startswith("🚀"), True)
        self.assertEqual(flat[1]["text"].startswith("⚡️"), True)

    def test_keyboard_small_batches_stay_two_columns(self):
        """A 2-proxy batch renders one row of 2 + the full-width join row."""
        rows = main.build_inline_keyboard(self.proxies[:2], [100.0, 100.0])
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rows[0]), 2)
        self.assertEqual(len(rows[1]), 1)
        self.assertEqual(rows[1][0]["text"], main.JOIN_BUTTON_TEXT)

    def test_channel_button_url_has_no_at_sign(self):
        os.environ["TELEGRAM_CHANNEL_TAG"] = "@my_channel"
        import importlib
        importlib.reload(main)
        try:
            rows = main.build_inline_keyboard(self.proxies, self.latencies)
        finally:
            del os.environ["TELEGRAM_CHANNEL_TAG"]
            importlib.reload(main)
        join = rows[-1][0]  # full-width row at the very bottom
        self.assertEqual(join["text"], main.JOIN_BUTTON_TEXT)
        self.assertTrue(join["url"].startswith("https://t.me/"))
        self.assertNotIn("@", join["url"])

    def test_keyboard_has_no_feedback_or_callback(self):
        flat = [btn for row in self.keyboard for btn in row]
        for btn in flat:
            self.assertNotIn("callback_data", btn)
            self.assertNotIn("بازخورد", btn["text"])
            self.assertNotIn("👍", btn["text"])
            self.assertNotIn("👎", btn["text"])
            # proxy buttons use the native tg:// scheme; help uses https
            self.assertTrue(btn["url"].startswith(("https://", "tg://")))

    def test_exactly_one_send_message_request(self):
        calls = []

        class Resp:
            def json(self):
                return {"ok": True, "result": {"message_id": 7}}

        def fake_post(url, json=None, timeout=None):
            calls.append(json)
            return Resp()

        _requests.post = fake_post
        try:
            ok = main.send_message("TOK", "@chan", self.msg,
                                   proxies=self.proxies, latencies=self.latencies)
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))

        self.assertTrue(ok)
        self.assertEqual(len(calls), 1, "exactly ONE sendMessage HTTP request")
        payload = calls[0]
        self.assertEqual(payload["chat_id"], "@chan")
        self.assertEqual(payload["parse_mode"], "HTML")
        self.assertNotIn("https://t.me/proxy?", payload["text"])
        kb = payload["reply_markup"]["inline_keyboard"]
        self.assertEqual(len(kb), 4)  # 2-col proxy grid (3 rows) + join row
        self.assertEqual([btn["url"] for btn in kb[0]],
                         [self.proxies[0].tg_link, self.proxies[1].tg_link])
        self.assertEqual(kb[-1][0]["text"], main.JOIN_BUTTON_TEXT)
        self.assertTrue(kb[-1][0]["url"].startswith("https://t.me/"))
        self.assertNotIn("callback_data", payload)
        self.assertNotIn("message_effect_id", payload)

    def test_parse_entity_error_falls_back_gracefully(self):
        attempts = []

        def flaky_post(url, json=None, timeout=None):
            attempts.append(json)

            class Resp:
                def json(self):
                    if "parse_mode" in json:
                        return {"ok": False,
                                "description": "Bad Request: can't parse entities"}
                    return {"ok": True, "result": {"message_id": 9}}

            return Resp()

        _requests.post = flaky_post
        try:
            ok = main.send_message("TOK", "@chan", self.msg,
                                   proxies=self.proxies, latencies=self.latencies)
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))

        self.assertTrue(ok)
        self.assertEqual(len(attempts), 2)
        # fallback keeps the compact keyboard, drops HTML entities
        self.assertNotIn("parse_mode", attempts[-1])
        self.assertEqual(len(attempts[-1]["reply_markup"]["inline_keyboard"]), 4)
        self.assertNotIn("<b>", attempts[-1]["text"])


class HistoryTests(unittest.TestCase):
    def test_append_all_five_only_on_success_path(self):
        import tempfile

        batch = [p for p, _ in make_batch(5)]
        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            with mock.patch.object(main, "HISTORY_FILE", hist):
                self.assertTrue(main.append_history(batch))
                loaded = main.load_history()
                self.assertEqual(loaded, {p.key for p in batch})
                main.append_history(batch)  # idempotent by identity
                self.assertEqual(len(main.load_history()), 5)

    def test_v2_timestamped_format_and_compaction(self):
        import tempfile

        batch = [p for p, _ in make_batch(7)]
        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            with mock.patch.object(main, "HISTORY_FILE", hist):
                main.append_history(batch)
                raw = hist.read_text(encoding="utf-8").splitlines()
                self.assertTrue(all("|" in line for line in raw))
                self.assertEqual(len(raw), 7)
                stamps = main.load_history_timestamps()
                self.assertEqual(len(stamps), 7)
                self.assertTrue(all(s > 0 for s in stamps.values()))

    def test_compaction_keeps_newest_entries(self):
        import tempfile

        old = [f"old{i}.example:443" for i in range(8)]
        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            hist.write_text("\n".join(
                f"2020-01-0{i + 1}T00:00:00|{old[i]}" for i in range(8)
            ) + "\n", encoding="utf-8")
            with mock.patch.object(main, "HISTORY_FILE", hist), \
                    mock.patch.object(main, "MAX_HISTORY_ENTRIES", 5):
                main.append_history([])
                lines = hist.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(lines), 5)
                self.assertNotIn("old0.example:443", main.load_history())
                self.assertIn("old7.example:443", main.load_history())

    def test_legacy_lines_migrate_with_recovery_ts(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            hist.write_text("https://t.me/proxy?server=old.example&port=443"
                            "&secret=eeAABBCCDDEEFF001122\n", encoding="utf-8")
            with mock.patch.object(main, "HISTORY_FILE", hist):
                stamps = main.load_history_timestamps()
                self.assertIn("old.example:443", stamps)
                # legacy entries get the recovery placeholder -> reusable
                self.assertEqual(stamps["old.example:443"],
                                 datetime(2000, 1, 1).timestamp())

    def test_extract_ident_from_deep_link_and_bare(self):
        self.assertEqual(
            main._extract_ident(
                "https://t.me/proxy?server=a.example&port=443&secret=eeXX"),
            "a.example:443")
        self.assertEqual(main._extract_ident("b.example:8443"), "b.example:8443")
        self.assertEqual(main._extract_ident(""), "")


class WorkflowConfigTests(unittest.TestCase):
    """workflow YAML lives on the default branch and is validated as text."""

    @classmethod
    def setUpClass(cls):
        cls.text = open(".github/workflows/auto_post.yml", encoding="utf-8").read()

    def test_cron_is_exactly_every_five_minutes(self):
        self.assertIn("cron: '*/5 * * * *'", self.text)
        self.assertNotIn("'0 * * * *'", self.text)

    def test_workflow_dispatch_enabled(self):
        self.assertIn("workflow_dispatch", self.text)

    def test_concurrency_configured(self):
        self.assertIn("group: proxgram", self.text)
        self.assertIn("cancel-in-progress: true", self.text)

    def test_permissions_contents_write(self):
        self.assertIn("permissions:", self.text)
        self.assertIn("contents: write", self.text)

    def test_checkout_v4_full_depth_and_credentials(self):
        self.assertIn("actions/checkout@v4", self.text)
        self.assertIn("fetch-depth: 0", self.text)
        self.assertIn("persist-credentials: true", self.text)

    def test_git_identity_configured_before_commit(self):
        self.assertIn("github-actions[bot]", self.text)
        self.assertIn("41898282+github-actions[bot]@users.noreply.github.com", self.text)

    def test_tests_run_before_posting(self):
        self.assertLess(self.text.index("Run unit tests"),
                        self.text.index("Run Proxy Publisher"))

    def test_history_committed_before_push(self):
        self.assertIn("history.txt", self.text)
        self.assertLess(self.text.index("git add history.txt"),
                        self.text.index("git diff --staged --quiet"))

    def test_yaml_syntax_valid(self):
        try:
            import yaml  # type: ignore
        except ImportError:
            self.skipTest("PyYAML not installed; structural assertions cover the rest")
        data = yaml.safe_load(self.text)
        self.assertTrue(data["on"]["schedule"])
        self.assertEqual(data["on"]["schedule"][0]["cron"], "*/5 * * * *")
        self.assertIn("workflow_dispatch", data["on"])
        self.assertEqual(data["permissions"], {"contents": "write"})
        self.assertEqual(data["concurrency"]["group"], "proxgram")


# ---------------------------------------------------------------------------
# News integration (news.py + caption wiring)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Jalali date formatting (rates.py)
# ---------------------------------------------------------------------------

class JalaliDateTests(unittest.TestCase):
    def test_known_conversions(self):
        pairs = [
            ((2026, 9, 17), (1405, 6, 26)),
            ((2026, 9, 16), (1405, 6, 25)),      # matches TGJU's own stamps
            ((2026, 3, 21), (1405, 1, 1)),        # Nowruz 1405
            ((2025, 3, 21), (1404, 1, 1)),        # Nowruz 1404
            ((2024, 3, 20), (1403, 1, 1)),        # Nowruz 1403
            ((2025, 12, 21), (1404, 9, 30)),      # end of Azar 1404
            ((2026, 3, 20), (1404, 12, 29)),      # end of Esfand 1404
            ((2028, 3, 20), (1407, 1, 1)),        # Nowruz 1407
        ]
        for g, expected in pairs:
            self.assertEqual(rates.gregorian_to_jalali(date(*g)), expected,
                             f"{g} -> {expected}")

    def test_leap_year_30_esfand(self):
        self.assertEqual(rates.gregorian_to_jalali(date(2028, 3, 20)), (1407, 1, 1))
        self.assertEqual(rates.gregorian_to_jalali(date(2027, 3, 20)), (1405, 12, 29))

    def test_roundtrip(self):
        for g in (date(2026, 9, 17), date(2026, 3, 21), date(2024, 3, 20),
                  date(2025, 12, 21), date(2030, 7, 15)):
            jy, jm, jd = rates.gregorian_to_jalali(g)
            self.assertEqual(rates.jalali_to_gregorian(jy, jm, jd),
                             (g.year, g.month, g.day))

    def test_weekday_names(self):
        self.assertEqual(rates.persian_weekday(datetime(2026, 9, 17)), "پنج‌شنبه")
        self.assertEqual(rates.persian_weekday(datetime(2026, 9, 18)), "جمعه")
        self.assertEqual(rates.persian_weekday(datetime(2026, 9, 19)), "شنبه")
        self.assertEqual(rates.persian_weekday(datetime(2026, 9, 21)), "دوشنبه")

    def test_format_zero_padded(self):
        self.assertEqual(rates.format_jalali_date(datetime(2026, 9, 17)),
                         "26/06/1405")
        self.assertEqual(rates.format_jalali_date(datetime(2026, 3, 21)),
                         "01/01/1405")


# ---------------------------------------------------------------------------
# Market rates parsing (TGJU bulk JSON)
# ---------------------------------------------------------------------------

def _tgju_entry(p, ts="2026-09-16 12:00:00"):
    return {"p": str(p), "h": str(p), "l": str(p), "d": "0", "dp": 0,
            "dt": "", "t": "", "t_en": "", "t-g": "", "ts": ts}


def _tgju_bulk():
    return {"current": {
        "price_dollar_rl": _tgju_entry("2,305,000"),
        "price_eur": _tgju_entry("2,622,900"),
        "price_aed": _tgju_entry("623,550"),
        "crypto-tether-irr": _tgju_entry("2,283,340"),
        "geram18": _tgju_entry("235,013,000"),
        "geram24": _tgju_entry("313,348,000"),
        "sekee": _tgju_entry("2,340,100,000"),
        "sekee_real": _tgju_entry("2,293,633,000"),
        "sekeb": _tgju_entry("2,292,400,000"),
        "sekeb_blubber": _tgju_entry("66,580,000"),
        "nim": _tgju_entry("1,178,000,000"),
        "nim_blubber": _tgju_entry("10,820,000"),
        "rob": _tgju_entry("630,000,000"),
        "rob_blubber": _tgju_entry("40,380,000"),
        "gerami": _tgju_entry("330,000,000"),
        "gerami_blubber": _tgju_entry("39,990,000"),
        "gold_melted_wholesale": _tgju_entry("1,018,530,000"),
        "ons": _tgju_entry("4,306.00"),
        "silver": _tgju_entry("63.81"),
    }}


class RatesParsingTests(unittest.TestCase):
    """TGJU quotes rials; parse_tgju_bulk normalizes every Iranian field to
    toman (÷10). Ounce benchmarks stay in dollars."""

    def test_extracts_all_direct_fields_normalized_to_toman(self):
        data = rates.parse_tgju_bulk(_tgju_bulk())
        self.assertEqual(data["usd"], 230500.0)          # 2,305,000 rial
        self.assertEqual(data["eur"], 262290.0)          # 2,622,900 rial
        self.assertEqual(data["aed"], 62355.0)           # 623,550 rial
        self.assertEqual(data["usdt"], 228334.0)         # 2,283,340 rial
        self.assertEqual(data["gold_18"], 23501300.0)    # 235,013,000 rial
        self.assertEqual(data["gold_24"], 31334800.0)    # 313,348,000 rial
        self.assertEqual(data["emami"], 234010000.0)     # 2,340,100,000 rial
        self.assertEqual(data["bahar"], 229240000.0)
        self.assertEqual(data["nim"], 117800000.0)
        self.assertEqual(data["rob"], 63000000.0)
        self.assertEqual(data["gerami"], 33000000.0)
        self.assertEqual(data["abshodeh"], 101853000.0)  # 1,018,530,000 rial
        self.assertEqual(data["ons_gold"], 4306.0)       # dollars: untouched
        self.assertEqual(data["ons_silver"], 63.81)

    def test_computed_emami_bubble_and_value(self):
        data = rates.parse_tgju_bulk(_tgju_bulk())
        self.assertEqual(data["value_emami"], 229363300.0)   # sekee_real ÷ 10
        self.assertAlmostEqual(data["bubble_emami"],
                               234010000.0 - 229363300.0, delta=0.01)

    def test_computed_abshodeh_value_and_bubble(self):
        data = rates.parse_tgju_bulk(_tgju_bulk())
        expected_value = 31334800.0 * rates.MISQAL_GRAMS * rates.GOLD_17_PURITY
        self.assertAlmostEqual(data["value_abshodeh"], expected_value, delta=0.01)
        self.assertAlmostEqual(data["bubble_abshodeh"],
                               101853000.0 - expected_value, delta=0.01)
        # sanity: value must be in the ~100 million toman range, not per gram
        self.assertGreater(data["value_abshodeh"], 100_000_000)

    def test_span_marked_prices_parsed(self):
        self.assertEqual(rates._to_number(
            '<span class="high" dir="ltr">2422000</span>'), 2422000.0)
        self.assertEqual(rates._to_number("4,306.00"), 4306.0)
        self.assertEqual(rates._to_number(4306), 4306.0)
        self.assertIsNone(rates._to_number("N/A"))
        self.assertIsNone(rates._to_number(None))

    def test_missing_keys_give_none_without_error(self):
        data = rates.parse_tgju_bulk({"current": {}})
        for field in rates.ALL_FIELDS:
            self.assertIsNone(data[field], field)

    def test_all_required_fields_defined(self):
        expected = {
            "usd", "eur", "aed", "usdt",
            "gold_18", "gold_24", "emami", "bahar", "nim", "rob",
            "gerami", "abshodeh", "ons_gold", "ons_silver",
            "bubble_abshodeh", "bubble_emami", "bubble_bahar", "bubble_nim",
            "bubble_rob", "bubble_gerami", "value_abshodeh", "value_emami",
        }
        self.assertEqual(set(rates.ALL_FIELDS), expected)


class RatesCacheTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "last_rates.json"
            with mock.patch.object(rates, "RATES_CACHE_FILE", cache):
                data = rates.parse_tgju_bulk(_tgju_bulk())
                self.assertTrue(rates.save_cached_rates(data))
                loaded = rates.load_cached_rates()
                self.assertIn("fetched_at", loaded)
                self.assertEqual(loaded["rates"]["usd"], 230500.0)

    def test_missing_or_corrupt_cache_returns_none(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(rates, "RATES_CACHE_FILE",
                                   Path(tmp) / "none.json"):
                self.assertIsNone(rates.load_cached_rates())
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            with mock.patch.object(rates, "RATES_CACHE_FILE", bad):
                self.assertIsNone(rates.load_cached_rates())

    def test_get_rates_falls_back_to_cache(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "last_rates.json"
            with mock.patch.object(rates, "RATES_CACHE_FILE", cache), \
                    mock.patch.object(rates, "fetch_tgju_bulk", return_value=None), \
                    mock.patch.object(rates, "fetch_usd_nobitex", return_value=None):
                rates.save_cached_rates(rates.parse_tgju_bulk(_tgju_bulk()))
                merged = rates.get_rates()
        self.assertEqual(merged["usd"], 230500.0)
        self.assertEqual(merged["emami"], 234010000.0)

    def test_get_rates_live_success_refreshes_cache(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "last_rates.json"
            with mock.patch.object(rates, "RATES_CACHE_FILE", cache), \
                    mock.patch.object(rates, "fetch_tgju_bulk",
                                      return_value=_tgju_bulk()):
                merged = rates.get_rates()
                cached = rates.load_cached_rates()
        self.assertEqual(merged["emami"], 234010000.0)
        self.assertEqual(cached["rates"]["emami"], 234010000.0)

    def test_get_rates_merges_cache_into_live_gaps(self):
        import tempfile

        partial = _tgju_bulk()
        del partial["current"]["geram24"]  # live feed missing this one
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "last_rates.json"
            with mock.patch.object(rates, "RATES_CACHE_FILE", cache), \
                    mock.patch.object(rates, "fetch_tgju_bulk",
                                      return_value=partial), \
                    mock.patch.object(rates, "fetch_usd_nobitex",
                                      return_value=None):
                rates.save_cached_rates({"gold_24": 30000000.0})
                merged = rates.get_rates()
        self.assertEqual(merged["gold_24"], 30000000.0)   # from cache
        self.assertEqual(merged["usd"], 230500.0)         # from live

    def test_rial_scale_cache_rejected_wholesale(self):
        """A cache written before toman normalization (or by a mismatched
        source) must be loudly rejected, never served as current rates."""
        import tempfile
        import json as json_mod

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "last_rates.json"
            stale_rial_cache = {
                "fetched_at": "2026-09-16T11:48:24",
                "rates": {
                    "usd": 2305000.0,          # rial-scale, not toman
                    "emami": 2340100000.0,
                    "gold_18": 235013000.0,
                },
            }
            cache.write_text(json_mod.dumps(stale_rial_cache), encoding="utf-8")
            with self.assertLogs("proxgram.rates", level="WARNING") as logs:
                with mock.patch.object(rates, "RATES_CACHE_FILE", cache), \
                        mock.patch.object(rates, "fetch_tgju_bulk",
                                          return_value=None), \
                        mock.patch.object(rates, "fetch_usd_nobitex",
                                          return_value=None):
                    merged = rates.get_rates()
        self.assertIsNone(
            merged,
            "a rial-scale cache with no live data must yield no rates at "
            "all - not silently served stale values",
        )
        self.assertTrue(
            any("plausibility" in line or "unit" in line for line in logs.output),
            f"rejection must be logged loudly, got: {logs.output}",
        )

    def test_get_rates_total_outage_without_cache_returns_none(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(rates, "RATES_CACHE_FILE",
                                   Path(tmp) / "none.json"), \
                    mock.patch.object(rates, "fetch_tgju_bulk", return_value=None), \
                    mock.patch.object(rates, "fetch_usd_nobitex", return_value=None):
                self.assertIsNone(rates.get_rates())


class RatesFetchTests(unittest.TestCase):
    def test_strict_timeout_and_endpoint(self):
        self.assertEqual(rates.RATE_TIMEOUT, 3.0)
        self.assertTrue(rates.TGJU_BULK_URL.startswith("https://call1.tgju.org"))

    def test_fetch_tgju_bulk_none_on_error(self):
        def boom(*a, **k):
            raise RequestException("timed out")

        with mock.patch.object(rates.requests, "get", side_effect=boom):
            self.assertIsNone(rates.fetch_tgju_bulk())

    def test_fetch_usd_nobitex_midpoint(self):
        class Resp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"stats": {"usdt-rls": {
                    "bestSell": "2310000", "bestBuy": "2300000"}}}

        with mock.patch.object(rates.requests, "get", return_value=Resp()):
            # Nobitex quotes rials: (2,310,000 + 2,300,000)/2 = 2,305,000
            # rial midpoint -> 230,500 toman after normalization.
            self.assertAlmostEqual(rates.fetch_usd_nobitex(), 230500.0)

    def test_fetch_usd_nobitex_missing_keys_returns_none(self):
        class Resp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"stats": {}}

        with mock.patch.object(rates.requests, "get", return_value=Resp()):
            self.assertIsNone(rates.fetch_usd_nobitex())


class RatesBoardTests(unittest.TestCase):
    """The full market board: 12 items (currencies, ounce, gold, coins,
    NO bubble/intrinsic), ━━ dividers, units outside <code>, missing
    fields dropped cleanly (no dashes/blank lines)."""

    def setUp(self):
        self.data = rates.parse_tgju_bulk(_tgju_bulk())
        self.now = datetime(2026, 9, 17)  # پنج‌شنبه 26/06/1405

    def test_html_board_matches_template(self):
        html = rates.format_board(self.data, "html", now=self.now)
        self.assertIn("📌 <b>تابلوی کامل طلا، سکه و ارز</b>", html)
        self.assertIn("🗓 <i>پنج‌شنبه 26/06/1405</i>", html)
        self.assertIn("━━━━━━━━━━━━", html)
        self.assertIn("💵 دلار: <code>230,500</code> تومان | 💶 یورو: <code>262,290</code> تومان",
                      html)
        self.assertIn("🇦🇪 درهم: <code>62,355</code> تومان | 🪙 تتر: <code>228,334</code> تومان",
                      html)
        self.assertIn("🌍 انس جهانی: <code>4,306.00</code> $ | "
                      "🟡 طلای ۱۸ عیار: <code>23,501,300</code> تومان", html)
        self.assertIn("🧊 آبشده: <code>101,853,000</code> تومان", html)
        self.assertIn("🪙 سکه امامی: <code>234,010,000</code> تومان | "
                      "🪙 تمام بهار: <code>229,240,000</code> تومان", html)
        self.assertIn("🪙 نیم‌سکه: <code>117,800,000</code> تومان | "
                      "🪙 ربع‌سکه: <code>63,000,000</code> تومان", html)
        self.assertIn("🪙 سکه گرمی: <code>33,000,000</code> تومان", html)

    def test_board_covers_full_market(self):
        """All 12 required items render; bubbles/intrinsic never do."""
        html = rates.format_board(self.data, "html", now=self.now)
        for label in ("دلار", "یورو", "درهم", "تتر", "انس جهانی",
                      "طلای ۱۸ عیار", "آبشده", "سکه امامی", "تمام بهار",
                      "نیم‌سکه", "ربع‌سکه", "سکه گرمی"):
            self.assertIn(label, html, f"missing board item: {label}")

    def test_board_is_compact(self):
        """Title + date + divider + 7 content rows + divider = 11 lines."""
        html = rates.format_board(self.data, "html", now=self.now)
        self.assertEqual(len(html.splitlines()), 11)
        plain = rates.format_board(self.data, "plain", now=self.now)
        self.assertEqual(len(plain.splitlines()), 11)

    def test_no_bubble_or_intrinsic_labels_anywhere(self):
        html = rates.format_board(self.data, "html", now=self.now)
        for banned in ("حباب", "بدون حباب", "ارزش ذاتی"):
            self.assertNotIn(banned, html)
        plain = rates.format_board(self.data, "plain", now=self.now)
        for banned in ("حباب", "ارزش ذاتی"):
            self.assertNotIn(banned, plain)

    def test_plain_twin_has_no_tags(self):
        plain = rates.format_board(self.data, "plain", now=self.now)
        self.assertNotIn("<", plain)
        self.assertNotIn(">", plain)
        self.assertIn("📌 تابلوی کامل طلا، سکه و ارز", plain)
        self.assertIn("💵 دلار: 230,500 تومان", plain)
        self.assertIn("🪙 سکه امامی: 234,010,000 تومان", plain)

    def test_missing_fields_removed_cleanly(self):
        """Absent fields vanish with their row; no dashes, no blanks."""
        empty = {field: None for field in rates.ALL_FIELDS}
        empty["usd"] = 230500.0
        html = rates.format_board(empty, "html", now=self.now)
        self.assertIn("💵 دلار: <code>230,500</code> تومان", html)
        self.assertNotIn("—", html)
        self.assertNotIn("N/A", html)
        self.assertNotIn("null", html)
        # every other row vanished -> title, date, divider, دلار row,
        # divider
        self.assertEqual(len(html.splitlines()), 5)
        self.assertNotIn("  \n", html)
        self.assertNotIn("\n\n", html)
        plain = rates.format_board(empty, "plain", now=self.now)
        self.assertIn("💵 دلار: 230,500 تومان", plain)

    def test_partial_rows_keep_survivors_paired(self):
        """One segment of a pair missing -> the survivor keeps its row;
        both missing -> the row disappears entirely."""
        partial = dict(self.data)
        partial["eur"] = None    # یورو gone -> دلار keeps row 1 alone
        partial["abshodeh"] = None
        html = rates.format_board(partial, "html", now=self.now)
        self.assertIn("💵 دلار: <code>230,500</code> تومان", html)
        self.assertNotIn("یورو", html)
        self.assertNotIn("آبشده", html)
        self.assertNotIn(" | \n", html)
        self.assertNotIn("\n | ", html)

    def test_thousands_separator_formatting(self):
        self.assertEqual(rates._fmt_toman(85400000), "85,400,000")
        self.assertEqual(rates._fmt_toman(1234567), "1,234,567")
        self.assertEqual(rates._fmt_toman(0), "0")  # formatter is honest;
        # the caller drops zero/missing via validate + segment filtering


class RatesValidationTests(unittest.TestCase):
    """Live values must be plausible; violations are reported loudly."""

    def test_valid_rates_pass_without_warnings(self):
        data = rates.parse_tgju_bulk(_tgju_bulk())
        self.assertEqual(rates.validate_rates(data), [])

    def test_implausible_value_flagged_with_field_and_range(self):
        data = rates.parse_tgju_bulk(_tgju_bulk())
        data["usd"] = 0.0  # zeroed feed
        warnings = rates.validate_rates(data)
        self.assertTrue(any("usd" in w and "plausible" in w for w in warnings))

    def test_missing_field_flagged(self):
        data = rates.parse_tgju_bulk({"current": {}})
        warnings = rates.validate_rates(data)
        self.assertTrue(any("usd" in w and "missing" in w for w in warnings))


class RatesCaptionTests(unittest.TestCase):
    def setUp(self):
        self.proxies = [p for p, _ in make_batch(5)]
        self.latencies = [100.0] * 5

    def test_rates_section_prepended_above_proxy_block(self):
        msg = main.format_message(self.proxies, self.latencies, "📊 RATES")
        self.assertIn("📊 RATES", msg)
        self.assertIn("⚡️ <b>پروکسی‌های فعال و پرسرعت</b>", msg)
        self.assertLess(msg.index("📊"), msg.index("پروکسی‌های فعال"))

    def test_no_rates_section_when_absent(self):
        msg = main.format_message(self.proxies, self.latencies, None)
        self.assertNotIn("📊", msg)
        plain = main.format_message_minimal(self.proxies, self.latencies, None)
        self.assertNotIn("📊", plain)

    def test_post_body_never_contains_proxy_links_even_with_rates(self):
        msg = main.format_message(self.proxies, self.latencies, "📊 RATES")
        self.assertNotIn("t.me/proxy", msg)

    def test_rates_survive_formatting_fallback(self):
        calls = []

        class Resp:
            def json(self):
                if "parse_mode" in (calls[-1] if calls else {}):
                    return {"ok": False,
                            "description": "Bad Request: can't parse entities"}
                return {"ok": True, "result": {"message_id": 3}}

        def flaky_post(url, json=None, timeout=None):
            calls.append(json)
            return Resp()

        _requests.post = flaky_post
        try:
            ok = main.send_message("TOK", "@chan", "<b>unused</b>",
                                   proxies=self.proxies, latencies=self.latencies,
                                   rates_section_plain="▫️ دلار آزاد: 230,500 تومان")
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))
        self.assertTrue(ok)
        self.assertEqual(len(calls), 2)  # HTML attempt rejected, plaintext retry
        self.assertIn("230,500 تومان", calls[-1]["text"])


class WorkflowRatesConfigTests(unittest.TestCase):
    def setUp(self):
        self.text = open(".github/workflows/auto_post.yml", encoding="utf-8").read()

    def test_last_rates_committed(self):
        add_idx = self.text.find("git add last_rates.json")
        self.assertGreater(add_idx, 0)
        commit_idx = self.text.index("git commit -m")
        self.assertLess(add_idx, commit_idx)

    def test_news_references_removed(self):
        self.assertNotIn("news_history.txt", self.text)

class EndToEndRatesFlowTests(unittest.TestCase):
    """The posting flow threads rates sections and writes history only on
    confirmed sends; a rates failure never blocks the proxy post."""

    # Well-formed but fake: must satisfy main.validate_credentials.
    TOKEN = "123456789:" + "A" * 34

    def _run_main(self, send_ok, n_proxies=5, history_preload=None,
                  rates_side_effect=None):
        import tempfile

        proxies = [
            main.Proxy(f"h{i}.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")
            for i in range(1, n_proxies + 1)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            if history_preload:
                hist.write_text("\n".join(history_preload) + "\n", encoding="utf-8")
            rates_kwargs = (
                {"side_effect": rates_side_effect}  # exceptions are raised
                if isinstance(rates_side_effect, Exception)
                else {"return_value": rates_side_effect}
            )
            with \
                    mock.patch.object(main, "HISTORY_FILE", hist), \
                    mock.patch.object(main, "collect_candidates", return_value=proxies), \
                    mock.patch.object(main, "rank_reachable",
                                      return_value=[(p, 100.0) for p in proxies]), \
                    mock.patch.object(main, "send_message", return_value=send_ok) as sm, \
                    mock.patch.object(main.rates_module, "get_rates",
                                      **rates_kwargs), \
                    mock.patch.object(main.prober_module, "load_health",
                                      return_value={}), \
                    mock.patch.dict(os.environ, {
                        "TELEGRAM_BOT_TOKEN": self.TOKEN,
                        "TELEGRAM_CHANNEL_ID": "@chan",
                    }):
                code = main.main()
                # read inside the temp context (it vanishes on exit)
                hist_lines = (hist.read_text(encoding="utf-8").splitlines()
                              if hist.exists() else None)
                sent_text = sm.call_args.args[2] if sm.call_args else None
                sent_plain = sm.call_args.kwargs.get("rates_section_plain") \
                    if sm.call_args else None
                send_calls = sm.call_count
        return code, hist_lines, send_calls, sent_text, sent_plain

    def test_success_writes_history_and_sends_rates(self):
        data = {"usd": 230500.0}
        code, hist_lines, send_calls, sent_text, sent_plain = self._run_main(
            send_ok=True, rates_side_effect=data)
        self.assertEqual(code, 0)
        self.assertEqual(len(hist_lines), 5)
        self.assertEqual(send_calls, 1)
        self.assertIn("دلار", sent_text)   # html body carries the rates section
        self.assertIn("دلار", sent_plain)  # plaintext rates section threaded

    def test_nothing_written_when_send_fails(self):
        data = {"usd": 230500.0}
        code, hist_lines, _calls, _text, _plain = self._run_main(
            send_ok=False, rates_side_effect=data)
        self.assertEqual(code, 0)
        self.assertEqual(hist_lines, [], "no proxy links after failed send")

    def test_partial_batch_still_posts(self):
        """Fewer than 5 fresh proxies -> publish 1-4 instead of skipping."""
        code, hist_lines, send_calls, _text, _plain = self._run_main(
            send_ok=True, n_proxies=3, rates_side_effect={"usd": 1.0})
        self.assertEqual(code, 0)
        self.assertEqual(send_calls, 1, "partial batch must still be posted")
        self.assertEqual(len(hist_lines), 3)

    def test_zero_fresh_proxies_reuses_known_good(self):
        """Everything recently posted -> Fallback 1 re-posts known-good
        proxies that re-probed healthy; no maintenance placeholder."""
        proxies = [
            main.Proxy(f"h{i}.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")
            for i in range(1, 6)
        ]
        now_iso = datetime.now().isoformat(timespec="seconds")
        code, hist_lines, send_calls, sent_text, _plain = self._run_main(
            send_ok=True,
            history_preload=[f"{now_iso}|{p.link}" for p in proxies],
            rates_side_effect={"usd": 1.0})
        self.assertEqual(code, 0)
        self.assertEqual(send_calls, 1, "known-good reuse must post a batch")
        self.assertIn("پروکسی‌های فعال", sent_text)
        self.assertNotIn("به‌روزرسانی", sent_text)
        # reuse appended a second entry per proxy (stamps refresh)
        self.assertEqual(len(hist_lines), 10)

    def test_rates_failure_never_blocks_the_post(self):
        # side_effect (not return_value) so the exception is raised
        code, hist_lines, send_calls, _text, sent_plain = self._run_main(
            send_ok=True, rates_side_effect=RuntimeError("rates down"))
        self.assertEqual(code, 0)
        self.assertEqual(send_calls, 1, "proxy post must survive rates failure")
        self.assertEqual(len(hist_lines), 5)
        self.assertIsNone(sent_plain)


class CredentialValidationTests(unittest.TestCase):
    def test_valid_credentials_pass(self):
        self.assertEqual(main.validate_credentials(
            "123456789:" + "A" * 34, "@mychannel"), [])
        self.assertEqual(main.validate_credentials(
            "123456789:" + "A" * 34, "-1001234567890"), [])

    def test_missing_credentials_actionable(self):
        problems = main.validate_credentials(None, None)
        self.assertEqual(len(problems), 2)
        self.assertIn("TELEGRAM_BOT_TOKEN", problems[0])
        self.assertIn("Secrets", problems[0] + problems[1])

    def test_malformed_token_detected(self):
        problems = main.validate_credentials("tok", "@chan")
        self.assertEqual(len(problems), 1)
        self.assertIn("malformed", problems[0])

    def test_bad_channel_id_detected(self):
        problems = main.validate_credentials(
            "123456789:" + "A" * 34, "chan")
        self.assertEqual(len(problems), 1)
        self.assertIn("@", problems[0])
        self.assertIn("-100", problems[0])

    def test_mask_token_never_leaks_secret(self):
        token = "123456789012:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        masked = main.mask_token(token)
        self.assertTrue(masked.startswith("123456789012:"))
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", masked)
        self.assertIn("***", masked)
        self.assertEqual(main.mask_token(None), "<missing>")


class TelegramErrorHandlingTests(unittest.TestCase):
    """4xx API responses surface actionable hints via annotations."""

    def setUp(self):
        self.proxies = [p for p, _ in make_batch(5)]
        self.latencies = [100.0] * 5
        self.msg = main.format_message(self.proxies, self.latencies)

    def _post_returning(self, body):
        class Resp:
            status_code = body.get("error_code", 400)

            def json(self):
                return body

        return lambda url, json=None, timeout=None: Resp()

    def _run_send(self, post_fn):
        captured = []
        with mock.patch.object(main, "gh_annotation",
                               side_effect=lambda lvl, msg: captured.append((lvl, msg))):
            _requests.post = post_fn
            try:
                ok = main.send_message("TOK", "@chan", self.msg,
                                       proxies=self.proxies,
                                       latencies=self.latencies)
            finally:
                _requests.post = lambda *a, **k: (_ for _ in ()).throw(
                    RequestException("offline"))
        return ok, captured

    def test_401_unauthorized_hint(self):
        ok, captured = self._run_send(self._post_returning(
            {"ok": False, "error_code": 401, "description": "Unauthorized"}))
        self.assertFalse(ok)
        level, msg = captured[-1]
        self.assertEqual(level, "error")
        self.assertIn("Unauthorized", msg)
        self.assertIn("@BotFather", msg)

    def test_403_forbidden_admin_hint(self):
        ok, captured = self._run_send(self._post_returning(
            {"ok": False, "error_code": 403,
             "description": "Forbidden: bot is not a member"}))
        self.assertFalse(ok)
        _, msg = captured[-1]
        self.assertIn("ADMIN", msg.upper())

    def test_400_chat_not_found_hint(self):
        ok, captured = self._run_send(self._post_returning(
            {"ok": False, "error_code": 400,
             "description": "Bad Request: chat not found"}))
        self.assertFalse(ok)
        _, msg = captured[-1]
        self.assertIn("chat not found", msg)
        self.assertIn("TELEGRAM_CHANNEL_ID", msg)

    def test_network_timeout_annotated(self):
        def timeout_post(url, json=None, timeout=None):
            raise RequestException("timed out")

        ok, captured = self._run_send(timeout_post)
        self.assertFalse(ok)
        level, msg = captured[-1]
        self.assertEqual(level, "error")
        self.assertIn("timed out", msg)


class ReliabilityHardeningTests(unittest.TestCase):
    """Phase 2/3 hardening: 429 retry, chat verification, POST DECISION."""

    def setUp(self):
        self.proxies = [p for p, _ in make_batch(5)]
        self.latencies = [100.0] * 5
        self.msg = main.format_message(self.proxies, self.latencies)

    def test_429_retries_same_payload_once_then_succeeds(self):
        calls = []

        class Resp:
            def __init__(self, body):
                self.status_code = body.get("error_code", 200)
                self._body = body

            def json(self):
                return self._body

        def rate_limited_then_ok(url, json=None, timeout=None):
            calls.append(json)
            if len(calls) == 1:
                return Resp({"ok": False, "error_code": 429,
                             "description": "Too Many Requests: retry after 3",
                             "parameters": {"retry_after": 3}})
            return Resp({"ok": True, "result": {"message_id": 11}})

        with mock.patch.object(main.time, "sleep") as fake_sleep:
            _requests.post = rate_limited_then_ok
            try:
                ok = main.send_message("TOK", "@chan", self.msg,
                                       proxies=self.proxies,
                                       latencies=self.latencies)
            finally:
                _requests.post = lambda *a, **k: (_ for _ in ()).throw(
                    RequestException("offline"))
        self.assertTrue(ok)
        self.assertEqual(len(calls), 2, "same payload retried after 429")
        self.assertEqual(calls[0], calls[1])
        fake_sleep.assert_called_once()
        self.assertGreaterEqual(fake_sleep.call_args.args[0], 1.0)

    def test_429_retry_cap_at_one(self):
        class Resp:
            status_code = 429

            def json(self):
                return {"ok": False, "error_code": 429,
                        "description": "Too Many Requests"}

        with mock.patch.object(main.time, "sleep"):
            _requests.post = lambda *a, **k: Resp()
            try:
                ok = main.send_message("TOK", "@chan", self.msg,
                                       proxies=self.proxies,
                                       latencies=self.latencies)
            finally:
                _requests.post = lambda *a, **k: (_ for _ in ()).throw(
                    RequestException("offline"))
        self.assertFalse(ok, "second 429 must fail fast (no infinite retry)")

    def test_get_chat_info_logs_destination(self):
        class Resp:
            status_code = 200

            def json(self):
                return {"ok": True, "result": {
                    "id": -1001234567890, "username": "mychannel",
                    "title": "My Channel"}}

        with mock.patch.object(main.requests, "post", return_value=Resp()):
            info = main.get_chat_info("TOK", "@mychannel")
        self.assertEqual(info["username"], "mychannel")

    def test_get_chat_info_failure_is_soft(self):
        def boom(*a, **k):
            raise RequestException("offline")

        with mock.patch.object(main.requests, "post", side_effect=boom):
            self.assertIsNone(main.get_chat_info("TOK", "@chan"))

    def test_post_decision_line_printed(self):
        import io
        import contextlib

        captured = io.StringIO()
        main.setup_logging()
        with contextlib.redirect_stdout(captured):
            main._post_decision(True, "batch dispatched", 12, 5,
                                "@chan", "HTML", 133)
        out = captured.getvalue()
        self.assertIn("POST DECISION", out)
        self.assertIn("will_post=yes", out)
        self.assertIn("selected_count=5", out)
        self.assertIn("chat_id=@chan", out)

    def test_maintenance_posts_removed(self):
        """The maintenance notice path is gone: no placeholder post ever.
        Zero-proxy situations use known-good reuse, then silent skip."""
        self.assertFalse(hasattr(main, "MAINTENANCE_TEXT"))
        self.assertFalse(hasattr(main, "MAINTENANCE_TAG"))
        self.assertFalse(hasattr(main, "_maintenance_fallback"))
        self.assertFalse(hasattr(main, "_low_maintenance"))

    def test_silent_skip_posts_nothing_and_exits_clean(self):
        import io
        import contextlib

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = main._silent_skip(0.0, "no viable proxies this cycle", 3)
        self.assertEqual(code, 0)
        self.assertIn("POST DECISION", captured.getvalue())
        self.assertIn("will_post=no", captured.getvalue())
        self.assertIn("fresh_count=3", captured.getvalue())

    def test_reuse_known_good_prefers_healthy_and_distinct(self):
        """Fallback 1: re-probed healthy proxies with recorded health
        rank first; distinct hostnames are preferred; count is honored."""
        reachable = make_batch(8)  # fresh probes (no health records)
        last_posted = {p.key: time.time() - 60 for p, _ in reachable}
        with mock.patch.object(main.prober_module, "load_health",
                               return_value={}), \
                mock.patch.object(main.prober_module, "HISTORY_JSON_FILE",
                                  Path("nonexistent-history.json")):
            picks = main._reuse_known_good(reachable, last_posted, 5)
        self.assertEqual(len(picks), 5)
        self.assertEqual(len({p.server.lower() for p, _ in picks}), 5)

    def test_reuse_known_good_uses_health_records_for_ranking(self):
        """A proxy with an alive health record and low recorded ping wins."""
        slow = (make_proxy("slow.example", 443, "eeAA" + "bb" * 8), 2000.0)
        fast = (make_proxy("fast.example", 443, "eeCC" + "dd" * 8), 1900.0)
        health = {
            "fast.example:443": {"alive": True, "strikes": 0,
                                 "latency_ms": 90.0, "last_seen": time.time()},
            "slow.example:443": {"alive": False, "strikes": 1,
                                 "last_seen": time.time()},
        }
        with mock.patch.object(main.prober_module, "load_health",
                               return_value=health), \
                mock.patch.object(main.prober_module, "HISTORY_JSON_FILE",
                                  Path("nonexistent-history.json")):
            picks = main._reuse_known_good([slow, fast], {}, 1)
        self.assertEqual([p.server for p, _ in picks], ["fast.example"])


class TimeoutAndTelemetryConfigTests(unittest.TestCase):
    def test_strict_timeout_constants(self):
        self.assertEqual(main.TELEGRAM_TIMEOUT, 10)
        self.assertEqual(main.HTTP_TIMEOUT, 10)
        self.assertEqual(rates.RATE_TIMEOUT, 3.0)
        self.assertEqual(main.PING_TIMEOUT, 2.0)
        self.assertLessEqual(main.MAX_TO_TEST, 90)

    def test_error_hints_cover_common_4xx(self):
        for code in (400, 401, 403, 404, 429):
            self.assertIn(code, main.TG_ERROR_HINTS)


class TcpPingTests(unittest.TestCase):
    def test_live_reachable_host(self):
        latency = main.tcp_ping("1.1.1.1", 443)
        self.assertIsNotNone(latency)
        self.assertGreater(latency, 0)

    def test_dead_host_returns_none(self):
        self.assertIsNone(main.tcp_ping("192.0.2.55", 9999, timeout=1.5))

    def test_invalid_inputs(self):
        self.assertIsNone(main.tcp_ping("", 443))
        self.assertIsNone(main.tcp_ping("x.example", 0))


class MultiSourceFetcherTests(unittest.TestCase):
    """fetcher.py: parallel fetch, normalization, strict MTProto filter."""

    TEXT_FEED = (
        "https://t.me/proxy?server=a.example&port=443"
        "&secret=eeNEgYdJvXrFGRMCIMJdCQ\n"
        "socks5://1.2.3.4:1080\n"
        "vless://uuid@host:443?security=tls\n"
        "tg://proxy?server=b.example&port=8880&secret=eeNEgYdJvXrFGRMCIMJdCQ\n"
        "  https://t.me/proxy?server=c.example&port=2053&secret=eeZZYYXXWWVVUUTTSSRR  \n"
    )

    def test_text_feed_strict_mtproto_filter(self):
        parsed = fetcher.parse_text_feed(self.TEXT_FEED)
        servers = {p.server for p in parsed}
        self.assertEqual(servers, {"a.example", "b.example", "c.example"})
        self.assertTrue(all(p.protocol == "MTProto" for p in parsed))

    def test_parallel_fetch_skips_failed_sources(self):
        sources = [
            ("https://ok.example/feed.txt", "text"),
            ("https://bad.example/feed.txt", "text"),
        ]
        with mock.patch.object(
            fetcher, "fetch_url",
            side_effect=lambda url, timeout=None: (
                self.TEXT_FEED if "ok" in url else None
            ),
        ):
            results = fetcher.fetch_all(sources)
        self.assertIsNotNone(results["https://ok.example/feed.txt"])
        self.assertIsNone(results["https://bad.example/feed.txt"])

    def test_fetch_pipeline_telemetry_and_dedup(self):
        sources = [("https://x.example/a.txt", "text")]
        with mock.patch.object(
            fetcher, "fetch_url", return_value=self.TEXT_FEED,
        ), mock.patch.object(fetcher, "MAX_PER_SOURCE", 60):
            candidates = fetcher.fetch_candidates(sources=sources, cap=90)
        # one entry lacks a Fake-TLS secret -> c.example dropped by validate
        keys = {p.key for p in candidates}
        self.assertIn("a.example:443", keys)
        self.assertIn("b.example:8880", keys)
        self.assertNotIn("c.example:2053", keys)

    def test_sources_backbone_configured(self):
        urls = [url for url, _ in fetcher.SOURCES]
        self.assertIn("https://raw.githubusercontent.com/hookzof/socks5_list/"
                      "master/proxy.txt", urls)
        self.assertIn("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/"
                      "master/mtproto.txt", urls)
        self.assertIn("https://raw.githubusercontent.com/jetkai/proxy-list/"
                      "main/online-proxies/proto.txt", urls)
        self.assertIn("https://raw.githubusercontent.com/roosterkid/"
                      "openproxylist/main/MTPROTO_RAW.txt", urls)
        self.assertLessEqual(fetcher.FETCH_TIMEOUT, 5.0)

    def test_main_collect_candidates_delegates(self):
        with mock.patch.object(
            fetcher, "fetch_candidates", return_value=[],
        ) as fc:
            main.collect_candidates(extra=30)
            fc.assert_called_once_with(cap=main.MAX_TO_TEST + 30)


class StrictProberTests(unittest.TestCase):
    """prober.py: latency cap, two-strike TTL purge, history.json."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        health_file = Path(self._tmp.name) / "history.json"
        self._patches = [
            mock.patch.object(prober, "HISTORY_JSON_FILE", health_file),
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_two_strikes_purge_from_active_list(self):
        results = {"h1.example:443": None, "h2.example:443": 100.0}
        purged = prober.update_health(results)
        self.assertEqual(purged, [])
        self.assertEqual(prober.banned_keys(), set())
        purged = prober.update_health({"h1.example:443": None})
        self.assertEqual(purged, ["h1.example:443"])
        self.assertIn("h1.example:443", prober.banned_keys())
        # ban persists in history.json (purged flag), never resurrected
        entry = prober.load_health()["h1.example:443"]
        self.assertTrue(entry["purged"])
        self.assertEqual(
            prober.load_health()["h2.example:443"]["latency_ms"], 100.0)

    def test_success_resets_strikes(self):
        prober.update_health({"h3.example:443": None})
        prober.update_health({"h3.example:443": 150.0})
        self.assertEqual(prober.load_health()["h3.example:443"]["strikes"], 0)
        self.assertTrue(prober.load_health()["h3.example:443"]["alive"])

    def test_probe_skips_banned_proxies(self):
        health = prober.load_health()
        health["banned.example:443"] = {
            "alive": False, "strikes": 2, "purged": True,
            "last_seen": time.time(),
        }
        prober.save_health(health)
        candidates = [main.Proxy("banned.example", 443, "eeAABBCCDDEEFF001122")]
        with mock.patch.object(prober, "tcp_ping") as ping:
            valid = prober.probe(candidates, enough=1)
        ping.assert_not_called()
        self.assertEqual(valid, [])

    def test_probe_enforces_latency_cap_and_records_health(self):
        candidates = [
            main.Proxy("fast.example", 443, "eeAABBCCDDEEFF001122"),
            main.Proxy("slow.example", 443, "eeAABBCCDDEEFF001122"),
        ]
        latencies = {"fast.example": 120.0, "slow.example": 3000.0}
        with mock.patch.object(
            prober, "tcp_ping",
            side_effect=lambda host, port, timeout=None:
                latencies[host],
        ):
            valid = prober.probe(candidates, enough=5)
        self.assertEqual([p.key for p, _ in valid], ["fast.example:443"])
        self.assertEqual(
            prober.load_health()["slow.example:443"]["strikes"], 1)

    def test_health_json_compaction_cap(self):
        health = {
            f"h{i}.example:443": {
                "alive": True, "strikes": 0,
                "latency_ms": 100.0, "last_seen": float(i),
            }
            for i in range(prober.MAX_HEALTH_ENTRIES + 50)
        }
        self.assertTrue(prober.save_health(health))
        self.assertLessEqual(len(prober.load_health()),
                             prober.MAX_HEALTH_ENTRIES)
        # newest (highest last_seen) retained, oldest dropped
        self.assertIn("h1049.example:443", prober.load_health())
        self.assertNotIn("h0.example:443", prober.load_health())

    def test_main_rank_reachable_delegates(self):
        proxies = [main.Proxy("x.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")]
        with mock.patch.object(
            prober, "probe", return_value=[],
        ) as probe_mock:
            main.rank_reachable(proxies, enough=7)
            probe_mock.assert_called_once()


class ResiliencePipelineTests(unittest.TestCase):
    """Refresh cycle + low-maintenance mode + runtime telemetry."""

    TOKEN = "123456789:" + "A" * 34

    def _run_main(self, collect_results, rank_results, send_ok=True):
        import tempfile
        self._send_count = 0

        def _send(*args, **kwargs):
            self._send_count += 1
            return send_ok

        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            with \
                    mock.patch.object(main, "HISTORY_FILE", hist), \
                    mock.patch.object(main, "collect_candidates",
                                      side_effect=collect_results), \
                    mock.patch.object(main, "rank_reachable",
                                      side_effect=rank_results), \
                    mock.patch.object(main, "send_message", side_effect=_send), \
                    mock.patch.dict(os.environ, {
                        "TELEGRAM_BOT_TOKEN": self.TOKEN,
                        "TELEGRAM_CHANNEL_ID": "@chan",
                    }):
                code = main.main()
        return code

    def test_refresh_cycle_retries_when_pool_empty(self):
        proxies = [main.Proxy(f"h{i}.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")
                   for i in range(1, 6)]
        code = self._run_main(
            collect_results=[[], proxies],          # 1st empty, refresh works
            rank_results=[[(p, 100.0) for p in proxies]],
        )
        self.assertEqual(code, 0)  # recovered via the refresh cycle

    def test_low_pool_falls_back_to_reuse_then_skips_silently(self):
        """Below the hard floor the run no longer posts a notice: with a
        healthy re-probed pool it still selects (reuse fills the batch),
        and with nothing viable it silently skips - no send at all."""
        proxies = [main.Proxy("h1.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")]
        code = self._run_main(
            collect_results=[proxies],
            rank_results=[[]],                       # nothing survives probing
        )
        self.assertEqual(code, 0)  # silent skip exits cleanly, no dispatch

    def test_no_dead_proxies_ever_posted(self):
        proxies = [main.Proxy("h1.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")]
        code = self._run_main(
            collect_results=[proxies],
            rank_results=[[]],                       # nothing survives probing
        )
        self.assertEqual(code, 0)
        self.assertEqual(self._send_count, 0,
                         "no dispatch may happen without validated proxies")

    def test_telemetry_constants(self):
        self.assertEqual(fetcher.FETCH_TIMEOUT, 5.0)
        self.assertEqual(prober.STRIKE_LIMIT, 2)
        self.assertLessEqual(fetcher.FETCH_TIMEOUT, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
