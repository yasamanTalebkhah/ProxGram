"""Unit tests for ProxGram's five-proxy batch posting logic.

Run with:  python -m unittest test_main -v
Uses only the standard library (unittest); `requests` and `feedparser`
are stubbed so the tests run without the packages installed.
"""

import os
import re
import sys
import types
import unittest
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

_feedparser = types.ModuleType("feedparser")
_feedparser.parse = lambda *a, **k: (_ for _ in ()).throw(AssertionError(
    "feedparser.parse called outside a test that mocks it"))
sys.modules["feedparser"] = _feedparser

import main  # noqa: E402
import news  # noqa: E402


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
        history = {p.link for p, _ in batch_items[:5]}
        picked = main.pick_batch(batch_items, history)
        self.assertEqual([p.server for p, _ in picked], ["h6.example"])

    def test_excludes_legacy_host_port_history(self):
        batch_items = make_batch(6)
        history = {f"h{i}.example:443" for i in range(1, 6)}
        picked = main.pick_batch(batch_items, history)
        self.assertEqual([p.server for p, _ in picked], ["h6.example"])

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
        self.assertIn("⚡️ <b>پروکسی‌های پرسرعت و پایدار تلگرام</b>", self.msg)
        self.assertIn("برای اتصال روی یکی از گزینه‌های زیر کلیک کنید.", self.msg)
        self.assertIn("در صورت عدم اتصال، دکمه بعدی را تست کنید.", self.msg)
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

    def test_keyboard_has_five_proxy_buttons_plus_channel(self):
        # default tag (@ChannelID) is a username, so the join row is included
        self.assertEqual(len(self.keyboard), 6)
        for i, row in enumerate(self.keyboard[:5], start=1):
            self.assertIn(f"پروکسی {main.fa_num(i)}", row[0]["text"])
            self.assertIn("ms", row[0]["text"])
            self.assertEqual(row[0]["url"], self.proxies[i - 1].link)
        self.assertEqual(self.keyboard[5][0]["text"], "📢 عضویت در کانال")
        self.assertEqual(self.keyboard[5][0]["url"], "https://t.me/ChannelID")
        # each proxy button on its own row
        self.assertTrue(all(len(row) == 1 for row in self.keyboard))

    def test_channel_button_url_has_no_at_sign(self):
        os.environ["TELEGRAM_CHANNEL_TAG"] = "@my_channel"
        import importlib
        importlib.reload(main)
        try:
            rows = main.build_inline_keyboard(self.proxies, self.latencies)
        finally:
            del os.environ["TELEGRAM_CHANNEL_TAG"]
            importlib.reload(main)
        self.assertEqual(rows[-1][0]["text"], "📢 عضویت در کانال")
        self.assertEqual(rows[-1][0]["url"], "https://t.me/my_channel")
        self.assertFalse(rows[-1][0]["url"].endswith("@my_channel"))

    def test_keyboard_has_no_feedback_or_callback(self):
        flat = [btn for row in self.keyboard for btn in row]
        for btn in flat:
            self.assertNotIn("callback_data", btn)
            self.assertNotIn("بازخورد", btn["text"])
            self.assertNotIn("👍", btn["text"])
            self.assertNotIn("👎", btn["text"])
            self.assertTrue(btn["url"].startswith("https://"))

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
        self.assertEqual(len(kb), 6)
        self.assertEqual([r[0]["url"] for r in kb[:5]],
                         [p.link for p in self.proxies])
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
        # fallback keeps the keyboard with all five links, drops HTML entities
        self.assertNotIn("parse_mode", attempts[-1])
        self.assertEqual(len(attempts[-1]["reply_markup"]["inline_keyboard"]), 6)
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
                self.assertEqual(loaded, {p.link for p in batch})
                main.append_history(batch)  # idempotent file append
                self.assertEqual(len(main.load_history()), 5)


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

    def test_news_history_committed_alongside_history(self):
        self.assertIn("news_history.txt", self.text)
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

def _fake_feed_response(text):
    class Resp:
        def raise_for_status(self):
            pass

    resp = Resp()
    resp.text = text
    resp.status_code = 200
    resp.apparent_encoding = "utf-8"
    resp.encoding = "utf-8"
    return resp


def _rss_xml(items):
    """Minimal RSS 2.0 document builder. items: list of (title, link, pubDate, desc)."""
    rows = []
    for title, link, pub, desc in items:
        desc = f"<description><![CDATA[{desc}]]></description>" if desc else ""
        rows.append(
            f"<item><title><![CDATA[{title}]]></title>"
            f"<link>{link}</link>{desc}"
            f"<pubDate>{pub}</pubDate><guid>{link}</guid></item>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<rss version='2.0'><channel>" + "".join(rows) + "</channel></rss>"
    )


def _fake_feedparser_parse(raw):
    """Test double for feedparser.parse: stdlib RSS parsing with dates."""
    import xml.etree.ElementTree as ET
    from email.utils import parsedate_to_datetime

    root = ET.fromstring(raw)
    entries = []
    for item in root.iter("item"):
        def txt(tag, item=item):
            el = item.find(tag)
            return (el.text or "").strip() if el is not None else ""
        entry = {
            "title": txt("title"),
            "link": txt("link"),
            "summary": txt("description"),
            "id": txt("guid"),
        }
        pub = txt("pubDate")
        if pub:
            try:
                entry["published_parsed"] = parsedate_to_datetime(pub).timetuple()
            except (TypeError, ValueError):
                pass
        entries.append(entry)
    return {"entries": entries}


class NewsSanitizeTests(unittest.TestCase):
    def test_strips_tags_urls_and_whitespace(self):
        text = news.sanitize_news_text(
            "  <b>Headline</b> details at https://bbc.in/xyz  ",
            "<p>more\n details\t here</p>",
        )
        self.assertEqual(text, "Headline details at — more details here")
        self.assertNotIn("http", text)
        self.assertNotIn("\n", text)

    def test_entity_disguised_tags_removed(self):
        text = news.sanitize_news_text("Safe &lt;script&gt; alert(1) end", None)
        self.assertNotIn("<", text)
        self.assertNotIn(">", text)
        self.assertNotIn("script", text)

    def test_redundant_summary_dropped(self):
        self.assertEqual(news.sanitize_news_text("Same", "Same"), "Same")

    def test_summary_falls_back_to_title(self):
        self.assertEqual(news.sanitize_news_text("Only title", None), "Only title")
        self.assertIsNone(news.sanitize_news_text(None, None))

    def test_truncation_to_140_chars(self):
        self.assertEqual(news.truncate_news_text("short"), "short")
        long_text = "x" * 150
        out = news.truncate_news_text(long_text)
        self.assertEqual(len(out), 143)  # 140 + "..."
        self.assertTrue(out.endswith("..."))
        self.assertEqual(news.truncate_news_text("y" * 140), "y" * 140)


class NewsHistoryTests(unittest.TestCase):
    def test_append_and_dedup_and_200_cap(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "news_history.txt"
            with mock.patch.object(news, "NEWS_HISTORY_FILE", hist):
                self.assertTrue(news.append_news_history("a"))
                self.assertTrue(news.append_news_history("b"))
                self.assertEqual(news.load_news_history(), {"a", "b"})
                # re-appending moves the ID to the end, no duplicate line
                news.append_news_history("a")
                self.assertEqual(len(news.load_news_history()), 2)
                # cap at 200
                for i in range(250):
                    news.append_news_history(f"id{i}")
                loaded = news.load_news_history()
                self.assertEqual(len(loaded), 200)
                self.assertIn("id249", loaded)
                self.assertNotIn("a", loaded)

    def test_missing_file_returns_empty_set(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(news, "NEWS_HISTORY_FILE", Path(tmp) / "none.txt"):
                self.assertEqual(news.load_news_history(), set())


class NewsSelectionTests(unittest.TestCase):
    def setUp(self):
        # Replace the (deliberately exploding) feedparser stub with the
        # stdlib test double for every selection test.
        patch = mock.patch.object(news.feedparser, "parse", _fake_feedparser_parse)
        patch.start()
        self.addCleanup(patch.stop)

    def test_fresh_item_selected_and_returned(self):
        xml = _rss_xml([
            ("Old news", "https://x.example/1", "Mon, 01 Sep 2025 10:00:00 GMT", "old"),
            ("Fresh news", "https://x.example/2", "Wed, 16 Sep 2026 10:00:00 GMT", "body"),
        ])
        with mock.patch.object(news, "NEWS_FEEDS", [("T", "http://t/feed")]), \
                mock.patch.object(news, "_fetch_feed", return_value=xml):
            text, entry_id = news.get_news(history=set())
        self.assertEqual(text, "Fresh news — body")
        self.assertEqual(entry_id, "https://x.example/2")

    def test_empty_feed_returns_none(self):
        with mock.patch.object(news, "NEWS_FEEDS", [("T", "http://t/feed")]), \
                mock.patch.object(news, "_fetch_feed", return_value=_rss_xml([])):
            self.assertEqual(news.get_news(history=set()), (None, None))

    def test_all_duplicates_returns_none(self):
        xml = _rss_xml([("Dup", "https://x.example/1", "Wed, 16 Sep 2026 10:00:00 GMT", "")])
        with mock.patch.object(news, "NEWS_FEEDS", [("T", "http://t/feed")]), \
                mock.patch.object(news, "_fetch_feed", return_value=xml):
            self.assertEqual(news.get_news(history={"https://x.example/1"}), (None, None))

    def test_duplicate_skipped_fresh_pick(self):
        xml = _rss_xml([
            ("Posted already", "https://x.example/1", "Wed, 16 Sep 2026 10:00:00 GMT", ""),
            ("New headline", "https://x.example/2", "Tue, 15 Sep 2026 09:00:00 GMT", ""),
        ])
        with mock.patch.object(news, "NEWS_FEEDS", [("T", "http://t/feed")]), \
                mock.patch.object(news, "_fetch_feed", return_value=xml):
            text, entry_id = news.get_news(history={"https://x.example/1"})
        self.assertEqual(text, "New headline")
        self.assertEqual(entry_id, "https://x.example/2")

    def test_network_failure_falls_through_to_next_feed(self):
        xml = _rss_xml([("Fallback news", "https://y.example/9", "Wed, 16 Sep 2026 08:00:00 GMT", "")])
        feeds = [("A", "http://a/feed"), ("B", "http://b/feed")]

        def fetch(url):
            if url == "http://a/feed":
                return None  # timeout / network error
            return xml

        with mock.patch.object(news, "NEWS_FEEDS", feeds), \
                mock.patch.object(news, "_fetch_feed", side_effect=fetch):
            text, entry_id = news.get_news(history=set())
        self.assertEqual(text, "Fallback news")
        self.assertEqual(entry_id, "https://y.example/9")

    def test_total_outage_returns_none(self):
        with mock.patch.object(news, "NEWS_FEEDS", [("A", "http://a/feed")]), \
                mock.patch.object(news, "_fetch_feed", return_value=None):
            self.assertEqual(news.get_news(history=set()), (None, None))

    def test_real_feeds_constant(self):
        urls = [u for _n, u in news.NEWS_FEEDS]
        self.assertIn("https://feeds.bbci.co.uk/persian/rss.xml", urls)
        self.assertIn("https://ir.voanews.com/api/z$g-m_eq_m", urls)
        self.assertIn("https://www.iranintl.com/rss/all", urls)
        self.assertEqual(urls[0], "https://feeds.bbci.co.uk/persian/rss.xml")  # priority


class NewsCaptionTests(unittest.TestCase):
    def setUp(self):
        self.proxies = [p for p, _ in make_batch(5)]
        self.latencies = [100.0] * 5

    def test_news_section_prepended_when_present(self):
        msg = main.format_message(self.proxies, self.latencies, "تست خبر")
        self.assertIn("📰 <b>خبر فوری:</b>", msg)
        self.assertIn("تست خبر", msg)
        self.assertIn("⚡️ <b>پروکسی‌های پرسرعت و پایدار تلگرام</b>", msg)
        # order: news first, then proxy block
        self.assertLess(msg.index("خبر فوری"), msg.index("پروکسی‌های پرسرعت"))

    def test_no_news_section_when_absent(self):
        msg = main.format_message(self.proxies, self.latencies, None)
        self.assertNotIn("خبر فوری", msg)
        plain = main.format_message_minimal(self.proxies, self.latencies, None)
        self.assertNotIn("خبر فوری", plain)

    def test_news_text_html_escaped_in_caption(self):
        msg = main.format_message(self.proxies, self.latencies,
                                  "a<b>&amp;c")
        self.assertIn("a&lt;b&gt;&amp;amp;c", msg)
        plain = main.format_message_minimal(self.proxies, self.latencies, "a<b>&amp;c")
        # plaintext mode needs no escaping - raw text renders literally
        self.assertIn("a<b>&amp;c", plain)

    def test_news_survives_formatting_fallback(self):
        calls = []

        class Resp:
            def json(self):
                if "parse_mode" in calls[-1] if calls else {}:
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
                                   news_text="خبر مهم")
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))
        self.assertTrue(ok)
        self.assertEqual(len(calls), 2)  # HTML attempt rejected, plaintext retry
        # plaintext retry still carries the headline
        self.assertIn("خبر فوری", calls[-1]["text"])
        self.assertIn("خبر مهم", calls[-1]["text"])

    def test_post_body_never_contains_proxy_links_even_with_news(self):
        msg = main.format_message(self.proxies, self.latencies, "headline")
        self.assertNotIn("t.me/proxy", msg)


class WorkflowNewsConfigTests(unittest.TestCase):
    def setUp(self):
        self.text = open(".github/workflows/auto_post.yml", encoding="utf-8").read()

    def test_news_history_in_commit_step(self):
        add_idx = self.text.find("git add news_history.txt")
        self.assertGreater(add_idx, 0)
        commit_idx = self.text.index("git commit -m")
        self.assertLess(add_idx, commit_idx)


class EndToEndNewsHistoryTests(unittest.TestCase):
    """The posting flow writes news_history.txt ONLY after a confirmed send."""

    # Well-formed but fake: must satisfy main.validate_credentials.
    TOKEN = "123456789:" + "A" * 34

    def _run_main(self, send_ok, n_proxies=5, history_preload=None):
        import tempfile

        proxies = [
            main.Proxy(f"h{i}.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")
            for i in range(1, n_proxies + 1)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.txt"
            nhist = Path(tmp) / "news_history.txt"
            if history_preload:
                hist.write_text("\n".join(history_preload) + "\n", encoding="utf-8")
            with \
                    mock.patch.object(main, "HISTORY_FILE", hist), \
                    mock.patch.object(news, "NEWS_HISTORY_FILE", nhist), \
                    mock.patch.object(main, "collect_candidates", return_value=proxies), \
                    mock.patch.object(main, "rank_reachable",
                                      return_value=[(p, 100.0) for p in proxies]), \
                    mock.patch.object(main, "send_message", return_value=send_ok) as sm, \
                    mock.patch.object(main.news_module, "get_news",
                                      return_value=("تیتر خبر", "https://n.example/1")), \
                    mock.patch.dict(os.environ, {
                        "TELEGRAM_BOT_TOKEN": self.TOKEN,
                        "TELEGRAM_CHANNEL_ID": "@chan",
                    }):
                code = main.main()
                # read inside the temp context (it vanishes on exit)
                hist_lines = (hist.read_text(encoding="utf-8").splitlines()
                              if hist.exists() else None)
                nhist_lines = (nhist.read_text(encoding="utf-8").split()
                               if nhist.exists() else None)
                send_calls = sm.call_count
        return code, hist_lines, nhist_lines, send_calls

    def test_history_and_news_history_written_on_success(self):
        code, hist_lines, nhist_lines, send_calls = self._run_main(send_ok=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(hist_lines), 5)
        self.assertEqual(send_calls, 1)
        self.assertEqual(nhist_lines, ["https://n.example/1"])

    def test_nothing_written_when_send_fails(self):
        code, hist_lines, nhist_lines, send_calls = self._run_main(send_ok=False)
        self.assertEqual(code, 0)
        # history.txt may exist (created empty by the pre-send touch) but
        # must contain zero links; news_history.txt must not exist at all.
        self.assertEqual(hist_lines, [], "no proxy links after failed send")
        self.assertIsNone(nhist_lines, "no news history after failed send")

    def test_partial_batch_still_posts(self):
        """Fewer than 5 fresh proxies -> publish 1-4 instead of skipping."""
        code, hist_lines, _nh, send_calls = self._run_main(
            send_ok=True, n_proxies=3)
        self.assertEqual(code, 0)
        self.assertEqual(send_calls, 1, "partial batch must still be posted")
        self.assertEqual(len(hist_lines), 3)

    def test_zero_fresh_proxies_skips_posting(self):
        """Everything already in history -> no post, graceful exit."""
        proxies = [
            main.Proxy(f"h{i}.example", 443, "eeNEgYdJvXrFGRMCIMJdCQ")
            for i in range(1, 6)
        ]
        code, hist_lines, _nh, send_calls = self._run_main(
            send_ok=True, history_preload=[p.link for p in proxies])
        self.assertEqual(code, 0)
        self.assertEqual(send_calls, 0, "no post when nothing fresh exists")
        self.assertEqual(hist_lines or [], [p.link for p in proxies],
                         "history unchanged")


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


class TimeoutAndTelemetryConfigTests(unittest.TestCase):
    def test_strict_timeout_constants(self):
        self.assertEqual(main.TELEGRAM_TIMEOUT, 10)
        self.assertEqual(main.HTTP_TIMEOUT, 10)
        self.assertEqual(news.NEWS_TIMEOUT, 4)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
