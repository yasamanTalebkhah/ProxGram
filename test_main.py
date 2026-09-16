"""Unit tests for ProxGram's five-proxy batch posting logic.

Run with:  python -m unittest test_main -v
Uses only the standard library (unittest); `requests` is stubbed so the
tests run without the package installed.
"""

import os
import re
import sys
import types
import unittest
from urllib.parse import urlparse

# Stub `requests` before main imports it.
_requests = types.ModuleType("requests")


class RequestException(Exception):
    pass


_requests.RequestException = RequestException
_requests.get = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))
_requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))
sys.modules["requests"] = _requests

import main  # noqa: E402


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

    def test_regression_fixture_mangled_link(self):
        """User-provided fixture: a mangled double-paste of a working proxy.

        bale.foltmeingop.co.uk:8880 with secret eeNEgYdJvXrFGRMCIMJdCQ is the
        known-good proxy; the fixture link pasted its query twice. The parser
        must tolerate duplicated params (last value wins) and the validator
        must keep accepting the b64url secret (no hex-only assumption).
        """
        mangled = ("https://t.me/proxy?server=bale.foltmeingop.co.uk"
                   "&port=8880&secret=.co.uk&port=8880&secret=GRMCIMJdCQ")
        parsed = urlparse(mangled)
        qs = main.parse_qs_last(parsed.query)
        self.assertEqual(qs.get("port"), "8880")
        self.assertEqual(qs.get("secret"), "GRMCIMJdCQ")  # last value wins
        # The orphan fragment alone is NOT a valid secret (no ee prefix)
        self.assertFalse(main.is_valid_faketls_secret("GRMCIMJdCQ"))
        # The real secret from the source feed remains valid (b64url, no hex assumption)
        self.assertTrue(main.is_valid_faketls_secret("eeNEgYdJvXrFGRMCIMJdCQ"))
        # Full working proxy passes the whole filter chain
        proxy = main.Proxy("bale.foltmeingop.co.uk", 8880, "eeNEgYdJvXrFGRMCIMJdCQ")
        kept, _ = main.apply_filters([proxy])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].link,
                         "https://t.me/proxy?server=bale.foltmeingop.co.uk&port=8880"
                         "&secret=eeNEgYdJvXrFGRMCIMJdCQ")

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
        # Same server+port+secret repeated: only one may ever be picked.
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
        # 1 fast proxy on hostA plus 8 slower proxies on 8 other hosts:
        # a second hostA entry must lose to slower distinct hosts.
        hostA_fast = (make_proxy("hosta.example", 443, "eeAA" + "bb" * 8), 50.0)
        hostA_slow = (make_proxy("hosta.example", 8443, "eeCC" + "dd" * 8), 60.0)
        others = make_batch(8, prefix="other", base_latency=70.0)
        batch = main.pick_batch([hostA_fast, hostA_slow] + others, set())
        servers = [p.server for p, _ in batch]
        self.assertEqual(len(batch), 5)
        self.assertEqual(servers.count("hosta.example"), 1)  # one per host preferred

    def test_repeats_server_only_when_distinct_pool_below_five(self):
        """4 distinct servers exist -> batch still reaches 5 by allowing one
        extra proxy from an already-picked server (spec's 'unless' clause)."""
        hostA1 = (make_proxy("solo.example", 443, "eeAA" + "bb" * 8), 50.0)
        hostA2 = (make_proxy("solo.example", 8443, "eeCC" + "dd" * 8), 60.0)
        others = make_batch(3, prefix="other", base_latency=70.0)
        batch = main.pick_batch([hostA1, hostA2] + others, set())
        self.assertEqual(len(batch), 5)
        servers = [p.server for p, _ in batch]
        self.assertEqual(len(set(servers)), 4)  # solo.example appears twice
        self.assertEqual(servers.count("solo.example"), 2)

    def test_short_pool_returns_all_available(self):
        batch = main.pick_batch(make_batch(3), set())
        self.assertEqual(len(batch), 3)  # fewer than 5 available -> no padding

    def test_latency_cap_applied(self):
        items = make_batch(6, base_latency=2400.0)  # all above 2500ms? no: 2400..2450
        items.append((make_proxy("tooslow.example", 443, "eeAA" + "bb" * 8), 2600.0))
        batch = main.pick_batch(items, set())
        self.assertTrue(all(l <= main.MAX_LATENCY_MS for _, l in batch))
        self.assertNotIn("tooslow.example", [p.server for p, _ in batch])


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.proxies = [p for p, _ in make_batch(5)]
        self.latencies = [100.0, 120.0, 140.0, 160.0, 180.0]

    def test_five_valid_deep_links(self):
        for proxy in self.proxies:
            parsed = urlparse(proxy.link)
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.netloc, "t.me")
            self.assertEqual(parsed.path, "/proxy")
            self.assertIn("secret=", proxy.link)

    def test_keyboard_five_buttons_plus_join(self):
        os.environ["TELEGRAM_CHANNEL_TAG"] = "@my_channel"
        import importlib
        importlib.reload(main)
        try:
            rows = main.build_inline_keyboard(self.proxies, self.latencies)
        finally:
            del os.environ["TELEGRAM_CHANNEL_TAG"]
            importlib.reload(main)
        self.assertEqual(len(rows), 6)
        for i, row in enumerate(rows[:5], start=1):
            self.assertIn(f"پروکسی {main.fa_num(i)}", row[0]["text"])
            self.assertIn("ms", row[0]["text"])
            self.assertEqual(row[0]["url"], self.proxies[i - 1].link)
        self.assertEqual(rows[5][0]["text"], "📢 عضویت در کانال")
        self.assertEqual(rows[5][0]["url"], "https://t.me/my_channel")  # no extra @

    def test_message_contains_all_five_proxies(self):
        msg = main.format_message(self.proxies, self.latencies)
        self.assertIn("🚀 <b>پنج پروکسی فعال تلگرام</b>", msg)
        for i, (proxy, latency) in enumerate(zip(self.proxies, self.latencies), 1):
            self.assertIn(f"<b>پروکسی {main.fa_num(i)}</b>", msg)
            self.assertIn(proxy.server, msg)
            self.assertIn(f"<code>{proxy.port}</code>", msg)
            self.assertIn(f"{max(1, round(latency))} ms", msg)
            self.assertIn(proxy.link.replace("&", "&amp;"), msg)
        self.assertIn("MTProto Fake-TLS", msg)
        self.assertLess(len(msg), main.MAX_MESSAGE_LENGTH)

    def test_minimal_fallback_keeps_all_five_links(self):
        msg = main.format_message_minimal(self.proxies, self.latencies)
        for proxy in self.proxies:
            self.assertIn(proxy.link, msg)
        self.assertNotIn("<b>", msg)

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
            ok = main.send_message("TOK", "@chan",
                                   main.format_message(self.proxies, self.latencies),
                                   proxies=self.proxies, latencies=self.latencies)
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))

        self.assertTrue(ok)
        self.assertEqual(len(calls), 1, "exactly ONE sendMessage request")
        kb = calls[0]["reply_markup"]["inline_keyboard"]
        self.assertEqual(len(kb), 6)

    def test_parse_entity_error_falls_back_in_one_flow(self):
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
            ok = main.send_message("TOK", "@chan",
                                   main.format_message(self.proxies, self.latencies),
                                   proxies=self.proxies, latencies=self.latencies)
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))

        self.assertTrue(ok)
        self.assertEqual(len(attempts), 3)
        self.assertNotIn("<code>", attempts[-1]["text"])  # final: plaintext w/ links


class HistoryTests(unittest.TestCase):
    def test_append_all_five_only_on_success_path(self):
        import tempfile
        from unittest import mock

        batch = [p for p, _ in make_batch(5)]
        with tempfile.TemporaryDirectory() as tmp:
            hist = os.path.join(tmp, "history.txt")
            with mock.patch.object(main, "HISTORY_FILE", __import__("pathlib").Path(hist)):
                self.assertTrue(main.append_history(batch))
                loaded = main.load_history()
                self.assertEqual(len(loaded), 5)
                self.assertEqual(loaded, {p.link for p in batch})
                # duplicate append would not add new lines
                main.append_history(batch)
                self.assertEqual(len(main.load_history()), 5)


class WorkflowConfigTests(unittest.TestCase):
    def test_five_minute_cron_expression(self):
        text = open(".github/workflows/auto_post.yml", encoding="utf-8").read()
        self.assertRegex(text, r"cron:\s*'\*/5 \* \* \* \*'")
        self.assertIn("workflow_dispatch", text)
        self.assertIn("cancel-in-progress: true", text)

    def test_workflow_runs_tests_before_posting(self):
        text = open(".github/workflows/auto_post.yml", encoding="utf-8").read()
        test_pos = text.index("Run unit tests")
        post_pos = text.index("Run ProxGram poster")
        self.assertLess(test_pos, post_pos)


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
