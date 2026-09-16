"""Unit tests for ProxGram's Fake-TLS MTProto logic.

Run with:  python -m unittest test_main.py -v
Uses only the standard library (unittest); `requests` is stubbed so the
tests run without the package installed.
"""

import os
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


class FakeTLSParsingTests(unittest.TestCase):
    def test_ee_secret_extracted(self):
        proxy = main.parse_mtproto_link(
            "https://t.me/proxy?server=rain.lavazemi2.co.uk&port=2053"
            "&secret=eeNEgYdJvXrFGRMCIMJdCQ"
        )
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy.secret, "eeNEgYdJvXrFGRMCIMJdCQ")
        self.assertEqual(proxy.server, "rain.lavazemi2.co.uk")
        self.assertEqual(proxy.port, 2053)
        self.assertTrue(proxy.secret.lower().startswith("ee"))

    def test_tg_scheme_normalized_to_https_deep_link(self):
        proxy = main.parse_mtproto_link(
            "tg://proxy?server=host.example&port=443&secret=eeABCDEF"
        )
        self.assertIsNotNone(proxy)
        parsed = urlparse(proxy.tg_link)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "t.me")
        self.assertEqual(parsed.path, "/proxy")
        self.assertEqual(proxy.tg_link,
                         "https://t.me/proxy?server=host.example&port=443&secret=eeABCDEF")

    def test_dd_secret_rejected(self):
        self.assertIsNone(main.parse_mtproto_link(
            "https://t.me/proxy?server=khaterate.2nafare.info&port=7799"
            "&secret=dd10400103324995b07c030386e886e7f1"
        ))

    def test_plain_secret_rejected(self):
        self.assertIsNone(main.parse_mtproto_link(
            "https://t.me/proxy?server=x.example&port=443&secret=00112233445566"
        ))

    def test_socks5_and_vless_links_rejected(self):
        self.assertIsNone(main.parse_mtproto_link("socks5://1.2.3.4:1080"))
        self.assertIsNone(main.parse_mtproto_link("1.2.3.4:1080"))
        self.assertIsNone(main.parse_mtproto_link(
            "vless://uuid@host:443?security=tls&type=ws#name"
        ))
        self.assertIsNone(main.parse_mtproto_link("vmess://eyJhZGQiOiJ4In0="))

    def test_malformed_links_rejected(self):
        self.assertIsNone(main.parse_mtproto_link(
            "https://t.me/proxy?server=x.example&port=443"  # no secret
        ))
        self.assertIsNone(main.parse_mtproto_link(
            "https://t.me/proxy?server=x.example&port=99999&secret=eeABCD"  # bad port
        ))
        self.assertIsNone(main.parse_mtproto_link(
            "https://t.me/proxy?server=x.example&port=abc&secret=eeABCD"  # non-numeric
        ))
        self.assertIsNone(main.parse_mtproto_link("not a link at all"))

    def test_uppercase_ee_accepted(self):
        proxy = main.parse_mtproto_link(
            "https://t.me/proxy?server=x.example&port=443&secret=EEabcdef0123"
        )
        self.assertIsNotNone(proxy)

    def test_port443_prioritized(self):
        proxies = [
            main.Proxy("a.example", 8080, "eeAA"),
            main.Proxy("b.example", 443, "eeBB"),
            main.Proxy("c.example", 8443, "eeCC"),
        ]
        ordered = main.prioritize(proxies)
        self.assertEqual(ordered[0].port, 443)
        self.assertEqual([p.server for p in ordered[1:]], ["a.example", "c.example"])


class KeyboardAndMessageTests(unittest.TestCase):
    def setUp(self):
        self.proxy = main.Proxy("s.example", 443, "eeSECRET01")

    def test_keyboard_connect_button(self):
        rows = main.build_inline_keyboard(self.proxy)
        self.assertEqual(rows[0][0]["text"],
                         "⚡️ اتصال مستقیم به پروکسی | Connect")
        self.assertEqual(rows[0][0]["url"], self.proxy.tg_link)

    def test_keyboard_join_button_with_username(self):
        os.environ["TELEGRAM_CHANNEL_TAG"] = "@my_channel"
        import importlib
        importlib.reload(main)
        rows = main.build_inline_keyboard(self.proxy)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][0]["text"], "📢 عضویت در کانال")
        self.assertEqual(rows[1][0]["url"], "https://t.me/my_channel")
        del os.environ["TELEGRAM_CHANNEL_TAG"]
        importlib.reload(main)

    def test_keyboard_join_button_omitted_for_numeric_channel(self):
        os.environ["TELEGRAM_CHANNEL_TAG"] = "-1001234567890"
        import importlib
        importlib.reload(main)
        rows = main.build_inline_keyboard(self.proxy)
        self.assertEqual(len(rows), 1)
        del os.environ["TELEGRAM_CHANNEL_TAG"]
        importlib.reload(main)

    def test_message_contains_required_fields(self):
        msg = main.format_message(self.proxy, 87.6)
        self.assertIn("🚀 <b>پروکسی ضدفیلتر تلگرام (Fake-TLS)</b>", msg)
        self.assertIn("⚡️ <b>پینگ:</b> <code>88 ms</code>", msg)
        self.assertIn("🛡 <b>نوع سکرت:</b> <code>Fake-TLS (EE)</code>", msg)
        self.assertIn("🚪 <b>پورت:</b> <code>443</code>", msg)
        escaped_link = self.proxy.tg_link.replace("&", "&amp;")
        self.assertIn(f"<code>{escaped_link}</code>", msg)

    def test_message_escapes_html(self):
        proxy = main.Proxy("a&b.example", 443, "ee<x>1")
        msg = main.format_message(proxy, 12.3)
        self.assertIn("a%26b.example", msg)   # server percent-encoded in link
        self.assertIn("&amp;", msg)           # link separators HTML-escaped
        self.assertIn("ee%3Cx%3E1", msg)      # secret percent-encoded in link

    def test_send_payload_shape(self):
        captured = {}

        class Resp:
            def json(self):
                return {"ok": True, "result": {"message_id": 7}}

        def fake_post(url, json=None, timeout=None):
            captured["url"], captured["json"] = url, json
            return Resp()

        _requests.post = fake_post
        try:
            ok = main.post_to_telegram("TOK", "@chan", self.proxy, "msg")
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(
                RequestException("offline"))

        self.assertTrue(ok)
        self.assertTrue(captured["url"].endswith("/botTOK/sendMessage"))
        payload = captured["json"]
        self.assertEqual(payload["chat_id"], "@chan")
        self.assertEqual(payload["parse_mode"], "HTML")
        kb = payload["reply_markup"]["inline_keyboard"]
        self.assertEqual(kb[0][0]["text"], main.CONNECT_BUTTON_TEXT)
        self.assertEqual(kb[0][0]["url"], self.proxy.tg_link)

    def test_history_dedup_by_host_port(self):
        reachable = [
            (main.Proxy("one.example", 443, "eeA"), 100.0),
            (main.Proxy("two.example", 443, "eeB"), 150.0),
        ]
        picked = main.pick_best_proxy(reachable, {"one.example:443"})
        self.assertIsNotNone(picked)
        self.assertEqual(picked[0].key, "two.example:443")
        self.assertIsNone(main.pick_best_proxy(reachable,
                                               {"one.example:443", "two.example:443"}))

    def test_rank_reachable_drops_dead_hosts(self):
        ranked = main.rank_reachable([
            main.Proxy("192.0.2.55", 9999, "eeAA"),   # TEST-NET, unreachable
            main.Proxy("1.1.1.1", 443, "eeBB"),        # live
        ])
        self.assertEqual([p.key for p, _ in ranked], ["1.1.1.1:443"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
