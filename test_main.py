"""Unit tests for ProxGram's verified Fake-TLS MTProto logic.

Run with:  python -m unittest test_main -v
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


def make_proxy(server="s.example", port=443, secret="ee" + "ab" * 8):
    return main.Proxy(server, port, secret)


class SecretValidationTests(unittest.TestCase):
    def test_ee_prefix_required(self):
        self.assertFalse(main.is_valid_faketls_secret("dd10400103324995b07c030386e886e7f1"))
        self.assertFalse(main.is_valid_faketls_secret("00112233445566778899aabbccddeeff"))
        self.assertFalse(main.is_valid_faketls_secret(""))

    def test_hex_secret_needs_domain_beyond_ee_plus_32(self):
        key_only = "ee" + "ab" * 16          # 34 chars: ee + 32 hex, no domain
        with_domain = "ee" + "ab" * 16 + "1a"  # + 1 hex byte of domain
        self.assertFalse(main.is_valid_faketls_secret(key_only))
        self.assertTrue(main.is_valid_faketls_secret(with_domain))

    def test_invalid_alphabet_rejected(self):
        # '.' is neither hex nor base64url -> cannot be a real Fake-TLS secret
        self.assertFalse(main.is_valid_faketls_secret("ee" + "0" * 15 + "." + "0" * 16))
        # non-hex chars like 'g'-'z' identify the secret as base64url (the spec
        # example eeNEgY... contains them too), so they are length-checked as b64
        self.assertTrue(main.is_valid_faketls_secret("ee" + "g" * 32))

    def test_base64url_faketls_secret_accepted(self):
        # eeNEgYdJvXrFGRMCIMJdCQ-style: ee + b64url key + domain chars
        self.assertTrue(main.is_valid_faketls_secret("eeNEgYdJvXrFGRMCIMJdCQ"))

    def test_b64url_too_short_rejected(self):
        self.assertFalse(main.is_valid_faketls_secret("eeAbC3"))  # key missing

    def test_mixed_alphabet_rejected(self):
        # contains '.' which is neither hex nor b64url
        self.assertFalse(main.is_valid_faketls_secret("eeNEgY.JvXrFGRMCIMJdCQ"))


class PortTests(unittest.TestCase):
    def test_allowed_https_ports(self):
        for port in (443, 8443, 2053, 2083, 8880):
            self.assertTrue(main.is_allowed_port(port))

    def test_other_ports_rejected(self):
        for port in (80, 1080, 7799, 9999, 65535):
            self.assertFalse(main.is_allowed_port(port))


class JsonSourceParsingTests(unittest.TestCase):
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
        self.assertEqual(len(proxies), 2)  # the two well-formed entries
        self.assertEqual(proxies[0].server, "79.137.196.223")
        self.assertEqual(proxies[0].port, 16443)
        self.assertEqual(proxies[0].latency_ms, 120)
        self.assertEqual(proxies[1].secret, "eeNEgYdJvXrFGRMCIMJdCQ")

    def test_parse_json_invalid(self):
        self.assertEqual(main.parse_json_source("not json"), [])
        self.assertEqual(main.parse_json_source('{"a": 1}'), [])


class PlaintextSourceParsingTests(unittest.TestCase):
    def test_parse_plaintext_links(self):
        raw = "\n".join([
            "https://t.me/proxy?server=rain.lavazemi2.co.uk&port=2053&secret=eeNEgYdJvXrFGRMCIMJdCQ",
            "tg://proxy?server=host2.example&port=443&secret=eeAABBCCDDEEFF00112233",
            "1.2.3.4:1080",                       # socks5 line - ignored
            "vless://uuid@host:443?type=ws#x",     # vless - ignored
            "vmess://eyJhZGQiOiJ4In0=",            # vmess - ignored
            "https://t.me/proxy?server=x&port=443",  # no secret - dropped
        ])
        proxies = main.parse_plaintext_source(raw)
        self.assertEqual(len(proxies), 2)
        self.assertEqual(proxies[0].server, "rain.lavazemi2.co.uk")
        self.assertEqual(proxies[1].port, 443)

    def test_filters_keep_only_valid_faketls_on_allowed_ports(self):
        parsed = [
            main.Proxy("a.example", 2053, "eeNEgYdJvXrFGRMCIMJdCQ"),   # keep
            main.Proxy("b.example", 7799, "eeNEgYdJvXrFGRMCIMJdCQ"),   # bad port
            main.Proxy("c.example", 443, "dd" + "ab" * 16),             # dd secret
            main.Proxy("d.example", 443, "ee" + "ab" * 16),             # hex, key-only -> reject
            main.Proxy("e.example", 8880, "eeNEgYdJvXrFGRMCIMJdCQ"),   # keep
        ]
        kept, stats = main.apply_filters(parsed)
        self.assertEqual([p.server for p in kept], ["a.example", "e.example"])
        self.assertEqual(stats["bad_secret"], 2)
        self.assertEqual(stats["bad_port"], 1)

    def test_spec_example_proxy_survives(self):
        # server=bale.foltmeingop.co.uk port=8880 secret=eeNEgYdJvXrFGRMCIMJdCQ
        parsed = [main.Proxy("bale.foltmeingop.co.uk", 8880, "eeNEgYdJvXrFGRMCIMJdCQ")]
        kept, _ = main.apply_filters(parsed)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].link,
                         "https://t.me/proxy?server=bale.foltmeingop.co.uk&port=8880&secret=eeNEgYdJvXrFGRMCIMJdCQ")


class LinkGenerationTests(unittest.TestCase):
    def test_standard_deep_link(self):
        proxy = make_proxy("host.example", 8443, "eeAABBCCDDEEFF00112233")
        self.assertEqual(proxy.link,
                         "https://t.me/proxy?server=host.example&port=8443&secret=eeAABBCCDDEEFF00112233")

    def test_link_escapes_query_values(self):
        proxy = make_proxy("a&b.example", 443, "ee<x>1")
        link = proxy.link
        parsed = urlparse(link)
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("a%26b.example", link)
        self.assertIn("ee%3Cx%3E1", link)

    def test_history_uses_full_link(self):
        proxy = make_proxy("h.example", 443, "eeAABBCCDDEEFF00112233")
        history = {proxy.link}
        picks = main.pick_best_proxies([(proxy, 100.0)], history)
        self.assertEqual(picks, [])
        picks = main.pick_best_proxies([(proxy, 100.0)], set())
        self.assertEqual(len(picks), 1)

    def test_history_honors_legacy_host_port_entries(self):
        proxy = make_proxy("legacy.example", 2083, "eeAABBCCDDEEFF00112233")
        picks = main.pick_best_proxies([(proxy, 100.0)], {"legacy.example:2083"})
        self.assertEqual(picks, [], "legacy host:port history must suppress repost")

    def test_latency_cap_filtering(self):
        fast = make_proxy("fast.example", 443)
        slow = make_proxy("slow.example", 443)
        picks = main.pick_best_proxies([(fast, 300.0), (slow, 2600.0)], set())
        self.assertEqual([p.server for p, _ in picks], ["fast.example"])

    def test_max_posts_limit(self):
        proxies = [(make_proxy(f"p{i}.example", 443), 100.0 + i) for i in range(5)]
        self.assertEqual(len(main.pick_best_proxies(proxies, set())), main.MAX_POSTS)


class MessageTests(unittest.TestCase):
    def test_message_contains_required_fields(self):
        proxy = make_proxy("s.example", 2083, "eeNEgYdJvXrFGRMCIMJdCQ")
        msg = main.format_message(proxy, 87.6)
        self.assertIn("🚀 <b>پروکسی ضدفیلتر تلگرام (Fake-TLS)</b>", msg)
        self.assertIn("⚡️ <b>پینگ:</b> <code>88 ms</code>", msg)
        self.assertIn("🌐 <b>سرور:</b> <code>s.example</code>", msg)
        self.assertIn("🚪 <b>پورت:</b> <code>2083</code>", msg)
        self.assertIn(proxy.link.replace("&", "&amp;"), msg)

    def test_minimal_fallback_message(self):
        proxy = make_proxy("s.example", 443)
        msg = main.format_message_minimal(proxy, 42.4)
        self.assertIn("42 ms", msg)
        self.assertIn(proxy.link, msg)
        self.assertNotIn("<b>", msg)  # plaintext

    def test_keyboard_and_payload_shape(self):
        proxy = make_proxy("k.example", 443, "eeAABBCCDDEEFF00112233")
        rows = main.build_inline_keyboard(proxy)
        self.assertEqual(rows[0][0]["text"], "⚡️ اتصال مستقیم به پروکسی")
        self.assertEqual(rows[0][0]["url"], proxy.link)

        captured = {}

        class Resp:
            def json(self):
                return {"ok": True, "result": {"message_id": 7}}

        def fake_post(url, json=None, timeout=None):
            captured["url"], captured["json"] = url, json
            return Resp()

        _requests.post = fake_post
        try:
            ok = main.post_to_telegram("TOK", "@chan", proxy, 55.0)
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))

        self.assertTrue(ok)
        self.assertTrue(captured["url"].endswith("/botTOK/sendMessage"))
        payload = captured["json"]
        self.assertEqual(payload["chat_id"], "@chan")
        self.assertEqual(payload["parse_mode"], "HTML")
        kb = payload["reply_markup"]["inline_keyboard"]
        self.assertEqual(kb[0][0]["url"], proxy.link)

    def test_parse_entity_error_falls_back_to_plaintext(self):
        proxy = make_proxy("k.example", 443, "eeAABBCCDDEEFF00112233")
        attempts = []

        def flaky_post(url, json=None, timeout=None):
            attempts.append(json)
            text = json["text"]

            class Resp:
                def json(self):
                    if "<b>" in text or "<code>" in text:
                        return {"ok": False,
                                "description": "Bad Request: can't parse entities"}
                    return {"ok": True, "result": {"message_id": 9}}

            return Resp()

        _requests.post = flaky_post
        try:
            ok = main.post_to_telegram("TOK", "@chan", proxy, 55.0)
        finally:
            _requests.post = lambda *a, **k: (_ for _ in ()).throw(RequestException("offline"))

        self.assertTrue(ok)
        self.assertGreaterEqual(len(attempts), 2)
        self.assertNotIn("<code>", attempts[-1]["text"])  # final attempt is plaintext

    def test_channel_username_rules(self):
        os.environ["TELEGRAM_CHANNEL_TAG"] = "@my_channel"
        import importlib
        importlib.reload(main)
        self.assertEqual(main.channel_username(), "my_channel")
        os.environ["TELEGRAM_CHANNEL_TAG"] = "-1001234567890"
        importlib.reload(main)
        self.assertIsNone(main.channel_username())
        del os.environ["TELEGRAM_CHANNEL_TAG"]
        importlib.reload(main)


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
        self.assertIsNone(main.tcp_ping("x.example", 99999))


if __name__ == "__main__":
    unittest.main(verbosity=2)
