import unittest
import tlsprobe

class TestTlsProbeBasic(unittest.TestCase):
    def test_parse_target_https(self):
        host, port = tlsprobe.parse_target('https://example.com')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 443)

    def test_parse_target_hostport(self):
        host, port = tlsprobe.parse_target('example.com:8443')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 8443)

    def test_parse_target_ipv6(self):
        # Brackets must be stripped so the host is usable with socket.create_connection.
        host, port = tlsprobe.parse_target('[::1]:8443')
        self.assertEqual(host, '::1')
        self.assertEqual(port, 8443)

    def test_parse_target_ipv6_no_port(self):
        host, port = tlsprobe.parse_target('[2001:db8::1]')
        self.assertEqual(host, '2001:db8::1')
        self.assertEqual(port, 443)

    def test_parse_target_no_scheme(self):
        host, port = tlsprobe.parse_target('example.com')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 443)

    def test_parse_target_invalid(self):
        with self.assertRaises(ValueError):
            tlsprobe.parse_target('ftp://example.com')

    def test_parse_asn1_time_utctime(self):
        # 'YYMMDDHHMMSSZ' -> UTCTime
        s = '251013120000Z'  # Oct 13 2025 12:00:00 UTC
        out = tlsprobe._parse_asn1_time(s)
        self.assertTrue(out.startswith('2025') or out.startswith('25'))

    def test_parse_asn1_time_generalized(self):
        s = '20251013120000Z'
        out = tlsprobe._parse_asn1_time(s)
        self.assertTrue(out.startswith('2025'))

    def test_dedupe_by_name(self):
        items = [{'cipher': 'A', 'bits': 1}, {'cipher': 'B', 'bits': 2}, {'cipher': 'A', 'bits': 1}]
        out = tlsprobe.dedupe_by_name(items)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]['cipher'], 'A')
        self.assertEqual(out[1]['cipher'], 'B')

    def _cert(self, dns=None, ip=None, subject=None):
        return {
            'subject': subject,
            'subject_alt_names': {'dns': dns or [], 'ip': ip or []},
        }

    def test_hostname_match_exact(self):
        res = tlsprobe.match_hostname(self._cert(dns=['example.com']), 'example.com')
        self.assertTrue(res['matched'])

    def test_hostname_match_case_insensitive(self):
        res = tlsprobe.match_hostname(self._cert(dns=['Example.COM']), 'example.com')
        self.assertTrue(res['matched'])

    def test_hostname_match_wildcard(self):
        cert = self._cert(dns=['*.example.com'])
        self.assertTrue(tlsprobe.match_hostname(cert, 'api.example.com')['matched'])
        # Wildcard matches exactly one label, not the bare domain or nested labels.
        self.assertFalse(tlsprobe.match_hostname(cert, 'example.com')['matched'])
        self.assertFalse(tlsprobe.match_hostname(cert, 'a.b.example.com')['matched'])

    def test_hostname_mismatch(self):
        res = tlsprobe.match_hostname(self._cert(dns=['example.com']), 'evil.com')
        self.assertFalse(res['matched'])

    def test_hostname_match_ip(self):
        cert = self._cert(ip=['192.0.2.10'])
        self.assertTrue(tlsprobe.match_hostname(cert, '192.0.2.10')['matched'])
        self.assertFalse(tlsprobe.match_hostname(cert, '192.0.2.11')['matched'])

    def test_hostname_match_cn_fallback(self):
        # No SAN present: fall back to the subject CN.
        cert = self._cert(subject='CN=example.com,O=Example')
        self.assertTrue(tlsprobe.match_hostname(cert, 'example.com')['matched'])

if __name__ == '__main__':
    unittest.main()

