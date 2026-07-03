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
        host, port = tlsprobe.parse_target('[::1]:8443')
        self.assertEqual(host, '[::1]')
        self.assertEqual(port, 8443)

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

if __name__ == '__main__':
    unittest.main()

