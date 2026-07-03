import unittest

import pqcprobe


class TestPqcProbeBasic(unittest.TestCase):
    def test_parse_target_https(self):
        host, port = pqcprobe.parse_target('https://example.com')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 443)

    def test_parse_target_hostport(self):
        host, port = pqcprobe.parse_target('example.com:8443')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 8443)

    def test_parse_target_ipv6(self):
        # Brackets must be stripped so the host is usable with socket.create_connection.
        host, port = pqcprobe.parse_target('[::1]:8443')
        self.assertEqual(host, '::1')
        self.assertEqual(port, 8443)

    def test_parse_target_ipv6_no_port(self):
        host, port = pqcprobe.parse_target('[2001:db8::1]')
        self.assertEqual(host, '2001:db8::1')
        self.assertEqual(port, 443)

    def test_parse_target_no_scheme(self):
        host, port = pqcprobe.parse_target('example.com')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 443)

    def test_parse_target_invalid(self):
        with self.assertRaises(ValueError):
            pqcprobe.parse_target('ftp://example.com')

    def test_parse_asn1_time_utctime(self):
        # 'YYMMDDHHMMSSZ' -> UTCTime
        s = '251013120000Z'  # Oct 13 2025 12:00:00 UTC
        out = pqcprobe._parse_asn1_time(s)
        self.assertTrue(out.startswith('2025') or out.startswith('25'))

    def test_parse_asn1_time_generalized(self):
        s = '20251013120000Z'
        out = pqcprobe._parse_asn1_time(s)
        self.assertTrue(out.startswith('2025'))

    def test_dedupe_by_name(self):
        items = [{'cipher': 'A', 'bits': 1}, {'cipher': 'B', 'bits': 2}, {'cipher': 'A', 'bits': 1}]
        out = pqcprobe.dedupe_by_name(items)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]['cipher'], 'A')
        self.assertEqual(out[1]['cipher'], 'B')

    def _cert(self, dns=None, ip=None, subject=None):
        return {
            'subject': subject,
            'subject_alt_names': {'dns': dns or [], 'ip': ip or []},
        }

    def test_hostname_match_exact(self):
        res = pqcprobe.match_hostname(self._cert(dns=['example.com']), 'example.com')
        self.assertTrue(res['matched'])

    def test_hostname_match_case_insensitive(self):
        res = pqcprobe.match_hostname(self._cert(dns=['Example.COM']), 'example.com')
        self.assertTrue(res['matched'])

    def test_hostname_match_wildcard(self):
        cert = self._cert(dns=['*.example.com'])
        self.assertTrue(pqcprobe.match_hostname(cert, 'api.example.com')['matched'])
        # Wildcard matches exactly one label, not the bare domain or nested labels.
        self.assertFalse(pqcprobe.match_hostname(cert, 'example.com')['matched'])
        self.assertFalse(pqcprobe.match_hostname(cert, 'a.b.example.com')['matched'])

    def test_hostname_mismatch(self):
        res = pqcprobe.match_hostname(self._cert(dns=['example.com']), 'evil.com')
        self.assertFalse(res['matched'])

    def test_hostname_match_ip(self):
        cert = self._cert(ip=['192.0.2.10'])
        self.assertTrue(pqcprobe.match_hostname(cert, '192.0.2.10')['matched'])
        self.assertFalse(pqcprobe.match_hostname(cert, '192.0.2.11')['matched'])

    def test_hostname_match_cn_fallback(self):
        # No SAN present: fall back to the subject CN.
        cert = self._cert(subject='CN=example.com,O=Example')
        self.assertTrue(pqcprobe.match_hostname(cert, 'example.com')['matched'])

    def test_is_pqc_group(self):
        self.assertTrue(pqcprobe._is_pqc_group('X25519MLKEM768'))
        self.assertTrue(pqcprobe._is_pqc_group('SecP256r1MLKEM768'))
        self.assertTrue(pqcprobe._is_pqc_group('X25519Kyber768Draft00'))
        self.assertFalse(pqcprobe._is_pqc_group('x25519'))
        self.assertFalse(pqcprobe._is_pqc_group('secp384r1'))
        self.assertFalse(pqcprobe._is_pqc_group(None))

    def test_classify_group_supported(self):
        out = ("depth=2 ...\n"
               "Negotiated TLS1.3 group: X25519MLKEM768\n"
               "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n")
        res = pqcprobe.classify_group_output('X25519MLKEM768', out)
        self.assertEqual(res['status'], 'supported')
        self.assertEqual(res['negotiated'], 'X25519MLKEM768')

    def test_classify_group_supported_classical_no_group_line(self):
        # Classical groups often produce no "Negotiated TLS1.3 group:" line;
        # a real negotiated cipher is the success signal.
        out = ("New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
               "No ALPN negotiated\n"
               "DONE\n")
        res = pqcprobe.classify_group_output('x25519', out)
        self.assertEqual(res['status'], 'supported')
        self.assertEqual(res['negotiated'], 'x25519')

    def test_classify_group_unsupported(self):
        out = ("...ssl/tls alert handshake failure...\n"
               "Negotiated TLS1.3 group: <NULL>\n"
               "New, (NONE), Cipher is (NONE)\n")
        res = pqcprobe.classify_group_output('ffdhe8192', out)
        self.assertEqual(res['status'], 'unsupported')

    def test_classify_group_unknown_locally(self):
        out = "Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed\n"
        res = pqcprobe.classify_group_output('X25519MLKEM768', out)
        self.assertEqual(res['status'], 'unknown_locally')

    def test_classify_group_error(self):
        out = "connect: Connection refused\nconnect:errno=61\n"
        res = pqcprobe.classify_group_output('x25519', out)
        self.assertEqual(res['status'], 'error')

if __name__ == '__main__':
    unittest.main()

