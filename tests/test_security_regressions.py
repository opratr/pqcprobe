import contextlib
import datetime
import io
import ipaddress
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

import pqcprobe


class LocalTLSServer:
    def __init__(self, tls12_only=False, certificate_ip='127.0.0.1'):
        self.tempdir = tempfile.TemporaryDirectory()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(certificate_ip))
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        self.cert_path = str(Path(self.tempdir.name) / 'cert.pem')
        key_path = str(Path(self.tempdir.name) / 'key.pem')
        Path(self.cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        Path(key_path).write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_path, key_path)
        if tls12_only:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('AES128-GCM-SHA256')
        self.context = context
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(20)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def _serve(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self.context.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.settimeout(0.5)
                    try:
                        tls_conn.recv(1)
                    except (OSError, ssl.SSLError):
                        pass
            except (OSError, ssl.SSLError):
                conn.close()


class TestSecurityRegressions(unittest.TestCase):
    def test_escaped_organization_cannot_supply_common_name(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                                'Example,CN=victim.example')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        summary = pqcprobe.summarize_cert_x509(crypto.X509.from_cryptography(cert))
        self.assertFalse(pqcprobe.match_hostname(summary, 'victim.example')['matched'])

    @unittest.skipUnless(pqcprobe.shutil.which('openssl'), 'native openssl unavailable')
    def test_tls12_rsa_server_cannot_claim_hybrid_group(self):
        with LocalTLSServer(tls12_only=True) as server:
            result = pqcprobe.probe_group('127.0.0.1', server.port,
                                          'X25519MLKEM768', 3, verify=False)
        self.assertNotEqual(result['status'], 'supported')

    @unittest.skipUnless(pqcprobe.shutil.which('openssl'), 'native openssl unavailable')
    def test_group_probe_requires_trusted_matching_certificate(self):
        with LocalTLSServer() as server:
            untrusted = pqcprobe.probe_group('127.0.0.1', server.port, 'x25519', 3)
            trusted = pqcprobe.probe_group('127.0.0.1', server.port, 'x25519', 3,
                                           ca_file=server.cert_path)
            pem = pqcprobe.fetch_peer_cert_pem('127.0.0.1', server.port, True, 3,
                                                server.cert_path)
        self.assertEqual(untrusted['status'], 'auth_error')
        self.assertEqual(trusted['status'], 'supported')
        self.assertTrue(pem.startswith('-----BEGIN CERTIFICATE-----'))

        with LocalTLSServer(certificate_ip='127.0.0.2') as server:
            wrong_host = pqcprobe.probe_group('127.0.0.1', server.port, 'x25519', 3,
                                              ca_file=server.cert_path)
            with self.assertRaises(pqcprobe.HostnameVerificationError):
                pqcprobe.fetch_peer_cert_pem('127.0.0.1', server.port, True, 3,
                                              server.cert_path)
        self.assertEqual(wrong_host['status'], 'auth_error')

    def test_policy_gate_distinguishes_unknown_and_unsupported(self):
        negotiated = {'tls_version': 'TLSv1.2', 'hostname_match': {'matched': True}}
        base = {'groups': {}, 'pqc_assessment': 'indeterminate'}
        with mock.patch.object(pqcprobe, 'checked_connect_once', return_value=negotiated), \
             mock.patch.object(pqcprobe, 'probe_versions', return_value={}), \
             mock.patch.object(pqcprobe, 'probe_tls12_ciphers', return_value={}), \
             mock.patch.object(pqcprobe, 'probe_tls13_ciphers', return_value={}), \
             mock.patch.object(pqcprobe, 'probe_kex_groups', return_value=base), \
             mock.patch.object(pqcprobe, 'client_cipher_profile', return_value=[]), \
             mock.patch('sys.argv', ['pqcprobe', 'example.com', '--fail-on-classical-only']), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pqcprobe.main(), 4)

    def test_group_assessment_preserves_unknown_and_negotiated_evidence(self):
        def unknown_probe(host, port, group, timeout, verify, ca_file):
            return {'group': group, 'status': 'unknown_locally'}

        with mock.patch.object(pqcprobe.shutil, 'which', return_value='/usr/bin/openssl'), \
             mock.patch.object(pqcprobe, 'probe_group', side_effect=unknown_probe):
            unknown = pqcprobe.probe_kex_groups('example.com', 443, 1)
            observed = pqcprobe.probe_kex_groups(
                'example.com', 443, 1,
                negotiated={'tls_version': 'TLSv1.3', 'group': 'X25519MLKEM768',
                            'hostname_match': {'matched': True}})
        self.assertEqual(unknown['pqc_assessment'], 'indeterminate')
        self.assertIsNone(unknown['hndl_risk'])
        self.assertEqual(observed['pqc_assessment'], 'supported')

    def test_all_hybrid_rejections_are_conclusive(self):
        def rejected_probe(host, port, group, timeout, verify, ca_file):
            return {'group': group, 'status': 'unsupported'}

        with mock.patch.object(pqcprobe.shutil, 'which', return_value='/usr/bin/openssl'), \
             mock.patch.object(pqcprobe, 'probe_group', side_effect=rejected_probe):
            result = pqcprobe.probe_kex_groups('example.com', 443, 1)
        self.assertEqual(result['pqc_assessment'], 'unsupported')
        self.assertTrue(result['hndl_risk'])

    def test_missing_openssl_is_indeterminate_without_negotiated_hybrid(self):
        with mock.patch.object(pqcprobe.shutil, 'which', return_value=None):
            result = pqcprobe.probe_kex_groups('example.com', 443, 1)
        self.assertEqual(result['pqc_assessment'], 'indeterminate')
        self.assertIsNone(result['pqc_ready'])

    def test_missing_hostname_result_fails_closed(self):
        with mock.patch.object(pqcprobe, 'connect_once',
                               return_value={'hostname_match': None}):
            with self.assertRaises(pqcprobe.HostnameVerificationError):
                pqcprobe.checked_connect_once('example.com', 443, object(), 1, True)

    def test_ipv6_group_probe_brackets_connect_address(self):
        output = 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n'
        completed = mock.Mock(stdout=output, stderr='', returncode=0)
        with mock.patch.object(pqcprobe.shutil, 'which', return_value='/usr/bin/openssl'), \
             mock.patch.object(pqcprobe.subprocess, 'run', return_value=completed) as run:
            result = pqcprobe.probe_group('::1', 443, 'x25519', 1)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index('-connect') + 1], '[::1]:443')
        self.assertEqual(command[command.index('-verify_ip') + 1], '::1')
        self.assertEqual(result['status'], 'error')
        self.assertIn('omitted the peer certificate', result['detail'])

    def test_native_probe_applies_strict_wildcard_rule(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('f*.example.com')]),
                               critical=False).sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        completed = mock.Mock(stdout=pem + '\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n',
                              stderr='', returncode=0)
        with mock.patch.object(pqcprobe.shutil, 'which', return_value='/usr/bin/openssl'), \
             mock.patch.object(pqcprobe.subprocess, 'run', return_value=completed):
            result = pqcprobe.probe_group('foo.example.com', 443, 'x25519', 1)
        self.assertEqual(result['status'], 'auth_error')

    def test_raw_cert_failure_is_nonzero_and_stderr_only(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(pqcprobe, 'fetch_peer_cert_pem',
                               side_effect=ValueError('no certificate')), \
             mock.patch('sys.argv', ['pqcprobe', 'example.com', '--raw-cert']), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pqcprobe.main()
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('no certificate', err.getvalue())

    def test_policy_rejects_skipped_or_unverified_assessment(self):
        for flag in ('--no-groups', '--no-verify', '--raw-cert'):
            with self.subTest(flag=flag), \
                 mock.patch('sys.argv', ['pqcprobe', 'example.com',
                                         '--fail-on-classical-only', flag]), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    pqcprobe.main()
                self.assertEqual(result.exception.code, 2)
