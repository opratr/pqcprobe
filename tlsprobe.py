# python
import argparse
import json
import socket
import select
import sys
import time
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime

from OpenSSL import SSL

# cryptography is used to make parsing X509 extensions easier
try:
    from cryptography import x509 as cx509
except Exception:
    cx509 = None

COMMON_TLS12_CIPHERS = [
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
]

COMMON_TLS13_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

# Helper to parse targets
def parse_target(url_or_hostport: str):
    # Support full URLs and plain host[:port], including bracketed IPv6 like [::1]:8443
    if "://" in url_or_hostport:
        u = urlparse(url_or_hostport)
        if u.scheme.lower() not in ("https", "ssl", "tls"):
            raise ValueError("Only https URLs are supported")
        host = u.hostname
        port = u.port or 443
        if not host:
            raise ValueError("Missing host")
        return host, port

    # Not a URL; could be host, host:port, or [ipv6]:port
    s = url_or_hostport.strip()
    if not s:
        raise ValueError("Missing host")

    # Bracketed IPv6 form: [addr]:port
    if s.startswith('['):
        # find matching bracket
        end = s.find(']')
        if end == -1:
            raise ValueError("Invalid IPv6 address format")
        # Return the address without brackets so it is usable directly with
        # socket.create_connection(); getaddrinfo does not accept the bracketed form.
        host = s[1:end]
        rest = s[end + 1:]
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except Exception:
                raise ValueError("Invalid port")
        else:
            port = 443
        return host, port

    # Otherwise, split on last ':' to allow IPv6 literals without brackets (not recommended)
    if ':' in s and s.count(':') == 1:
        # host:port
        host, port_str = s.rsplit(':', 1)
        try:
            port = int(port_str)
        except Exception:
            raise ValueError('Invalid port')
        return host, port

    # Default: hostname only
    return s, 443

# Create a pyOpenSSL context with reasonable defaults
def new_context(verify: bool, alpn=True):
    # Use a flexible method and then disable unwanted protocol versions explicitly
    ctx = SSL.Context(SSL.TLS_METHOD)

    # Verification
    # define a verify callback with the correct signature for pyOpenSSL
    def _verify_cb(conn, x509_obj, errnum, errdepth, ok):
        # Return True only if the certificate has been validated by OpenSSL
        try:
            return bool(ok)
        except Exception:
            return False

    if verify:
        ctx.set_verify(SSL.VERIFY_PEER, callback=_verify_cb)
        try:
            ctx.set_default_verify_paths()
        except Exception:
            pass
    else:
        ctx.set_verify(SSL.VERIFY_NONE)

    # ALPN
    if alpn:
        try:
            # set_alpn_protos expects a list of bytes (pyOpenSSL >= 19)
            ctx.set_alpn_protos([b"h2", b"http/1.1"])  # ignore return
        except Exception:
            # older pyOpenSSL/OpenSSL may not support ALPN
            pass

    # Prefer strong defaults: we'll prevent SSLv3/old TLS by setting options where available
    opts = 0
    for name in ("OP_NO_SSLv2", "OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1"):
        if hasattr(SSL, name):
            opts |= getattr(SSL, name)
    try:
        ctx.set_options(opts)
    except Exception:
        pass

    return ctx

# Configure context to restrict to a single TLS version (TLS1.2 or TLS1.3)
def restrict_context_to_version(ctx, version_label: str):
    # Attempt to use set_min_proto_version / set_max_proto_version if available, otherwise rely on OP_NO_* flags
    try:
        if hasattr(ctx, 'set_min_proto_version') and hasattr(ctx, 'set_max_proto_version'):
            if version_label == 'TLSv1.3':
                ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
                ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
            elif version_label == 'TLSv1.2':
                ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
                ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
            return
    except Exception:
        # ignore and fall back to options
        pass

    # Fallback: set options to disable all other versions
    opts = 0
    # Disable TLS versions we don't want
    try:
        if version_label == 'TLSv1.3':
            # disable TLS 1.2 and below
            for name in ('OP_NO_TLSv1_2', 'OP_NO_TLSv1_1', 'OP_NO_TLSv1', 'OP_NO_SSLv3'):
                if hasattr(SSL, name):
                    opts |= getattr(SSL, name)
        elif version_label == 'TLSv1.2':
            # disable TLS 1.3 and TLS 1.1/1.0
            for name in ('OP_NO_TLSv1_3', 'OP_NO_TLSv1_1', 'OP_NO_TLSv1', 'OP_NO_SSLv3'):
                if hasattr(SSL, name):
                    opts |= getattr(SSL, name)
    except Exception:
        pass
    try:
        ctx.set_options(opts)
    except Exception:
        pass

# Perform a single TLS handshake and gather info using pyOpenSSL
def connect_once(host, port, ctx, timeout):
    addr = (host, port)
    sock = socket.create_connection(addr, timeout=timeout)
    # Wrap the socket in a pyOpenSSL Connection
    conn = SSL.Connection(ctx, sock)
    # SNI
    try:
        conn.set_tlsext_host_name(host.encode())
    except Exception:
        pass
    conn.set_connect_state()

    # Do handshake with support for non-blocking WANT_READ/WANT_WRITE
    deadline = time.time() + float(timeout or 5.0)
    while True:
        try:
            conn.do_handshake()
            break
        except SSL.WantReadError:
            # wait until socket is readable or timeout
            remaining = deadline - time.time()
            if remaining <= 0:
                conn.close()
                sock.close()
                raise Exception('handshake failed: timeout waiting for read')
            r, w, _ = select.select([sock], [], [], remaining)
            if not r:
                conn.close()
                sock.close()
                raise Exception('handshake failed: timeout waiting for read')
            continue
        except SSL.WantWriteError:
            remaining = deadline - time.time()
            if remaining <= 0:
                conn.close()
                sock.close()
                raise Exception('handshake failed: timeout waiting for write')
            r, w, _ = select.select([], [sock], [], remaining)
            if not w:
                conn.close()
                sock.close()
                raise Exception('handshake failed: timeout waiting for write')
            continue
        except Exception as e:
            # ensure socket is closed
            err_msg = repr(e)
            try:
                conn.close()
                sock.close()
            except Exception:
                pass
            # raise a clearer exception so callers capture a non-empty message
            raise Exception(f"handshake failed: {err_msg}")

    # Collect negotiated parameters
    tls_version = None
    try:
        tls_version = conn.get_protocol_version_name()
    except Exception:
        tls_version = None

    cipher = None
    try:
        # pyOpenSSL provides get_cipher_name / get_cipher_bits / get_cipher_version
        name = None
        bits = None
        proto = None
        try:
            name = conn.get_cipher_name()
        except Exception:
            pass
        try:
            bits = conn.get_cipher_bits()
        except Exception:
            pass
        try:
            proto = conn.get_cipher_version()
        except Exception:
            pass
        cipher = (name, proto, bits)
    except Exception:
        cipher = None

    # ALPN
    alpn = None
    try:
        get_alpn = getattr(conn, 'get_alpn_proto_negotiated', None)
        if callable(get_alpn):
            res = get_alpn()
            if res is not None:
                if isinstance(res, (bytes, bytearray)):
                    try:
                        alpn = res.decode()
                    except Exception:
                        alpn = res
                else:
                    alpn = res
    except Exception:
        alpn = None

    # Certificate
    cert = None
    try:
        peer = conn.get_peer_certificate()
        if peer:
            cert = summarize_cert_x509(peer)
    except Exception:
        cert = None

    # Hostname verification: OpenSSL's chain validation does not check that the
    # certificate actually identifies the host we asked for, so we do it here.
    hostname_match = match_hostname(cert, host) if cert else None

    # Close
    try:
        conn.shutdown()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass

    return {
        'peer': f"{host}:{port}",
        'tls_version': tls_version,
        'cipher': cipher,
        'alpn': alpn,
        'certificate': cert,
        'hostname_match': hostname_match,
    }

# New helper: fetch the server certificate PEM (raw) without parsing into dict
def fetch_peer_cert_pem(host, port, verify, timeout):
    addr = (host, port)
    ctx = new_context(verify=verify)
    sock = socket.create_connection(addr, timeout=timeout)
    conn = SSL.Connection(ctx, sock)
    try:
        try:
            conn.set_tlsext_host_name(host.encode())
        except Exception:
            pass
        conn.set_connect_state()
        # handshake with WANT read/write support
        deadline = time.time() + float(timeout or 5.0)
        while True:
            try:
                conn.do_handshake()
                break
            except SSL.WantReadError:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise Exception('handshake failed: timeout waiting for read')
                r, w, _ = select.select([sock], [], [], remaining)
                if not r:
                    raise Exception('handshake failed: timeout waiting for read')
                continue
            except SSL.WantWriteError:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise Exception('handshake failed: timeout waiting for write')
                r, w, _ = select.select([], [sock], [], remaining)
                if not w:
                    raise Exception('handshake failed: timeout waiting for write')
                continue
        peer = conn.get_peer_certificate()
        if peer is not None:
            try:
                from OpenSSL import crypto as _crypto
                pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, peer)
                return pem.decode()
            except Exception:
                return None
        return None
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

# Convert pyOpenSSL.crypto.X509 to a normalized dict using cryptography where possible
def summarize_cert_x509(x509_obj):
    try:
        # If cryptography bindings are available, use them (more convenient for SANs)
        cert = x509_obj.to_cryptography()
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        # prefer the timezone-aware UTC properties when available
        not_before_dt = getattr(cert, 'not_valid_before_utc', None) or getattr(cert, 'not_valid_before', None)
        not_after_dt = getattr(cert, 'not_valid_after_utc', None) or getattr(cert, 'not_valid_after', None)
        not_before = not_before_dt.isoformat() + 'Z' if not_before_dt is not None else None
        not_after = not_after_dt.isoformat() + 'Z' if not_after_dt is not None else None
        san_dns = []
        san_ip = []
        try:
            if cx509 is not None:
                san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
                sans = san_ext.value
                try:
                    san_dns = sans.get_values_for_type(cx509.DNSName)
                except Exception:
                    san_dns = []
                try:
                    san_ip = [str(ip) for ip in sans.get_values_for_type(cx509.IPAddress)]
                except Exception:
                    san_ip = []
        except Exception:
            pass

        # normalize version to a JSON-serializable value
        version_obj = getattr(cert, 'version', None)
        if version_obj is None:
            version_val = None
        else:
            # cryptography.x509.Version enums expose a .name attribute
            version_val = getattr(version_obj, 'name', None) or str(version_obj)

        sigalg = None
        try:
            sigalg = getattr(cert.signature_algorithm_oid, 'dotted_string', None) or getattr(cert.signature_algorithm_oid, 'name', None)
        except Exception:
            sigalg = None

        return {
            'subject': subject,
            'issuer': issuer,
            'not_before': not_before,
            'not_after': not_after,
            'subject_alt_names': {'dns': san_dns, 'ip': san_ip},
            'serial_number': hex(cert.serial_number),
            'version': version_val,
            'sigalg': sigalg,
        }
    except Exception:
        # Fallback: use pyOpenSSL APIs
        try:
            subj_components = x509_obj.get_subject().get_components()
            subj = ",".join([f"{k.decode()}={v.decode()}" for k, v in subj_components])
        except Exception:
            subj = None
        try:
            iss_components = x509_obj.get_issuer().get_components()
            iss = ",".join([f"{k.decode()}={v.decode()}" for k, v in iss_components])
        except Exception:
            iss = None
        try:
            nb = x509_obj.get_notBefore().decode()
            # ASN1_GENERALIZEDTIME or ASN1_UTCTIME: try to normalize
            not_before = _parse_asn1_time(nb)
        except Exception:
            not_before = None
        try:
            na = x509_obj.get_notAfter().decode()
            not_after = _parse_asn1_time(na)
        except Exception:
            not_after = None
        return {
            'subject': subj,
            'issuer': iss,
            'not_before': not_before,
            'not_after': not_after,
            'subject_alt_names': {'dns': [], 'ip': []},
            'serial_number': hex(x509_obj.get_serial_number()) if hasattr(x509_obj, 'get_serial_number') else None,
            'version': None,
            'sigalg': None,
        }

# Check whether a certificate identifies the host we connected to.
# OpenSSL validates the chain but not the identity, so this closes that gap.
def match_hostname(cert, hostname):
    if not cert or not hostname:
        return None

    # Normalize: drop IPv6 brackets and lowercase for DNS comparison.
    host = hostname.strip()
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]

    sans = cert.get('subject_alt_names') or {}
    dns_names = sans.get('dns') or []
    ip_names = sans.get('ip') or []

    # If the target is an IP literal, match against IP SANs only.
    try:
        import ipaddress
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None

    if target_ip is not None:
        matched = any(_ip_equal(ip, target_ip) for ip in ip_names)
        return {'matched': matched, 'target': host, 'checked_against': ip_names}

    host_l = host.rstrip('.').lower()
    checked = list(dns_names)
    matched = any(_dns_match(pattern, host_l) for pattern in dns_names)

    # Legacy fallback: some certs still rely on the subject CN when no SAN is present.
    if not matched and not dns_names:
        cn = _subject_cn(cert.get('subject'))
        if cn:
            checked.append(cn)
            matched = _dns_match(cn, host_l)

    return {'matched': matched, 'target': host_l, 'checked_against': checked}


def _ip_equal(san_ip, target_ip):
    import ipaddress
    try:
        return ipaddress.ip_address(str(san_ip)) == target_ip
    except ValueError:
        return False


def _dns_match(pattern, host):
    if not pattern:
        return False
    pattern = pattern.rstrip('.').lower()
    if '*' not in pattern:
        return pattern == host
    # Wildcards are only valid in the leftmost label and match exactly one label.
    p_labels = pattern.split('.')
    h_labels = host.split('.')
    if len(p_labels) != len(h_labels) or len(p_labels) < 2:
        return False
    if '*' not in p_labels[0]:
        return False
    if p_labels[1:] != h_labels[1:]:
        return False
    prefix, _, suffix = p_labels[0].partition('*')
    return h_labels[0].startswith(prefix) and h_labels[0].endswith(suffix)


def _subject_cn(subject):
    if not subject:
        return None
    # subject is an RFC4514 / comma-joined string such as "CN=example.com,O=..."
    for part in subject.split(','):
        part = part.strip()
        if part.upper().startswith('CN='):
            return part[3:].strip()
    return None


# Helper to parse pyOpenSSL ASN1 time strings
def _parse_asn1_time(s: str):
    # Typical formats: '20251013120000Z' or '251013120000Z'
    try:
        if len(s) == 13 and s.endswith('Z'):
            # YYMMDDHHMMSSZ -> UTCTime
            dt = datetime.strptime(s, '%y%m%d%H%M%SZ')
            return dt.isoformat() + 'Z'
        elif len(s) == 15 and s.endswith('Z'):
            # YYYYMMDDHHMMSSZ
            dt = datetime.strptime(s, '%Y%m%d%H%M%SZ')
            return dt.isoformat() + 'Z'
    except Exception:
        return s

# Probe which TLS versions are supported by trying to restrict to each version
def probe_versions(host, port, verify, timeout):
    results = {}
    for vlabel in ("TLSv1.3", "TLSv1.2"):
        ctx = new_context(verify=verify)
        restrict_context_to_version(ctx, vlabel)
        try:
            info = connect_once(host, port, ctx, timeout)
            results[vlabel] = {
                'supported': True,
                'negotiated_cipher': info.get('cipher'),
                'alpn': info.get('alpn'),
            }
        except Exception as e:
            results[vlabel] = {'supported': False, 'error': str(e)}
    return results

# Probe a sample of TLS 1.2 ciphers by setting the cipher list on the context
def probe_tls12_ciphers(host, port, verify, timeout, ciphers, workers=8):
    supported = []
    unsupported = []

    def _worker(c):
        ctx = new_context(verify=verify)
        restrict_context_to_version(ctx, 'TLSv1.2')
        setter = getattr(ctx, 'set_cipher_list', None)
        if not callable(setter):
            return {'cipher': c, 'error': 'no set_cipher_list API'}
        try:
            try:
                setter(c)
            except Exception:
                setter(c.encode())
        except Exception as e:
            return {'cipher': c, 'error': repr(e)}
        try:
            info = connect_once(host, port, ctx, timeout)
            name, _, bits = info['cipher'] or (None, None, None)
            return {'cipher': name, 'bits': bits, 'ok': True}
        except Exception as e:
            return {'cipher': c, 'error': repr(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_worker, c): c for c in ciphers}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is None:
                continue
            if res.get('ok'):
                supported.append({'cipher': res.get('cipher'), 'bits': res.get('bits')})
            else:
                unsupported.append({'cipher': res.get('cipher'), 'error': res.get('error')})
    return {'supported': dedupe_by_name(supported), 'skipped_or_unsupported': unsupported}

# Probe TLS1.3 ciphersuites (requires pyOpenSSL/OpenSSL supporting set_ciphersuites)
def probe_tls13_ciphers(host, port, verify, timeout, ciphersuites, workers=8):
    # Quick capability test
    cap_ctx = new_context(verify=verify)
    set_cs = getattr(cap_ctx, 'set_ciphersuites', None)
    if not callable(set_cs):
        return {
            'supported': [],
            'skipped_or_unsupported': list(ciphersuites),
            'error': 'TLS 1.3 ciphersuite override not supported by this pyOpenSSL/OpenSSL',
        }

    supported = []
    unsupported = []

    def _worker(cs):
        ctx = new_context(verify=verify)
        restrict_context_to_version(ctx, 'TLSv1.3')
        setter = getattr(ctx, 'set_ciphersuites', None)
        if not callable(setter):
            return {'cipher': cs, 'error': 'no set_ciphersuites API'}
        try:
            setter(cs)
        except Exception as e:
            return {'cipher': cs, 'error': repr(e)}
        try:
            info = connect_once(host, port, ctx, timeout)
            name, _, bits = info['cipher'] or (None, None, None)
            return {'cipher': name, 'bits': bits, 'ok': True}
        except Exception as e:
            return {'cipher': cs, 'error': repr(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_worker, cs): cs for cs in ciphersuites}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is None:
                continue
            if res.get('ok'):
                supported.append({'cipher': res.get('cipher'), 'bits': res.get('bits')})
            else:
                unsupported.append({'cipher': res.get('cipher'), 'error': res.get('error')})
    return {'supported': dedupe_by_name(supported), 'skipped_or_unsupported': unsupported}


def dedupe_by_name(items):
    seen = set()
    out = []
    for it in items:
        name = it.get('cipher')
        if name and name not in seen:
            seen.add(name)
            out.append(it)
    return out

# Attempt to reflect the client's available ciphers using pyOpenSSL Context
def client_cipher_profile():
    ctx = new_context(verify=True)
    try:
        getter = getattr(ctx, 'get_ciphers', None)
        if callable(getter):
            ciphers = getter()
        else:
            ciphers = []
    except Exception:
        ciphers = []
    out = []
    for c in ciphers:
        try:
            if isinstance(c, dict):
                out.append({'name': c.get('name'), 'protocol': c.get('protocol'), 'bits': c.get('strength_bits')})
            else:
                out.append({'name': getattr(c, 'name', None), 'protocol': getattr(c, 'protocol', None), 'bits': getattr(c, 'strength_bits', None)})
        except Exception:
            continue
    return out

# Small helper to pretty-print the report
def print_pretty(report):
    print('TLS probe report for', report.get('target'))
    negotiated = report.get('negotiated') or {}
    print('\nNegotiated TLS session:')
    if 'error' in negotiated:
        print('  Handshake error:', negotiated.get('error'))
    else:
        print('  Protocol:', negotiated.get('tls_version'))
        c = negotiated.get('cipher') or (None, None, None)
        print('  Cipher:', c[0])
        print('  ALPN:', negotiated.get('alpn'))
        cert = negotiated.get('certificate') or {}
        if cert:
            print('  Certificate:')
            print('    Subject:', cert.get('subject'))
            print('    Issuer :', cert.get('issuer'))
            print('    Not After:', cert.get('not_after'))
        hm = negotiated.get('hostname_match')
        if hm is not None:
            status = 'OK' if hm.get('matched') else 'MISMATCH'
            print('  Hostname match:', status, '- checked against', hm.get('checked_against'))

    print('\nServer probe summary:')
    versions = report.get('server_probe', {}).get('versions', {})
    for v, info in versions.items():
        print(f'  {v}:', 'supported' if info.get('supported') else 'not supported', '-', info.get('negotiated_cipher'))

    print('\nClient profile:')
    cp = report.get('client_profile', {})
    offered = cp.get('offered_ciphers', [])
    print('  Offered cipher count:', len(offered))

def main():
    ap = argparse.ArgumentParser(description="Probe an HTTPS server's TLS configuration.")
    ap.add_argument("url", help="Target, e.g. https://example.com or host[:port]")
    ap.add_argument("--timeout", type=float, default=5.0, help="Connect timeout in seconds")
    ap.add_argument("--no-verify", action="store_true", help="Do not verify server certificates")
    ap.add_argument("--json", action="store_true", help="Output JSON only")
    ap.add_argument("--pretty", action="store_true", help="Print a human-friendly summary")
    ap.add_argument("--raw-cert", action="store_true", help="Fetch and print the server certificate PEM")
    ap.add_argument("--concurrency", type=int, default=8, help="Concurrency for cipher probing")
    args = ap.parse_args()

    host, port = parse_target(args.url)
    verify = not args.no_verify

    # If requested, fetch raw PEM and exit
    if args.raw_cert:
        try:
            pem = fetch_peer_cert_pem(host, port, verify, args.timeout)
            if pem:
                print(pem)
            else:
                print('# no peer certificate (or failed to fetch)')
            return
        except Exception as e:
            print('# error fetching PEM:', e)
            return

    # Negotiated session (default settings)
    try:
        ctx = new_context(verify=verify)
        negotiated = connect_once(host, port, ctx, args.timeout)
    except Exception as e:
        negotiated = {"error": str(e), "peer": f"{host}:{port}"}

    versions = probe_versions(host, port, verify, args.timeout)
    tls12 = probe_tls12_ciphers(host, port, verify, args.timeout, COMMON_TLS12_CIPHERS, workers=args.concurrency)
    tls13 = probe_tls13_ciphers(host, port, verify, args.timeout, COMMON_TLS13_CIPHERS, workers=args.concurrency)
    client_profile = client_cipher_profile()

    report = {
        "target": f"{host}:{port}",
        "negotiated": negotiated,
        "server_probe": {
            "versions": versions,
            "tls13_ciphers_sample": tls13,
            "tls12_ciphers_sample": tls12,
        },
        "client_profile": {
            "offered_ciphers": client_profile,
            "min_version": "TLSv1.2",
            "max_version": "TLSv1.3",
        },
    }

    if args.pretty:
        print_pretty(report)
    if args.json:
        print(json.dumps(report, indent=2))
    if not args.pretty and not args.json:
        print(json.dumps(report, indent=2))

    # Non-zero exit so the tool is usable in scripts/CI: fail on a broken
    # handshake, or on a hostname mismatch when certificate verification is on.
    if 'error' in negotiated:
        return 1
    hm = negotiated.get('hostname_match')
    if verify and hm is not None and not hm.get('matched'):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
