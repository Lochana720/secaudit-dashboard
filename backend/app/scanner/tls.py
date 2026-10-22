"""HTTPS / TLS configuration checks using the standard library + cryptography."""
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .base import Finding

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon")
REF = "https://wiki.mozilla.org/Security/Server_Side_TLS"


def _f(check_id, title, severity, passed, desc, rec="", evidence=None, ref=REF):
    return Finding(check_id, "tls", title, severity, passed, desc, rec, evidence, ref)


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.version(), ssock.cipher(), ssock.getpeercert(binary_form=True)


def _insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _probe_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> str:
    """Returns 'supported', 'not_supported' or 'untestable'."""
    try:
        ctx = _insecure_ctx()
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        ctx.minimum_version = version
        ctx.maximum_version = version
        _connect(host, port, ctx, timeout)
        return "supported"
    except ValueError:
        return "untestable"
    except ssl.SSLError as exc:
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "no protocols available" in str(exc):
            return "untestable"
        return "not_supported"
    except OSError:
        return "not_supported"


def _name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    org = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return str(org[0].value) if org else name.rfc4514_string()


def check_tls(host: str, port: int, timeout: float) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    meta: dict = {"host": host, "port": port}

    cert_trusted, verify_error = True, None
    try:
        version, cipher, der = _connect(host, port, ssl.create_default_context(), timeout)
    except ssl.SSLCertVerificationError as exc:
        cert_trusted, verify_error = False, exc.verify_message or str(exc)
        try:
            version, cipher, der = _connect(host, port, _insecure_ctx(), timeout)
        except (OSError, ssl.SSLError) as exc2:
            meta.update(available=False, error=str(exc2))
            return [_f("tls.available", "HTTPS is not available", "critical", False,
                       "A TLS connection could not be established.",
                       "Enable HTTPS with a valid certificate (e.g. Let's Encrypt).", str(exc2))], meta
    except (OSError, ssl.SSLError) as exc:
        meta.update(available=False, error=str(exc))
        return [_f("tls.available", "HTTPS is not available", "critical", False,
                   f"Could not connect to {host}:{port} over TLS. All traffic may be sent in plain text.",
                   "Enable HTTPS with a valid certificate (e.g. Let's Encrypt) and redirect HTTP to HTTPS.",
                   str(exc))], meta

    meta["available"] = True
    findings.append(_f("tls.available", "HTTPS is available", "critical", True,
                       "The server accepts TLS connections."))

    # --- certificate ---
    cert = x509.load_der_x509_certificate(der)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = f"EC ({pub.curve.name})", pub.curve.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", pub.key_size
    else:
        key_type, key_bits = type(pub).__name__.replace("PublicKey", ""), None
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"

    meta.update(
        protocol=version,
        cipher=cipher[0] if cipher else None,
        cipher_bits=cipher[2] if cipher else None,
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        sans=sans[:50],
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_left=days_left,
        key_type=key_type,
        key_bits=key_bits,
        signature_hash=sig_hash,
        serial=format(cert.serial_number, "x"),
        trusted=cert_trusted,
        verify_error=verify_error,
    )

    if cert_trusted:
        findings.append(_f("tls.cert_trusted", "Certificate is trusted and matches hostname", "high", True,
                           f"Issued by {meta['issuer']}."))
    else:
        findings.append(_f("tls.cert_trusted", "Certificate is not trusted", "high", False,
                           "Browsers will show a security warning. Possible causes: self-signed certificate, "
                           "incomplete chain, or hostname mismatch.",
                           "Install a certificate from a trusted CA and serve the full intermediate chain.",
                           verify_error))

    if days_left < 0:
        findings.append(_f("tls.cert_expiry", "Certificate has expired", "critical", False,
                           f"The certificate expired {abs(days_left)} days ago.",
                           "Renew the certificate immediately and enable automatic renewal.",
                           f"notAfter={not_after:%Y-%m-%d}"))
    elif days_left < 14:
        findings.append(_f("tls.cert_expiry", "Certificate expires very soon", "high", False,
                           f"Only {days_left} days left before expiry.",
                           "Renew now and automate renewal (certbot / ACME).", f"notAfter={not_after:%Y-%m-%d}"))
    elif days_left < 30:
        findings.append(_f("tls.cert_expiry", "Certificate expires within 30 days", "medium", False,
                           f"{days_left} days left before expiry.", "Plan renewal or verify auto-renewal works.",
                           f"notAfter={not_after:%Y-%m-%d}"))
    else:
        findings.append(_f("tls.cert_expiry", "Certificate validity period is healthy", "high", True,
                           f"{days_left} days until expiry.", evidence=f"notAfter={not_after:%Y-%m-%d}"))

    weak_key = (key_type == "RSA" and key_bits and key_bits < 2048) or (key_type == "DSA")
    findings.append(_f("tls.key_strength", "Weak certificate key" if weak_key else "Certificate key strength is adequate",
                       "high", not weak_key,
                       f"Key: {key_type} {key_bits or ''} bits.",
                       "Use RSA ≥ 2048 bits or an ECDSA P-256 key." if weak_key else "",
                       f"{key_type} {key_bits}"))

    weak_sig = sig_hash.lower() in {"md5", "sha1"}
    findings.append(_f("tls.signature", "Weak certificate signature algorithm" if weak_sig else "Strong signature algorithm",
                       "high", not weak_sig, f"Signature hash: {sig_hash}.",
                       "Reissue the certificate with SHA-256 or stronger." if weak_sig else "", sig_hash))

    # --- negotiated protocol / cipher ---
    modern = version in {"TLSv1.3", "TLSv1.2"}
    findings.append(_f("tls.protocol", f"Negotiated protocol: {version}", "high", modern,
                       "TLS 1.2 and 1.3 are the only versions considered secure today.",
                       "" if modern else "Disable SSLv3/TLS 1.0/1.1 and enable TLS 1.2+ (prefer 1.3).", version))
    if version == "TLSv1.2":
        findings.append(_f("tls.tls13", "TLS 1.3 not negotiated", "info", False,
                           "The server negotiated TLS 1.2. TLS 1.3 is faster and removes legacy ciphers.",
                           "Enable TLS 1.3 in your web server / load balancer.", version))

    cname = cipher[0] if cipher else ""
    weak_cipher = any(m.upper() in cname.upper() for m in WEAK_CIPHER_MARKERS)
    findings.append(_f("tls.cipher", "Weak cipher negotiated" if weak_cipher else "Strong cipher negotiated",
                       "high", not weak_cipher, f"Cipher: {cname} ({cipher[2] if cipher else '?'} bits).",
                       "Restrict ciphers to AEAD suites (AES-GCM, CHACHA20-POLY1305)." if weak_cipher else "",
                       cname))

    # --- legacy protocol support ---
    legacy = {}
    for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        legacy[label] = _probe_protocol(host, port, ver, timeout)
    meta["legacy_protocols"] = legacy
    enabled = [k for k, v in legacy.items() if v == "supported"]
    untestable = [k for k, v in legacy.items() if v == "untestable"]
    if enabled:
        findings.append(_f("tls.legacy", "Deprecated TLS versions enabled", "medium", False,
                           f"Server still accepts {', '.join(enabled)}, deprecated by RFC 8996.",
                           "Disable TLS 1.0 and 1.1 in the server configuration.", ", ".join(enabled)))
    elif len(untestable) < len(legacy):
        findings.append(_f("tls.legacy", "Deprecated TLS versions disabled", "medium", True,
                           "TLS 1.0 / 1.1 handshakes were rejected."
                           + (f" (Could not test: {', '.join(untestable)})" if untestable else "")))

    return findings, meta
