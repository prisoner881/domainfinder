"""Live TLS certificate: Subject O= and SANs.

The certificate is read, not trusted: verification is off on purpose because
the goal is to look at whatever certificate the host presents. Behind a
TLS-intercepting proxy the certificate is the proxy's, which normally carries
no O=, so the check then simply yields no evidence.
"""

from __future__ import annotations

import asyncio
import ssl

from ..models import CertInfo


def parse_der(der: bytes) -> CertInfo:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    import warnings

    info = CertInfo(fetched=True)
    with warnings.catch_warnings():
        # Some servers present certificates with a non-positive serial number;
        # we only read their names, so cryptography's deprecation warning is noise.
        warnings.simplefilter("ignore")
        cert = x509.load_der_x509_certificate(der)
    try:
        orgs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        info.subject_org = str(orgs[0].value).strip() if orgs else ""
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info.subject_cn = str(cns[0].value).strip() if cns else ""
        info.issuer = cert.issuer.rfc4514_string()[:200]
    except (ValueError, IndexError):
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        info.sans = [n.lower() for n in ext.value.get_values_for_type(x509.DNSName)][:500]
    except (x509.ExtensionNotFound, ValueError):
        pass
    import hashlib

    from cryptography.hazmat.primitives import serialization

    info.sha256 = hashlib.sha256(der).hexdigest()
    try:
        spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        info.spki_sha256 = hashlib.sha256(spki).hexdigest()
    except (ValueError, TypeError):
        pass
    info.has_scts = has_scts(der)
    return info


# DER encoding of OID 1.3.6.1.4.1.11129.2.4.2 (embedded SCT list). Publicly
# trusted certificates carry it; certificates minted by a TLS-intercepting
# proxy normally do not, which is how interception is told apart.
_SCT_OID_DER = bytes.fromhex("060a2b06010401d679020402")


def has_scts(der: bytes) -> bool:
    return _SCT_OID_DER in der


def covers(sans: list[str], host: str) -> bool:
    """Does a certificate with these SANs cover `host` (exact or one-label wildcard)?"""
    host = host.lower().rstrip(".")
    for san in sans:
        san = san.lower().rstrip(".")
        if san == host:
            return True
        if san.startswith("*.") and "." in host and host.split(".", 1)[1] == san[2:]:
            return True
    return False


async def fetch_cert(host: str, port: int = 443, timeout: float = 8.0) -> CertInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
        )
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        if not der:
            return CertInfo(error="no certificate")
        return parse_der(der)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError) as e:
        return CertInfo(error=f"{type(e).__name__}: {e}"[:200])
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError, ssl.SSLError):
                pass
