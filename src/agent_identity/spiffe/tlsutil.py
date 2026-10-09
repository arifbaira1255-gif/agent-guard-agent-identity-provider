"""mTLS helpers built from the workload's X.509-SVID. Chain validation by OpenSSL against the
trust-domain roots, then SPIFFE-ID authorization through the provider (hostnames are not used)."""
import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .errors import SvidError

_MIN = {"TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}


def _context(server: bool, svid, bundle_roots, min_version: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _MIN[min_version]
    ctx.check_hostname = False                    # identity is the SPIFFE ID, checked post-handshake
    ctx.verify_mode = ssl.CERT_REQUIRED
    pem_roots = "".join(r.public_bytes(serialization.Encoding.PEM).decode() for r in bundle_roots)
    ctx.load_verify_locations(cadata=pem_roots)
    chain_pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in svid.chain)
    key_pem = serialization.load_der_private_key(svid.private_key_pkcs8_der(), None).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd, path = tempfile.mkstemp(prefix="svid-")   # 0600; removed immediately after load
    try:
        os.write(fd, chain_pem.encode() + key_pem)
        os.close(fd)
        ctx.load_cert_chain(path)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    return ctx


def server_context(svid, bundle_roots, min_version="TLSv1.3"):
    return _context(True, svid, bundle_roots, min_version)


def client_context(svid, bundle_roots, min_version="TLSv1.3"):
    return _context(False, svid, bundle_roots, min_version)


def peer_chain_der(ssl_sock) -> list:
    """Full chain the peer PRESENTED (leaf first), DER. SPIFFE SVIDs may carry intermediates, so the
    leaf alone is not enough. Chain trust is still decided by verify_x509 against the bundle; if the
    runtime cannot expose the presented chain we fail closed rather than verify a partial one."""
    getter = getattr(ssl_sock, "get_unverified_chain", None)            # public API on Python 3.13+
    if getter is None:
        getter = getattr(getattr(ssl_sock, "_sslobj", None), "get_unverified_chain", None)  # 3.10-3.12
    if getter is None:
        raise SvidError("runtime cannot expose the peer certificate chain")
    certs = getter()
    if not certs:
        raise SvidError("peer presented no certificate")
    out = []
    for c in certs:
        if isinstance(c, bytes):
            out.append(c)
        else:   # _ssl.Certificate: public_bytes() default is PEM text
            out.append(ssl.PEM_cert_to_DER_cert(c.public_bytes()))
    return out
