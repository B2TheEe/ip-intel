import ssl
import socket
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID


def inspect(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Fetch and parse SSL/TLS certificate + connection info for host:port."""
    try:
        raw_cert, conn_info = _fetch_cert(host, port, timeout)
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}

    try:
        cert = x509.load_der_x509_certificate(raw_cert)
    except Exception as e:
        return {"host": host, "port": port, "error": f"Failed to parse cert: {e}"}

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_remaining = (not_after - now).days
    is_expired = days_remaining < 0
    expiry_warning = not is_expired and days_remaining < 30

    subject = _parse_name(cert.subject)
    issuer = _parse_name(cert.issuer)
    is_self_signed = subject.get("CN") == issuer.get("CN") and subject.get("O") == issuer.get("O")

    return {
        "host": host,
        "port": port,
        "subject": subject,
        "issuer": issuer,
        "serial": format(cert.serial_number, "x").upper(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "expiry_warning": expiry_warning,
        "is_self_signed": is_self_signed,
        "sans": _get_sans(cert),
        "sig_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        "key_type": _key_type(cert),
        "key_bits": _key_bits(cert),
        "tls_version": conn_info.get("tls_version"),
        "cipher": conn_info.get("cipher"),
        "chain": conn_info.get("chain", []),
        "error": None,
    }


def _fetch_cert(host: str, port: int, timeout: float) -> tuple[bytes, dict]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cipher_info = ssock.cipher()
            tls_version = ssock.version()

            # Grab chain via ctx with CERT_OPTIONAL
            chain = []
            try:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_OPTIONAL
                with socket.create_connection((host, port), timeout=timeout) as s2:
                    with ctx2.wrap_socket(s2, server_hostname=host) as ss2:
                        for c in ss2.get_verified_chain() or []:
                            parsed = x509.load_der_x509_certificate(c)
                            chain.append({
                                "subject": _name_str(parsed.subject),
                                "issuer": _name_str(parsed.issuer),
                                "not_after": parsed.not_valid_after_utc.isoformat(),
                            })
            except Exception:
                pass

            return der, {
                "tls_version": tls_version,
                "cipher": {"name": cipher_info[0], "protocol": cipher_info[1], "bits": cipher_info[2]} if cipher_info else None,
                "chain": chain,
            }


def _parse_name(name) -> dict:
    result = {}
    oid_map = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
    }
    for attr in name:
        key = oid_map.get(attr.oid)
        if key:
            result[key] = attr.value
    return result


def _name_str(name) -> str:
    parts = []
    for attr in name:
        parts.append(f"{attr.oid.dotted_string}={attr.value}")
    cn = next((a.value for a in name if a.oid == NameOID.COMMON_NAME), None)
    return cn or ", ".join(parts)


def _get_sans(cert) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = []
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                sans.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                sans.append(f"email:{name.value}")
        return sans
    except x509.ExtensionNotFound:
        return []


def _key_type(cert) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})"
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    return "Unknown"


def _key_bits(cert) -> int | None:
    pub = cert.public_key()
    try:
        return pub.key_size
    except AttributeError:
        return None
