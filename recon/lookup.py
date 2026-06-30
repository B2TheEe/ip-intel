import socket
import ipaddress
import requests
import whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError


def resolve_target(target: str) -> dict:
    """Resolve hostname to IP or validate IP. Returns {ip, hostname, is_private}."""
    result = {"ip": None, "hostname": target, "is_private": False, "error": None}
    try:
        ip = ipaddress.ip_address(target)
        result["ip"] = str(ip)
        result["is_private"] = ip.is_private
        try:
            result["hostname"] = socket.gethostbyaddr(str(ip))[0]
        except socket.herror:
            result["hostname"] = None
    except ValueError:
        try:
            result["ip"] = socket.gethostbyname(target)
            result["is_private"] = ipaddress.ip_address(result["ip"]).is_private
        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {e}"
    return result


def whois_lookup(target: str) -> dict:
    """WHOIS lookup for domain or IP."""
    try:
        w = whois.whois(target)
        raw = w.text if hasattr(w, "text") else str(w)
        return {
            "registrar": getattr(w, "registrar", None),
            "creation_date": _serialize_date(getattr(w, "creation_date", None)),
            "expiration_date": _serialize_date(getattr(w, "expiration_date", None)),
            "updated_date": _serialize_date(getattr(w, "updated_date", None)),
            "name_servers": _to_list(getattr(w, "name_servers", None)),
            "status": _to_list(getattr(w, "status", None)),
            "org": getattr(w, "org", None),
            "country": getattr(w, "country", None),
            "emails": _to_list(getattr(w, "emails", None)),
            "raw": raw,
            "error": None,
        }
    except Exception as e:
        return {"error": str(e), "raw": None}


def asn_lookup(ip: str) -> dict:
    """ASN + network info via ipwhois (RDAP)."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        network = result.get("network", {})
        asn_desc = result.get("asn_description", "")
        return {
            "asn": result.get("asn"),
            "asn_cidr": result.get("asn_cidr"),
            "asn_country": result.get("asn_country_code"),
            "asn_description": asn_desc,
            "asn_registry": result.get("asn_registry"),
            "network_name": network.get("name"),
            "network_cidr": network.get("cidr"),
            "network_type": network.get("type"),
            "abuse_emails": _extract_abuse_emails(result),
            "error": None,
        }
    except IPDefinedError:
        return {"error": "Private/reserved IP — no ASN data", "asn": None}
    except Exception as e:
        return {"error": str(e), "asn": None}


def geo_lookup(ip: str) -> dict:
    """Geolocation via ip-api.com (free, no key required)."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") == "fail":
            return {"error": data.get("message", "Lookup failed")}
        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "error": None,
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"hostname": hostname, "error": None}
    except socket.herror as e:
        return {"hostname": None, "error": str(e)}


def run_all(target: str) -> dict:
    """Run full recon on target. Returns combined results."""
    resolved = resolve_target(target)
    if resolved["error"]:
        return {"target": target, "error": resolved["error"]}

    ip = resolved["ip"]
    is_private = resolved["is_private"]

    results = {
        "target": target,
        "ip": ip,
        "hostname": resolved["hostname"],
        "is_private": is_private,
        "whois": whois_lookup(target),
        "asn": asn_lookup(ip) if not is_private else {"error": "Private IP — skipped"},
        "geo": geo_lookup(ip) if not is_private else {"error": "Private IP — skipped"},
        "reverse_dns": reverse_dns(ip),
        "error": None,
    }
    return results


def _serialize_date(value):
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value)


def _to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _extract_abuse_emails(rdap_result: dict) -> list:
    emails = set()
    for obj in rdap_result.get("objects", {}).values():
        for role in obj.get("roles", []):
            if "abuse" in role.lower():
                contact = obj.get("contact", {})
                for email_entry in contact.get("email", []):
                    if isinstance(email_entry, dict):
                        emails.add(email_entry.get("value", ""))
                    else:
                        emails.add(str(email_entry))
    return list(emails)
