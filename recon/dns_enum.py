import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

WORDLIST_SMALL = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "cdn", "static", "assets", "media", "img", "images",
    "vpn", "ssh", "smtp", "imap", "pop", "pop3", "ns1", "ns2",
    "mx", "mx1", "mx2", "remote", "secure", "portal", "git", "gitlab",
    "github", "jenkins", "ci", "jira", "confluence", "wiki", "docs",
    "help", "support", "status", "monitor", "grafana", "kibana", "elastic",
    "app", "apps", "web", "webmail", "owa", "autodiscover", "mobile",
]

WORDLIST_MEDIUM = WORDLIST_SMALL + [
    "alpha", "beta", "gamma", "prod", "production", "preview", "demo",
    "old", "new", "v1", "v2", "v3", "internal", "intranet", "corp",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
    "payment", "pay", "billing", "invoice", "store", "checkout",
    "search", "analytics", "track", "data", "db", "database", "mysql",
    "postgres", "redis", "mongo", "cache", "queue", "mq", "rabbitmq",
    "kafka", "zookeeper", "k8s", "kube", "kubernetes", "docker",
    "registry", "repo", "nexus", "artifactory", "sonar", "vault",
    "consul", "nomad", "terraform", "ansible", "puppet", "chef",
    "backup", "bak", "archive", "logs", "log", "metrics", "stats",
    "reporting", "reports", "dashboard", "panel", "control", "manage",
    "mgmt", "management", "admin2", "sysadmin", "root", "cpanel",
    "whm", "plesk", "directadmin", "phpmyadmin", "adminer",
    "ns3", "ns4", "dns", "dns1", "dns2", "ntp", "time",
    "ldap", "ad", "exchange", "sharepoint", "teams", "meet", "video",
    "chat", "slack", "crm", "erp", "hr", "finance", "legal",
    "download", "downloads", "upload", "uploads", "files", "file",
    "s3", "storage", "backup1", "backup2", "mirror", "proxy",
    "gateway", "edge", "lb", "load", "haproxy", "nginx", "apache",
    "server", "server1", "server2", "host", "host1", "host2",
    "node", "node1", "node2", "worker", "master", "slave",
    "primary", "secondary", "replica", "standby", "dr",
]

WORDLISTS = {
    "small": WORDLIST_SMALL,
    "medium": WORDLIST_MEDIUM,
}


def lookup_records(domain: str) -> dict:
    """Look up all common DNS record types for a domain."""
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append({"priority": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")})
                elif rtype == "SOA":
                    records.append({
                        "mname": str(rdata.mname).rstrip("."),
                        "rname": str(rdata.rname).rstrip("."),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum,
                    })
                elif rtype == "TXT":
                    records.append(" ".join(p.decode("utf-8", errors="replace") for p in rdata.strings))
                else:
                    records.append(str(rdata).rstrip("."))
            results[rtype] = {"records": records, "error": None}
        except dns.resolver.NoAnswer:
            results[rtype] = {"records": [], "error": None}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"records": [], "error": "NXDOMAIN"}
        except dns.exception.DNSException as e:
            results[rtype] = {"records": [], "error": str(e)}

    return results


def zone_transfer(domain: str, nameservers: list[str]) -> dict:
    """Attempt AXFR zone transfer against each nameserver."""
    attempts = []
    for ns in nameservers[:4]:
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            records = []
            for name, node in z.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} {rdataset.ttl} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
            attempts.append({"ns": ns, "success": True, "records": records, "error": None})
        except dns.exception.FormError:
            attempts.append({"ns": ns, "success": False, "records": [], "error": "Transfer refused"})
        except Exception as e:
            attempts.append({"ns": ns, "success": False, "records": [], "error": str(e)})

    return {"attempts": attempts}


def _resolve_subdomain(subdomain: str, domain: str) -> dict | None:
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
        ips = [str(r) for r in answers]
        return {"subdomain": fqdn, "ips": ips}
    except Exception:
        return None


def brute_subdomains(domain: str, wordlist: str = "small", max_workers: int = 50) -> dict:
    """Brute-force subdomains using wordlist. Returns found subdomains."""
    words = WORDLISTS.get(wordlist, WORDLIST_SMALL)
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve_subdomain, w, domain): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x["subdomain"])
    return {
        "domain": domain,
        "wordlist": wordlist,
        "checked": len(words),
        "found": found,
        "found_count": len(found),
        "error": None,
    }


def run_dns_enum(domain: str, brute: bool = True, wordlist: str = "small") -> dict:
    """Full DNS enumeration: records + zone transfer + optional brute-force."""
    records = lookup_records(domain)

    ns_list = [r for r in records.get("NS", {}).get("records", [])]
    zone = zone_transfer(domain, ns_list)

    brute_results = brute_subdomains(domain, wordlist) if brute else None

    return {
        "domain": domain,
        "records": records,
        "zone_transfer": zone,
        "brute": brute_results,
        "error": None,
    }
