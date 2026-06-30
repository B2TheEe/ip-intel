import asyncio
import socket
from typing import Optional

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888, 27017, 6379, 5432, 1433, 2181, 9200, 9300, 6443,
]

TOP_100_PORTS = sorted(set(COMMON_PORTS + [
    7, 9, 13, 19, 37, 42, 49, 79, 81, 82, 83, 84, 85, 88, 106,
    113, 119, 144, 179, 199, 389, 427, 444, 458, 554, 587, 631,
    646, 873, 990, 992, 1080, 1099, 1194, 1433, 1521, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2222, 3000, 3128, 4444, 4848,
    5000, 5001, 5060, 5061, 5357, 5985, 5986, 7001, 7002, 7070,
    7777, 8000, 8001, 8008, 8009, 8010, 8081, 8090, 8180, 8888,
    9000, 9090, 9999, 10000, 49152,
]))


SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    587: "smtp/s", 993: "imaps", 995: "pop3s", 1723: "pptp",
    2181: "zookeeper", 3000: "dev-server", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    6443: "k8s-api", 8080: "http-alt", 8443: "https-alt",
    8888: "jupyter", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    9999: "abyss", 10000: "webmin", 27017: "mongodb",
}


async def _check_port(host: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = await _grab_banner(reader, writer, port, timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "state": "open", "service": _service_name(port), "banner": banner}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def _grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, timeout: float) -> Optional[str]:
    try:
        if port in (80, 8080, 8000, 8008, 8081, 8090, 8180, 8443, 443):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 1.5))
        if data:
            return data.decode("utf-8", errors="replace").strip()[:120]
    except Exception:
        pass
    return None


def _service_name(port: int) -> str:
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def parse_ports(spec: str) -> list[int]:
    """Parse port spec: 'common', 'top100', '80,443', '1-1024', or combinations."""
    spec = spec.strip().lower()
    if spec == "common":
        return COMMON_PORTS
    if spec in ("top100", "top-100"):
        return TOP_100_PORTS

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


async def scan(host: str, port_spec: str = "common", timeout: float = 1.0, max_concurrent: int = 200) -> dict:
    """Run async TCP port scan. Returns open ports sorted ascending."""
    ports = parse_ports(port_spec)
    if not ports:
        return {"error": "No valid ports specified", "open": [], "scanned": 0}

    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_check_port(host, p, timeout, semaphore) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = sorted(
        [r for r in results if r is not None],
        key=lambda x: x["port"]
    )
    return {
        "host": host,
        "scanned": len(ports),
        "open_count": len(open_ports),
        "open": open_ports,
        "error": None,
    }


def run_scan(host: str, port_spec: str = "common", timeout: float = 1.0) -> dict:
    """Sync wrapper for use outside async context."""
    return asyncio.run(scan(host, port_spec, timeout))
