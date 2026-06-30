# IP Intel

Network reconnaissance web app. Enter an IP or domain — get WHOIS, ASN, geolocation, reverse DNS, port scan, DNS enumeration, and SSL/TLS certificate inspection in one place.

![Stack](https://img.shields.io/badge/stack-Python%20%2F%20Flask-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

## Features

| Panel | Module | What you get |
|-------|--------|-------------|
| 01 | **WHOIS** | Registrar, org, country, creation/expiry/updated dates, nameservers, status flags, contact emails, raw WHOIS output |
| 02 | **ASN / Network** | AS number, description, CIDR, country, registry (ARIN/RIPE/…), network name, network type, abuse contact email (via RDAP) |
| 03 | **Geolocation** | Country, region, city, ZIP, lat/lon, ISP, org, AS string — no API key needed (ip-api.com free tier) |
| 04 | **Reverse DNS** | PTR record for resolved IP |
| 05 | **Port Scanner** | Async TCP scan with banner grabbing; presets: Common (30), Top 100, 1–1024, Custom range/list |
| 06 | **DNS Enumeration** | Record lookup, subdomain brute-force, AXFR zone transfer — three-tab UI |
| 07 | **SSL/TLS Inspector** | x509 cert details, cipher suite, TLS version, SANs, cert chain — configurable port |
| 08 | **Raw WHOIS** | Collapsible raw WHOIS text |

Accepts IP addresses or hostnames. Private/reserved IPs skip ASN, geo, and SSL panels automatically.

## Setup

```bash
git clone https://github.com/B2TheEe/ip-intel.git
cd ip-intel
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Usage

1. Enter IP or domain → click **Scan** (runs panels 01–04 + 08)
2. Panel 05 → choose preset → **Scan Ports**
3. Panel 06 → choose wordlist → **Enumerate**
4. Panel 07 → set port (default 443) → **Inspect**

### Port scan presets

| Preset | Description |
|--------|-------------|
| Common (30) | Key services: FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, SMB, RDP, MySQL, Redis, MongoDB, Elasticsearch, … |
| Top 100 | Extended list covering dev/infra/cloud ports |
| 1–1024 | Full privileged port range |
| Custom | Comma-separated or range — e.g. `22,80,443` or `8080-8090` |

Banner grabbing: HTTP ports get a `HEAD /` probe; all ports read first 256 bytes on connect.

### DNS enumeration tabs

| Tab | Details |
|-----|---------|
| **Records** | A, AAAA, MX (with priority), NS, TXT, SOA (mname/rname/serial/refresh/retry), CNAME, CAA |
| **Subdomains** | Concurrent brute-force — Small wordlist (50 entries) or Medium (200 entries); shows FQDN + resolved IPs |
| **Zone Transfer** | AXFR attempt against each discovered nameserver; shows "VULNERABLE" if transfer succeeds |

### SSL/TLS inspection

| Field | Notes |
|-------|-------|
| Subject / Issuer | CN, O, OU, C |
| Serial | Hex-encoded |
| Validity | Not-before, not-after, days remaining |
| Warnings | Orange badge for < 30 days remaining; red badge if expired; badge for self-signed |
| SANs | Full list — DNS and IP entries |
| Key | Type (RSA / EC with curve / Ed25519 / …) and bit size |
| Signature | Hash algorithm |
| TLS version | Negotiated version (TLSv1.2 / TLSv1.3 / …) |
| Cipher suite | Name and bit strength |
| Chain | Issuer chain with per-cert expiry |

Works on any port — useful for SMTPS (465), LDAPS (636), IMAPS (993), custom HTTPS.

## API

All endpoints accept `POST` with JSON body.

```
POST /api/recon         { "target": "example.com" }
POST /api/portscan      { "target": "example.com", "ports": "common", "timeout": 1.0 }
POST /api/dnsenum       { "target": "example.com", "brute": true, "wordlist": "small" }
POST /api/sslinspect    { "target": "example.com", "port": 443 }
```

`ports` accepts: `"common"`, `"top100"`, `"1-1024"`, or a custom spec like `"22,80,443,8080-8090"`.

## Stack

| Layer | Technology |
|-------|-----------|
| Web framework | Flask 3 |
| WHOIS | python-whois |
| ASN / IP intel | ipwhois (RDAP) |
| Geolocation | ip-api.com (no key) |
| Port scanner | asyncio + semaphore (200 concurrent) |
| DNS | dnspython |
| Subdomain brute | ThreadPoolExecutor (50 workers) |
| SSL/TLS parsing | stdlib `ssl` + `cryptography` |
| Frontend | Vanilla JS, dark terminal theme |

## Project structure

```
ip-intel/
├── app.py                  # Flask routes
├── requirements.txt
├── recon/
│   ├── lookup.py           # WHOIS, ASN (RDAP), geolocation, reverse DNS
│   ├── portscan.py         # Async TCP scanner + banner grabbing
│   ├── dns_enum.py         # DNS records, subdomain brute-force, zone transfer
│   └── ssl_inspect.py      # x509 cert parsing, cipher/TLS info, chain
├── templates/
│   └── index.html
└── static/
    └── style.css
```

## Legal

For authorized use only. Only scan systems you own or have explicit permission to test.
