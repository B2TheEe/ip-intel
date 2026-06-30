# IP Intel

Network reconnaissance web app. Enter an IP or domain — get WHOIS, ASN, geolocation, reverse DNS, port scan, and DNS enumeration in one place.

![Dark terminal UI](https://img.shields.io/badge/stack-Python%20%2F%20Flask-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue)

## Features

| Module | Details |
|--------|---------|
| **WHOIS** | Registrar, dates, nameservers, status, emails, raw output |
| **ASN / Network** | AS number, CIDR, description, registry, abuse contact (RDAP) |
| **Geolocation** | Country, region, city, lat/lon, ISP, org (ip-api.com, no key needed) |
| **Reverse DNS** | PTR record lookup |
| **Port Scanner** | Async TCP scan, banner grabbing, presets: Common (30) / Top 100 / 1–1024 / Custom |
| **DNS Enumeration** | Record lookup (A/AAAA/MX/NS/TXT/SOA/CNAME/CAA), subdomain brute-force, AXFR zone transfer |

## Setup

```bash
git clone <repo>
cd ip-intel
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Usage

1. Enter an IP address or domain in the search box
2. Click **Scan** to run WHOIS / ASN / geo / reverse DNS
3. Click **Scan Ports** in panel 05 to run port scan
4. Click **Enumerate** in panel 06 to run DNS enumeration

### Port scan presets

| Preset | Ports |
|--------|-------|
| Common (30) | Top services: SSH, HTTP, HTTPS, MySQL, RDP, Redis, MongoDB, … |
| Top 100 | Extended common port list |
| 1–1024 | Full privileged range |
| Custom | Comma-separated or range: `22,80,443` or `8080-8090` |

### DNS enumeration options

- **Wordlist: Small (50)** — most common subdomains
- **Wordlist: Medium (200)** — extended list including dev/infra/admin subdomains
- **Brute-force** checkbox — disable to only run record lookup + zone transfer

## Stack

- **Backend** — Python 3.12, Flask 3, dnspython, ipwhois, python-whois, requests
- **Port scanner** — `asyncio` with semaphore (200 concurrent connections)
- **Subdomain brute-force** — `ThreadPoolExecutor` (50 workers)
- **Geolocation** — [ip-api.com](http://ip-api.com) free tier (no API key)
- **Frontend** — Vanilla JS, dark terminal theme

## Project structure

```
ip-intel/
├── app.py               # Flask routes: /api/recon, /api/portscan, /api/dnsenum
├── requirements.txt
├── recon/
│   ├── lookup.py        # WHOIS, ASN (RDAP), geolocation, reverse DNS
│   ├── portscan.py      # Async TCP port scanner + banner grabbing
│   └── dns_enum.py      # DNS records, subdomain brute-force, zone transfer
├── templates/
│   └── index.html
└── static/
    └── style.css
```

## Legal

For authorized use only. Only scan systems you own or have explicit permission to test.
