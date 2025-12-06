# fscan Plugin Guide

## Overview

The fscan plugin integrates the [fscan](https://github.com/shadow1ng/fscan) fast network scanner into jVision. fscan is a comprehensive intranet scanning tool that performs quick port scanning, service detection, and vulnerability checks.

## Installation

1. Download fscan binary for your platform from: https://github.com/shadow1ng/fscan/releases
2. Place the `fscan` binary in your PATH or in the same directory as jvisionclient.py
3. Make it executable (Linux/Mac): `chmod +x fscan`

## Usage

### Single Plugin Mode

Use fscan only:
```bash
python3 jvisionclient.py <target> --plugin fscan --server <server-ip> --port 7777
```

Use nmap only (default):
```bash
python3 jvisionclient.py <target> --plugin nmap --server <server-ip> --port 7777
```

### Multi-Stage Mode (Recommended)

Run fscan for fast initial discovery, then nmap for detailed enumeration:
```bash
python3 multiscan.py <target> --server <server-ip> --port 7777
```

Options:
- `--skip-fscan` - Skip the fscan stage
- `--skip-nmap` - Skip the nmap stage
- `--timing <0-5>` - Nmap timing template (default: 3)
- `--top-ports <N>` - Scan only top N ports with nmap (default: 200)

## Examples

### Fast scan of a single host
```bash
python3 jvisionclient.py 192.168.1.100 --plugin fscan --server 10.10.10.5
```

### Scan a subnet with fscan, label as "internal"
```bash
python3 jvisionclient.py 192.168.1.0/24 --plugin fscan --subnet internal --server 10.10.10.5
```

### Multi-stage scan with custom timing
```bash
python3 multiscan.py 192.168.1.0/24 --server 10.10.10.5 --timing 4 --top-ports 1000
```

### Skip fscan, only run nmap
```bash
python3 multiscan.py 192.168.1.0/24 --server 10.10.10.5 --skip-fscan
```

## What Gets Captured

The fscan plugin extracts and uploads:

- **Host information**: IP address, hostname, OS detection
- **Service details**: Open ports, protocols, service names/versions
- **Domain assets**: Domain controllers, domain names, AD information
- **Vulnerabilities**: POCs and vulnerability findings (stored in comments)
- **Banners**: Service banners and additional info

## Output Format

fscan results are parsed from JSON output (preferred) or text format and converted into jVision's BoxPayload format with:
- Services mapped to ServicePayload objects
- Domain information mapped to DomainAssetPayload objects
- Vulnerability findings stored in the comments field

## Advantages of fscan

- **Speed**: Much faster initial discovery than nmap
- **Chinese targets**: Better at detecting Chinese services and applications
- **Integrated checks**: Includes built-in vulnerability checks
- **Domain awareness**: Good at identifying AD infrastructure

## Workflow Recommendation

1. **Fast discovery with fscan** → Get quick overview of the network
2. **Detailed enumeration with nmap** → Deep dive into interesting targets
3. **Review in jVision dashboard** → Assign ownership and track progress

This two-stage approach balances speed and thoroughness for red team operations.
