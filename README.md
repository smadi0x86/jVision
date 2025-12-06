# jVision

Collaboration dashboard for red team reconnaissance operations. Share your scan results with the team and assign ownership to every target (Alex owns 192.168.1.1, Bob owns 192.168.1.2, etc...).

## Server

### Quickstart

```bash
docker compose up -d
```

### Build

**Schema update:** After pulling the latest changes (DomainAsset support), run the EF migration before starting:

```bash
cd Server
DOTNET_ROLL_FORWARD=Major dotnet ef database update
```

Then build and run:

```bash
docker build -t jvision-local .
docker run -d -p 7777:7777 --name jvision jvision-local
```

## Client

### Quickstart

```bash
pip install --user requests beautifulsoup4 lxml pwntools
python3 jvisionclient.py -i <server-ip> -p 7777 -s <target-subnet>
```

### Plugin Options

**Nmap (default):**
```bash
python3 jvisionclient.py <target> --server <server-ip> --port 7777 --plugin nmap
```

**fscan (fast Chinese scanner):**
```bash
python3 jvisionclient.py <target> --server <server-ip> --port 7777 --plugin fscan
```

**Multi-stage (fscan → nmap):**
```bash
python3 multiscan.py <target> --server <server-ip> --port 7777
```

> Need more control? POST your own JSON to `http://<server>:7777/box` matching the `BoxDTO` shape (IP, hostname, standing, services[], domainAssets[]).

## User Guide

1. Join the shared server and register.
2. Pick your assigned subnet/target list.
3. Use the uploader to send your scan results.
4. Update box ownership/standing/comments in the dashboard after each action so everyone sees the current state.

## Changes Made by Saif

### fscan Plugin Integration
- **New plugin**: `uploader/plugins/fscan.py` - Fast network scanner integration with domain controller detection
- **Auto-detection**: Finds fscan binary in home directory or PATH
- **Domain asset parsing**: Detects domain controllers by hostname patterns (DC01, JD-DC01, CORP-DC01, etc.)
- **JSON/Text parsing**: Handles fscan's comma-separated JSON output format
- **Web title extraction**: Captures HTTP titles and redirects
- **Duplicate prevention**: Avoids creating duplicate domain assets
- **Comments integration**: Adds domain controller status to box comments for GUI visibility

### Multi-Stage Scanner
- **New tool**: `multiscan.py` - Runs fscan (fast) → nmap (detailed) sequentially
- **Flexible options**: Skip either stage with `--skip-fscan` or `--skip-nmap`

### CLI Updates
- **Plugin selection**: `--plugin` argument supports both `nmap` and `fscan`
- **Plugin-specific handling**: Different parameter handling for each scanner type

### Documentation
- **Plugin guide**: `FSCAN_PLUGIN.md` - Complete fscan usage and installation guide
- **README updates**: Added plugin options and usage examples
- **TODO tracking**: Marked plugin implementation tasks as completed

### Docker Improvements
- **Local build**: Changed docker-compose to build locally instead of pulling from Docker Hub
- **Environment config**: Added proper environment variables for development
