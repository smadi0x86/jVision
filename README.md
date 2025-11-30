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

> Need more control? POST your own JSON to `http://<server>:7777/box` matching the `BoxDTO` shape (IP, hostname, standing, services[]).

## User Guide

1. Join the shared server and register.
2. Pick your assigned subnet/target list.
3. Use the uploader to send your scan results.
4. Update box ownership/standing/comments in the dashboard after each action so everyone sees the current state.
