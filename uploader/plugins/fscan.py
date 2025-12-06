from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, List

from ..core import BoxPayload, ServicePayload, DomainAssetPayload


def _find_fscan() -> Path:
    """Locate the fscan binary in the home directory or PATH."""
    # Check home directory first
    home = Path.home()
    fscan_home = home / "fscan"
    if fscan_home.exists() and fscan_home.is_file():
        return fscan_home
    
    # Check common locations in home directory
    for pattern in ["fscan*", "*/fscan", "bin/fscan"]:
        matches = list(home.glob(pattern))
        for match in matches:
            if match.is_file() and os.access(match, os.X_OK):
                return match
    
    # Fallback to PATH
    import shutil
    fscan_path = shutil.which("fscan")
    if fscan_path:
        return Path(fscan_path)
    
    raise FileNotFoundError(
        "fscan binary not found in home directory or PATH. "
        "Please place fscan in your home directory or add it to PATH."
    )


def _run_fscan(target: str) -> Path:
    """Run fscan and return the path to the JSON output file."""
    fscan_bin = _find_fscan()
    print(f"[info] Using fscan binary at: {fscan_bin}")
    
    safe_name = re.sub(r"[^0-9A-Za-z._-]", "_", target)
    tmp_dir = Path(tempfile.gettempdir())
    output_path = tmp_dir / f"fscan_{safe_name}.json"
    
    cmd = [
        str(fscan_bin),
        "-h", target,
        "-o", str(output_path),
        "-nobr",
        "-json"
    ]
    
    print(f"[info] Running fscan on {target}...")
    subprocess.run(cmd, check=True)
    return output_path


def parse_fscan_json(json_path: Path, subnet: str | None = None) -> Iterable[BoxPayload]:
    """Parse fscan JSON output and yield BoxPayload objects."""
    try:
        data = json.loads(Path(json_path).read_text(encoding='utf-8'))
    except Exception as e:
        print(f"[warning] Failed to parse fscan JSON: {e}")
        return
    
    # Group results by IP address
    hosts = {}
    
    for result in data:
        ip = result.get("ip") or result.get("host")
        if not ip:
            continue
        
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "hostname": result.get("hostname"),
                "services": [],
                "domain_assets": [],
                "os": result.get("os"),
                "comments": []
            }
        
        # Extract service information
        port = result.get("port")
        if port:
            service = ServicePayload(
                port=int(port),
                protocol=result.get("protocol", "tcp"),
                state="open",
                name=result.get("service"),
                version=result.get("version"),
                script=result.get("banner") or result.get("info")
            )
            hosts[ip]["services"].append(service)
        
        # Extract domain information (if present)
        if result.get("is_domain_controller") or result.get("domain"):
            domain_asset = DomainAssetPayload(
                hostname=result.get("hostname", ip),
                domainName=result.get("domain"),
                distinguishedName=result.get("dn"),
                role=result.get("role"),
                ip=ip,
                isDomainController=result.get("is_domain_controller", False),
                notes=result.get("notes")
            )
            hosts[ip]["domain_assets"].append(domain_asset)
        
        # Collect vulnerability or additional info
        vuln = result.get("vulnerability") or result.get("poc")
        if vuln:
            hosts[ip]["comments"].append(vuln)
    
    # Yield BoxPayload for each host
    for ip, host_data in hosts.items():
        yield BoxPayload(
            ip=host_data["ip"],
            hostname=host_data["hostname"],
            state="up",
            subnet=subnet,
            os=host_data["os"],
            comments="\n".join(host_data["comments"]) if host_data["comments"] else None,
            services=host_data["services"],
            domainAssets=host_data["domain_assets"]
        )


def parse_fscan_txt(txt_path: Path, subnet: str | None = None) -> Iterable[BoxPayload]:
    """Parse fscan text output (fallback if JSON not available)."""
    try:
        content = Path(txt_path).read_text(encoding='utf-8')
    except Exception as e:
        print(f"[warning] Failed to read fscan output: {e}")
        return
    
    hosts = {}
    
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        
        # Match patterns like: [+] 192.168.1.1:80 open
        match = re.match(r'\[.*?\]\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)', line)
        if match:
            ip, port, state = match.groups()
            if ip not in hosts:
                hosts[ip] = {"ip": ip, "services": [], "domain_assets": []}
            
            hosts[ip]["services"].append(
                ServicePayload(
                    port=int(port),
                    protocol="tcp",
                    state=state,
                )
            )
    
    for ip, host_data in hosts.items():
        yield BoxPayload(
            ip=host_data["ip"],
            state="up",
            subnet=subnet,
            services=host_data["services"],
            domainAssets=host_data["domain_assets"]
        )


def collect(target: str, subnet: str | None = None, **kwargs) -> Iterable[BoxPayload]:
    """Run fscan and collect results."""
    output_path = _run_fscan(target)
    print(f"[info] fscan output saved to {output_path}")
    
    # Try JSON parsing first, fallback to text parsing
    if output_path.suffix == ".json":
        return parse_fscan_json(output_path, subnet=subnet or target)
    else:
        return parse_fscan_txt(output_path, subnet=subnet or target)
