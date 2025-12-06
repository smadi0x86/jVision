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
    if not json_path.exists():
        print(f"[warning] fscan output file not found: {json_path}")
        return
    
    try:
        content = Path(json_path).read_text(encoding='utf-8').strip()
        
        if not content:
            print("[warning] fscan output is empty - no hosts found")
            return
        
        # fscan outputs comma-separated JSON objects, not a valid JSON array
        # Wrap it in brackets to make it a valid JSON array
        if content.endswith(','):
            content = content[:-1]  # Remove trailing comma
        json_content = '[' + content + ']'
        data = json.loads(json_content)
        
        if not data:
            print("[warning] No results in fscan JSON output")
            return
            
    except Exception as e:
        print(f"[warning] Failed to parse fscan JSON: {e}")
        print(f"[info] Attempting to parse as text format...")
        return parse_fscan_txt(json_path, subnet)
    
    # Group results by IP address
    hosts = {}
    
    for result in data:
        result_type = result.get("type")
        text = result.get("text", "")
        
        # Parse port scan results
        if result_type == "msg":
            # Format: "10.129.244.72:22 open"
            match = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)', text)
            if match:
                ip, port, state = match.groups()
                if ip not in hosts:
                    hosts[ip] = {
                        "ip": ip,
                        "hostname": None,
                        "services": [],
                        "domain_assets": [],
                        "os": None,
                        "comments": []
                    }
                
                hosts[ip]["services"].append(
                    ServicePayload(
                        port=int(port),
                        protocol="tcp",
                        state=state,
                    )
                )
        
        # Parse web titles
        elif result_type == "WebTitle":
            # Format: "http://10.129.244.72      code:302 len:154    title:302 Found 跳转url: http://fries.htb/"
            match = re.search(r'https?://(\d+\.\d+\.\d+\.\d+)', text)
            if match:
                ip = match.group(1)
                if ip not in hosts:
                    hosts[ip] = {
                        "ip": ip,
                        "hostname": None,
                        "services": [],
                        "domain_assets": [],
                        "os": None,
                        "comments": []
                    }
                
                # Extract title or redirect info
                title_match = re.search(r'title:(.+?)(?:\s+跳转url:|$)', text)
                if title_match:
                    title = title_match.group(1).strip()
                    if title and title != "None":
                        hosts[ip]["comments"].append(f"WebTitle: {title}")
                
                # Extract redirect URL
                redirect_match = re.search(r'跳转url:\s*(\S+)', text)
                if redirect_match:
                    redirect_url = redirect_match.group(1)
                    # Extract hostname from redirect
                    hostname_match = re.search(r'https?://([^/:]+)', redirect_url)
                    if hostname_match:
                        hostname = hostname_match.group(1)
                        if not hosts[ip]["hostname"]:
                            hosts[ip]["hostname"] = hostname
                    hosts[ip]["comments"].append(f"Redirect: {redirect_url}")
        
        # Parse NetInfo (domain/hostname info)
        elif result_type == "NetInfo":
            # Format: "\n[*]10.129.244.72\n   [->]DC01\n   [->]192.168.100.1..."
            lines = text.strip().split('\n')
            current_ip = None
            
            for line in lines:
                line = line.strip()
                # Match IP line
                ip_match = re.match(r'\[\*\](\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    if current_ip not in hosts:
                        hosts[current_ip] = {
                            "ip": current_ip,
                            "hostname": None,
                            "services": [],
                            "domain_assets": [],
                            "os": None,
                            "comments": []
                        }
                
                # Match info lines - handle both [->] and variations
                elif current_ip and line.startswith('[->]'):
                    info = line[4:].strip()
                    
                    if not info:
                        continue
                    
                    # Check if it's a hostname (not an IP or IPv6)
                    if not re.match(r'\d+\.\d+\.\d+\.\d+', info) and not info.startswith('dead:beef'):
                        if not hosts[current_ip]["hostname"]:
                            hosts[current_ip]["hostname"] = info
                            print(f"[info] Found hostname {info} for {current_ip}")
                        
                        # Check if it looks like a domain controller
                        # Match DC01, DC-01, JD-DC01, CORP-DC01, etc.
                        if re.search(r'DC[-_]?\d+', info, re.IGNORECASE):
                            print(f"[info] Detected domain controller: {info} at {current_ip}")
                            domain_asset = DomainAssetPayload(
                                hostname=info,
                                ip=current_ip,
                                isDomainController=True,
                            )
                            hosts[current_ip]["domain_assets"].append(domain_asset)
    
    if not hosts:
        print("[warning] No hosts extracted from fscan output")
        return
    
    print(f"[info] Parsed {len(hosts)} host(s) from fscan output")
    
    # Yield BoxPayload for each host
    for ip, host_data in hosts.items():
        # Fallback: If hostname looks like a DC but no domain asset was created, create one now
        hostname = host_data["hostname"]
        if hostname and not host_data["domain_assets"]:
            # Check if hostname indicates it's a domain controller
            if re.search(r'DC[-_]?\d+', hostname, re.IGNORECASE):
                print(f"[info] Detected DC from hostname fallback: {hostname} at {ip}")
                domain_asset = DomainAssetPayload(
                    hostname=hostname,
                    ip=ip,
                    isDomainController=True,
                )
                host_data["domain_assets"].append(domain_asset)
        
        services_count = len(host_data["services"])
        domain_count = len(host_data["domain_assets"])
        print(f"[info]   {ip} ({host_data.get('hostname') or 'no hostname'}) - {services_count} service(s), {domain_count} domain asset(s)")
        
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
        
        # Match patterns like: 10.129.244.72:80 open
        match = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)', line)
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
