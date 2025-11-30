from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, List
from bs4 import BeautifulSoup

from ..core import BoxPayload, ServicePayload


def _run_nmap(target: str, timing: str, top_ports: int | None = None) -> Path:
    safe_name = re.sub(r"[^0-9A-Za-z._-]", "_", target)
    tmp_dir = Path(tempfile.gettempdir())
    output_path = tmp_dir / f"nmap_{safe_name}.xml"
    cmd = [
        "nmap",
        f"-T{timing}",
        "-sV",
        "--host-timeout",
        "30s",
        "-oX",
        str(output_path),
        target,
    ]
    if top_ports:
        cmd[2:2] = ["--top-ports", str(top_ports)]
    subprocess.run(cmd, check=True)
    return output_path


def parse_nmap_xml(xml_path: Path, subnet: str | None = None) -> Iterable[BoxPayload]:
    soup = BeautifulSoup(Path(xml_path).read_text(), "xml")
    for host in soup.find_all("host"):
        addresses = host.find_all("address")
        ip = None
        for addr in addresses:
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue

        hostname_node = host.find("hostname")
        hostname = hostname_node.get("name") if hostname_node else None
        status_node = host.find("status")
        state = status_node.get("state") if status_node else None

        services: List[ServicePayload] = []
        for port in host.find_all("port"):
            services.append(
                ServicePayload(
                    port=int(port.get("portid", 0)),
                    protocol=port.get("protocol"),
                    state=port.state.get("state") if port.state else None,
                    name=port.service.get("name") if port.service else None,
                    version=port.service.get("version") if port.service else None,
                    script=port.script.get("output") if port.script else None,
                )
            )

        yield BoxPayload(
            ip=ip,
            hostname=hostname,
            state=state,
            subnet=subnet,
            services=services,
        )


def collect(target: str, subnet: str | None, timing: str, top_ports: int | None) -> Iterable[BoxPayload]:
    xml_path = _run_nmap(target, timing, top_ports)
    print(f"[info] Nmap XML saved to {xml_path}")
    return parse_nmap_xml(xml_path, subnet=subnet or target)
