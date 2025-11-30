from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class ServicePayload:
    port: int
    protocol: Optional[str] = None
    state: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    script: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomainAssetPayload:
    hostname: str
    domainName: Optional[str] = None
    distinguishedName: Optional[str] = None
    role: Optional[str] = None
    ip: Optional[str] = None
    isDomainController: Optional[bool] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BoxPayload:
    ip: str
    state: Optional[str] = None
    hostname: Optional[str] = None
    subnet: Optional[str] = None
    standing: Optional[str] = None
    os: Optional[str] = None
    comments: Optional[str] = None
    services: List[ServicePayload] = field(default_factory=list)
    domainAssets: List[DomainAssetPayload] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["services"] = [svc.to_dict() for svc in self.services]
        payload["domainAssets"] = [asset.to_dict() for asset in self.domainAssets]
        return payload
