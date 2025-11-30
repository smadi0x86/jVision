from dataclasses import dataclass
from pathlib import Path
import json


@dataclass
class UploaderConfig:
    server_url: str
    verify_ssl: bool = False
    batch_size: int = 50
    timeout: int = 15
    max_retries: int = 3
    backoff_seconds: float = 2.0
    rate_limit_delay: float = 0.5

    @staticmethod
    def from_file(path: Path) -> "UploaderConfig":
        data = json.loads(Path(path).read_text())
        return UploaderConfig(
            server_url=data["server_url"],
            verify_ssl=data.get("verify_ssl", False),
            batch_size=data.get("batch_size", 50),
            timeout=data.get("timeout", 15),
            max_retries=data.get("max_retries", 3),
            backoff_seconds=data.get("backoff_seconds", 2.0),
            rate_limit_delay=data.get("rate_limit_delay", 0.5),
        )
