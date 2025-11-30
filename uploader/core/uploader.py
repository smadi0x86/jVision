from __future__ import annotations

import time
import json
from typing import Iterable, List
import requests

from .config import UploaderConfig
from .models import BoxPayload


class UploadError(Exception):
    pass


class Uploader:
    def __init__(self, config: UploaderConfig):
        self.config = config

    def send_boxes(self, boxes: Iterable[BoxPayload]):
        batch: List[BoxPayload] = []
        for box in boxes:
            batch.append(box)
            if len(batch) >= self.config.batch_size:
                self._flush(batch)
                batch = []
                time.sleep(self.config.rate_limit_delay)
        if batch:
            self._flush(batch)

    def _flush(self, batch: List[BoxPayload]):
        payload = [box.to_dict() for box in batch]
        for attempt in range(1, self.config.max_retries + 1):
            try:
                response = requests.post(
                    f"{self.config.server_url}/box",
                    json=payload,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                )
                if response.status_code >= 400:
                    raise UploadError(response.text)
                return
            except Exception as exc:
                if attempt == self.config.max_retries:
                    raise UploadError(f"Failed after {attempt} attempts: {exc}")
                time.sleep(self.config.backoff_seconds * attempt)
