from __future__ import annotations

from typing import Protocol

from bharatguard.models import PIIEntity


class Detector(Protocol):
    def detect(self, text: str) -> list[PIIEntity]: ...
