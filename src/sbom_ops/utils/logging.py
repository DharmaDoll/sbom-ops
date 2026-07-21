from __future__ import annotations

import logging


def configure_logging(level: str) -> None:
    logging.basicConfig(level=level.upper())
