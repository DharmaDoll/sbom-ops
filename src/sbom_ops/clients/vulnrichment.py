"""Bounded HTTPS retrieval from the official CISA repository only."""

import json
import ssl
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from sbom_ops.domain.vulnrichment import VulnrichmentError, validate_request

MAX_RESPONSE_BYTES = 1024 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("nonstandard JSON constant")


class VulnrichmentClient:
    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._opener = build_opener(HTTPSHandler(context=context), _NoRedirect())

    def get_record(self, cve: str, revision: str) -> object:
        validate_request(cve, revision)
        _, year, sequence = cve.split("-")
        request = Request(
            f"https://raw.githubusercontent.com/cisagov/vulnrichment/{revision}/"
            f"{year}/{sequence[:-3]}xxx/{cve}.json",
            headers={"Accept": "application/json", "User-Agent": "sbom-ops/0.1"},
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise VulnrichmentError("http_error", status=response.status)
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise VulnrichmentError("response_too_large")
        except HTTPError as exc:
            exc.close()
            raise VulnrichmentError("http_error", status=exc.code) from None
        except (URLError, OSError, HTTPException):
            raise VulnrichmentError("transport_error") from None
        try:
            return json.loads(
                body, object_pairs_hook=_unique_object, parse_constant=_reject_constant
            )
        except (ValueError, UnicodeError, RecursionError):
            raise VulnrichmentError("invalid_json") from None
