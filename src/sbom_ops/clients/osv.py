"""Official OSV GET-by-ID adapter; no linked URL access or business decisions."""

from __future__ import annotations

import json
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sbom_ops.domain.identifier_candidates import IdentifierFetchError


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class OsvClient:
    def __init__(self) -> None:
        self._opener = build_opener(_NoRedirect())

    def get_vulnerability(self, identifier: str) -> object:
        request = Request(
            f"https://api.osv.dev/v1/vulns/{quote(identifier, safe='')}",
            headers={"Accept": "application/json", "User-Agent": "sbom-ops/0.1"},
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise IdentifierFetchError("http_error", status=response.status)
                body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise IdentifierFetchError("response_too_large")
            return json.loads(body)
        except HTTPError as exc:
            exc.close()
            raise IdentifierFetchError("http_error", status=exc.code) from None
        except (URLError, OSError, HTTPException):
            raise IdentifierFetchError("transport_error") from None
        except (ValueError, UnicodeError):
            raise IdentifierFetchError("invalid_json") from None
