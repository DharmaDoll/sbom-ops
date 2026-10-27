"""Bounded, read-only transport for official advisory feeds."""

import re
import ssl
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

_SOURCES = {
    "jpcert": "https://www.jpcert.or.jp/rss/jpcert.rdf",
    "ubuntu": "https://ubuntu.com/security/notices/rss.xml",
}
_MAX_BYTES = 1024 * 1024


def _retry_after(value: str | None) -> str | None:
    if not value or len(value) > 128 or not value.isascii():
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if re.fullmatch(r"[0-9]{1,9}", value):
        return value
    try:
        date = parsedate_to_datetime(value)
        return value if date.utcoffset() is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


class AdvisoryFetchError(Exception):
    """Sanitized failure without remote response content."""

    def __init__(
        self, code: str, *, status: int | None = None, retry_after: str | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after = _retry_after(retry_after)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class AdvisoryFeedClient:
    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._opener = build_opener(HTTPSHandler(context=context), _NoRedirect())

    def fetch(self, source_id: str) -> bytes:
        if source_id not in _SOURCES:
            raise ValueError("unsupported advisory source")
        request = Request(
            _SOURCES[source_id],
            headers={
                "Accept": "application/rss+xml, application/rdf+xml, application/xml",
                "Accept-Encoding": "identity",
                "User-Agent": "sbom-ops/0.1 (+https://github.com/DharmaDoll/sbom-ops)",
            },
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise AdvisoryFetchError(
                        "http_error",
                        status=response.status,
                        retry_after=response.headers.get("Retry-After"),
                    )
                encoding = response.headers.get("Content-Encoding", "identity")
                if encoding.strip().lower() != "identity":
                    raise AdvisoryFetchError("unsupported_encoding")
                body = response.read(_MAX_BYTES + 1)
                if len(body) > _MAX_BYTES:
                    raise AdvisoryFetchError("response_too_large")
                return body
        except HTTPError as exc:
            retry = exc.headers.get("Retry-After") if exc.headers else None
            exc.close()
            raise AdvisoryFetchError(
                "http_error", status=exc.code, retry_after=retry
            ) from None
        except (URLError, OSError, HTTPException):
            raise AdvisoryFetchError("transport_error") from None
