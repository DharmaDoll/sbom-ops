import io
import json
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from sbom_ops.clients.slack import SlackClient


class Opener:
    def __init__(self, value: bytes | BaseException) -> None:
        self.value = value
        self.requests = []

    def open(self, request: Request, timeout: float) -> io.BytesIO:
        self.requests.append(request)
        assert timeout == 30
        if isinstance(self.value, BaseException):
            raise self.value
        return io.BytesIO(self.value)


def client(value: bytes | BaseException) -> tuple[SlackClient, Opener]:
    instance = SlackClient("synthetic-not-a-credential")
    opener = Opener(value)
    instance._opener = opener
    return instance, opener


def test_exact_request_and_confirmation() -> None:
    instance, opener = client(
        json.dumps({"ok": True, "channel": "C12345678", "ts": "123.456"}).encode()
    )
    result = instance.post("C12345678", "literal", thread_ts="100.001")
    assert result.state == "confirmed" and result.ts == "123.456"
    request = opener.requests[0]
    assert request.full_url == "https://slack.com/api/chat.postMessage"
    assert request.method == "POST"
    assert json.loads(request.data) == {
        "channel": "C12345678",
        "text": "literal",
        "mrkdwn": False,
        "parse": "none",
        "link_names": False,
        "unfurl_links": False,
        "unfurl_media": False,
        "thread_ts": "100.001",
    }


@pytest.mark.parametrize(
    "value,state,error",
    [
        (TimeoutError("secret provider body"), "unknown", "transport_or_response"),
        (b"not json", "unknown", "transport_or_response"),
        (b"x" * 65537, "unknown", "response_limit"),
        (
            b'{"ok":true,"channel":"wrong","ts":"123.456"}',
            "unknown",
            "invalid_confirmation",
        ),
        (b'{"ok":true,"channel":"C12345678"}', "unknown", "invalid_confirmation"),
        (b'{"ok":false,"error":"missing_scope"}', "rejected", "missing_scope"),
        (b'{"ok":false,"error":"internal_error"}', "unknown", "api_unconfirmed"),
        (b'{"ok":false,"error":"secret body"}', "unknown", "api_unconfirmed"),
    ],
)
def test_no_automatic_retry_or_response_leak(
    value: bytes | BaseException, state: str, error: str
) -> None:
    instance, opener = client(value)
    result = instance.post("C12345678", "body")
    assert (result.state, result.error) == (state, error)
    assert len(opener.requests) == 1
    assert "secret" not in repr(result)


@pytest.mark.parametrize(
    "status,state",
    [
        (429, "rate_limited"),
        (500, "unknown"),
        (503, "unknown"),
        (403, "rejected"),
        (302, "unknown"),
    ],
)
def test_http_outcomes(status: int, state: str) -> None:
    instance, opener = client(
        HTTPError(
            "https://slack.com",
            status,
            "secret",
            {"Retry-After": "45"},
            io.BytesIO(b"secret body"),
        )
    )
    result = instance.post("C12345678", "body")
    assert result.state == state
    assert len(opener.requests) == 1
    assert "secret" not in repr(result)
    if status == 429:
        assert result.retry_seconds == 45
