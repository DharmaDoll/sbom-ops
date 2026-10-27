from io import BytesIO
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from sbom_ops.clients.advisory_feed import AdvisoryFeedClient, AdvisoryFetchError


class Response(BytesIO):
    status = 200

    def __init__(self, body=b"<rss/>", headers=None):
        super().__init__(body)
        self.headers = headers or {}


def client_with(response):
    client = AdvisoryFeedClient()
    client._opener = Mock()
    client._opener.open.return_value = response
    return client


@pytest.mark.parametrize(
    "source,host", [("jpcert", "www.jpcert.or.jp"), ("ubuntu", "ubuntu.com")]
)
def test_fixed_destination_and_bounded_read(source, host):
    response = Response()
    client = client_with(response)
    assert client.fetch(source) == b"<rss/>"
    request = client._opener.open.call_args.args[0]
    assert request.host == host
    assert request.get_header("Accept-encoding") == "identity"
    assert request.get_header("Authorization") is None
    assert request.get_header("Cookie") is None
    assert client._opener.open.call_args.kwargs == {"timeout": 30}
    assert response.closed


def test_arbitrary_url_rejected_without_request():
    client = client_with(Response())
    with pytest.raises(ValueError):
        client.fetch("https://127.0.0.1/private")
    client._opener.open.assert_not_called()


@pytest.mark.parametrize(
    "body,headers,code",
    [
        (b"x" * (1024 * 1024 + 1), {}, "response_too_large"),
        (b"private", {"Content-Encoding": "gzip"}, "unsupported_encoding"),
    ],
    ids=["oversize", "compressed"],
)
def test_rejected_response_closed(body, headers, code):
    response = Response(body, headers)
    client = client_with(response)
    with pytest.raises(AdvisoryFetchError) as caught:
        client.fetch("jpcert")
    assert str(caught.value) == code
    assert response.closed


@pytest.mark.parametrize("status", [301, 302, 307, 308, 429, 503])
def test_http_error_has_no_body_and_no_retry(status):
    body = BytesIO(b"private remote content")
    client = client_with(Response())
    client._opener.open.side_effect = HTTPError(
        "https://example.invalid",
        status,
        "private reason",
        {"Retry-After": "60"},
        body,
    )
    with pytest.raises(AdvisoryFetchError) as caught:
        client.fetch("ubuntu")
    assert str(caught.value) == "http_error"
    assert caught.value.status == status
    assert caught.value.retry_after == "60"
    assert body.closed
    assert client._opener.open.call_count == 1


def test_transport_error_sanitized():
    client = client_with(Response())
    client._opener.open.side_effect = URLError("private details")
    with pytest.raises(AdvisoryFetchError, match="^transport_error$"):
        client.fetch("jpcert")


def test_read_timeout_closes_response_without_retry():
    class SlowResponse(Response):
        def read(self, size=-1):
            raise TimeoutError("private timeout details")

    response = SlowResponse()
    client = client_with(response)
    with pytest.raises(AdvisoryFetchError, match="^transport_error$"):
        client.fetch("jpcert")
    assert response.closed
    assert client._opener.open.call_count == 1


def test_exact_limit_accepted():
    body = b"x" * (1024 * 1024)
    assert client_with(Response(body)).fetch("jpcert") == body


@pytest.mark.parametrize("value", ["-1", "9" * 200, "60\r\nInjected: x", "bad"])
def test_invalid_retry_header_not_retained(value):
    assert AdvisoryFetchError("http_error", retry_after=value).retry_after is None


def test_http_date_retry_header_retained():
    date = "Wed, 28 Oct 2026 00:00:00 GMT"
    assert AdvisoryFetchError("http_error", retry_after=date).retry_after == date


def test_redirect_handler_and_tls_verification():
    import ssl
    from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request

    client = AdvisoryFeedClient()
    redirects = [
        h for h in client._opener.handlers if isinstance(h, HTTPRedirectHandler)
    ]
    assert len(redirects) == 1
    assert (
        redirects[0].redirect_request(
            Request("https://ubuntu.com/security/notices/rss.xml"),
            None,
            302,
            "redirect",
            {},
            "http://127.0.0.1/private",
        )
        is None
    )
    https = next(h for h in client._opener.handlers if isinstance(h, HTTPSHandler))
    assert https._context.check_hostname
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    assert https._context.minimum_version == ssl.TLSVersion.TLSv1_3
