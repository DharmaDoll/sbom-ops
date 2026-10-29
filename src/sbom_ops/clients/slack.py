"""One bounded Slack POST, no business rules, retries, or response-body logging."""

from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class SlackOutcome:
    state: str
    ts: str | None = None
    error: str | None = None
    retry_seconds: int = 0


class SlackClient:
    def __init__(self, token: str) -> None:
        if not token or not token.isascii() or any(c.isspace() for c in token):
            raise ValueError("invalid Slack credential")
        self._token = token
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))

    def post(
        self, channel: str, text: str, *, thread_ts: str | None = None
    ) -> SlackOutcome:
        payload = {
            "channel": channel,
            "text": text,
            "mrkdwn": False,
            "parse": "none",
            "link_names": False,
            "unfurl_links": False,
            "unfurl_media": False,
        }
        if thread_ts:
            payload["thread_ts"] = thread_ts
        request = Request(
            "https://slack.com/api/chat.postMessage",
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json; charset=utf-8",
            },
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                body = response.read(65537)
                if len(body) > 65536:
                    return SlackOutcome("unknown", error="response_limit")
                result = json.loads(body)
        except HTTPError as exc:
            try:
                if exc.code == 429:
                    retry = exc.headers.get("Retry-After", "")
                    if not re.fullmatch(r"[0-9]{1,8}", retry):
                        return SlackOutcome("unknown", error="invalid_retry_after")
                    return SlackOutcome(
                        "rate_limited",
                        error="rate_limited",
                        retry_seconds=max(1, int(retry)),
                    )
                if exc.code in (400, 401, 403, 404):
                    return SlackOutcome("rejected", error="http_rejected")
                return SlackOutcome("unknown", error="http_server_or_transport")
            finally:
                exc.close()
        except (OSError, URLError, HTTPException, ValueError):
            return SlackOutcome("unknown", error="transport_or_response")
        if not isinstance(result, dict):
            return SlackOutcome("unknown", error="invalid_response")
        if result.get("ok") is False:
            # Only documented definitive failures permit an explicit later retry.
            rejected = {
                "invalid_auth",
                "not_authed",
                "token_revoked",
                "account_inactive",
                "missing_scope",
                "no_permission",
                "not_in_channel",
                "channel_not_found",
                "is_archived",
                "restricted_action",
                "msg_too_long",
                "invalid_arguments",
            }
            code = result.get("error")
            if isinstance(code, str) and code in rejected:
                return SlackOutcome("rejected", error=code)
            return SlackOutcome("unknown", error="api_unconfirmed")
        ts = result.get("ts")
        if (
            result.get("ok") is not True
            or result.get("channel") != channel
            or not isinstance(ts, str)
            or not re.fullmatch(r"[0-9]{1,16}\.[0-9]{1,10}", ts)
        ):
            return SlackOutcome("unknown", error="invalid_confirmation")
        return SlackOutcome("confirmed", ts=ts)
