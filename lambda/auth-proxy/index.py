"""API Gateway Lambda proxy for Amazon Quick on desktop OAuth requests.

Amazon Quick sends an `offline_access` scope on every OAuth request, but
Amazon Cognito does not support that scope and rejects the request. This proxy
sits in front of the Cognito hosted UI and strips `offline_access` from the
`scope` parameter before forwarding:

  - GET  /oauth2/authorize -> 302 redirect to the Cognito authorize endpoint
  - POST /oauth2/token     -> proxied (server-side) to the Cognito token endpoint

The token request is forwarded server-side (rather than redirected) so the
JSON token response is returned directly to the desktop client.
"""

import base64
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from enum import Enum, StrEnum


class Route(StrEnum):
    AUTHORIZE = "/oauth2/authorize"
    TOKEN = "/oauth2/token"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class StatusCode(int, Enum):
    REDIRECT = 302
    NOT_FOUND = 404
    INTERNAL_ERROR = 500
    BAD_GATEWAY = 502


class ContentType(StrEnum):
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"


# Scope that Amazon Quick sends but Cognito does not support.
UNSUPPORTED_SCOPE = "offline_access"


@dataclass
class ProxyResponse:
    statusCode: int
    body: str = ""
    headers: dict | None = None

    def to_dict(self) -> dict:
        result = asdict(self)
        if self.headers is None:
            del result["headers"]
        return result


def _strip_unsupported_scope(scope_str: str) -> str:
    """Removes the unsupported scope from a space-delimited OAuth scope string."""
    return " ".join(s for s in scope_str.split() if s != UNSUPPORTED_SCOPE)


class AuthorizeHandler:
    """Handles GET /oauth2/authorize by redirecting to Cognito with a cleaned scope."""

    def __init__(self, cognito_domain: str) -> None:
        self._cognito_domain = cognito_domain

    def handle(self, event: dict) -> ProxyResponse:
        params = event.get("queryStringParameters") or {}
        if "scope" in params:
            params["scope"] = _strip_unsupported_scope(params["scope"])
        qs = urllib.parse.urlencode(params)
        return ProxyResponse(
            statusCode=StatusCode.REDIRECT,
            headers={"Location": f"{self._cognito_domain}{Route.AUTHORIZE.value}?{qs}"},
        )


class TokenHandler:
    """Handles POST /oauth2/token by forwarding the request to Cognito server-side."""

    def __init__(self, cognito_domain: str) -> None:
        self._cognito_domain = cognito_domain

    def handle(self, event: dict) -> ProxyResponse:
        body = event.get("body", "") or ""
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode()

        # Strip the unsupported scope from the token request body as well, in
        # case the client includes it on the token exchange.
        body = self._clean_body(body)

        headers = {"Content-Type": ContentType.FORM.value}
        req_headers = event.get("headers") or {}
        # API Gateway lower-cases header keys; forward the client's Authorization
        # header (used by confidential clients) if present.
        if "authorization" in req_headers:
            headers["Authorization"] = req_headers["authorization"]
        elif "Authorization" in req_headers:
            headers["Authorization"] = req_headers["Authorization"]

        req = urllib.request.Request(
            f"{self._cognito_domain}{Route.TOKEN.value}",
            data=body.encode(),
            headers=headers,
            method=HttpMethod.POST.value,
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return ProxyResponse(
                    statusCode=resp.status,
                    headers={"Content-Type": ContentType.JSON.value},
                    body=resp.read().decode(),
                )
        except urllib.error.HTTPError as e:
            # Pass Cognito's error response straight through to the client.
            return ProxyResponse(
                statusCode=e.code,
                headers={"Content-Type": ContentType.JSON.value},
                body=e.read().decode(),
            )
        except urllib.error.URLError as e:
            return ProxyResponse(
                statusCode=StatusCode.BAD_GATEWAY,
                headers={"Content-Type": ContentType.JSON.value},
                body=f'{{"error": "upstream_unreachable", "reason": "{e.reason}"}}',
            )

    def _clean_body(self, body: str) -> str:
        if "scope=" not in body:
            return body
        pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
        cleaned = [
            (k, _strip_unsupported_scope(v) if k == "scope" else v) for k, v in pairs
        ]
        return urllib.parse.urlencode(cleaned)


COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"]
_authorize_handler = AuthorizeHandler(COGNITO_DOMAIN)
_token_handler = TokenHandler(COGNITO_DOMAIN)


def handler(event: dict, _context: object) -> dict:
    path = event.get("path", "")
    method = event.get("httpMethod", "")
    print(f"REQUEST: {method} {path}")

    try:
        match (path, method):
            case (Route.AUTHORIZE, HttpMethod.GET):
                response = _authorize_handler.handle(event)
            case (Route.TOKEN, HttpMethod.POST):
                response = _token_handler.handle(event)
            case _:
                response = ProxyResponse(
                    statusCode=StatusCode.NOT_FOUND, body="Not found"
                )
    except Exception as e:  # noqa: BLE001 - proxy must never leak a stack trace
        print(f"ERROR: {e}")
        response = ProxyResponse(
            statusCode=StatusCode.INTERNAL_ERROR,
            headers={"Content-Type": ContentType.JSON.value},
            body='{"error": "internal_error"}',
        )

    print(f"RESPONSE: {response.statusCode} {response.headers}")
    return response.to_dict()
