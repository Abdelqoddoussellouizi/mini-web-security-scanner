import socket
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import create_app
from app.scanner import MAX_RESPONSE_BYTES, scan_url

PUBLIC_ADDRESS = "93.184.216.34"


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "resolve_hostname", lambda hostname, port: [PUBLIC_ADDRESS])


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    return tmp_path / "test-scans.sqlite3"


def make_client(
    database_path: Path,
    handler: httpx.MockTransport,
) -> TestClient:
    return TestClient(create_app(database_path=database_path, transport=handler))


def test_successful_scan_and_history_persistence(
    database_path: Path, public_dns: None
) -> None:
    headers = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
    }
    handler = httpx.MockTransport(
        lambda request: httpx.Response(200, headers=headers, request=request)
    )

    with make_client(database_path, handler) as client:
        response = client.post("/scans", json={"url": "https://example.com"})
        assert response.status_code == 201
        scan = response.json()
        assert scan["http_status"] == 200
        assert scan["status"] == "completed"
        assert len(scan["findings"]) == 8
        assert scan["findings"][0]["check_name"] == "https"

        history = client.get("/scans")
        assert history.status_code == 200
        assert history.json()["scans"][0]["id"] == scan["id"]

        details = client.get(f"/scans/{scan['id']}")
        assert details.status_code == 200
        assert details.json()["findings"] == scan["findings"]

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_missing_security_headers_are_reported_as_warnings(
    public_dns: None,
) -> None:
    handler = httpx.MockTransport(
        lambda request: httpx.Response(200, request=request)
    )
    result = scan_url("https://example.com", transport=handler)
    warnings = [finding for finding in result["findings"] if finding["status"] == "warning"]

    assert len(warnings) == 6
    assert all("configuration weakness" in finding["explanation"] for finding in warnings)


@pytest.mark.parametrize(
    "csp",
    ["frame-ancestors", "frame-ancestors *"],
)
def test_empty_or_unrestricted_csp_does_not_count_as_frame_restriction(
    csp: str,
) -> None:
    findings = security.analyze_security_headers(
        "https://example.com", {"content-security-policy": csp}
    )
    frame_finding = next(
        finding for finding in findings if finding["check_name"] == "frame_restriction"
    )

    assert frame_finding["status"] == "warning"


@pytest.mark.parametrize(
    "url",
    ["ftp://example.com", "file://example.com/file", "javascript:alert(1)"],
)
def test_invalid_schemes_are_rejected(url: str) -> None:
    with pytest.raises(security.URLValidationError):
        security.validate_target_url(url)


def test_credentials_in_url_are_rejected() -> None:
    with pytest.raises(security.URLValidationError, match="Credentials"):
        security.validate_target_url("https://user:password@example.com")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://[::1]",
    ],
)
def test_localhost_and_private_ip_addresses_are_rejected(url: str) -> None:
    with pytest.raises(security.URLValidationError):
        security.validate_target_url(url)


def test_hostname_resolving_to_private_address_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security, "resolve_hostname", lambda hostname, port: ["192.168.1.10"])
    with pytest.raises(security.URLValidationError, match="private"):
        security.validate_target_url("https://example.com")


def test_private_target_is_rejected_before_http_request() -> None:
    requests: list[httpx.Request] = []
    handler = httpx.MockTransport(
        lambda request: requests.append(request) or httpx.Response(200, request=request)
    )

    with pytest.raises(security.URLValidationError):
        scan_url("http://127.0.0.1", transport=handler)

    assert requests == []


def test_connection_timeout_is_reported(public_dns: None) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated timeout", request=request)

    result = scan_url("https://example.com", transport=httpx.MockTransport(timeout))
    assert result["status"] == "error"
    assert result["http_status"] is None
    assert result["findings"][0]["check_name"] == "request_timeout"


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("simulated connection failure"),
        httpx.ConnectError("simulated DNS failure"),
    ],
)
def test_connection_or_dns_failure_is_reported(
    public_dns: None, failure: httpx.ConnectError
) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise failure

    result = scan_url("https://example.com", transport=httpx.MockTransport(fail))
    assert result["status"] == "error"
    assert result["findings"][0]["check_name"] == "request_failure"


def test_unknown_scan_id_returns_404(database_path: Path) -> None:
    with make_client(database_path, httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        response = client.get("/scans/not-a-saved-id")
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan ID was not found."


def test_health_endpoint_initializes_database(database_path: Path) -> None:
    handler = httpx.MockTransport(lambda request: httpx.Response(200))
    with make_client(database_path, handler) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert database_path.exists()


def test_homepage_serves_scanner_interface(database_path: Path) -> None:
    handler = httpx.MockTransport(lambda request: httpx.Response(200))
    with make_client(database_path, handler) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Check a website" in response.text
    assert "Scan history" in response.text


def test_redirect_is_not_followed(public_dns: None) -> None:
    requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"location": "http://127.0.0.1"}, request=request)

    result = scan_url("https://example.com", transport=httpx.MockTransport(redirect))
    assert len(requests) == 1
    assert result["findings"][-1]["check_name"] == "redirect_not_followed"


def test_response_size_limit_is_reported(public_dns: None) -> None:
    handler = httpx.MockTransport(
        lambda request: httpx.Response(
            200, content=b"x" * (MAX_RESPONSE_BYTES + 1), request=request
        )
    )

    result = scan_url("https://example.com", transport=handler)

    assert result["status"] == "error"
    assert result["findings"][-1]["check_name"] == "response_size_limit"


def test_dns_resolution_failure_is_rejected_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_resolution(
        hostname: str, port: int, type: int
    ) -> list[tuple[object, ...]]:
        raise socket.gaierror("simulated DNS failure")

    monkeypatch.setattr(security.socket, "getaddrinfo", fail_resolution)
    with pytest.raises(security.URLValidationError, match="could not be resolved"):
        security.validate_target_url("https://unresolvable.example")
