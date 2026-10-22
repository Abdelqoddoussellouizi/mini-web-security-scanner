import logging
from typing import Any

import httpx

from app.security import URLValidationError, analyze_security_headers, validate_target_url

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1_000_000


def scan_url(url: str, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    validate_target_url(url)
    timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT_SECONDS,
        read=READ_TIMEOUT_SECONDS,
        write=5.0,
        pool=5.0,
    )

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            trust_env=False,
        ) as client:
            with client.stream("GET", url) as response:
                findings = analyze_security_headers(url, response.headers)
                http_status = response.status_code
                if 300 <= response.status_code < 400:
                    findings.append(
                        _operational_finding(
                            "redirect_not_followed",
                            "warning",
                            "The response is a redirect. It was not followed to avoid contacting an unchecked destination.",
                            "Scan the redirect destination separately only if you are authorized to do so.",
                        )
                    )
                if response.status_code >= 400:
                    findings.append(
                        _operational_finding(
                            "http_response",
                            "warning",
                            f"The target returned HTTP status {response.status_code}.",
                            "Confirm the URL and review the target's response; this scanner does not treat HTTP errors as proof of a security issue.",
                        )
                    )

                if response.is_stream_consumed:
                    received_bytes = len(response.content)
                    too_large = received_bytes > MAX_RESPONSE_BYTES
                else:
                    received_bytes = 0
                    too_large = False
                    for chunk in response.iter_raw():
                        received_bytes += len(chunk)
                        if received_bytes > MAX_RESPONSE_BYTES:
                            too_large = True
                            break

                if too_large:
                    findings.append(
                        _operational_finding(
                            "response_size_limit",
                            "error",
                            "The response exceeded the configured size limit; reading was stopped.",
                            "Reduce the response size or review the target manually.",
                        )
                    )
                    return {
                        "http_status": http_status,
                        "status": "error",
                        "findings": findings,
                    }

                return {
                    "http_status": http_status,
                    "status": _overall_status(findings),
                    "findings": findings,
                }
    except URLValidationError:
        raise
    except httpx.TimeoutException as exc:
        logger.warning("Scan request timed out (%s).", type(exc).__name__)
        finding = _operational_finding(
            "request_timeout",
            "error",
            "The target did not respond within the configured timeout.",
            "Check that the target is reachable and try again later.",
        )
    except httpx.RequestError as exc:
        logger.warning("Scan request failed (%s).", type(exc).__name__)
        finding = _operational_finding(
            "request_failure",
            "error",
            "The scanner could not complete the HTTP request.",
            "Check that the target is reachable and that its TLS configuration is valid.",
        )

    return {"http_status": None, "status": "error", "findings": [finding]}


def _overall_status(findings: list[dict[str, str]]) -> str:
    if any(finding["status"] == "error" for finding in findings):
        return "error"
    if any(finding["status"] == "warning" for finding in findings):
        return "completed_with_warnings"
    return "completed"


def _operational_finding(
    check_name: str, status: str, explanation: str, remediation: str
) -> dict[str, str]:
    return {
        "check_name": check_name,
        "status": status,
        "severity": "medium" if status == "error" else "low",
        "explanation": explanation,
        "remediation": remediation,
    }
