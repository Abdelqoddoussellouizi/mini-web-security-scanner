import ipaddress
import socket
from collections.abc import Mapping
from urllib.parse import urlsplit


class URLValidationError(ValueError):
    """Raised when a scan target is malformed or unsafe to contact."""


def resolve_hostname(hostname: str, port: int) -> list[str]:
    try:
        results = socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise URLValidationError("The target hostname could not be resolved.") from exc

    return list({result[4][0] for result in results})


def validate_target_url(url: str) -> None:
    if not url or len(url) > 2048 or any(character.isspace() for character in url):
        raise URLValidationError("Provide a valid HTTP or HTTPS URL.")
    if any(ord(character) < 32 for character in url) or "\\" in url:
        raise URLValidationError("Provide a valid HTTP or HTTPS URL.")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("The target URL contains an invalid port or host.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise URLValidationError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.netloc or not parsed.hostname or parsed.fragment:
        raise URLValidationError("Provide an absolute URL without a fragment.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise URLValidationError("Credentials in target URLs are not allowed.")

    hostname = parsed.hostname.rstrip(".").lower()
    if not hostname or "%" in hostname:
        raise URLValidationError("The target URL contains an invalid hostname.")
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        raise URLValidationError("Localhost and local network hostnames are not allowed.")

    if port == 0:
        raise URLValidationError("The target URL contains an invalid port or host.")
    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        addresses = [str(ipaddress.ip_address(hostname))]
    except ValueError:
        addresses = resolve_hostname(hostname, effective_port)

    if not addresses:
        raise URLValidationError("The target hostname did not resolve to an address.")

    for address in addresses:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise URLValidationError("The target hostname resolved to an invalid address.") from exc
        if not parsed_address.is_global:
            raise URLValidationError(
                "Targets resolving to private, local, or reserved IP addresses are not allowed."
            )


def analyze_security_headers(
    url: str, headers: Mapping[str, str]
) -> list[dict[str, str]]:
    header_values = {name.lower(): value for name, value in headers.items()}
    findings: list[dict[str, str]] = []

    is_https = urlsplit(url).scheme.lower() == "https"
    findings.append(
        _finding(
            "https",
            "pass" if is_https else "warning",
            "informational" if is_https else "medium",
            "The target uses HTTPS." if is_https else "The target URL uses HTTP, so the connection is not encrypted.",
            "Use HTTPS and redirect HTTP traffic to HTTPS." if not is_https else "No action needed.",
        )
    )

    checks = (
        (
            "content_security_policy",
            "content-security-policy",
            "medium",
            "Content-Security-Policy is present.",
            "Content-Security-Policy is missing; this may be a configuration weakness depending on the application.",
            "Define a Content-Security-Policy suited to the application's resources and test it before enforcement.",
        ),
        (
            "strict_transport_security",
            "strict-transport-security",
            "medium",
            "Strict-Transport-Security is present.",
            "Strict-Transport-Security is missing; this may be a configuration weakness depending on the application's HTTPS requirements.",
            "After confirming HTTPS works across the site, configure an appropriate Strict-Transport-Security policy.",
        ),
        (
            "x_content_type_options",
            "x-content-type-options",
            "low",
            "X-Content-Type-Options is present.",
            "X-Content-Type-Options is missing; this may be a configuration weakness depending on the application's content types.",
            "Set X-Content-Type-Options to nosniff.",
        ),
        (
            "referrer_policy",
            "referrer-policy",
            "low",
            "Referrer-Policy is present.",
            "Referrer-Policy is missing; this may be a configuration weakness depending on the application's privacy requirements.",
            "Set a Referrer-Policy that matches the application's privacy requirements.",
        ),
        (
            "permissions_policy",
            "permissions-policy",
            "low",
            "Permissions-Policy is present.",
            "Permissions-Policy is missing; this may be a configuration weakness depending on the browser features the application uses.",
            "Define a Permissions-Policy for browser features the application does not need.",
        ),
    )

    for name, header, severity, success, missing, remediation in checks:
        present = bool(header_values.get(header, "").strip())
        findings.append(
            _finding(
                name,
                "pass" if present else "warning",
                "informational" if present else severity,
                success if present else missing,
                "No action needed." if present else remediation,
            )
        )

    csp = header_values.get("content-security-policy", "")
    frame_ancestor_directives = [
        directive.strip().split()
        for directive in csp.split(";")
        if directive.strip()
    ]
    has_frame_ancestors = any(
        len(tokens) > 1
        and tokens[0].lower() == "frame-ancestors"
        and "*" not in tokens[1:]
        for tokens in frame_ancestor_directives
    )
    frame_header = header_values.get("x-frame-options", "").strip().lower()
    frame_restricted = frame_header in {"deny", "sameorigin"} or has_frame_ancestors
    findings.append(
        _finding(
            "frame_restriction",
            "pass" if frame_restricted else "warning",
            "informational" if frame_restricted else "medium",
            "A recognized frame restriction is present."
            if frame_restricted
            else "No recognized frame restriction was found; this may be a configuration weakness depending on whether the application should be framed.",
            "No action needed."
            if frame_restricted
            else "Use CSP frame-ancestors and/or X-Frame-Options to limit framing where appropriate.",
        )
    )

    technology_headers = (
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
    )
    exposed_names = [name for name in technology_headers if header_values.get(name, "").strip()]
    findings.append(
        _finding(
            "technology_disclosure",
            "warning" if exposed_names else "pass",
            "low" if exposed_names else "informational",
            "Response headers expose technology-identifying fields: "
            + ", ".join(exposed_names)
            + "."
            if exposed_names
            else "No commonly identifying technology headers were detected.",
            "Remove or minimize unnecessary technology details in response headers."
            if exposed_names
            else "No action needed.",
        )
    )
    return findings


def _finding(
    check_name: str,
    status: str,
    severity: str,
    explanation: str,
    remediation: str,
) -> dict[str, str]:
    return {
        "check_name": check_name,
        "status": status,
        "severity": severity,
        "explanation": explanation,
        "remediation": remediation,
    }
