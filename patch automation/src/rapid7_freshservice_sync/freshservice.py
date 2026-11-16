import base64
import hashlib
import html
from typing import Any
from urllib.parse import urlparse

from .http import ApiError, HttpClient
from .models import Finding

OPEN_STATUSES = (2, 3)


class FreshserviceClient:
    def __init__(
        self,
        domain: str,
        api_key: str,
        requester_email: str,
        http: HttpClient | None = None,
    ) -> None:
        parsed = urlparse(domain.strip().rstrip("/"))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.endswith(".freshservice.com")
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Freshservice domain must be an HTTPS Freshservice domain")
        if not api_key.strip():
            raise ValueError("Freshservice API key is required")
        if not requester_email.strip():
            raise ValueError("Freshservice requester email is required")

        self.base_url = f"https://{parsed.netloc}/api/v2"
        self.requester_email = requester_email.strip()
        token = base64.b64encode(f"{api_key}:X".encode()).decode("ascii")
        self.http = http or HttpClient(
            headers={
                "Authorization": f"Basic {token}",
                "Accept": "application/json",
            },
            allowed_hosts={parsed.hostname},
        )

    def create_ticket_if_missing(self, finding: Finding) -> dict[str, Any] | None:
        tag = finding_tag(finding)
        for status in OPEN_STATUSES:
            response = self.http.request_json(
                "GET",
                f"{self.base_url}/tickets/filter",
                params={"query": f"tag: '{tag}' AND status:{status}"},
            )
            tickets = response.get("tickets") if isinstance(response, dict) else None
            if not isinstance(tickets, list):
                raise ApiError("Freshservice ticket filter returned an invalid response")
            if tickets:
                return None

        payload = {
            "email": self.requester_email,
            "subject": _ticket_subject(finding.solution),
            "description": _ticket_description(finding),
            "priority": 3,
            "status": 2,
            "tags": ["rapid7-insightvm", tag],
        }
        response = self.http.request_json(
            "POST",
            f"{self.base_url}/tickets",
            json_body=payload,
            retryable=False,
        )
        ticket = response.get("ticket") if isinstance(response, dict) else None
        if not isinstance(ticket, dict) or "id" not in ticket:
            raise ApiError("Freshservice ticket creation returned an invalid response")
        return ticket


def finding_tag(finding: Finding) -> str:
    stable_id = hashlib.sha256(
        f"{finding.solution}\0{finding.fix_details}".encode("utf-8")
    ).hexdigest()[:24]
    return f"rapid7-remediation-{stable_id}"


def _ticket_subject(solution: str) -> str:
    subject = f"Rapid7 remediation: {solution or 'Review vulnerability findings'}"
    return subject[:250]


def _ticket_description(finding: Finding) -> str:
    hosts = "".join(f"<li>{html.escape(host)}</li>" for host in finding.hosts)
    solution = html.escape(finding.solution)
    fix_details = html.escape(finding.fix_details)
    return (
        "<p>Rapid7 InsightVM identified active vulnerability findings requiring "
        "remediation.</p>"
        f"<p><strong>Solution:</strong> {solution}</p>"
        f"<p><strong>Fix details:</strong> {fix_details}</p>"
        f"<p><strong>Affected hosts:</strong></p><ul>{hosts}</ul>"
    )
