import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com/advisories"
SOURCE_NAME = "github_advisory"


def _create_session() -> requests.Session:
    """Create an HTTP session with retry handling."""
    session = requests.Session()

    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CyberVulnerabilityIntelligence/1.0",
    }

    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    session.headers.update(headers)
    return session


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _get_cvss_v3(
    advisory: dict[str, Any],
) -> tuple[str | None, float | None, str | None]:
    """
    Extract CVSS v3 from GitHub's cvss_severities object.

    Do not treat a CVSS v4 or legacy score as a CVSS v3 score.
    """
    severities = advisory.get("cvss_severities") or {}
    v3_data = severities.get("cvss_v3") or {}

    vector = v3_data.get("vector_string", "")
    score = v3_data.get("score")

    if not vector or score is None:
        # Some responses provide a vector through the cvss field.
        legacy = advisory.get("cvss") or {}
        vector = legacy.get("vector_string", "")
        score = legacy.get("score")

    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None, None, None

    try:
        score = float(score)
    except (TypeError, ValueError):
        return None, None, None

    version = "3.1" if vector.startswith("CVSS:3.1/") else "3.0"
    severity = (advisory.get("severity") or "").upper()

    if not severity:
        severity = "CRITICAL" if score >= 9.0 else "UNKNOWN"

    return version, score, severity


def fetch_github_advisories() -> list[dict[str, Any]]:
    """
    Fetch GitHub advisories published within LOOKBACK_DAYS
    with CVSS v3 score >= CVSS_MIN_SCORE.
    """
    lookback_days = max(1, int(os.getenv("LOOKBACK_DAYS", "60")))
    minimum_score = float(os.getenv("CVSS_MIN_SCORE", "9.0"))

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    # GitHub's published filter accepts an ISO 8601 date range.
    published_range = (
        f"{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}.."
        f"{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    )

    session = _create_session()
    records: list[dict[str, Any]] = []
    page = 1
    max_pages = 10

    try:
        while page <= max_pages:
            params = {
                "type": "reviewed",
                "published": published_range,
                "per_page": 100,
                "page": page,
            }

            response = session.get(
                GITHUB_API_URL,
                params=params,
                timeout=(10, 60),
            )
            response.raise_for_status()
            advisories = response.json()

            if not isinstance(advisories, list) or not advisories:
                break

            for advisory in advisories:
                identifiers = advisory.get("identifiers", [])
                cve_id = advisory.get("cve_id")

                if not cve_id:
                    cve_id = next(
                        (
                            item.get("value")
                            for item in identifiers
                            if item.get("type") == "CVE"
                            and item.get("value", "").startswith("CVE-")
                        ),
                        None,
                    )

                if not cve_id:
                    continue

                version, score, severity = _get_cvss_v3(advisory)

                if score is None or score < minimum_score:
                    continue

                published_at = _parse_datetime(advisory.get("published_at"))
                updated_at = _parse_datetime(advisory.get("updated_at"))

                if published_at is None:
                    continue

                if not (start_time <= published_at <= end_time):
                    continue

                references = advisory.get("references", [])
                reference_urls = sorted({
                    item.get("url")
                    for item in references
                    if item.get("url")
                })

                affected_products = []
                for item in advisory.get("vulnerabilities", []):
                    package = item.get("package") or {}
                    name = package.get("name")
                    ecosystem = package.get("ecosystem")

                    if name:
                        label = f"{ecosystem}:{name}" if ecosystem else name
                        affected_products.append(label)

                ghsa_id = advisory.get("ghsa_id")

                records.append({
                    "cve_id": cve_id,
                    "description": (
                        advisory.get("description")
                        or advisory.get("summary")
                        or ""
                    ),
                    "cvss_version": version,
                    "cvss_score": score,
                    "severity": severity,
                    "published_at": published_at.isoformat(),
                    "last_modified_at": (
                        updated_at.isoformat() if updated_at else None
                    ),
                    "affected_products": sorted(set(affected_products)),
                    "reference_urls": reference_urls,
                    "source_name": SOURCE_NAME,
                    "source_record_id": ghsa_id or cve_id,
                    "source_published_at": published_at.isoformat(),
                    "source_updated_at": (
                        updated_at.isoformat() if updated_at else None
                    ),
                    "source_url": (
                        f"https://github.com/advisories/{ghsa_id}"
                        if ghsa_id
                        else "https://github.com/advisories"
                    ),
                    "raw_data": advisory,
                })

            # Respect pagination limits and avoid unbounded API requests.
            if len(advisories) < 100:
                break

            page += 1

        logger.info(
            "GitHub Advisory Database returned %s qualifying records",
            len(records),
        )
        return records

    finally:
        session.close()