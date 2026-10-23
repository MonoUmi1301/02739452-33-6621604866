import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE_NAME = "nvd"


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
    session.mount("http://", adapter)

    session.headers.update({
        "User-Agent": "CyberVulnerabilityIntelligence/1.0",
        "Accept": "application/json",
    })

    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        session.headers["apiKey"] = api_key

    return session


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO 8601 datetime into a timezone-aware datetime."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _get_cvss_v3(metrics: dict[str, Any]) -> tuple[str | None, float | None, str | None]:
    """Prefer CVSS v3.1, then v3.0. Ignore CVSS v4 and v2."""
    for metric_key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
    ):
        entries = metrics.get(metric_key, [])
        if not entries:
            continue

        for entry in entries:
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")

            if score is None:
                continue

            try:
                score = float(score)
            except (TypeError, ValueError):
                continue

            severity = (
                cvss_data.get("baseSeverity")
                or entry.get("baseSeverity")
                or ("CRITICAL" if score >= 9.0 else "UNKNOWN")
            )

            return version, score, str(severity).upper()

    return None, None, None


def _extract_products(cve: dict[str, Any]) -> list[str]:
    """Extract unique CPE product identifiers from NVD configurations."""
    products: set[str] = set()

    def walk(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable", False):
                cpe = match.get("criteria")
                if cpe:
                    products.add(cpe)

        for child in node.get("children", []):
            walk(child)

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            walk(node)

    return sorted(products)


def fetch_nvd_vulnerabilities() -> list[dict[str, Any]]:
    """
    Fetch recent critical CVEs from NVD.

    Inclusion criteria:
    - Published within LOOKBACK_DAYS.
    - CVSS v3.0 or v3.1 score >= CVSS_MIN_SCORE.

    Returns records in the shared extractor format.
    """
    lookback_days = max(1, int(os.getenv("LOOKBACK_DAYS", "60")))
    minimum_score = float(os.getenv("CVSS_MIN_SCORE", "9.0"))

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    params = {
        "pubStartDate": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    session = _create_session()
    records: list[dict[str, Any]] = []

    try:
        while True:
            logger.info(
                "Requesting NVD results: startIndex=%s",
                params["startIndex"],
            )

            response = session.get(
                NVD_API_URL,
                params=params,
                timeout=(10, 60),
            )
            response.raise_for_status()
            payload = response.json()

            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")

                if not cve_id:
                    continue

                version, score, severity = _get_cvss_v3(
                    cve.get("metrics", {})
                )

                if score is None or score < minimum_score:
                    continue

                published_at = _parse_datetime(cve.get("published"))
                modified_at = _parse_datetime(cve.get("lastModified"))

                if published_at is None:
                    continue

                if not (start_time <= published_at <= end_time):
                    continue

                descriptions = cve.get("descriptions", [])
                description = next(
                    (
                        item.get("value", "")
                        for item in descriptions
                        if item.get("lang") == "en"
                    ),
                    "",
                )

                reference_urls = sorted({
                    reference.get("url")
                    for reference in cve.get("references", [])
                    if reference.get("url")
                })

                records.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_version": version,
                    "cvss_score": score,
                    "severity": severity,
                    "published_at": published_at.isoformat(),
                    "last_modified_at": (
                        modified_at.isoformat() if modified_at else None
                    ),
                    "affected_products": _extract_products(cve),
                    "reference_urls": reference_urls,
                    "source_name": SOURCE_NAME,
                    "source_record_id": cve_id,
                    "source_published_at": published_at.isoformat(),
                    "source_updated_at": (
                        modified_at.isoformat() if modified_at else None
                    ),
                    "source_url": (
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    ),
                    "raw_data": item,
                })

            total_results = int(payload.get("totalResults", 0))
            params["startIndex"] += len(vulnerabilities)

            if params["startIndex"] >= total_results:
                break

        logger.info("NVD returned %s qualifying records", len(records))
        return records

    finally:
        session.close()