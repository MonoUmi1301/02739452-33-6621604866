import logging
import os
import time
from typing import Any

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker"
SOURCE_NAME = "debian_security_tracker"


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

    session.headers.update({
        "User-Agent": "CyberVulnerabilityIntelligence/1.0",
        "Accept": "text/html,application/xhtml+xml",
    })

    return session


def _extract_page_text(soup: BeautifulSoup) -> str:
    """Extract readable text while excluding scripts and styles."""
    for element in soup(["script", "style", "noscript"]):
        element.decompose()

    return " ".join(soup.get_text(" ", strip=True).split())


def _extract_package_statuses(soup: BeautifulSoup) -> list[dict[str, str]]:
    """
    Extract package and release status information from available tables.

    The tracker page structure may change; retain only values that can
    be extracted from actual table cells.
    """
    results: list[dict[str, str]] = []

    for table in soup.find_all("table"):
        headers = [
            cell.get_text(" ", strip=True).lower()
            for cell in table.find_all("th")
        ]

        for row in table.find_all("tr"):
            cells = [
                cell.get_text(" ", strip=True)
                for cell in row.find_all(["td", "th"])
            ]

            if not cells or all(not cell for cell in cells):
                continue

            # Skip a header row.
            if all(cell.lower() in headers for cell in cells if cell):
                continue

            results.append({
                "row_text": " | ".join(cells),
            })

    return results


def fetch_debian_tracker(
    cve_ids: list[str],
    max_records: int = 200,
) -> list[dict[str, Any]]:
    """
    Scrape Debian Security Tracker pages for a supplied list of CVE IDs.

    This extractor enriches CVEs discovered by NVD/GitHub; it does not
    independently determine CVSS v3 scores or publication dates.

    Args:
        cve_ids: CVE identifiers from the other extractors.
        max_records: Maximum number of CVE pages to request per run.
    """
    unique_ids = sorted({
        cve_id.strip().upper()
        for cve_id in cve_ids
        if isinstance(cve_id, str)
        and cve_id.strip().upper().startswith("CVE-")
    })[:max_records]

    if not unique_ids:
        logger.info("No CVE IDs supplied to Debian tracker extractor")
        return []

    session = _create_session()
    records: list[dict[str, Any]] = []

    try:
        for index, cve_id in enumerate(unique_ids):
            url = f"{DEBIAN_TRACKER_URL}/{cve_id}"

            try:
                response = session.get(url, timeout=(10, 30))

                if response.status_code == 404:
                    logger.info("Debian tracker has no page for %s", cve_id)
                    continue

                response.raise_for_status()

                soup = BeautifulSoup(response.text, "lxml")
                page_text = _extract_page_text(soup)
                title = soup.title.get_text(" ", strip=True) if soup.title else cve_id

                records.append({
                    "cve_id": cve_id,
                    "description": title,
                    "cvss_version": None,
                    "cvss_score": None,
                    "severity": None,
                    "published_at": None,
                    "last_modified_at": None,
                    "affected_products": [],
                    "reference_urls": [url],
                    "source_name": SOURCE_NAME,
                    "source_record_id": cve_id,
                    "source_published_at": None,
                    "source_updated_at": None,
                    "source_url": url,
                    "raw_data": {
                        "title": title,
                        "page_text": page_text[:20000],
                        "package_status_rows": _extract_package_statuses(soup),
                    },
                })

                logger.debug(
                    "Collected Debian tracker information for %s",
                    cve_id,
                )

            except requests.RequestException as exc:
                logger.warning(
                    "Could not fetch Debian tracker page for %s: %s",
                    cve_id,
                    exc,
                )
                # Keep processing other CVEs if one page fails.
                continue

            # Be polite to the public tracker.
            if index < len(unique_ids) - 1:
                time.sleep(0.25)

        logger.info(
            "Debian Security Tracker returned %s records from %s CVEs",
            len(records),
            len(unique_ids),
        )
        return records

    finally:
        session.close()