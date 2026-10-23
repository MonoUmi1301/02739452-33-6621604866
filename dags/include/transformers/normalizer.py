import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

SOURCE_PRIORITY = {
    "nvd": 1,
    "github_advisory": 2,
    "debian_security_tracker": 3,
}


def _parse_datetime(value: Any) -> datetime | None:
    """Convert an ISO 8601 string to a timezone-aware datetime."""
    if not value or not isinstance(value, str):
        return None

    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


def _record_priority(record: dict[str, Any]) -> tuple[int, int, int]:
    """
    Prefer records with a usable CVSS score and publication date.
    If equally complete, use the configured source priority.
    """
    has_score = record.get("cvss_score") is not None
    has_published = _parse_datetime(record.get("published_at")) is not None
    source_priority = SOURCE_PRIORITY.get(
        record.get("source_name", ""),
        99,
    )

    return (
        0 if has_score and has_published else 1,
        source_priority,
        0 if record.get("description") else 1,
    )


def normalize_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge records from NVD, GitHub Advisory Database, and Debian Tracker.

    Output contains one consolidated record per CVE ID.
    Source-specific records remain available in the sources field.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}

    for record in records:
        cve_id = str(record.get("cve_id", "")).strip().upper()

        if not cve_id:
            logger.warning("Skipping record without a CVE ID")
            continue

        grouped.setdefault(cve_id, []).append(record)

    normalized: list[dict[str, Any]] = []

    for cve_id, source_records in grouped.items():
        ordered = sorted(source_records, key=_record_priority)
        primary = ordered[0]

        # Collect unique products and reference URLs from every source.
        products: set[str] = set()
        reference_urls: set[str] = set()
        source_names: set[str] = set()

        for record in source_records:
            for product in record.get("affected_products") or []:
                if isinstance(product, str) and product.strip():
                    products.add(product.strip())

            for url in record.get("reference_urls") or []:
                if isinstance(url, str) and url.strip():
                    reference_urls.add(url.strip())

            source_name = record.get("source_name")
            if source_name:
                source_names.add(source_name)

            source_url = record.get("source_url")
            if source_url:
                reference_urls.add(source_url)

        # Fill missing descriptive fields from another source without
        # replacing a valid score or publication date with null values.
        description = next(
            (
                record.get("description")
                for record in ordered
                if record.get("description")
                and str(record["description"]).strip()
            ),
            "",
        )

        published_at = next(
            (
                record.get("published_at")
                for record in ordered
                if _parse_datetime(record.get("published_at")) is not None
            ),
            None,
        )

        last_modified_at = next(
            (
                record.get("last_modified_at")
                for record in ordered
                if _parse_datetime(record.get("last_modified_at")) is not None
            ),
            None,
        )

        # Preserve individual source payloads for auditing and debugging.
        source_details = []

        for record in sorted(
            source_records,
            key=lambda item: item.get("source_name", ""),
        ):
            source_details.append({
                "source_name": record.get("source_name"),
                "source_record_id": record.get("source_record_id"),
                "source_url": record.get("source_url"),
                "source_published_at": record.get("source_published_at"),
                "source_updated_at": record.get("source_updated_at"),
            })

        merged = {
            "cve_id": cve_id,
            "description": description,
            "cvss_version": primary.get("cvss_version"),
            "cvss_score": primary.get("cvss_score"),
            "severity": primary.get("severity"),
            "published_at": published_at,
            "last_modified_at": last_modified_at,
            "affected_products": sorted(products),
            "reference_urls": sorted(reference_urls),
            "source_count": len(source_names),
            "sources": sorted(source_names),
            "source_details": source_details,
        }

        normalized.append(merged)

    normalized.sort(
        key=lambda item: (
            item.get("published_at") or "",
            item.get("cvss_score") or 0,
        ),
        reverse=True,
    )

    logger.info(
        "Normalized %s input records into %s unique CVEs",
        len(records),
        len(normalized),
    )

    return normalized