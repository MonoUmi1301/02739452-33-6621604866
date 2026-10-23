import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
SUPPORTED_CVSS_VERSIONS = {"3.0", "3.1"}


def _parse_datetime(value: Any) -> datetime | None:
    """Parse an ISO 8601 date or datetime."""
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def validate_record(
    record: dict[str, Any],
    minimum_score: float | None = None,
    lookback_days: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    Return a list of quality checks for one normalized CVE.

    Each check includes:
    - check_name
    - passed
    - details
    """
    if minimum_score is None:
        minimum_score = float(os.getenv("CVSS_MIN_SCORE", "9.0"))

    if lookback_days is None:
        lookback_days = max(1, int(os.getenv("LOOKBACK_DAYS", "60")))

    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    checks: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, details: str) -> None:
        checks.append({
            "cve_id": record.get("cve_id"),
            "source_name": "normalized",
            "check_name": name,
            "passed": passed,
            "details": details,
        })

    # Check 1: CVE identifier.
    cve_id = str(record.get("cve_id", "")).strip().upper()
    cve_valid = bool(CVE_PATTERN.fullmatch(cve_id))

    add_check(
        "valid_cve_id",
        cve_valid,
        "CVE ID format is valid" if cve_valid else "Invalid or missing CVE ID",
    )

    # Check 2: Description.
    description = record.get("description")
    description_valid = (
        isinstance(description, str)
        and bool(description.strip())
    )

    add_check(
        "description_present",
        description_valid,
        "Description is present"
        if description_valid
        else "Description is missing or empty",
    )

    # Check 3: CVSS version.
    version = str(record.get("cvss_version") or "")
    version_valid = version in SUPPORTED_CVSS_VERSIONS

    add_check(
        "supported_cvss_v3",
        version_valid,
        f"CVSS version: {version}"
        if version_valid
        else "CVSS v3.0 or v3.1 is required",
    )

    # Check 4: CVSS score.
    try:
        score = float(record.get("cvss_score"))
        score_valid = 0.0 <= score <= 10.0
        score_critical = score_valid and score >= minimum_score
    except (TypeError, ValueError):
        score = None
        score_valid = False
        score_critical = False

    add_check(
        "valid_cvss_score",
        score_valid,
        f"CVSS score: {score}"
        if score_valid
        else "CVSS score is missing or outside 0.0–10.0",
    )

    add_check(
        "critical_cvss_threshold",
        score_critical,
        f"Score meets threshold {minimum_score}"
        if score_critical
        else f"CVSS score must be at least {minimum_score}",
    )

    # Check 5: Publication date.
    published_at = _parse_datetime(record.get("published_at"))
    start_time = now - timedelta(days=lookback_days)

    published_valid = (
        published_at is not None
        and start_time <= published_at <= now
    )

    add_check(
        "published_within_lookback",
        published_valid,
        (
            f"Published at {published_at.isoformat()}"
            if published_valid
            else f"Publication date must be within the last {lookback_days} days"
        ),
    )

    # Check 6: At least one source was recorded.
    sources = record.get("sources") or []
    sources_valid = (
        isinstance(sources, list)
        and len(sources) > 0
    )

    add_check(
        "source_present",
        sources_valid,
        f"Sources: {', '.join(sources)}"
        if sources_valid
        else "No source information found",
    )

    return checks


def run_quality_checks(
    records: list[dict[str, Any]],
    minimum_score: float | None = None,
    lookback_days: int | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """
    Validate normalized records and separate accepted/rejected records.

    Returns:
        accepted_records, rejected_records, all_quality_checks
    """
    accepted_records: list[dict[str, Any]] = []
    rejected_records: list[dict[str, Any]] = []
    all_checks: list[dict[str, Any]] = []

    for record in records:
        checks = validate_record(
            record,
            minimum_score=minimum_score,
            lookback_days=lookback_days,
        )

        all_checks.extend(checks)

        failed_checks = [
            check for check in checks
            if not check["passed"]
        ]

        if failed_checks:
            rejected = dict(record)
            rejected["quality_errors"] = [
                check["details"] for check in failed_checks
            ]
            rejected_records.append(rejected)

            logger.warning(
                "Rejected %s: %s",
                record.get("cve_id"),
                "; ".join(rejected["quality_errors"]),
            )
        else:
            accepted_records.append(record)

    logger.info(
        "Quality checks complete: accepted=%s rejected=%s checks=%s",
        len(accepted_records),
        len(rejected_records),
        len(all_checks),
    )

    return accepted_records, rejected_records, all_checks