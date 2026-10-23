import os
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, render_template, request


app = Flask(__name__)

# =====================================================
# Database Configuration
# =====================================================

def get_db_connection():
    """Create a PostgreSQL connection using environment variables."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME", "cyber_vulnerability_db"),
        user=os.getenv("DB_USER", "cyber_user"),
        password=os.getenv("DB_PASSWORD", ""),
        connect_timeout=5,
    )


# =====================================================
# Database Query Helpers
# =====================================================

def query_database(sql, params=None):
    """Execute a read-only query and return dictionary rows."""
    with get_db_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(sql, params or ())
            return cursor.fetchall()


def query_one(sql, params=None):
    """Execute a query and return one row."""
    with get_db_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(sql, params or ())
            return cursor.fetchone()


# =====================================================
# Web Pages
# =====================================================

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/health")
def health():
    """Check whether the web application is responding."""
    return jsonify({
        "status": "ok",
        "service": "cyber-vulnerability-dashboard",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


# =====================================================
# Dashboard KPI API
# =====================================================

@app.route("/api/stats")
def api_stats():
    """Return dashboard KPI statistics."""
    try:
        stats = query_one("""
            SELECT
                COUNT(*) AS total_critical,
                COUNT(*) FILTER (
                    WHERE published_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
                ) AS published_last_7_days,
                COUNT(*) FILTER (
                    WHERE published_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
                ) AS published_last_30_days,
                ROUND(AVG(cvss_score), 1) AS average_cvss,
                COUNT(*) FILTER (
                    WHERE cvss_score = 10.0
                ) AS maximum_cvss
            FROM critical_vulnerabilities
        """)

        source_stats = query_database("""
            SELECT
                source_name,
                COUNT(DISTINCT cve_id) AS total
            FROM vulnerability_sources
            GROUP BY source_name
            ORDER BY source_name
        """)

        return jsonify({
            "stats": stats,
            "sources": source_stats,
        })

    except psycopg2.Error:
        app.logger.exception("Database error while loading dashboard statistics")
        return jsonify({
            "error": "Unable to load dashboard statistics"
        }), 503


# =====================================================
# Vulnerability List API
# =====================================================

@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    """Return filtered, paginated critical vulnerabilities."""

    keyword = request.args.get("q", "").strip()
    min_score = request.args.get("min_score", "9.0")
    days = request.args.get("days", "60")
    page = request.args.get("page", "1")
    per_page = request.args.get("per_page", "20")

    try:
        min_score = float(min_score)
        days = int(days)
        page = int(page)
        per_page = int(per_page)

        if not 9.0 <= min_score <= 10.0:
            raise ValueError("min_score must be between 9.0 and 10.0")

        if not 1 <= days <= 60:
            raise ValueError("days must be between 1 and 60")

        if page < 1:
            raise ValueError("page must be at least 1")

        if not 1 <= per_page <= 100:
            raise ValueError("per_page must be between 1 and 100")

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    where_sql = """
        WHERE cvss_version IN ('3.0', '3.1')
          AND cvss_score >= %s
          AND published_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')
          AND published_at <= CURRENT_TIMESTAMP
    """

    params = [min_score, days]

    if keyword:
        where_sql += """
            AND (
                cve_id ILIKE %s
                OR description ILIKE %s
            )
        """
        params.extend([f"%{keyword}%", f"%{keyword}%"])

    try:
        count_row = query_one(
            f"""
                SELECT COUNT(*) AS total
                FROM vulnerabilities
                {where_sql}
            """,
            params,
        )

        total = count_row["total"]

        rows = query_database(
            f"""
                SELECT
                    cve_id,
                    description,
                    cvss_version,
                    cvss_score,
                    severity,
                    published_at,
                    last_modified_at,
                    affected_products,
                    source_count,
                    sources
                FROM vulnerabilities
                {where_sql}
                ORDER BY published_at DESC, cvss_score DESC
                LIMIT %s OFFSET %s
            """,
            params + [per_page, (page - 1) * per_page],
        )

        return jsonify({
            "data": rows,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page,
            },
            "filters": {
                "keyword": keyword,
                "min_score": min_score,
                "days": days,
            },
        })

    except psycopg2.Error:
        app.logger.exception("Database error while loading vulnerabilities")
        return jsonify({
            "error": "Unable to load vulnerabilities"
        }), 503


# =====================================================
# CVE Source Details API
# =====================================================

@app.route("/api/vulnerabilities/<cve_id>/sources")
def api_vulnerability_sources(cve_id):
    """Return source records associated with a CVE."""

    try:
        rows = query_database("""
            SELECT
                source_name,
                source_record_id,
                source_published_at,
                source_updated_at,
                source_url,
                collected_at
            FROM vulnerability_sources
            WHERE cve_id = %s
            ORDER BY source_name
        """, (cve_id,))

        return jsonify({
            "cve_id": cve_id,
            "sources": rows,
        })

    except psycopg2.Error:
        app.logger.exception("Database error while loading CVE sources")
        return jsonify({
            "error": "Unable to load CVE sources"
        }), 503


# =====================================================
# Pipeline Status API
# =====================================================

@app.route("/api/pipeline-runs")
def api_pipeline_runs():
    """Return recent pipeline execution history."""

    try:
        limit = request.args.get("limit", "20")
        limit = int(limit)

        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        rows = query_database("""
            SELECT
                id,
                dag_id,
                run_id,
                source_name,
                status,
                records_fetched,
                records_inserted,
                records_updated,
                records_rejected,
                error_message,
                started_at,
                finished_at
            FROM pipeline_runs
            ORDER BY started_at DESC
            LIMIT %s
        """, (limit,))

        return jsonify({"data": rows})

    except psycopg2.Error:
        app.logger.exception("Database error while loading pipeline history")
        return jsonify({
            "error": "Unable to load pipeline history"
        }), 503


# =====================================================
# Data Quality API
# =====================================================

@app.route("/api/data-quality")
def api_data_quality():
    """Return recent data quality check results."""

    try:
        rows = query_database("""
            SELECT
                id,
                cve_id,
                source_name,
                check_name,
                passed,
                details,
                checked_at
            FROM data_quality_checks
            ORDER BY checked_at DESC
            LIMIT 100
        """)

        summary = query_one("""
            SELECT
                COUNT(*) AS total_checks,
                COUNT(*) FILTER (WHERE passed) AS passed_checks,
                COUNT(*) FILTER (WHERE NOT passed) AS failed_checks
            FROM data_quality_checks
        """)

        return jsonify({
            "summary": summary,
            "data": rows,
        })

    except psycopg2.Error:
        app.logger.exception("Database error while loading data quality checks")
        return jsonify({
            "error": "Unable to load data quality results"
        }), 503


# =====================================================
# Application Entry Point
# =====================================================

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
