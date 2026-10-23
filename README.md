# Cyber Vulnerability Intelligence

**Course:** 02739452 — Big Data Platforms and Analytics  
**GitHub Repository:** https://github.com/MonoUmi1301/02739452-33-6621604866

## 1. Project Overview

Cyber Vulnerability Intelligence is a data engineering project designed to collect, process, normalize, and analyze cybersecurity vulnerability information from multiple public sources.

The project focuses on critical vulnerabilities with a CVSS v3 score of **9.0 or higher**, published within a configurable lookback period of **60 days**.

The system is designed to help users organize vulnerability information in a centralized database and view the collected data through a web dashboard.

## 2. Objectives

- Collect vulnerability information from multiple public sources.
- Normalize vulnerability records into a consistent data structure.
- Apply data quality checks to the collected records.
- Store vulnerability information in PostgreSQL.
- Use Apache Airflow to orchestrate the data pipeline.
- Provide a web dashboard for viewing vulnerability information.
- Run the services using Docker Compose.

## 3. Data Sources

The project uses the following sources:

1. **National Vulnerability Database (NVD API)**  
   Provides information about CVEs, including vulnerability descriptions and CVSS scores.

2. **GitHub Advisory Database**  
   Provides security advisories related to software vulnerabilities and affected packages.

3. **Debian Security Tracker**  
   Provides security issue information relevant to Debian packages and distributions.

The available fields and coverage may differ between sources. The completeness of data collection depends on source availability, API access, and successful pipeline execution.

## 4. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Data extraction and transformation |
| Apache Airflow | Pipeline orchestration and scheduling |
| PostgreSQL | Structured data storage |
| Flask | Backend web application |
| HTML, CSS, JavaScript | Dashboard interface |
| Docker Compose | Running and managing services |
| SQL | Database schema, indexes, and queries |

## 5. Project Structure

```text
cyber-vulnerability-intelligence/
├── dags/
│   ├── cyber_vulnerability_pipeline.py
│   └── include/
│       ├── extractors/
│       │   ├── __init__.py
│       │   ├── nvd.py
│       │   ├── github_advisory.py
│       │   └── debian.py
│       └── transformers/
│           ├── __init__.py
│           ├── normalizer.py
│           └── quality.py
├── web/
│   ├── app.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── dashboard.js
├── sql/
│   └── init.sql
├── docs/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## 6. Data Pipeline

The intended data pipeline consists of the following stages:

1. **Extraction:** Retrieve vulnerability information from the configured public sources.
2. **Transformation:** Normalize source records into a common structure.
3. **Data Quality:** Validate records and check data quality.
4. **Storage:** Store processed records in PostgreSQL.
5. **Orchestration:** Use Apache Airflow to manage pipeline tasks.
6. **Visualization:** Present stored vulnerability information through the Flask dashboard.

### Architecture

```text
NVD API ───────────────┐
GitHub Advisory DB ────┼──> Extractors
Debian Security Tracker┘
                            |
                            v
                    Data Normalization
                            |
                            v
                     Quality Checks
                            |
                            v
                        PostgreSQL
                            |
                            v
                      Flask Dashboard

       Apache Airflow orchestrates the pipeline.
       Docker Compose manages the application services.
```

## 7. Database

The database initialization script is located at `sql/init.sql`.

The schema is designed to include:

- `vulnerabilities` — vulnerability records.
- `vulnerability_sources` — source information associated with records.
- `pipeline_runs` — pipeline execution tracking.
- `data_quality_checks` — data quality check results.
- `critical_vulnerabilities` — a view for recent critical vulnerabilities.

The configured critical vulnerability criteria are CVSS v3 scores of 9.0 or higher and a recent publication window.

## 8. Installation and Execution

### Prerequisites

- Docker Desktop
- Docker Compose
- Git
- A terminal such as PowerShell

### Configuration

1. Clone the repository or open the project directory.
2. Copy `.env.example` to `.env`.
3. Configure the database credentials and optional API tokens.
4. Verify that the database settings are consistent across the PostgreSQL, Airflow, and dashboard services.
5. Keep `.env` private and never commit passwords or API tokens to GitHub.

### Start the services

Run the following commands from the project root:

```powershell
docker compose up -d --build
```

Check the service status:

```powershell
docker compose ps -a
```

View the dashboard logs:

```powershell
docker compose logs --tail 100 dashboard
```

View the Airflow scheduler logs:

```powershell
docker compose logs --tail 100 airflow-scheduler
```

### Local URLs

- **Apache Airflow:** http://localhost:8080
- **Web Dashboard:** http://localhost:5000

Access depends on the services starting successfully and the local configuration being correct.

## 9. Testing and Verification Status

Based on the development logs available during preparation of this project:

- PostgreSQL started and reported a healthy status.
- Airflow database initialization completed successfully.
- The Airflow webserver reported a healthy status.
- The Airflow scheduler was running.
- The dashboard container was restarting and required further troubleshooting.

End-to-end data ingestion from all three sources, dashboard functionality, and the target of collecting at least 100 records have not been confirmed by the available logs.

These items should be verified before describing the complete system as fully operational.

## 10. Limitations and Future Improvements

Potential future improvements include:

- Troubleshooting and verifying the dashboard.
- Testing successful extraction from all configured sources.
- Improving error handling and retry logic.
- Adding automated tests for normalization and data quality.
- Verifying duplicate handling and source attribution.
- Measuring the number and completeness of collected records.
- Adding monitoring and clearer pipeline execution reports.

## 11. Security Considerations

- Do not commit `.env` files, passwords, API keys, or other secrets.
- Use placeholder values in `.env.example`.
- Respect the terms of use and rate limits of external data sources.
- Validate incoming data before storing it.
- Avoid collecting unnecessary personal information.

## 12. Conclusion

Cyber Vulnerability Intelligence provides a foundation for a multi-source cybersecurity data pipeline using Python, Apache Airflow, PostgreSQL, Flask, and Docker Compose.

The project is designed to centralize vulnerability information and support the identification of critical vulnerabilities. Further integration testing is required to confirm complete data ingestion and dashboard operation.

---

**Project:** Cyber Vulnerability Intelligence  
**Course:** 02739452 — Big Data Platforms and Analytics  
**Repository:** https://github.com/MonoUmi1301/02739452-33-6621604866