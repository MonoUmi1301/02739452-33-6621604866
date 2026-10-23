"use strict";

// ==========================================
// Cyber Vulnerability Intelligence Dashboard
// ==========================================

const API = {
    stats: "/api/stats",
    vulnerabilities: "/api/vulnerabilities",
    pipeline: "/api/pipeline-runs"
};

const state = {
    page: 1,
    perPage: 20,
    totalPages: 1,
    timelineChart: null,
    sourceChart: null
};

// ==========================================
// DOM Helpers
// ==========================================

function getElement(id) {
    return document.getElementById(id);
}

function createElement(tag, className, text) {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== undefined && text !== null) {
        element.textContent = String(text);
    }

    return element;
}

async function fetchJSON(url) {
    const response = await fetch(url, {
        headers: {
            Accept: "application/json"
        }
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
}

function formatNumber(value) {
    if (value === null || value === undefined) {
        return "—";
    }

    return Number(value).toLocaleString("en-US");
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return date.toLocaleString("th-TH", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function showStatus(message, type = "secondary") {
    const status = getElement("statusMessage");

    status.className = `alert alert-${type}`;
    status.textContent = message;
}

// ==========================================
// Dashboard Statistics
// ==========================================

async function loadStats() {
    const result = await fetchJSON(API.stats);

    const stats = result.stats || {};

    getElement("totalCritical").textContent =
        formatNumber(stats.total_critical);

    getElement("last7Days").textContent =
        formatNumber(stats.published_last_7_days);

    getElement("last30Days").textContent =
        formatNumber(stats.published_last_30_days);

    getElement("averageCvss").textContent =
        stats.average_cvss === null ||
        stats.average_cvss === undefined
            ? "—"
            : Number(stats.average_cvss).toFixed(1);

    getElement("maximumCvss").textContent =
        formatNumber(stats.maximum_cvss);

    renderSourceChart(result.sources || []);
}

// ==========================================
// Source Chart
// ==========================================

function renderSourceChart(sources) {
    const canvas = getElement("sourceChart");

    if (state.sourceChart) {
        state.sourceChart.destroy();
    }

    const labels = sources.map(item => item.source_name);
    const values = sources.map(item => Number(item.total));

    state.sourceChart = new Chart(canvas, {
        type: "doughnut",

        data: {
            labels: labels,
            datasets: [{
                label: "Unique CVEs per source",
                data: values,
                borderWidth: 2
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            plugins: {
                legend: {
                    position: "bottom"
                },

                tooltip: {
                    callbacks: {
                        label(context) {
                            return `${context.label}: ${context.parsed}`;
                        }
                    }
                }
            }
        }
    });
}

// ==========================================
// Timeline Chart
// ==========================================

function renderTimelineChart(rows) {
    const canvas = getElement("timelineChart");

    if (state.timelineChart) {
        state.timelineChart.destroy();
    }

    // Group the currently returned records by publication date.
    // This chart represents the loaded records, not every database row.
    const counts = new Map();

    rows.forEach(row => {
        if (!row.published_at) {
            return;
        }

        const date = new Date(row.published_at);

        if (Number.isNaN(date.getTime())) {
            return;
        }

        const key = date.toISOString().slice(0, 10);

        counts.set(key, (counts.get(key) || 0) + 1);
    });

    const labels = [...counts.keys()].sort();

    const values = labels.map(label => counts.get(label));

    state.timelineChart = new Chart(canvas, {
        type: "line",

        data: {
            labels: labels,

            datasets: [{
                label: "Loaded CVE records",
                data: values,
                borderWidth: 2,
                tension: 0.25,
                fill: false
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },

            plugins: {
                legend: {
                    display: true,
                    position: "bottom"
                }
            }
        }
    });
}

// ==========================================
// Vulnerability Filters
// ==========================================

function getFilters() {
    return {
        q: getElement("keyword").value.trim(),
        min_score: getElement("minScore").value,
        days: getElement("daysFilter").value
    };
}

function buildVulnerabilityURL() {
    const filters = getFilters();

    const params = new URLSearchParams({
        ...filters,
        page: String(state.page),
        per_page: String(state.perPage)
    });

    return `${API.vulnerabilities}?${params.toString()}`;
}

// ==========================================
// Vulnerability Table
// ==========================================

function renderVulnerabilityTable(rows) {
    const tbody = getElement("vulnerabilityTable");

    tbody.replaceChildren();

    if (!rows.length) {
        const tr = createElement("tr");
        const td = createElement(
            "td",
            "text-center py-5 text-secondary",
            "ไม่พบข้อมูลที่ตรงกับเงื่อนไข"
        );

        td.colSpan = 5;
        tr.appendChild(td);
        tbody.appendChild(tr);

        return;
    }

    rows.forEach(row => {
        const tr = document.createElement("tr");

        // CVE ID
        const cveCell = document.createElement("td");
        const cveLink = createElement(
            "a",
            "cve-link",
            row.cve_id
        );

        cveLink.href =
            `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(row.cve_id)}`;

        cveLink.target = "_blank";
        cveLink.rel = "noopener noreferrer";

        cveCell.appendChild(cveLink);
        tr.appendChild(cveCell);

        // Description
        const descriptionCell = createElement(
            "td",
            "description-cell",
            row.description || "ไม่มีรายละเอียด"
        );

        tr.appendChild(descriptionCell);

        // CVSS score
        const scoreCell = document.createElement("td");
        const scoreBadge = createElement(
            "span",
            "severity-badge",
            Number(row.cvss_score).toFixed(1)
        );

        scoreCell.appendChild(scoreBadge);
        tr.appendChild(scoreCell);

        // Publication date
        tr.appendChild(
            createElement("td", "", formatDate(row.published_at))
        );

        // Sources
        const sourceCell = document.createElement("td");

        let sources = row.sources || [];

        if (typeof sources === "string") {
            try {
                sources = JSON.parse(sources);
            } catch {
                sources = [];
            }
        }

        if (!Array.isArray(sources)) {
            sources = [];
        }

        sources.forEach(source => {
            sourceCell.appendChild(
                createElement("span", "source-badge", source)
            );
        });

        if (sources.length === 0) {
            sourceCell.textContent =
                `${Number(row.source_count || 0)} แหล่ง`;
        }

        tr.appendChild(sourceCell);

        tbody.appendChild(tr);
    });
}

// ==========================================
// Load Vulnerabilities
// ==========================================

async function loadVulnerabilities() {
    const tbody = getElement("vulnerabilityTable");

    tbody.replaceChildren();

    const loadingRow = document.createElement("tr");
    const loadingCell = createElement(
        "td",
        "text-center py-5",
        "กำลังโหลดข้อมูล..."
    );

    loadingCell.colSpan = 5;
    loadingRow.appendChild(loadingCell);
    tbody.appendChild(loadingRow);

    try {
        const result = await fetchJSON(buildVulnerabilityURL());

        const rows = result.data || [];
        const pagination = result.pagination || {};

        state.page = Number(pagination.page || 1);
        state.totalPages = Number(pagination.total_pages || 1);

        renderVulnerabilityTable(rows);
        renderTimelineChart(rows);

        getElement("resultCount").textContent =
            `${formatNumber(pagination.total)} รายการ`;

        getElement("pageInfo").textContent =
            `หน้า ${state.page} / ${state.totalPages}`;

        getElement("previousPage").disabled =
            state.page <= 1;

        getElement("nextPage").disabled =
            state.page >= state.totalPages;

    } catch (error) {
        console.error("Failed to load vulnerabilities:", error);

        tbody.replaceChildren();

        const tr = document.createElement("tr");
        const td = createElement(
            "td",
            "text-center py-5 text-danger",
            "โหลดข้อมูลไม่สำเร็จ กรุณาตรวจสอบ API และฐานข้อมูล"
        );

        td.colSpan = 5;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}

// ==========================================
// Pipeline Execution History
// ==========================================

async function loadPipelineRuns() {
    const tbody = getElement("pipelineTable");

    try {
        const result = await fetchJSON(
            `${API.pipeline}?limit=20`
        );

        tbody.replaceChildren();

        const rows = result.data || [];

        if (rows.length === 0) {
            const tr = document.createElement("tr");
            const td = createElement(
                "td",
                "text-center py-4 text-secondary",
                "ยังไม่มีประวัติการทำงาน"
            );

            td.colSpan = 6;
            tr.appendChild(td);
            tbody.appendChild(tr);

            return;
        }

        rows.forEach(row => {
            const tr = document.createElement("tr");

            tr.appendChild(
                createElement("td", "", formatDate(row.started_at))
            );

            tr.appendChild(
                createElement(
                    "td",
                    "",
                    row.source_name || row.dag_id || "—"
                )
            );

            const statusCell = document.createElement("td");

            const status = String(row.status || "unknown").toLowerCase();

            let badgeClass = "text-bg-secondary";

            if (status === "success") {
                badgeClass = "text-bg-success";
            } else if (
                status === "failed" ||
                status === "failure"
            ) {
                badgeClass = "text-bg-danger";
            } else if (
                status === "running"
            ) {
                badgeClass = "text-bg-primary";
            }

            statusCell.appendChild(
                createElement(
                    "span",
                    `badge ${badgeClass}`,
                    status.toUpperCase()
                )
            );

            tr.appendChild(statusCell);

            tr.appendChild(
                createElement(
                    "td",
                    "",
                    formatNumber(row.records_fetched)
                )
            );

            tr.appendChild(
                createElement(
                    "td",
                    "",
                    formatNumber(row.records_inserted)
                )
            );

            tr.appendChild(
                createElement(
                    "td",
                    "",
                    formatNumber(row.records_updated)
                )
            );

            tbody.appendChild(tr);
        });

    } catch (error) {
        console.error("Failed to load pipeline history:", error);

        tbody.replaceChildren();

        const tr = document.createElement("tr");
        const td = createElement(
            "td",
            "text-center py-4 text-danger",
            "โหลดประวัติ Pipeline ไม่สำเร็จ"
        );

        td.colSpan = 6;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}

// ==========================================
// Refresh Dashboard
// ==========================================

async function refreshDashboard() {
    showStatus("กำลังโหลดข้อมูลจากระบบ...", "secondary");

    const results = await Promise.allSettled([
        loadStats(),
        loadVulnerabilities(),
        loadPipelineRuns()
    ]);

    const failed = results.filter(
        result => result.status === "rejected"
    );

    if (failed.length > 0) {
        showStatus(
            "โหลดข้อมูลบางส่วนไม่สำเร็จ กรุณาตรวจสอบการเชื่อมต่อฐานข้อมูล",
            "warning"
        );
    } else {
        showStatus(
            `อัปเดต Dashboard สำเร็จ เวลา ${new Date().toLocaleTimeString("th-TH")}`,
            "success"
        );
    }
}

// ==========================================
// Event Listeners
// ==========================================

getElement("filterForm").addEventListener("submit", event => {
    event.preventDefault();

    state.page = 1;

    loadVulnerabilities();
});

getElement("previousPage").addEventListener("click", () => {
    if (state.page > 1) {
        state.page -= 1;
        loadVulnerabilities();
    }
});

getElement("nextPage").addEventListener("click", () => {
    if (state.page < state.totalPages) {
        state.page += 1;
        loadVulnerabilities();
    }
});

getElement("refreshButton").addEventListener(
    "click",
    refreshDashboard
);

getElement("refreshPipeline").addEventListener(
    "click",
    loadPipelineRuns
);

// ==========================================
// Start Dashboard
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();
});