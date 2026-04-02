// --- DOM references ---
const form = document.getElementById("calc-form");
const cweInput = document.getElementById("cwe-input");
const submitBtn = document.getElementById("submit-btn");
const btnLabel = document.getElementById("btn-label");
const btnSpinner = document.getElementById("btn-spinner");
const statusDot = document.querySelector(".status-dot");
const statusText = document.getElementById("status-text");
const emptyState = document.getElementById("empty-state");
const errorState = document.getElementById("error-state");
const errorMessage = document.getElementById("error-message");
const resultsSection = document.getElementById("results");

// Metric elements
const metricCwe = document.getElementById("metric-cwe");
const metricCount = document.getElementById("metric-count");
const metricMaxEpss = document.getElementById("metric-max-epss");
const metricAvgEpss = document.getElementById("metric-avg-epss");

// Table
const cveTbody = document.getElementById("cve-tbody");

// --- Chart setup ---
let chart = null;

function initChart() {
    chart = new ApexCharts(document.getElementById("chart"), {
        chart: {
            type: "bar",
            height: 360,
            background: "transparent",
            toolbar: { show: false },
            animations: {
                enabled: true,
                easing: "easeinout",
                speed: 600,
            },
        },
        plotOptions: {
            bar: {
                horizontal: true,
                borderRadius: 2,
                barHeight: "60%",
            },
        },
        dataLabels: { enabled: false },
        series: [{ name: "EPSS Score", data: [] }],
        xaxis: {
            categories: [],
            max: 1,
            labels: {
                style: {
                    colors: "#334155",
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: "10px",
                },
                formatter: (val) => val.toFixed(2),
            },
            axisBorder: { color: "#1a2234" },
            axisTicks: { color: "#1a2234" },
        },
        yaxis: {
            labels: {
                style: {
                    colors: "#64748b",
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: "10px",
                },
            },
        },
        grid: {
            borderColor: "#1a2234",
            xaxis: { lines: { show: true } },
            yaxis: { lines: { show: false } },
        },
        tooltip: {
            theme: "dark",
            style: { fontFamily: "IBM Plex Sans, sans-serif", fontSize: "12px" },
            y: {
                formatter: (val) => (val * 100).toFixed(2) + "% probability",
            },
        },
        colors: ["#e2b44a"],
        noData: {
            text: "No data",
            style: {
                color: "#334155",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "12px",
            },
        },
    });
    chart.render();
}

// --- Helpers ---

function getEpssSeverity(score) {
    if (score >= 0.5) return "critical";
    if (score >= 0.2) return "high";
    if (score >= 0.05) return "medium";
    return "low";
}

function getSeverityColor(severity) {
    const colors = {
        critical: "#ef5350",
        high: "#ff9800",
        medium: "#e2b44a",
        low: "#4db6ac",
    };
    return colors[severity] || colors.low;
}

function formatEpss(val) {
    const num = parseFloat(val);
    if (isNaN(num)) return "—";
    if (num < 0.001) return "<0.1%";
    return (num * 100).toFixed(2) + "%";
}

function formatPercentile(val) {
    const num = parseFloat(val);
    if (isNaN(num)) return "—";
    return (num * 100).toFixed(1) + "%";
}

function setStatus(state, text) {
    statusDot.className = "status-dot" + (state !== "idle" ? " " + state : "");
    statusText.textContent = text;
}

function setLoading(loading) {
    submitBtn.disabled = loading;
    btnLabel.textContent = loading ? "Scanning" : "Analyze";
    btnSpinner.classList.toggle("hidden", !loading);
    if (loading) {
        setStatus("active", "Querying NVD + EPSS");
    }
}

function showError(msg) {
    emptyState.classList.add("hidden");
    resultsSection.classList.add("hidden");
    errorState.classList.remove("hidden");
    errorMessage.textContent = msg;
    setStatus("error", "Error");
}

function showResults() {
    emptyState.classList.add("hidden");
    errorState.classList.add("hidden");
    resultsSection.classList.remove("hidden");
    // Trigger stagger animation
    const metricsGrid = resultsSection.querySelector(".grid");
    if (metricsGrid) {
        metricsGrid.classList.add("stagger");
    }
}

// --- Normalize CWE input ---
function normalizeCwe(raw) {
    const trimmed = raw.trim().toUpperCase();
    if (/^\d+$/.test(trimmed)) return "CWE-" + trimmed;
    if (/^CWE-?\d+$/.test(trimmed)) return trimmed.replace(/^CWE(\d)/, "CWE-$1");
    return trimmed;
}

// --- Render results ---

function renderMetrics(data) {
    metricCwe.textContent = data.cwe;
    metricCount.textContent = data.cve_count;

    if (data.epss && data.epss.length > 0) {
        const scores = data.epss.map((e) => parseFloat(e.epss)).filter((n) => !isNaN(n));
        const max = Math.max(...scores);
        const avg = scores.reduce((a, b) => a + b, 0) / scores.length;

        metricMaxEpss.textContent = formatEpss(max);
        metricMaxEpss.className = "metric-value epss-" + getEpssSeverity(max);

        metricAvgEpss.textContent = formatEpss(avg);
        metricAvgEpss.className = "metric-value epss-" + getEpssSeverity(avg);
    } else {
        metricMaxEpss.textContent = "—";
        metricMaxEpss.className = "metric-value";
        metricAvgEpss.textContent = "—";
        metricAvgEpss.className = "metric-value";
    }
}

function renderTable(data) {
    cveTbody.innerHTML = "";

    // Build a map of CVE -> EPSS data
    const epssMap = {};
    if (data.epss) {
        data.epss.forEach((entry) => {
            epssMap[entry.cve] = entry;
        });
    }

    // Sort CVEs by EPSS score descending
    const sorted = [...data.cves].sort((a, b) => {
        const scoreA = epssMap[a] ? parseFloat(epssMap[a].epss) : 0;
        const scoreB = epssMap[b] ? parseFloat(epssMap[b].epss) : 0;
        return scoreB - scoreA;
    });

    sorted.forEach((cveId, i) => {
        const epss = epssMap[cveId];
        const score = epss ? parseFloat(epss.epss) : 0;
        const percentile = epss ? parseFloat(epss.percentile) : 0;
        const severity = getEpssSeverity(score);

        const tr = document.createElement("tr");
        tr.style.animationDelay = Math.min(i * 30, 500) + "ms";
        tr.classList.add("fade-up");

        tr.innerHTML = `
            <td>
                <span class="font-mono text-xs text-gray-400">${cveId}</span>
            </td>
            <td class="text-right pr-4">
                <span class="font-mono text-xs epss-${severity}">${formatEpss(score)}</span>
                <div class="epss-bar-track">
                    <div class="epss-bar-fill" style="width: ${Math.max(score * 100, 0.5)}%; background: ${getSeverityColor(severity)};"></div>
                </div>
            </td>
            <td class="text-right">
                <span class="font-mono text-xs text-base-500">${formatPercentile(percentile)}</span>
            </td>
        `;
        cveTbody.appendChild(tr);
    });
}

function renderChart(data) {
    if (!data.epss || data.epss.length === 0) {
        chart.updateSeries([{ name: "EPSS Score", data: [] }]);
        return;
    }

    // Sort by EPSS score descending, take top 25 for readability
    const sorted = [...data.epss]
        .map((e) => ({ cve: e.cve, score: parseFloat(e.epss) || 0 }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 25);

    const categories = sorted.map((e) => e.cve);
    const scores = sorted.map((e) => e.score);
    const colors = sorted.map((e) => getSeverityColor(getEpssSeverity(e.score)));

    chart.updateOptions({
        series: [{ name: "EPSS Score", data: scores }],
        xaxis: { categories },
        colors: [function({ value, dataPointIndex }) {
            return colors[dataPointIndex] || "#e2b44a";
        }],
        plotOptions: {
            bar: {
                distributed: true,
                horizontal: true,
                borderRadius: 2,
                barHeight: Math.max(30, 70 - sorted.length) + "%",
            },
        },
        legend: { show: false },
    });
}

// --- Form submission ---

form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rawCwe = cweInput.value;
    if (!rawCwe.trim()) {
        cweInput.focus();
        return;
    }

    const cwe = normalizeCwe(rawCwe);
    cweInput.value = cwe;
    setLoading(true);

    try {
        const baseUrl = window.API_URL || "";
        const res = await fetch(`${baseUrl}/api/calculate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cwe }),
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => null);
            throw new Error(errData?.error || `API returned ${res.status}`);
        }

        const data = await res.json();

        if (data.error) {
            showError(data.error);
            return;
        }

        if (data.cve_count === 0) {
            showError(`No CVEs found for ${cwe}. Verify the identifier and try again.`);
            return;
        }

        showResults();
        renderMetrics(data);
        renderTable(data);
        renderChart(data);
        setStatus("active", `${data.cve_count} CVEs loaded`);

        // Fade status back after a moment
        setTimeout(() => setStatus("idle", "Ready"), 4000);
    } catch (err) {
        showError("Request failed: " + err.message);
    } finally {
        setLoading(false);
    }
});

// --- Keyboard shortcut ---
document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== cweInput) {
        e.preventDefault();
        cweInput.focus();
    }
});

// --- Init ---
initChart();
