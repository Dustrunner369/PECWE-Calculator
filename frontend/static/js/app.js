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
const dateInput = document.getElementById("date-input");
const metricCwe = document.getElementById("metric-cwe");
const metricPecwe = document.getElementById("metric-pecwe");
const metricCount = document.getElementById("metric-count");
const metricMaxEpss = document.getElementById("metric-max-epss");
const metricAvgEpss = document.getElementById("metric-avg-epss");

// Chip row
const chipRow = document.getElementById("chip-row");
const chipList = document.getElementById("chip-list");
const chipSummary = document.getElementById("chip-summary");
const includeAllToggle = document.getElementById("include-all-children");

// Table
const cveTbody = document.getElementById("cve-tbody");

// --- State ---
let currentPerCwe = {};     // { "CWE-20": { name, cves, epss }, ... }
let primaryCwe = null;      // the CWE the user typed
let childCwes = [];         // children of primaryCwe (empty if not a parent)
const selectedCwes = new Set();

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

// --- Aggregate computation (client-side) ---

function computeAggregate() {
    // Union of CVEs + EPSS records across selected CWEs, deduped by CVE id.
    const cveSet = new Set();
    const epssMap = new Map(); // cve -> epss record

    for (const cwe of selectedCwes) {
        const bucket = currentPerCwe[cwe];
        if (!bucket) continue;
        for (const cve of bucket.cves) cveSet.add(cve);
        for (const entry of bucket.epss) {
            if (!epssMap.has(entry.cve)) epssMap.set(entry.cve, entry);
        }
    }

    const cves = Array.from(cveSet);
    const epss = Array.from(epssMap.values());

    // PECWE = 1 - prod(1 - EPSS(cve))  over the unique CVE set.
    // CVEs with no EPSS entry contribute a factor of 1 (EPSS = 0).
    let product = 1.0;
    for (const cve of cves) {
        const entry = epssMap.get(cve);
        const score = entry ? parseFloat(entry.epss) || 0 : 0;
        product *= 1 - score;
    }
    const pecwe = 1 - product;

    return { cves, epss, pecwe, cve_count: cves.length };
}

function computeTrend(epssRecords) {
    const recent = [];
    const old = [];
    for (const entry of epssRecords) {
        const year = parseInt(entry.cve.split("-")[1], 10);
        const score = parseFloat(entry.epss) || 0;
        if (Number.isNaN(year)) continue;
        (year >= 2022 ? recent : old).push(score);
    }
    if (!recent.length || !old.length) return "STABLE";
    const avg = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
    const avgRecent = avg(recent);
    const avgOld = avg(old);
    if (avgRecent > avgOld + 0.1) return "UP";
    if (avgRecent < avgOld - 0.1) return "DOWN";
    return "STABLE";
}

// --- Render results ---

function renderMetrics(agg) {
    // Metric CWE label: primary + child count indicator if aggregate
    if (childCwes.length > 0) {
        const selectedCount = selectedCwes.size;
        metricCwe.textContent = `${primaryCwe} +${Math.max(selectedCount - 1, 0)}`;
    } else {
        metricCwe.textContent = primaryCwe;
    }

    metricCount.textContent = agg.cve_count;

    const pecwe = typeof agg.pecwe === "number" ? agg.pecwe : null;
    if (pecwe !== null) {
        metricPecwe.textContent = formatEpss(pecwe);
        metricPecwe.className = "metric-value epss-" + getEpssSeverity(pecwe);
    } else {
        metricPecwe.textContent = "—";
        metricPecwe.className = "metric-value";
    }

    if (agg.epss && agg.epss.length > 0) {
        const scores = agg.epss.map((e) => parseFloat(e.epss)).filter((n) => !isNaN(n));
        const max = scores.length ? Math.max(...scores) : 0;
        const avg = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;

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

function renderTable(agg) {
    cveTbody.innerHTML = "";

    const epssMap = {};
    for (const entry of agg.epss) epssMap[entry.cve] = entry;

    const sorted = [...agg.cves].sort((a, b) => {
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

function renderChart(agg) {
    if (!agg.epss || agg.epss.length === 0) {
        chart.updateSeries([{ name: "EPSS Score", data: [] }]);
        return;
    }

    const sorted = [...agg.epss]
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

function renderAll() {
    const agg = computeAggregate();
    renderMetrics(agg);
    renderTable(agg);
    renderChart(agg);
    updateChipSummary(agg);
    syncIncludeAllToggle();
}

// --- Chips ---

function renderChips() {
    chipList.innerHTML = "";

    if (childCwes.length === 0) {
        chipRow.classList.add("hidden");
        return;
    }

    chipRow.classList.remove("hidden");

    const order = [primaryCwe, ...childCwes];
    for (const cwe of order) {
        const bucket = currentPerCwe[cwe] || {};
        const name = bucket.name || "";
        const count = (bucket.cves || []).length;
        const isPrimary = cwe === primaryCwe;

        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "cwe-chip" + (isPrimary ? " is-parent" : "");
        if (selectedCwes.has(cwe)) chip.classList.add("is-selected");
        chip.title = `${cwe} — ${name} · ${count} CVEs`;
        chip.innerHTML = `
            <span class="chip-dot"></span>
            <span>${cwe}</span>
            <span class="chip-name">${name}</span>
        `;
        chip.addEventListener("click", () => toggleCwe(cwe));
        chipList.appendChild(chip);
    }
}

function toggleCwe(cwe) {
    if (selectedCwes.has(cwe)) {
        selectedCwes.delete(cwe);
    } else {
        selectedCwes.add(cwe);
    }
    // Update the specific chip class without full rerender
    const idx = [primaryCwe, ...childCwes].indexOf(cwe);
    if (idx >= 0 && chipList.children[idx]) {
        chipList.children[idx].classList.toggle("is-selected", selectedCwes.has(cwe));
    }
    renderAll();
}

function updateChipSummary(agg) {
    if (childCwes.length === 0) {
        chipSummary.textContent = "";
        return;
    }
    const childrenSelected = childCwes.filter((c) => selectedCwes.has(c)).length;
    const parentSelected = selectedCwes.has(primaryCwe) ? 1 : 0;
    chipSummary.textContent = `${parentSelected + childrenSelected}/${childCwes.length + 1} selected · ${agg.cve_count} unique CVEs`;
}

function syncIncludeAllToggle() {
    // Toggle reflects whether every CHILD is selected (parent is independent).
    const allChildrenOn = childCwes.length > 0 && childCwes.every((c) => selectedCwes.has(c));
    includeAllToggle.checked = allChildrenOn;
}

includeAllToggle.addEventListener("change", (e) => {
    const on = e.target.checked;
    for (const c of childCwes) {
        if (on) selectedCwes.add(c);
        else selectedCwes.delete(c);
    }
    renderChips();
    renderAll();
});

// --- Form submission ---

form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rawCwe = cweInput.value;
    if (!rawCwe.trim()) {
        cweInput.focus();
        return;
    }

    const cwe = normalizeCwe(rawCwe);
    setLoading(true);

    try {
        const baseUrl = window.API_URL || "";
        const res = await fetch(`${baseUrl}/api/calculate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cwe, date: dateInput.value || undefined }),
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

        // Reset state from new response
        currentPerCwe = data.per_cwe || {};
        primaryCwe = data.cwe;
        childCwes = data.is_parent
            ? Object.keys(currentPerCwe).filter((c) => c !== primaryCwe)
            : [];

        // Default selection: everything that was fetched
        selectedCwes.clear();
        for (const c of Object.keys(currentPerCwe)) selectedCwes.add(c);

        const initialAgg = computeAggregate();
        if (initialAgg.cve_count === 0) {
            showError(`No CVEs found for ${cwe}. Verify the identifier and try again.`);
            return;
        }

        showResults();
        renderChips();
        renderAll();

        const label = data.is_parent
            ? `${initialAgg.cve_count} CVEs across ${selectedCwes.size} CWEs`
            : `${initialAgg.cve_count} CVEs loaded`;
        setStatus("active", label);

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
dateInput.value = new Date().toISOString().slice(0, 10);
initChart();
