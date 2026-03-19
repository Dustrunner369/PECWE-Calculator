const form = document.getElementById("calc-form");
const resultsDiv = document.getElementById("results");
const resultsOutput = document.getElementById("results-output");

// Placeholder chart
const chart = new ApexCharts(document.getElementById("chart"), {
  chart: { type: "line", height: 320 },
  series: [{ name: "Sample", data: [] }],
  xaxis: { categories: [] },
  noData: { text: "Run a calculation to see results" },
});
chart.render();

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const formData = new FormData(form);
  const payload = Object.fromEntries(formData.entries());

  try {
    const res = await fetch("/api/calculate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    resultsOutput.textContent = JSON.stringify(data, null, 2);
    resultsDiv.classList.remove("hidden");

    // TODO: update chart with real data
    // chart.updateSeries([{ name: "Result", data: [...] }]);
  } catch (err) {
    resultsOutput.textContent = "Error: " + err.message;
    resultsDiv.classList.remove("hidden");
  }
});
