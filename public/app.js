const domainInput = document.getElementById("domainInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("errorBox");
const results = document.getElementById("results");

let latencyChart;
let securityChart;

function setLoading(state) {
  loading.classList.toggle("hidden", !state);
  analyzeBtn.disabled = state;
}

function setError(message = "") {
  errorBox.textContent = message;
  errorBox.classList.toggle("hidden", !message);
}

function renderCharts(payload) {
  const latencyCtx = document.getElementById("latencyChart");
  const securityCtx = document.getElementById("securityChart");

  if (latencyChart) latencyChart.destroy();
  if (securityChart) securityChart.destroy();

  const samples = payload.latency.samplesMs || [];
  latencyChart = new Chart(latencyCtx, {
    type: "line",
    data: {
      labels: samples.map((_, idx) => `Tentativa ${idx + 1}`),
      datasets: [
        {
          label: "ms",
          data: samples,
          borderColor: "#6ea8ff",
          backgroundColor: "rgba(110,168,255,0.2)",
          tension: 0.35,
        },
      ],
    },
    options: { responsive: true, maintainAspectRatio: false },
  });

  const securityScore = [
    payload.http.strictTransportSecurity === "enabled" ? 1 : 0,
    payload.http.contentSecurityPolicy === "enabled" ? 1 : 0,
    payload.security.wafEnabled === "integrated" ? 1 : 0,
    payload.security.ddosProtection === "integrated" ? 1 : 0,
  ];

  securityChart = new Chart(securityCtx, {
    type: "bar",
    data: {
      labels: ["HSTS", "CSP", "WAF", "DDoS"],
      datasets: [
        {
          label: "Ativo (1=sim)",
          data: securityScore,
          backgroundColor: ["#44d18b", "#44d18b", "#3f7cff", "#3f7cff"],
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: { y: { min: 0, max: 1, ticks: { stepSize: 1 } } },
    },
  });
}

function renderData(payload) {
  document.getElementById("domainValue").textContent = payload.domain;
  document.getElementById("ttlValue").textContent =
    payload.dns.ttl !== null ? `${payload.dns.ttl}s` : "N/A";
  document.getElementById("sslValue").textContent = payload.ssl.valid
    ? `${payload.ssl.tlsVersion || "TLS"} | expira em ${payload.ssl.daysRemaining} dias`
    : "SSL nao detectado";
  document.getElementById("latencyValue").textContent =
    payload.latency.avgMs !== null ? `${payload.latency.avgMs} ms` : "N/A";
  document.getElementById("regionValue").textContent =
    `${payload.geo.country} / ${payload.geo.region}`;
  document.getElementById("securityValue").textContent =
    `${payload.security.wafEnabled} | ${payload.security.ddosProtection}`;

  const recList = document.getElementById("recommendations");
  recList.innerHTML = "";
  (payload.recommendations || []).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    recList.appendChild(li);
  });

  renderCharts(payload);
  results.classList.remove("hidden");
}

async function analyzeDomain() {
  const domain = domainInput.value.trim();
  if (!domain) {
    setError("Informe um dominio valido.");
    return;
  }

  setError("");
  setLoading(true);
  results.classList.add("hidden");

  try {
    const response = await fetch(`/api/analyze?domain=${encodeURIComponent(domain)}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Falha ao analisar dominio");
    renderData(payload);
  } catch (error) {
    setError(error.message || "Falha inesperada.");
  } finally {
    setLoading(false);
  }
}

analyzeBtn.addEventListener("click", analyzeDomain);
domainInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") analyzeDomain();
});
