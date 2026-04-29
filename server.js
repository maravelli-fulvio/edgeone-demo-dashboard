const express = require("express");
const dns = require("node:dns").promises;
const tls = require("node:tls");
const net = require("node:net");
const { URL } = require("node:url");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));

const EDGEONE_API_BASE = process.env.EDGEONE_API_BASE || "";
const EDGEONE_API_TOKEN = process.env.EDGEONE_API_TOKEN || "";

function sanitizeDomain(input) {
  const trimmed = String(input || "").trim();
  if (!trimmed) return "";

  try {
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      return new URL(trimmed).hostname.toLowerCase();
    }
  } catch {
    return "";
  }

  return trimmed.toLowerCase().replace(/^www\./, "");
}

function isValidDomain(domain) {
  const pattern =
    /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;
  return pattern.test(domain);
}

async function getDnsInfo(domain) {
  const [aRecords, aaaaRecords, cnameRecords, nsRecords, mxRecords] =
    await Promise.allSettled([
      dns.resolve4(domain, { ttl: true }),
      dns.resolve6(domain),
      dns.resolveCname(domain),
      dns.resolveNs(domain),
      dns.resolveMx(domain),
    ]);

  const resolvedA = aRecords.status === "fulfilled" ? aRecords.value : [];
  const ttl = resolvedA.length ? resolvedA[0].ttl : null;

  return {
    ttl,
    aRecords: resolvedA.map((entry) => entry.address),
    aaaaRecords: aaaaRecords.status === "fulfilled" ? aaaaRecords.value : [],
    cnameRecords: cnameRecords.status === "fulfilled" ? cnameRecords.value : [],
    nsRecords: nsRecords.status === "fulfilled" ? nsRecords.value : [],
    mxRecords:
      mxRecords.status === "fulfilled"
        ? mxRecords.value.map((mx) => `${mx.exchange} (p${mx.priority})`)
        : [],
  };
}

function parseCert(cert) {
  if (!cert || !cert.valid_to) {
    return {
      valid: false,
      issuer: "N/A",
      validTo: null,
      daysRemaining: null,
      tlsVersion: null,
    };
  }

  const expiry = new Date(cert.valid_to);
  const now = new Date();
  const diffDays = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));

  return {
    valid: true,
    issuer: cert.issuer?.O || cert.issuer?.CN || "N/A",
    validTo: cert.valid_to,
    daysRemaining: diffDays,
    tlsVersion: null,
  };
}

async function getSslInfo(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
        timeout: 7000,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const parsed = parseCert(cert);
        parsed.tlsVersion = socket.getProtocol() || "unknown";
        socket.end();
        resolve(parsed);
      }
    );

    socket.on("error", () => {
      resolve({
        valid: false,
        issuer: "N/A",
        validTo: null,
        daysRemaining: null,
        tlsVersion: null,
      });
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        valid: false,
        issuer: "N/A",
        validTo: null,
        daysRemaining: null,
        tlsVersion: null,
      });
    });
  });
}

async function measureLatency(host, port = 443, runs = 4) {
  const checks = Array.from({ length: runs }, () =>
    new Promise((resolve) => {
      const start = Date.now();
      const socket = new net.Socket();
      let done = false;

      const finalize = (value) => {
        if (done) return;
        done = true;
        socket.destroy();
        resolve(value);
      };

      socket.setTimeout(4000);
      socket.connect(port, host, () => finalize(Date.now() - start));
      socket.on("timeout", () => finalize(null));
      socket.on("error", () => finalize(null));
    })
  );

  const values = (await Promise.all(checks)).filter((value) => value !== null);
  if (!values.length) return { avgMs: null, samplesMs: [] };

  const avgMs = Math.round(values.reduce((sum, v) => sum + v, 0) / values.length);
  return { avgMs, samplesMs: values };
}

async function getGeoInfo(ip) {
  if (!ip) {
    return { country: "N/A", region: "N/A", city: "N/A", org: "N/A" };
  }

  try {
    const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 5000,
    });
    return {
      country: response.data.country_name || "N/A",
      region: response.data.region || "N/A",
      city: response.data.city || "N/A",
      org: response.data.org || "N/A",
    };
  } catch {
    return { country: "N/A", region: "N/A", city: "N/A", org: "N/A" };
  }
}

async function getHttpInfo(domain) {
  const startedAt = Date.now();
  try {
    const response = await axios.get(`https://${domain}`, {
      timeout: 8000,
      maxRedirects: 5,
      validateStatus: () => true,
    });
    return {
      statusCode: response.status,
      ttfbMs: Date.now() - startedAt,
      server: response.headers.server || "N/A",
      allHeaders: response.headers,
      cacheControl: response.headers["cache-control"] || "N/A",
      age: response.headers.age || "N/A",
      etag: response.headers.etag || "N/A",
      vary: response.headers.vary || "N/A",
      transferEncoding: response.headers["transfer-encoding"] || "N/A",
      contentType: response.headers["content-type"] || "N/A",
      strictTransportSecurity: response.headers["strict-transport-security"]
        ? "enabled"
        : "missing",
      contentSecurityPolicy: response.headers["content-security-policy"]
        ? "enabled"
        : "missing",
      streamingHint:
        response.headers["transfer-encoding"] === "chunked" ? "possible" : "not-detected",
    };
  } catch {
    return {
      statusCode: null,
      ttfbMs: null,
      server: "N/A",
      allHeaders: {},
      cacheControl: "N/A",
      age: "N/A",
      etag: "N/A",
      vary: "N/A",
      transferEncoding: "N/A",
      contentType: "N/A",
      strictTransportSecurity: "missing",
      contentSecurityPolicy: "missing",
      streamingHint: "not-detected",
    };
  }
}

function inferSecuritySignals(httpInfo, dnsInfo, sslInfo, edgeone) {
  const headers = httpInfo.allHeaders || {};
  const providerHint = `${httpInfo.server} ${dnsInfo.cnameRecords.join(" ")}`.toLowerCase();

  const wafSignal =
    edgeone.enabled ||
    Boolean(
      headers["cf-ray"] ||
        headers["x-sucuri-id"] ||
        headers["x-akamai-request-id"] ||
        providerHint.includes("cloudflare") ||
        providerHint.includes("edgeone") ||
        providerHint.includes("akamai")
    );

  const ddosSignal =
    edgeone.enabled ||
    Boolean(
      headers["cf-ray"] ||
        providerHint.includes("cloudflare") ||
        providerHint.includes("edgeone") ||
        providerHint.includes("akamai")
    );

  return {
    waf: wafSignal ? "detected-or-likely" : "not-detected",
    antiDdos: ddosSignal ? "detected-or-likely" : "not-detected",
    httpsEnforced: httpInfo.strictTransportSecurity === "enabled" ? "yes" : "no",
    cspEnabled: httpInfo.contentSecurityPolicy === "enabled" ? "yes" : "no",
    secureTls: sslInfo.valid && (sslInfo.tlsVersion || "").startsWith("TLSv1.3") ? "yes" : "partial",
    providerHint: httpInfo.server !== "N/A" ? httpInfo.server : "N/A",
    note: "Heuristica por headers/DNS; para status oficial use API EdgeOne.",
  };
}

async function getEdgeOneMetrics(domain) {
  if (!EDGEONE_API_BASE || !EDGEONE_API_TOKEN) {
    return {
      enabled: false,
      reason: "Configure EDGEONE_API_BASE and EDGEONE_API_TOKEN for real WAF/DDoS.",
      wafHits24h: null,
      ddosEvents24h: null,
    };
  }

  try {
    const response = await axios.get(`${EDGEONE_API_BASE}/metrics`, {
      timeout: 6000,
      headers: {
        Authorization: `Bearer ${EDGEONE_API_TOKEN}`,
      },
      params: { domain },
    });

    return {
      enabled: true,
      reason: null,
      wafHits24h: response.data?.wafHits24h ?? null,
      ddosEvents24h: response.data?.ddosEvents24h ?? null,
    };
  } catch {
    return {
      enabled: false,
      reason: "Could not fetch EdgeOne metrics with current credentials.",
      wafHits24h: null,
      ddosEvents24h: null,
    };
  }
}

async function getSubdomainInsights(domain) {
  try {
    const response = await axios.get(`https://crt.sh/?q=%25.${domain}&output=json`, {
      timeout: 7000,
    });

    const rows = Array.isArray(response.data) ? response.data : [];
    const discovered = new Set();

    rows.forEach((row) => {
      const rawNames = String(row.name_value || "").split("\n");
      rawNames.forEach((name) => {
        const normalized = name.trim().toLowerCase().replace(/^\*\./, "");
        if (!normalized || normalized === domain) return;
        if (normalized.endsWith(`.${domain}`)) {
          discovered.add(normalized);
        }
      });
    });

    const samples = [...discovered].sort().slice(0, 10);
    return {
      totalDetected: discovered.size,
      sampleList: samples,
      source: "crt.sh certificate transparency",
      note: "Pode nao listar 100% dos subdominios ativos.",
    };
  } catch {
    return {
      totalDetected: null,
      sampleList: [],
      source: "crt.sh certificate transparency",
      note: "Nao foi possivel consultar a fonte agora.",
    };
  }
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "edgeone-demo-dashboard" });
});

app.get("/api/sse-check", (_req, res) => {
  res.json({
    supportedByBrowser: true,
    endpoint: "/api/sse-stream",
    notes: "Use EventSource in browser to consume server-sent events.",
  });
});

app.get("/api/sse-stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  res.write(`event: connected\ndata: ${JSON.stringify({ ok: true })}\n\n`);
  const timer = setInterval(() => {
    res.write(`event: heartbeat\ndata: ${JSON.stringify({ ts: new Date().toISOString() })}\n\n`);
  }, 5000);

  req.on("close", () => {
    clearInterval(timer);
    res.end();
  });
});

app.get("/api/analyze", async (req, res) => {
  const domain = sanitizeDomain(req.query.domain);
  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: "Invalid domain." });
  }

  try {
    const dnsInfo = await getDnsInfo(domain);
    const primaryIp = dnsInfo.aRecords[0] || null;

    const [sslInfo, httpInfo, latencyInfo, geoInfo, edgeone, subdomains] = await Promise.all([
      getSslInfo(domain),
      getHttpInfo(domain),
      measureLatency(domain),
      getGeoInfo(primaryIp),
      getEdgeOneMetrics(domain),
      getSubdomainInsights(domain),
    ]);
    const securitySignals = inferSecuritySignals(httpInfo, dnsInfo, sslInfo, edgeone);

    res.json({
      analyzedAt: new Date().toISOString(),
      domain,
      dns: dnsInfo,
      ssl: sslInfo,
      http: httpInfo,
      latency: latencyInfo,
      geo: geoInfo,
      security: {
        wafEnabled: edgeone.enabled ? "integrated" : "unknown",
        ddosProtection: edgeone.enabled ? "integrated" : "unknown",
        wafHits24h: edgeone.wafHits24h,
        ddosEvents24h: edgeone.ddosEvents24h,
        edgeoneNote: edgeone.reason,
      },
      securitySignals,
      subdomains,
      coverage: {
        terraformNative: [
          "basic_domain_and_dns",
          "certificate_attachment",
          "rule_engine_basics",
        ],
        apiOrModule: [
          "advanced_waf_rate_limit",
          "log_delivery_s3",
          "versioned_config_rollout",
        ],
        notAvailableYet: [
          "full_formal_coverage_for_all_edgeone_features",
          "complete_subdomain_lifecycle_automation",
        ],
      },
      recommendations: [
        sslInfo.daysRemaining !== null && sslInfo.daysRemaining < 30
          ? "SSL expira em menos de 30 dias."
          : "SSL com validade confortavel.",
        httpInfo.strictTransportSecurity === "missing"
          ? "Habilite HSTS para reforcar HTTPS."
          : "HSTS ja habilitado.",
        dnsInfo.ttl !== null && dnsInfo.ttl > 3600
          ? "TTL alto; considere reduzir para mudancas mais rapidas."
          : "TTL adequado para operacao normal.",
      ],
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to analyze domain.",
      details: error.message || "Unknown error",
    });
  }
});

app.listen(PORT, () => {
  console.log(`EdgeOne demo dashboard running on port ${PORT}`);
});
