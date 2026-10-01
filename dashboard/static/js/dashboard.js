/* HoneyScope dashboard front-end - vanilla JS + vendored Chart.js */
"use strict";

const $ = (sel) => document.querySelector(sel);
const PAGE = document.body.dataset.page;

const SEV_COLORS = {
  LOW: "#34d399", MEDIUM: "#eab308", HIGH: "#f97316", CRITICAL: "#ef4444",
};
const PALETTE = [
  "#38bdf8", "#a78bfa", "#34d399", "#fbbf24",
  "#fb7185", "#60a5fa", "#f97316", "#e879f9",
];
const charts = {};

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function esc(value) {
  if (value === null || value === undefined || value === "") {
    return '<span class="hint">—</span>';
  }
  const div = document.createElement("div");
  div.textContent = String(value);
  return div.innerHTML;
}

function sevBadge(sev) {
  const s = (sev || "LOW").toUpperCase();
  return `<span class="sev sev-${s.toLowerCase()}">${s}</span>`;
}

function makeChart(id, config) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!window.Chart) {
    el.replaceWith(Object.assign(document.createElement("p"),
      { textContent: "Chart.js unavailable - tables still work.", className: "hint" }));
    return;
  }
  Chart.defaults.color = "#8ea3c2";
  Chart.defaults.borderColor = "rgba(34,49,79,.8)";
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart(el, config);
}

function qs(params) {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== "" && v !== null && v !== undefined) p.set(k, v);
  });
  const s = p.toString();
  return s ? `?${s}` : "";
}

/* ------------------------------------------------------------------ modal */
function openEventModal(id) {
  fetchJSON(`/api/events/${id}`).then((ev) => {
    $("#modalOverlay").hidden = false;
    $("#modalBox").innerHTML = `
      <h3>Event #${esc(ev.id)} ${sevBadge(ev.severity)}
        <span class="chip" style="margin-left:8px">score ${esc(ev.score)}</span></h3>
      <dl>
        <dt>Timestamp</dt><dd>${esc(ev.ts)} (UTC)</dd>
        <dt>Source</dt><dd class="mono">${esc(ev.src_ip)}:${esc(ev.src_port)}</dd>
        <dt>Destination port</dt><dd class="mono">${esc(ev.dst_port)} (${esc(ev.protocol)})</dd>
        <dt>Service</dt><dd>${esc(ev.service)}</dd>
        <dt>Event type</dt><dd>${esc(ev.event_type)}</dd>
        <dt>Attack pattern</dt><dd class="pattern-tag">${esc(ev.attack_pattern)}</dd>
        <dt>Username</dt><dd class="mono">${esc(ev.username)}</dd>
        <dt>Password</dt><dd class="mono">${esc(ev.password)}</dd>
        <dt>Geolocation</dt><dd>${esc(ev.geo_country)}${ev.geo_city ? " / " + esc(ev.geo_city) : ""}
            ${ev.geo_asn ? " · " + esc(ev.geo_asn) : ""}</dd>
        <dt>User agent</dt><dd class="mono">${esc(ev.user_agent)}</dd>
      </dl>
      <p class="hint" style="margin-bottom:6px">Payload</p>
      <pre>${esc(ev.payload)}</pre>
      <button onclick="document.getElementById('modalOverlay').hidden=true">Close</button>`;
  }).catch(() => {});
}
window.openEventModal = openEventModal;

/* ---------------------------------------------------------------- overview */
async function loadOverview() {
  const stats = await fetchJSON("/api/stats");
  $("#kpi-total").textContent = stats.total_events.toLocaleString();
  $("#kpi-ips").textContent = stats.unique_ips.toLocaleString();
  $("#kpi-24h").textContent = stats.events_last_24h.toLocaleString();
  $("#kpi-critical").textContent = (stats.critical_events || 0).toLocaleString();
  $("#kpi-creds").textContent = stats.credentials_captured.toLocaleString();

  const timeline = await fetchJSON("/api/timeline?hours=48&buckets=48");
  makeChart("chartTimeline", {
    type: "line",
    data: {
      labels: timeline.map((p) => p.label),
      datasets: [
        { label: "All events", data: timeline.map((p) => p.count),
          borderColor: "#38bdf8", backgroundColor: "rgba(56,189,248,.15)",
          fill: true, tension: 0.35, pointRadius: 0 },
        { label: "Critical", data: timeline.map((p) => p.critical),
          borderColor: "#ef4444", tension: 0.35, pointRadius: 0 },
      ],
    },
    options: { scales: { y: { beginAtZero: true } } },
  });

  const sev = stats.by_severity || {};
  makeChart("chartSeverity", {
    type: "doughnut",
    data: { labels: Object.keys(sev), datasets: [{ data: Object.values(sev),
      backgroundColor: Object.keys(sev).map((k) => SEV_COLORS[k.toUpperCase()] || "#60a5fa") }] },
    options: { plugins: { legend: { position: "right" } } },
  });

  const svc = stats.by_service || {};
  makeChart("chartService", {
    type: "pie",
    data: { labels: Object.keys(svc).map((s) => s.toUpperCase()),
      datasets: [{ data: Object.values(svc),
        backgroundColor: Object.keys(svc).map((_, i) => PALETTE[i % PALETTE.length]) }] },
    options: { plugins: { legend: { position: "right" } } },
  });

  const topIps = await fetchJSON("/api/top/ips?limit=10");
  makeChart("chartTopIps", {
    type: "bar",
    data: { labels: topIps.map((r) => r.ip), datasets: [{ label: "Events",
      data: topIps.map((r) => r.count),
      backgroundColor: topIps.map((r) => SEV_COLORS[r.max_severity] || "#38bdf8") }] },
    options: { indexAxis: "y",
      plugins: { legend: { display: false },
        tooltip: { callbacks: { afterLabel: (c) =>
          `worst severity: ${topIps[c.dataIndex].max_severity}` } } } },
  });

  const pat = stats.by_pattern || {};
  makeChart("chartPatterns", {
    type: "bar",
    data: { labels: Object.keys(pat), datasets: [{ label: "Events",
      data: Object.values(pat),
      backgroundColor: Object.keys(pat).map((_, i) => PALETTE[i % PALETTE.length]) }] },
    options: { indexAxis: "y", plugins: { legend: { display: false } } },
  });

  const recent = await fetchJSON("/api/events?per_page=8&page=1");
  $("#recentBody").innerHTML = recent.events.length
    ? recent.events.map((ev) => `
      <tr style="cursor:pointer" onclick="openEventModal(${ev.id})">
        <td class="mono">${esc((ev.ts || "").slice(11, 19))}</td>
        <td class="mono">${esc(ev.src_ip)}</td>
        <td>${esc((ev.service || "").toUpperCase())}</td>
        <td>${esc(ev.event_type)}</td>
        <td>${sevBadge(ev.severity)}</td>
      </tr>`).join("")
    : '<tr><td colspan="5" class="empty">No events captured yet — run scripts/simulate_attacks.py</td></tr>';

  const status = await fetchJSON("/api/status");
  const tbody = $("#statusBody");
  if (status.listeners && status.listeners.length) {
    tbody.innerHTML = status.listeners.filter((l) =>
      ["ssh", "http", "ftp", "telnet"].includes(l.service)).map((l) => `
      <tr><td>${esc(l.name)}</td><td class="mono">${l.port}</td>
      <td>${l.running ? '<span style="color:#34d399">● running</span>'
                      : '<span style="color:#ef4444">● stopped</span>'}</td></tr>`).join("");
    if (status.uptime_seconds !== null && status.uptime_seconds !== undefined) {
      const h = Math.floor(status.uptime_seconds / 3600);
      const m = Math.floor((status.uptime_seconds % 3600) / 60);
      $("#uptimeLine").textContent =
        `Uptime: ${h}h ${m}m · sensors active on ${(status.listeners || []).length} ports`;
    }
  }
}

/* ------------------------------------------------------------------ events */
const evState = { page: 1, perPage: 50, q: "", severity: "", service: "", pattern: "", ip: "" };

function readUrlFilters() {
  const p = new URLSearchParams(location.search);
  evState.ip = p.get("ip") || "";
  evState.severity = p.get("severity") || "";
  evState.page = parseInt(p.get("page") || "1", 10);
}

async function initEventsPage() {
  readUrlFilters();
  const meta = await fetchJSON("/api/meta/filters");
  const fill = (sel, list, current) => {
    const el = $(sel);
    list.forEach((v) => {
      const opt = document.createElement("option");
      opt.value = v; opt.textContent = v;
      el.appendChild(opt);
    });
    if (current) el.value = current;
  };
  fill("#fSeverity", meta.severities, evState.severity);
  fill("#fService", meta.services);
  fill("#fPattern", meta.patterns);

  $("#filterForm").addEventListener("submit", (e) => {
    e.preventDefault();
    evState.q = $("#fQ").value.trim();
    evState.severity = $("#fSeverity").value;
    evState.service = $("#fService").value;
    evState.pattern = $("#fPattern").value;
    evState.perPage = parseInt($("#fPerPage").value, 10);
    evState.page = 1;
    loadEventsTable();
  });
  $("#resetFilters").addEventListener("click", () => {
    ["#fQ", "#fSeverity", "#fService", "#fPattern"].forEach((s) => { $(s).value = ""; });
    Object.assign(evState, { page: 1, q: "", severity: "", service: "", pattern: "", ip: "" });
    loadEventsTable();
  });
  $("#prevPage").addEventListener("click", () => { if (evState.page > 1) { evState.page--; loadEventsTable(); } });
  $("#nextPage").addEventListener("click", () => { evState.page++; loadEventsTable(); });

  $("#clearEvents").addEventListener("click", async () => {
    if (!confirm("Clear ALL captured events and the raw log? This cannot be undone.")) return;
    try {
      await fetchJSON("/api/reset", { method: "POST" });
      evState.page = 1;
      loadEventsTable();
      refreshDbTotal();
    } catch (err) { alert("Reset failed: " + err.message); }
  });

  loadEventsTable();
}

async function loadEventsTable() {
  const data = await fetchJSON("/api/events" + qs({
    q: evState.q, severity: evState.severity, service: evState.service,
    pattern: evState.pattern, ip: evState.ip,
    page: evState.page, per_page: evState.perPage,
  }));
  const lastPage = Math.max(1, Math.ceil(data.total / data.per_page));
  if (evState.page > lastPage) { evState.page = lastPage; }
  $("#pageInfo").textContent =
    `${data.total.toLocaleString()} events · page ${data.page} / ${lastPage}`;
  $("#eventsBody").innerHTML = data.events.length ? data.events.map((ev) => `
    <tr style="cursor:pointer" onclick="openEventModal(${ev.id})">
      <td class="hint">${ev.id}</td>
      <td class="mono">${esc((ev.ts || "").replace("T", " ").slice(0, 19))}</td>
      <td class="mono">${esc(ev.src_ip)}:${esc(ev.src_port ?? "")}</td>
      <td class="mono">${esc(ev.dst_port ?? "")}</td>
      <td>${esc((ev.service || "").toUpperCase())}</td>
      <td>${esc(ev.event_type)}</td>
      <td class="mono">${esc(ev.username)}</td>
      <td class="mono">${esc(ev.password)}</td>
      <td class="pattern-tag">${esc(ev.attack_pattern)}</td>
      <td class="mono">${esc(ev.score)}</td>
      <td>${sevBadge(ev.severity)}</td>
    </tr>`).join("")
    : '<tr><td colspan="11" class="empty">No events match the current filters.</td></tr>';
}

/* ------------------------------------------------------------------- intel */
async function initIntelPage() {
  $("#geoNote").textContent =
    "private/lab addresses are labelled locally; online lookups are privacy-controlled";
  const data = await fetchJSON("/api/intel?limit=300");
  $("#intelBody").innerHTML = data.ips.length ? data.ips.map((r) => `
    <tr>
      <td class="mono"><strong>${esc(r.ip)}</strong></td>
      <td>${r.is_private ? "🏠 " : "🌍 "}${esc(r.country || "Unknown")}${r.city ? " / " + esc(r.city) : ""}</td>
      <td class="mono">${esc(r.asn)}</td>
      <td class="mono">${r.total_events}</td>
      <td>${sevBadge(r.max_severity)}</td>
      <td class="mono">${esc((r.first_seen || "").replace("T", " ").slice(0, 16))}</td>
      <td class="mono">${esc((r.last_seen || "").replace("T", " ").slice(0, 16))}</td>
      <td><a href="/events?ip=${encodeURIComponent(r.ip)}" style="color:#38bdf8">view log →</a></td>
    </tr>`).join("")
    : '<tr><td colspan="8" class="empty">No attacker IPs recorded yet.</td></tr>';
}

/* ------------------------------------------------------------- credentials */
async function initCredentialsPage() {
  const [users, passes, combos] = await Promise.all([
    fetchJSON("/api/top/usernames?limit=12"),
    fetchJSON("/api/top/passwords?limit=12"),
    fetchJSON("/api/credentials/combos?limit=20"),
  ]);
  const labels = [...new Set([...users.map((r) => r.value), ...passes.map((r) => r.value)])].slice(0, 14);
  const uMap = Object.fromEntries(users.map((r) => [r.value, r.count]));
  const pMap = Object.fromEntries(passes.map((r) => [r.value, r.count]));
  makeChart("chartCreds", {
    type: "bar",
    data: { labels, datasets: [
      { label: "Username attempts", data: labels.map((l) => uMap[l] || 0), backgroundColor: "#a78bfa" },
      { label: "Password attempts", data: labels.map((l) => pMap[l] || 0), backgroundColor: "#34d399" },
    ] },
    options: { indexAxis: "y" },
  });
  $("#combosBody").innerHTML = combos.length ? combos.map((r) => `
    <tr>
      <td class="mono">${esc(r.username)}</td>
      <td class="mono">${esc(r.password)}</td>
      <td class="mono">${r.count}</td>
      <td class="mono">${r.sources}</td>
    </tr>`).join("")
    : '<tr><td colspan="4" class="empty">No credentials captured yet.</td></tr>';
}

/* ------------------------------------------------------------------ report */
async function initReportPage() {
  $("#genReport").addEventListener("click", async () => {
    const btn = $("#genReport");
    btn.disabled = true; btn.textContent = "Generating…";
    try {
      const res = await fetchJSON("/api/report/generate", { method: "POST" });
      const box = $("#reportResult");
      box.hidden = false;
      box.innerHTML = `
        <strong>✅ Report generated</strong> — summary:
        ${res.summary.total_events} events · ${res.summary.unique_ips} unique IPs ·
        ${res.summary.critical_events} critical · ${res.summary.credentials_captured} credential attempts
        <ul class="nice-list">
          <li><a href="/api/report/file?name=${res.files.html}" target="_blank"
                 style="color:#38bdf8">Open HTML report</a> (self-contained, printable to PDF)</li>
          <li><code>reports/out/${res.files.markdown}</code></li>
        </ul>`;
    } catch (err) {
      alert("Report generation failed: " + err.message);
    } finally {
      btn.disabled = false; btn.textContent = "Generate report now";
    }
  });
}

/* -------------------------------------------------------------------- boot */
async function refreshDbTotal() {
  try {
    const s = await fetchJSON("/api/status");
    $("#dbTotal").textContent = `${s.total_events.toLocaleString()} events`;
  } catch (e) { /* server restarting */ }
}

window.addEventListener("DOMContentLoaded", () => {
  refreshDbTotal();
  if (PAGE === "overview") { loadOverview().catch(console.error); }
  if (PAGE === "events") { initEventsPage().catch(console.error); }
  if (PAGE === "intel") { initIntelPage().catch(console.error); }
  if (PAGE === "credentials") { initCredentialsPage().catch(console.error); }
  if (PAGE === "report") { initReportPage(); }

  // auto-refresh: overview polls everything; other pages poll the counter
  setInterval(() => {
    if (PAGE === "overview") loadOverview().catch(() => {});
    refreshDbTotal();
  }, 5000);

  $("#modalOverlay").addEventListener("click", (e) => {
    if (e.target.id === "modalOverlay") e.target.hidden = true;
  });
});
