const $ = (id) => document.getElementById(id);

const state = {
  packets: new Map(),
  selected: null,
  selectedDetail: null,
  after: 0,
  filter: "",
  view: "capture",
  autoScroll: true,
  anomalyCount: 0,
  lastStats: null,
};

// Protocol badge helper
function getProtocolBadgeClass(proto) {
  const p = (proto || "").toLowerCase();
  if (p === "tcp") return "proto-tcp";
  if (p === "udp") return "proto-udp";
  if (p === "dns" || p === "mdns" || p === "llmnr") return "proto-dns";
  if (p === "http") return "proto-http";
  if (p === "tls" || p === "dtls") return "proto-tls";
  if (p === "arp") return "proto-arp";
  if (p === "icmp" || p === "icmpv6") return "proto-icmp";
  return "";
}

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || JSON.stringify(body);
    } catch (_error) {
      /* keep status text */
    }
    throw new Error(detail);
  }
  if (response.headers.get("content-type")?.includes("json")) {
    return response.json();
  }
  return response;
}

function renderPackets() {
  const body = $("packetBody");
  body.replaceChildren();
  const fragment = document.createDocumentFragment();
  const rows = [...state.packets.values()];
  const start = Math.max(0, rows.length - 2500);

  for (const packet of rows.slice(start)) {
    const tr = document.createElement("tr");
    tr.dataset.no = String(packet.no);
    if (packet.no === state.selected) tr.classList.add("selected");
    if (packet.flagged) tr.classList.add("flagged");

    const protoClass = getProtocolBadgeClass(packet.protocol);
    tr.innerHTML = `
      <td class="col-no">${packet.no}</td>
      <td class="col-time">${packet.rel_time.toFixed(6)}</td>
      <td class="col-src" title="${escapeHtml(packet.src)}">${escapeHtml(packet.src)}</td>
      <td class="col-dst" title="${escapeHtml(packet.dst)}">${escapeHtml(packet.dst)}</td>
      <td class="col-proto"><span class="badge-proto ${protoClass}">${escapeHtml(packet.protocol)}</span></td>
      <td class="col-len">${packet.length}</td>
      <td class="col-info" title="${escapeHtml(packet.info)}">${escapeHtml(packet.info)}</td>
    `;
    fragment.appendChild(tr);
  }
  body.appendChild(fragment);

  // Update counters
  const total = state.packets.size;
  $("counts").textContent = `${total} paquetes en búfer`;
  $("tabPacketCount").textContent = total > 9999 ? "9999+" : String(total);

  // Auto-scroll if enabled
  if (state.autoScroll && state.view === "capture") {
    const wrapper = document.querySelector(".packet-table-wrapper");
    if (wrapper) {
      wrapper.scrollTop = wrapper.scrollHeight;
    }
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function selectPacket(number) {
  state.selected = number;
  for (const row of $("packetBody").querySelectorAll("tr")) {
    row.classList.toggle("selected", Number(row.dataset.no) === number);
  }

  const pkt = state.packets.get(number);
  if (pkt) {
    $("selectedSummary").textContent = `Paquete #${pkt.no} · ${pkt.protocol} · ${pkt.src} → ${pkt.dst} · ${pkt.length} bytes · ${pkt.info}`;
    $("btnCopySummary").disabled = false;
    $("btnCopyHex").disabled = false;
    $("btnFollowStream").disabled = !pkt.stream_id;
  }

  try {
    const detail = await api(`/api/v1/sniffer/packets/${number}`);
    state.selectedDetail = detail;

    const tree = (detail.layers || [])
      .map((layer) => {
        const fields = (layer.fields || [])
          .map((field) => `  ├─ ${field.name.padEnd(20)}: ${field.value}`)
          .join("\n");
        return `▼ [ ${layer.name} ]\n${fields}`;
      })
      .join("\n\n");

    $("detailTree").textContent = tree || "Sin capas diseccionadas.";
    $("hexDump").textContent = detail.hex || "(Sin datos raw disponibles)";
  } catch (error) {
    $("detailTree").textContent = `Error al cargar detalle: ${error.message}`;
    $("hexDump").textContent = "";
  }
}

async function loadInterfaces() {
  const data = await api("/api/v1/sniffer/interfaces");
  const select = $("iface");
  select.replaceChildren();
  for (const iface of data.interfaces) {
    const option = document.createElement("option");
    option.value = iface.id;
    option.textContent = iface.mac ? `${iface.name} [${iface.mac}]` : iface.name;
    select.appendChild(option);
  }
}

async function refreshStatus() {
  const status = await api("/api/v1/sniffer/status");
  const isCapturing = Boolean(status.running);

  document.body.classList.toggle("capturing", isCapturing);
  $("runState").textContent = isCapturing ? `● capturando · ${status.interface}` : "○ detenido";
  $("start").disabled = isCapturing;
  $("stop").disabled = !isCapturing;
  $("captureError").textContent = status.error ? `Error: ${status.error}` : "";
  return status;
}

async function startCapture() {
  await api("/api/v1/sniffer/start", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      interface: $("iface").value,
      bpf: $("bpf").value,
      promiscuous: $("promisc").checked,
    }),
  });
  await refreshStatus();
}

async function stopCapture() {
  await api("/api/v1/sniffer/stop", { method: "POST" });
  await refreshStatus();
}

async function clearCapture() {
  await api("/api/v1/sniffer/clear", { method: "POST" });
  state.packets.clear();
  state.after = 0;
  state.selected = null;
  state.selectedDetail = null;
  state.anomalyCount = 0;
  $("detailTree").textContent = "";
  $("hexDump").textContent = "";
  $("selectedSummary").textContent = "Búfer limpio. Selecciona un paquete cuando inicies una captura.";
  $("btnCopySummary").disabled = true;
  $("btnCopyHex").disabled = true;
  $("btnFollowStream").disabled = true;
  $("tabAnomalyCount").textContent = "0";
  renderPackets();
}

async function applyFilter(filterText) {
  const expression = filterText !== undefined ? filterText : $("displayFilter").value.trim();
  $("displayFilter").value = expression;

  const pill = $("filterState");
  if (!expression) {
    pill.textContent = "filtro vacío";
    pill.className = "filter-pill";
    state.filter = "";
  } else {
    const check = await api(`/api/v1/sniffer/filter?q=${encodeURIComponent(expression)}`);
    if (check.ok) {
      pill.textContent = "✓ filtro válido";
      pill.className = "filter-pill ok";
      state.filter = expression;
    } else {
      pill.textContent = `✕ ${check.error}`;
      pill.className = "filter-pill bad";
      return;
    }
  }

  // Sync quick pills
  for (const qp of document.querySelectorAll(".quick-pill")) {
    qp.classList.toggle("active", qp.dataset.filter === expression);
  }

  state.packets.clear();
  state.after = 0;
  const data = await api(
    `/api/v1/sniffer/packets?limit=1500&after=0&display_filter=${encodeURIComponent(state.filter)}`
  );
  for (const packet of data.packets) {
    state.packets.set(packet.no, packet);
    state.after = Math.max(state.after, packet.no);
  }
  renderPackets();
}

function rememberPacket(packet) {
  if (state.filter) {
    const f = state.filter.toLowerCase();
    if (f === "flagged" || f === "anomaly") {
      if (!packet.flagged) return;
    } else {
      const haystack = `${packet.protocol} ${packet.src} ${packet.dst} ${packet.info}`.toLowerCase();
      const tokens = f.split(/\s+or\s+|\s+and\s+/);
      const simple = tokens.every((token) => {
        const clean = token.replaceAll("==", "").trim();
        if (["tcp", "udp", "arp", "icmp", "dns", "http", "tls", "ip", "ipv4", "ipv6", "dhcp", "ssh"].includes(clean)) {
          return packet.protocol.toLowerCase() === clean || (clean === "ip" && true);
        }
        return haystack.includes(clean);
      });
      if (!simple && !haystack.includes(f)) {
        return;
      }
    }
  }
  state.packets.set(packet.no, packet);
  state.after = Math.max(state.after, packet.no);
}

function connectLive() {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${location.host}/api/v1/sniffer/live`);

  socket.addEventListener("open", () => {
    $("wsState").textContent = "socket: conectado";
  });

  socket.addEventListener("close", () => {
    $("wsState").textContent = "socket: reconectando…";
    setTimeout(connectLive, 1500);
  });

  socket.addEventListener("message", (event) => {
    try {
      const message = JSON.parse(event.data);
      if (message.type === "packet") {
        rememberPacket(message.packet);
        if (state.view === "capture") {
          scheduleRender();
        }
      }
      if (message.type === "anomaly") {
        state.anomalyCount++;
        $("tabAnomalyCount").textContent = String(state.anomalyCount);
        prependFinding($("anomalyList"), message.anomaly);
      }
    } catch (_err) {
      /* ignore malformed frames */
    }
  });
}

let renderTimer = null;
function scheduleRender() {
  if (renderTimer) return;
  renderTimer = setTimeout(() => {
    renderTimer = null;
    renderPackets();
  }, 100);
}

function prependFinding(list, item) {
  const li = document.createElement("li");
  li.className = "anomaly-card";

  const sev = (item.severity || "info").toLowerCase();
  const sevClass = `severity-${sev}`;
  const timeStr = item.created_at ? new Date(item.created_at).toLocaleTimeString() : new Date().toLocaleTimeString();

  li.innerHTML = `
    <div class="anomaly-header">
      <strong class="anomaly-title">${escapeHtml(item.title || item.kind)}</strong>
      <span class="severity-badge ${sevClass}">${escapeHtml(item.severity || "INFO")}</span>
    </div>
    <div class="anomaly-desc">${escapeHtml(item.description || "")}</div>
    <div class="anomaly-meta">
      <span>Hora: ${timeStr}</span>
      <span>${item.packet_no ? `Paquete #${item.packet_no}` : ""}</span>
      <span>ID: ${escapeHtml(item.kind || item.rule_id || "")}</span>
    </div>
  `;
  list.prepend(li);
}

async function loadFeeds() {
  const [anomalies, alerts, events] = await Promise.all([
    api("/api/v1/sniffer/anomalies?limit=200"),
    api("/api/v1/alerts?limit=200"),
    api("/api/v1/events?limit=200"),
  ]);

  state.anomalyCount = anomalies.anomalies.length;
  $("tabAnomalyCount").textContent = String(state.anomalyCount);

  $("anomalyList").replaceChildren();
  for (const item of anomalies.anomalies) prependFinding($("anomalyList"), item);

  $("alertList").replaceChildren();
  for (const item of alerts) {
    prependFinding($("alertList"), {
      title: item.title,
      description: item.description,
      severity: item.severity,
      kind: item.rule_id,
      created_at: item.timestamp,
    });
  }

  $("eventList").replaceChildren();
  for (const item of events) {
    prependFinding($("eventList"), {
      title: `${item.event_type} · ${item.host?.hostname || ""}`,
      description: JSON.stringify(item.data, null, 2),
      severity: item.severity,
      kind: item.source,
      created_at: item.timestamp,
    });
  }
}

async function loadStats() {
  const stats = await api("/api/v1/sniffer/stats");
  state.lastStats = stats;

  $("rateStat").textContent = `${stats.packets_per_second} pps · ${formatBytes(stats.bytes)}`;

  $("statCards").innerHTML = [
    ["Paquetes Capturados", stats.captured],
    ["Volumen Total", formatBytes(stats.bytes)],
    ["Tasa Actual", `${stats.packets_per_second} pps`],
    ["Descartados / Caídos", stats.dropped],
  ]
    .map(([label, value]) => `<div class="card"><span>${label}</span><b>${value}</b></div>`)
    .join("");

  // Protocol bar chart
  const protocols = Object.entries(stats.protocols || {});
  const maxProto = Math.max(1, ...protocols.map(([, count]) => count));
  $("statProtocols").innerHTML = protocols.length
    ? protocols
        .map(([name, count]) => {
          const pct = Math.round((count / maxProto) * 100);
          return `
          <div class="proto-stat-row">
            <span class="proto-stat-name">${escapeHtml(name)}</span>
            <div class="proto-stat-bar-wrap">
              <div class="proto-stat-bar" style="width: ${pct}%"></div>
            </div>
            <span class="proto-stat-count">${count}</span>
          </div>`;
        })
        .join("")
    : "<div style='color:var(--ink-muted)'>Sin protocolos registrados todavía.</div>";

  $("statConvos").textContent = (stats.conversations || []).length
    ? stats.conversations
        .map((row) => `${row.protocol.padEnd(6)} ${row.a} ↔ ${row.b}  [${row.packets} pkts, ${formatBytes(row.bytes)}]`)
        .join("\n")
    : "Sin conversaciones registradas.";

  $("statEndpoints").textContent = (stats.endpoints || []).length
    ? stats.endpoints
        .map((row) => `${row.address.padEnd(28)} [${row.packets} pkts, ${formatBytes(row.bytes)}]`)
        .join("\n")
    : "Sin endpoints registrados.";
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function showView(name) {
  state.view = name;
  for (const view of document.querySelectorAll(".view")) {
    view.classList.toggle("hidden", view.id !== `view-${name}`);
  }
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("active", tab.dataset.view === name);
  }
  if (name === "stats") loadStats();
  if (name === "anomalies" || name === "alerts" || name === "events") loadFeeds();
}

async function followStream(streamId) {
  if (!streamId) return;
  const stream = await api(`/api/v1/sniffer/streams/${encodeURIComponent(streamId)}`);
  $("streamModalTitle").textContent = `Seguimiento de Stream: ${stream.stream_id}`;
  $("streamModalContent").textContent = stream.text || "(Sin carga útil de aplicación o datos binarios no imprimibles)";
  $("streamModal").classList.remove("hidden");
}

function copyToClipboard(text, button, successLabel = "¡Copiado!") {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const original = button.textContent;
    button.textContent = successLabel;
    setTimeout(() => {
      button.textContent = original;
    }, 1200);
  });
}

// EVENT LISTENERS
$("packetBody").addEventListener("click", (event) => {
  const row = event.target.closest("tr");
  if (!row) return;
  selectPacket(Number(row.dataset.no)).catch(showError);
});

$("packetBody").addEventListener("dblclick", async (event) => {
  const row = event.target.closest("tr");
  if (!row) return;
  const packet = state.packets.get(Number(row.dataset.no));
  if (packet?.stream_id) {
    followStream(packet.stream_id).catch(showError);
  }
});

$("start").addEventListener("click", () => startCapture().catch(showError));
$("stop").addEventListener("click", () => stopCapture().catch(showError));
$("clear").addEventListener("click", () => clearCapture().catch(showError));

$("toggleScroll").addEventListener("click", () => {
  state.autoScroll = !state.autoScroll;
  $("toggleScroll").textContent = `Auto-scroll: ${state.autoScroll ? "ON" : "OFF"}`;
  $("toggleScroll").style.borderStyle = state.autoScroll ? "dashed" : "solid";
});

$("displayFilter").addEventListener("change", () => applyFilter().catch(showError));
$("displayFilter").addEventListener("keydown", (event) => {
  if (event.key === "Enter") applyFilter().catch(showError);
});

$("clearFilterBtn").addEventListener("click", () => {
  $("displayFilter").value = "";
  applyFilter("").catch(showError);
});

for (const qp of document.querySelectorAll(".quick-pill")) {
  qp.addEventListener("click", () => {
    applyFilter(qp.dataset.filter).catch(showError);
  });
}

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => showView(tab.dataset.view));
}

// Packet action buttons
$("btnFollowStream").addEventListener("click", () => {
  if (state.selectedDetail?.stream_id) {
    followStream(state.selectedDetail.stream_id).catch(showError);
  }
});

$("btnCopyHex").addEventListener("click", (e) => {
  if (state.selectedDetail?.hex) {
    copyToClipboard(state.selectedDetail.hex, e.target, "Hex Copiado");
  }
});

$("btnCopySummary").addEventListener("click", (e) => {
  const pkt = state.packets.get(state.selected);
  if (pkt) {
    const summary = `${pkt.no}\t${pkt.rel_time.toFixed(6)}\t${pkt.src}\t${pkt.dst}\t${pkt.protocol}\t${pkt.length}\t${pkt.info}`;
    copyToClipboard(summary, e.target, "Resumen Copiado");
  }
});

// Modal controls
$("closeStreamModal").addEventListener("click", () => {
  $("streamModal").classList.add("hidden");
});

$("btnCloseStreamBtn").addEventListener("click", () => {
  $("streamModal").classList.add("hidden");
});

$("btnCopyStream").addEventListener("click", (e) => {
  copyToClipboard($("streamModalContent").textContent, e.target, "Copiado");
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    $("streamModal").classList.add("hidden");
  }
});

function showError(error) {
  $("captureError").textContent = `Error: ${error.message}`;
}

async function boot() {
  await loadInterfaces();
  await refreshStatus();
  await applyFilter();
  connectLive();

  setInterval(() => {
    refreshStatus().catch(() => {});
    if (state.view === "stats") loadStats().catch(() => {});
  }, 2000);
}

boot().catch(showError);
