const $ = (id) => document.getElementById(id);

const state = {
  packets: new Map(),
  selectedNo: null,
  selectedDetail: null,
  after: 0,
  filter: "",
  view: "capture",
  autoScroll: true,
  anomalies: [],
  anomalyFilter: "all",
  stats: null,
  zoomLevel: 12,
};

// HELPER API FETCH
async function api(path, options = {}) {
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

// RENDER PACKET LIST (PANE 1)
function renderPackets() {
  const body = $("packetBody");
  body.replaceChildren();
  const fragment = document.createDocumentFragment();
  const rows = [...state.packets.values()];
  const start = Math.max(0, rows.length - 3000);

  for (const packet of rows.slice(start)) {
    const tr = document.createElement("tr");
    tr.dataset.no = String(packet.no);
    if (packet.no === state.selectedNo) tr.classList.add("selected");
    if (packet.flagged) tr.classList.add("flagged");

    const proto = (packet.protocol || "").toUpperCase();
    const protoClass = `proto-${proto.toLowerCase()}`;

    tr.innerHTML = `
      <td class="th-no">${packet.no}</td>
      <td class="th-time">${packet.rel_time.toFixed(6)}</td>
      <td class="th-src" title="${escapeHtml(packet.src)}">${escapeHtml(packet.src)}</td>
      <td class="th-dst" title="${escapeHtml(packet.dst)}">${escapeHtml(packet.dst)}</td>
      <td class="th-proto"><span class="proto-tag ${protoClass}">${escapeHtml(proto)}</span></td>
      <td class="th-len">${packet.length}</td>
      <td class="th-info" title="${escapeHtml(packet.info)}">${escapeHtml(packet.info)}</td>
    `;
    fragment.appendChild(tr);
  }
  body.appendChild(fragment);

  // Update status bar
  const total = state.packets.size;
  $("badgePackets").textContent = total > 9999 ? "9999+" : String(total);
  $("sbPacketsText").textContent = `Paquetes: ${total}`;
  $("sbDisplayedText").textContent = `Mostrados: ${rows.length}`;

  // Auto-scroll
  if (state.autoScroll && state.view === "capture") {
    const pane = $("packetListPane");
    if (pane) pane.scrollTop = pane.scrollHeight;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// SELECT PACKET & RENDER PANES 2 & 3
async function selectPacket(number) {
  state.selectedNo = number;
  for (const row of $("packetBody").querySelectorAll("tr")) {
    row.classList.toggle("selected", Number(row.dataset.no) === number);
  }

  const pkt = state.packets.get(number);
  if (pkt) {
    $("selectedPacketLabel").textContent = `Paquete #${pkt.no} · ${pkt.protocol} · ${pkt.src} ➔ ${pkt.dst} (${pkt.length} bytes) · ${pkt.info}`;
    $("btnFollowStreamSelected").disabled = !pkt.stream_id;
    $("btnCopyHexSelected").disabled = false;
    $("btnCopySummarySelected").disabled = false;
  }

  try {
    const detail = await api(`/api/v1/sniffer/packets/${number}`);
    state.selectedDetail = detail;

    // Render Dissection Tree (Pane 2)
    renderTree(detail);

    // Render Hex Dump (Pane 3)
    $("hexContainer").textContent = detail.hex || "(Sin volcado disponible)";
  } catch (error) {
    $("treeContainer").innerHTML = `<div class="empty-state">Error cargando detalle: ${escapeHtml(error.message)}</div>`;
    $("hexContainer").textContent = "";
  }
}

function renderTree(detail) {
  const container = $("treeContainer");
  container.replaceChildren();

  // Synthetic Frame Node
  const frameNode = document.createElement("div");
  frameNode.className = "tree-node";
  frameNode.innerHTML = `
    <div class="tree-node-title">▼ Frame ${detail.no}: ${detail.length} bytes on wire (${detail.length * 8} bits)</div>
    <div class="tree-fields">
      <div class="tree-field">Arrival Time: ${new Date(detail.timestamp * 1000).toISOString()}</div>
      <div class="tree-field">Epoch Time: ${detail.timestamp.toFixed(6)} seconds</div>
      <div class="tree-field">Frame Number: ${detail.no}</div>
      <div class="tree-field">Frame Length: ${detail.length} bytes</div>
    </div>
  `;
  container.appendChild(frameNode);

  // Decoded Layers
  for (const layer of detail.layers || []) {
    const node = document.createElement("div");
    node.className = "tree-node";
    const title = document.createElement("div");
    title.className = "tree-node-title";
    title.textContent = `▼ ${layer.name}`;
    
    const fieldsDiv = document.createElement("div");
    fieldsDiv.className = "tree-fields";

    for (const field of layer.fields || []) {
      const fRow = document.createElement("div");
      fRow.className = "tree-field";
      fRow.textContent = `${field.name}: ${field.value}`;
      fieldsDiv.appendChild(fRow);
    }

    // Toggle collapse on click
    title.addEventListener("click", () => {
      const isHidden = fieldsDiv.style.display === "none";
      fieldsDiv.style.display = isHidden ? "block" : "none";
      title.textContent = `${isHidden ? "▼" : "▶"} ${layer.name}`;
    });

    node.appendChild(title);
    node.appendChild(fieldsDiv);
    container.appendChild(node);
  }
}

// CAPTURE CONTROL
async function loadInterfaces() {
  const data = await api("/api/v1/sniffer/interfaces");
  const quickSelect = $("ifaceSelect");
  const modalSelect = $("modalIfaceSelect");
  quickSelect.replaceChildren();
  modalSelect.replaceChildren();

  for (const iface of data.interfaces) {
    const opt = document.createElement("option");
    opt.value = iface.id;
    opt.textContent = iface.mac ? `${iface.name} [${iface.mac}]` : iface.name;
    quickSelect.appendChild(opt);
    modalSelect.appendChild(opt.cloneNode(true));
  }
}

async function refreshStatus() {
  const status = await api("/api/v1/sniffer/status");
  const isCapturing = Boolean(status.running);

  $("tbStart").disabled = isCapturing;
  $("tbStop").disabled = !isCapturing;
  $("menuStart").disabled = isCapturing;
  $("menuStop").disabled = !isCapturing;

  $("sbStatusText").textContent = isCapturing ? `● Capturando [${status.interface}]` : "○ Detenido";
  $("sbStatusText").style.color = isCapturing ? "#ffffff" : "var(--ink-muted)";
  $("sbErrorText").textContent = status.error ? `Aviso: ${status.error}` : "";

  return status;
}

async function startCapture(customInterface, customBpf, customPromisc) {
  const iface = customInterface || $("ifaceSelect").value;
  const bpf = customBpf !== undefined ? customBpf : $("modalBpfInput").value;
  const promisc = customPromisc !== undefined ? customPromisc : $("modalPromiscCheck").checked;

  await api("/api/v1/sniffer/start", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ interface: iface, bpf: bpf, promiscuous: promisc }),
  });
  await refreshStatus();
}

async function stopCapture() {
  await api("/api/v1/sniffer/stop", { method: "POST" });
  await refreshStatus();
}

async function restartCapture() {
  await stopCapture();
  setTimeout(() => startCapture().catch(showError), 200);
}

async function clearCapture() {
  await api("/api/v1/sniffer/clear", { method: "POST" });
  state.packets.clear();
  state.after = 0;
  state.selectedNo = null;
  state.selectedDetail = null;
  state.anomalies = [];
  $("treeContainer").innerHTML = `<div class="empty-state">Búfer limpio. Haz clic en "Iniciar" o "Tráfico de Prueba IDS".</div>`;
  $("hexContainer").textContent = "";
  $("selectedPacketLabel").textContent = "Búfer limpio.";
  $("btnFollowStreamSelected").disabled = true;
  $("btnCopyHexSelected").disabled = true;
  $("btnCopySummarySelected").disabled = true;
  $("badgeAnomalies").textContent = "0";
  $("sbMarkedText").textContent = "Anomalías: 0";
  $("anomalyFeed").replaceChildren();
  renderPackets();
}

// DISPLAY FILTERS
async function applyFilter(expr) {
  const expression = expr !== undefined ? expr : $("displayFilter").value.trim();
  $("displayFilter").value = expression;

  const box = $("filterBox");
  if (!expression) {
    box.className = "filter-box";
    state.filter = "";
  } else {
    const check = await api(`/api/v1/sniffer/filter?q=${encodeURIComponent(expression)}`);
    if (check.ok) {
      box.className = "filter-box valid";
      state.filter = expression;
    } else {
      box.className = "filter-box invalid";
      $("sbErrorText").textContent = `Error de filtro: ${check.error}`;
      return;
    }
  }

  state.packets.clear();
  state.after = 0;
  const data = await api(
    `/api/v1/sniffer/packets?limit=2500&after=0&display_filter=${encodeURIComponent(state.filter)}`
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
      const match = tokens.every((tok) => {
        const c = tok.replaceAll("==", "").trim();
        if (["tcp", "udp", "arp", "icmp", "dns", "http", "tls", "ip", "ipv4", "ipv6", "dhcp", "ssh"].includes(c)) {
          return packet.protocol.toLowerCase() === c || (c === "ip" && true);
        }
        return haystack.includes(c);
      });
      if (!match && !haystack.includes(f)) return;
    }
  }
  state.packets.set(packet.no, packet);
  state.after = Math.max(state.after, packet.no);
}

// SIMULATE IDS TRAFFIC
async function simulateTraffic() {
  $("sbErrorText").textContent = "Generando tráfico y anomalías de prueba en memoria...";
  const res = await api("/api/v1/sniffer/simulate", { method: "POST" });
  $("sbErrorText").textContent = `Inyectadas ${res.simulated} tramas de prueba. Revisando anomalías...`;
  setTimeout(() => applyFilter(state.filter).catch(() => {}), 150);
}

// IMPORT PCAP
async function handlePcapFile(file) {
  if (!file) return;
  $("sbErrorText").textContent = `Importando ${file.name}...`;
  const buffer = await file.arrayBuffer();
  const res = await api("/api/v1/sniffer/import-pcap", {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body: buffer,
  });
  $("sbErrorText").textContent = `✓ Importadas ${res.imported} tramas desde ${file.name}.`;
  await applyFilter(state.filter);
}

// WEBSOCKET LIVE
function connectLive() {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${location.host}/api/v1/sniffer/live`);

  socket.addEventListener("open", () => {
    $("wsPill").textContent = "WS: Conectado";
    $("wsPill").style.color = "#ffffff";
  });

  socket.addEventListener("close", () => {
    $("wsPill").textContent = "WS: Reconectando...";
    $("wsPill").style.color = "var(--ink-muted)";
    setTimeout(connectLive, 1500);
  });

  socket.addEventListener("message", (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "packet") {
        rememberPacket(msg.packet);
        if (state.view === "capture") scheduleRender();
      }
      if (msg.type === "anomaly") {
        state.anomalies.unshift(msg.anomaly);
        $("badgeAnomalies").textContent = String(state.anomalies.length);
        $("sbMarkedText").textContent = `Anomalías: ${state.anomalies.length}`;
        renderAnomalies();
      }
    } catch (_err) {
      /* ignore */
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

// ANOMALIES FEED
function renderAnomalies() {
  const feed = $("anomalyFeed");
  feed.replaceChildren();

  const filtered = state.anomalies.filter((item) => {
    if (state.anomalyFilter === "all") return true;
    return (item.severity || "").toLowerCase() === state.anomalyFilter;
  });

  if (filtered.length === 0) {
    feed.innerHTML = `<li class="empty-state">No hay anomalías registradas para el filtro actual. Pulsa "⚡ Tráfico de Prueba IDS" para generar eventos.</li>`;
    return;
  }

  for (const item of filtered) {
    const li = document.createElement("li");
    li.className = "anomaly-card";
    const time = item.created_at ? new Date(item.created_at).toLocaleTimeString() : new Date().toLocaleTimeString();
    const sev = (item.severity || "info").toUpperCase();

    li.innerHTML = `
      <div class="anomaly-head">
        <strong class="anomaly-title">${escapeHtml(item.title || item.kind)}</strong>
        <span class="sev-tag">${escapeHtml(sev)}</span>
      </div>
      <div class="anomaly-desc">${escapeHtml(item.description || "")}</div>
      <div class="anomaly-meta">
        <span>Hora: ${time}</span>
        ${item.packet_no ? `<span>Paquete asociado: <a href="#" class="inspect-packet-link" data-no="${item.packet_no}">#${item.packet_no}</a></span>` : ""}
        <span>Regla: ${escapeHtml(item.kind || item.event_type || "")}</span>
      </div>
    `;
    feed.appendChild(li);
  }
}

// FOLLOW STREAM
async function followStream(streamId) {
  if (!streamId) return;
  const stream = await api(`/api/v1/sniffer/streams/${encodeURIComponent(streamId)}`);
  $("modalStreamTitle").textContent = `Seguimiento de Stream: ${stream.stream_id}`;
  $("streamContent").textContent = stream.text || "(Sin carga útil de aplicación / datos binarios)";
  $("modalStream").classList.remove("hidden");
}

// STATS & CONVERSATIONS
async function loadStats() {
  const stats = await api("/api/v1/sniffer/stats");
  state.stats = stats;

  $("sbRateText").textContent = `${stats.packets_per_second} pps · ${formatBytes(stats.bytes)}`;

  // Cards
  $("statsCards").innerHTML = [
    ["Paquetes Capturados", stats.captured],
    ["Volumen Total", formatBytes(stats.bytes)],
    ["Tasa de Transferencia", `${stats.packets_per_second} pps`],
    ["Tramas Caídas", stats.dropped],
  ]
    .map(([k, v]) => `<div class="stat-metric"><span>${k}</span><b>${v}</b></div>`)
    .join("");

  // Protocol bar chart
  const protos = Object.entries(stats.protocols || {});
  const max = Math.max(1, ...protos.map(([, c]) => c));
  $("protocolsChart").innerHTML = protos.length
    ? protos
        .map(([name, count]) => {
          const pct = Math.round((count / max) * 100);
          return `
            <div class="proto-bar-row">
              <span style="width:70px; font-weight:700;">${escapeHtml(name)}</span>
              <div class="proto-bar-track"><div class="proto-bar-fill" style="width:${pct}%;"></div></div>
              <span style="width:45px; text-align:right; color:var(--ink-muted);">${count}</span>
            </div>`;
        })
        .join("")
    : `<div class="empty-state">Sin protocolos.</div>`;

  // Conversations
  const convosBody = $("convosTableBody");
  convosBody.replaceChildren();
  for (const c of stats.conversations || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${c.protocol}</td><td>${c.a}</td><td>${c.b}</td><td>${c.packets}</td><td>${formatBytes(c.bytes)}</td>`;
    convosBody.appendChild(tr);
  }

  // Endpoints
  const epBody = $("endpointsTableBody");
  epBody.replaceChildren();
  for (const ep of stats.endpoints || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${ep.address}</td><td>${ep.packets}</td><td>${formatBytes(ep.bytes)}</td>`;
    epBody.appendChild(tr);
  }
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// SWITCH VIEWS
function showView(name) {
  state.view = name;
  for (const p of document.querySelectorAll(".view-panel")) {
    p.classList.toggle("hidden", p.id !== `view-${name}`);
  }
  for (const btn of document.querySelectorAll(".tab-btn")) {
    btn.classList.toggle("active", btn.dataset.view === name);
  }
  if (name === "stats") loadStats().catch(() => {});
  if (name === "anomalies") renderAnomalies();
}

function copyText(str, button, okLabel = "✓ Copiado") {
  if (!str) return;
  navigator.clipboard.writeText(str).then(() => {
    const old = button.textContent;
    button.textContent = okLabel;
    setTimeout(() => { button.textContent = old; }, 1200);
  });
}

function showError(err) {
  $("sbErrorText").textContent = `Error: ${err.message}`;
}

// EVENT LISTENERS & SETUP
function setupEvents() {
  // Table row click & dblclick
  $("packetBody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    selectPacket(Number(tr.dataset.no)).catch(showError);
  });

  $("packetBody").addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tr");
    if (!tr) return;
    const pkt = state.packets.get(Number(tr.dataset.no));
    if (pkt?.stream_id) followStream(pkt.stream_id).catch(showError);
  });

  // Toolbar buttons
  $("tbStart").addEventListener("click", () => startCapture().catch(showError));
  $("tbStop").addEventListener("click", () => stopCapture().catch(showError));
  $("tbRestart").addEventListener("click", () => restartCapture().catch(showError));
  $("tbClear").addEventListener("click", () => clearCapture().catch(showError));
  $("tbSimulate").addEventListener("click", () => simulateTraffic().catch(showError));

  $("tbAutoScroll").addEventListener("click", () => {
    state.autoScroll = !state.autoScroll;
    $("tbAutoScroll").classList.toggle("active-toggle", state.autoScroll);
  });

  // Open PCAP File
  $("tbOpenPcap").addEventListener("click", () => $("pcapFileInput").click());
  $("pcapFileInput").addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handlePcapFile(e.target.files[0]).catch(showError);
    }
  });

  // Drag and Drop PCAP file
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    if (e.dataTransfer.files.length > 0) {
      handlePcapFile(e.dataTransfer.files[0]).catch(showError);
    }
  });

  // Options modal
  $("tbOptions").addEventListener("click", () => $("modalOptions").classList.remove("hidden"));
  $("btnModalStartCapture").addEventListener("click", () => {
    $("modalOptions").classList.add("hidden");
    startCapture($("modalIfaceSelect").value, $("modalBpfInput").value, $("modalPromiscCheck").checked).catch(showError);
  });

  // Filter bar
  $("btnFilterApply").addEventListener("click", () => applyFilter().catch(showError));
  $("displayFilter").addEventListener("keydown", (e) => {
    if (e.key === "Enter") applyFilter().catch(showError);
  });
  $("btnFilterClear").addEventListener("click", () => {
    $("displayFilter").value = "";
    applyFilter("").catch(showError);
  });
  $("btnFilterExpr").addEventListener("click", () => $("modalExpr").classList.remove("hidden"));

  // Expression items
  for (const btn of document.querySelectorAll(".expr-item")) {
    btn.addEventListener("click", () => {
      $("displayFilter").value = btn.dataset.expr;
      $("modalExpr").classList.add("hidden");
      applyFilter().catch(showError);
    });
  }

  // View tabs
  for (const tab of document.querySelectorAll(".tab-btn")) {
    tab.addEventListener("click", () => showView(tab.dataset.view));
  }

  // Severity pills
  for (const pill of document.querySelectorAll(".sev-pill")) {
    pill.addEventListener("click", () => {
      for (const p of document.querySelectorAll(".sev-pill")) p.classList.remove("active");
      pill.classList.add("active");
      state.anomalyFilter = pill.dataset.sev;
      renderAnomalies();
    });
  }

  // Inspect link in anomaly card
  $("anomalyFeed").addEventListener("click", (e) => {
    const link = e.target.closest(".inspect-packet-link");
    if (!link) return;
    e.preventDefault();
    showView("capture");
    selectPacket(Number(link.dataset.no)).catch(showError);
  });

  // Selected packet actions
  $("btnFollowStreamSelected").addEventListener("click", () => {
    if (state.selectedDetail?.stream_id) followStream(state.selectedDetail.stream_id).catch(showError);
  });
  $("btnCopyHexSelected").addEventListener("click", (e) => {
    if (state.selectedDetail?.hex) copyText(state.selectedDetail.hex, e.target);
  });
  $("btnCopySummarySelected").addEventListener("click", (e) => {
    const pkt = state.packets.get(state.selectedNo);
    if (pkt) {
      const summary = `${pkt.no}\t${pkt.rel_time.toFixed(6)}\t${pkt.src}\t${pkt.dst}\t${pkt.protocol}\t${pkt.length}\t${pkt.info}`;
      copyText(summary, e.target);
    }
  });

  // Stream copy
  $("btnCopyStreamText").addEventListener("click", (e) => {
    copyText($("streamContent").textContent, e.target);
  });

  // Modals close buttons
  for (const close of document.querySelectorAll("[data-close]")) {
    close.addEventListener("click", () => {
      const target = $(close.dataset.close);
      if (target) target.classList.add("hidden");
    });
  }

  // Menubar events
  $("menuOpenPcap").addEventListener("click", () => $("pcapFileInput").click());
  $("menuClearCapture").addEventListener("click", () => clearCapture().catch(showError));
  $("menuStart").addEventListener("click", () => startCapture().catch(showError));
  $("menuStop").addEventListener("click", () => stopCapture().catch(showError));
  $("menuRestart").addEventListener("click", () => restartCapture().catch(showError));
  $("menuOptions").addEventListener("click", () => $("modalOptions").classList.remove("hidden"));
  $("menuFollowStream").addEventListener("click", () => {
    if (state.selectedDetail?.stream_id) followStream(state.selectedDetail.stream_id).catch(showError);
  });
  $("menuFilterSelected").addEventListener("click", () => {
    const pkt = state.packets.get(state.selectedNo);
    if (pkt) applyFilter(`ip.addr == ${pkt.src.split(":")[0]}`);
  });
  $("menuExpressionBuilder").addEventListener("click", () => $("modalExpr").classList.remove("hidden"));
  $("menuSimulate").addEventListener("click", () => simulateTraffic().catch(showError));
  $("menuViewAnomalies").addEventListener("click", () => showView("anomalies"));
  $("menuViewAlerts").addEventListener("click", () => showView("rules"));
  $("menuViewStats").addEventListener("click", () => showView("stats"));
  $("menuViewEndpoints").addEventListener("click", () => showView("stats"));
  $("menuToggleAutoscroll").addEventListener("click", () => {
    state.autoScroll = !state.autoScroll;
    $("tbAutoScroll").classList.toggle("active-toggle", state.autoScroll);
  });
  $("menuCopySummary").addEventListener("click", (e) => $("btnCopySummarySelected").click());
  $("menuCopyHex").addEventListener("click", (e) => $("btnCopyHexSelected").click());
  $("menuCopyJson").addEventListener("click", (e) => {
    if (state.selectedDetail) copyText(JSON.stringify(state.selectedDetail, null, 2), e.target);
  });

  // Keyboard Navigation (Up / Down arrows to traverse packets)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      for (const m of document.querySelectorAll(".modal-overlay")) m.classList.add("hidden");
    }
    if (state.view === "capture" && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      if (document.activeElement?.tagName === "INPUT" || document.activeElement?.tagName === "SELECT") return;
      e.preventDefault();
      const keys = [...state.packets.keys()];
      if (keys.length === 0) return;
      let idx = keys.indexOf(state.selectedNo);
      if (idx === -1) idx = 0;
      else idx = e.key === "ArrowDown" ? Math.min(keys.length - 1, idx + 1) : Math.max(0, idx - 1);
      selectPacket(keys[idx]).catch(() => {});
      const targetRow = document.querySelector(`tr[data-no="${keys[idx]}"]`);
      if (targetRow) targetRow.scrollIntoView({ block: "nearest" });
    }
  });
}

// ==========================================================================
// AUTO-UPDATE SYSTEM
// ==========================================================================
const updateState = {
  info: null,        // UpdateInfo from API
  dismissed: false,
  applying: false,
};

async function checkForUpdate() {
  try {
    const info = await api("/api/v1/update/check");
    updateState.info = info;
    if (info.has_update && !updateState.dismissed) {
      showUpdateBanner(info);
    }
  } catch (_err) {
    // Silent — no network or GitHub unreachable
  }
}

function showUpdateBanner(info) {
  const banner = $("updateBanner");
  $("updateBannerText").textContent =
    `Nueva versión disponible: v${info.latest}  (tienes v${info.current})`;

  // Show first line of release notes as subtitle
  const firstLine = (info.release_notes || "")
    .split("\n")
    .filter(Boolean)[0] || "";
  $("updateBannerNotes").textContent = firstLine ? `· ${firstLine}` : "";

  banner.classList.remove("hidden");
}

async function applyUpdate() {
  if (updateState.applying || !updateState.info?.download_url) return;
  updateState.applying = true;

  const btn = $("btnUpdate");
  btn.disabled = true;
  btn.textContent = "⏬ Descargando...";
  $("sbErrorText").textContent = "Descargando actualización, espera...";

  try {
    await api("/api/v1/update/apply", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ download_url: updateState.info.download_url }),
    });
    btn.textContent = "✓ Reiniciando...";
    $("sbErrorText").textContent = "Actualización aplicada. La app se reiniciará en segundos.";
    // Reconnect after delay
    setTimeout(() => location.reload(), 4000);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "⬆ Actualizar ahora";
    updateState.applying = false;
    $("sbErrorText").textContent = `Error al actualizar: ${err.message}`;
  }
}

function setupUpdateEvents() {
  $("btnUpdate").addEventListener("click", () => applyUpdate().catch(showError));
  $("btnUpdateDismiss").addEventListener("click", () => {
    updateState.dismissed = true;
    $("updateBanner").classList.add("hidden");
  });
}

// INITIAL BOOT
async function boot() {
  setupEvents();
  setupUpdateEvents();
  await loadInterfaces();
  await refreshStatus();
  await applyFilter();
  connectLive();

  // Check for updates 5 seconds after boot, then every 30 minutes
  setTimeout(() => checkForUpdate(), 5000);
  setInterval(() => checkForUpdate(), 30 * 60 * 1000);

  setInterval(() => {
    refreshStatus().catch(() => {});
    if (state.view === "stats") loadStats().catch(() => {});
  }, 2000);
}

boot().catch(showError);
