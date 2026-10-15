// Kuruta IDS Official Website Interactive Logic
document.addEventListener("DOMContentLoaded", () => {
  // Sample forensic packet dataset for playground
  const samplePackets = [
    { no: 1, proto: "TCP", src: "192.168.1.14:55176", dst: "185.70.42.63:443", len: 78, info: "443 → 55176 [SYN, ACK] Seq=0 Win=65535", flags: "SA", isAnomaly: false },
    { no: 2, proto: "TLS", src: "192.168.1.14:55176", dst: "185.70.42.63:443", len: 517, info: "Client Hello, TLS 1.3, ServerName: github.com", flags: "PA", isAnomaly: false },
    { no: 3, proto: "DNS", src: "192.168.1.14:5353", dst: "224.0.0.251:5353", len: 128, info: "Standard query 0x0000 PTR _googlecast._tcp.local", flags: "", isAnomaly: false },
    { no: 4, proto: "TCP", src: "185.70.42.63:48821", dst: "192.168.1.14:22", len: 60, info: "48821 → 22 [SYN] Seq=0 Win=1024", flags: "S", isAnomaly: true, alert: "vertical-port-scan" },
    { no: 5, proto: "TCP", src: "185.70.42.63:48822", dst: "192.168.1.14:23", len: 60, info: "48822 → 23 [SYN] Seq=0 Win=1024", flags: "S", isAnomaly: true, alert: "vertical-port-scan" },
    { no: 6, proto: "HTTP", src: "192.168.1.50:49210", dst: "10.0.0.1:80", len: 240, info: "POST /login HTTP/1.1 (application/x-www-form-urlencoded)", flags: "PA", isAnomaly: false, text: "username=admin&password=secretPassword123" },
    { no: 7, proto: "UDP", src: "192.168.1.14:51820", dst: "198.51.100.1:51820", len: 148, info: "WireGuard VPN Handshake Initiation", flags: "", isAnomaly: false },
    { no: 8, proto: "DNS", src: "192.168.1.14:49812", dst: "1.1.1.1:53", len: 310, info: "Standard query A a1b2c3d4e5f6g7h8.tunnel.badactor.com", flags: "", isAnomaly: true, alert: "dns-tunneling" },
    { no: 9, proto: "TCP", src: "192.168.1.200:60111", dst: "192.168.1.14:80", len: 54, info: "60111 → 80 [SYN, FIN] Invalid flag combination", flags: "SF", isAnomaly: true, alert: "invalid-tcp-flags" },
    { no: 10, proto: "TLS", src: "172.217.113.4:443", dst: "192.168.1.14:55022", len: 1444, info: "Application Data [TLSv1.3]", flags: "PA", isAnomaly: false }
  ];

  const tableBody = document.getElementById("demoTableBody");
  const filterInput = document.getElementById("demoFilterInput");
  const btnRunFilter = document.getElementById("btnRunFilter");
  const chips = document.querySelectorAll(".quick-chip");

  function renderRows(highlightFilter = "") {
    tableBody.innerHTML = "";
    const filter = highlightFilter.trim().toLowerCase();

    samplePackets.forEach((p) => {
      let matches = false;
      if (!filter) {
        matches = true;
      } else if (filter === "tcp" && (p.proto === "TCP" || p.proto === "TLS" || p.proto === "HTTP")) {
        matches = true;
      } else if (filter.includes("443") && (p.src.includes(":443") || p.dst.includes(":443"))) {
        matches = true;
      } else if ((filter === "dns" || filter.includes("dns")) && p.proto === "DNS") {
        matches = true;
      } else if ((filter.includes("flagged") || filter.includes("anomaly")) && p.isAnomaly) {
        matches = true;
      } else if (filter.includes("syn == 1") && p.flags.includes("S") && !p.flags.includes("A")) {
        matches = true;
      } else if (filter.includes("cidr") || filter.includes("192.168.1.0/24")) {
        matches = p.src.startsWith("192.168.1.") || p.dst.startsWith("192.168.1.");
      } else if (filter.includes("password") || filter.includes("bearer")) {
        matches = (p.text && p.text.includes("password")) || p.info.toLowerCase().includes("password");
      } else {
        // Fallback text match
        matches = p.proto.toLowerCase().includes(filter) ||
                  p.src.toLowerCase().includes(filter) ||
                  p.dst.toLowerCase().includes(filter) ||
                  p.info.toLowerCase().includes(filter);
      }

      const tr = document.createElement("tr");
      if (matches) tr.classList.add("highlight");
      tr.style.opacity = matches ? "1" : "0.3";

      const alertBadge = p.isAnomaly ? ` <span style="color:#ef4444; font-weight:700;">[IDS: ${p.alert}]</span>` : "";

      tr.innerHTML = `
        <td style="color:${matches ? '#fff' : 'inherit'}; font-weight:700;">${p.no}</td>
        <td><span style="display:inline-block; padding:1px 6px; border-radius:3px; background:rgba(255,255,255,0.08); font-size:11px;">${p.proto}</span></td>
        <td>${escapeHtml(p.src)}</td>
        <td>${escapeHtml(p.dst)}</td>
        <td>${p.len}</td>
        <td>${escapeHtml(p.info)}${alertBadge}</td>
      `;
      tableBody.appendChild(tr);
    });
  }

  function escapeHtml(str) {
    return String(str || "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[m]);
  }

  // Initial render with default filter
  renderRows(filterInput.value);

  btnRunFilter.addEventListener("click", () => {
    renderRows(filterInput.value);
  });

  filterInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") renderRows(filterInput.value);
  });

  filterInput.addEventListener("input", () => {
    renderRows(filterInput.value);
  });

  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const q = chip.dataset.query;
      filterInput.value = q;
      renderRows(q);
    });
  });
});
