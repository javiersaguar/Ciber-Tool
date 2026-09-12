"use strict";
const $ = (id) => document.getElementById(id);
const svgNS = "http://www.w3.org/2000/svg";
let token = "",
  controller = null,
  latest = null;
const short = (value) => value.slice(0, 12);
const utc = (epoch) => new Date(epoch * 1000).toISOString().slice(11, 16);
function element(tag, text) {
  const el = document.createElement(tag);
  el.textContent = text;
  return el;
}
function svg(tag, attrs) {
  const el = document.createElementNS(svgNS, tag);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, value));
  return el;
}
// Siluetas esquemáticas originales en lon/lat; proyección equirectangular.
const continents = [
  [
    [-168, 72],
    [-140, 70],
    [-124, 55],
    [-125, 40],
    [-115, 28],
    [-100, 20],
    [-84, 10],
    [-77, 8],
    [-87, 22],
    [-81, 25],
    [-80, 32],
    [-65, 46],
    [-55, 52],
    [-65, 60],
    [-95, 72],
    [-120, 73],
  ],
  [
    [-73, 60],
    [-48, 59],
    [-20, 76],
    [-42, 84],
    [-60, 81],
  ],
  [
    [-81, 12],
    [-62, 10],
    [-50, 1],
    [-35, -6],
    [-40, -23],
    [-55, -36],
    [-68, -55],
    [-75, -45],
    [-72, -18],
    [-81, -4],
  ],
  [
    [-10, 36],
    [-10, 44],
    [0, 50],
    [8, 55],
    [5, 62],
    [25, 71],
    [40, 68],
    [60, 73],
    [100, 77],
    [140, 70],
    [175, 65],
    [160, 53],
    [140, 45],
    [130, 32],
    [120, 23],
    [110, 2],
    [100, 10],
    [80, 8],
    [70, 24],
    [50, 12],
    [40, 30],
    [28, 41],
    [20, 39],
    [10, 44],
    [3, 39],
  ],
  [
    [-17, 15],
    [-17, 28],
    [-5, 36],
    [12, 37],
    [33, 31],
    [44, 12],
    [51, 11],
    [43, -12],
    [32, -29],
    [18, -35],
    [10, -20],
    [10, 0],
    [-4, 5],
  ],
  [
    [112, -22],
    [115, -34],
    [138, -36],
    [153, -28],
    [146, -15],
    [131, -11],
    [122, -16],
  ],
  [
    [47, -13],
    [50, -16],
    [46, -26],
    [43, -24],
  ],
  [
    [166, -35],
    [178, -38],
    [173, -46],
    [167, -47],
  ],
  [
    [96, 5],
    [108, -6],
    [120, -9],
    [134, -7],
    [141, -4],
    [130, 0],
    [116, 7],
    [108, 18],
  ],
  [
    [130, 32],
    [142, 45],
    [146, 43],
    [140, 35],
  ],
];
continents.forEach((points) =>
  $("land").append(
    svg("polygon", {
      points: points.map(([lon, lat]) => `${(lon + 180) * 2},${(90 - lat) * 2}`).join(" "),
    }),
  ),
);
function render(data) {
  latest = data;
  $("total").textContent = data.total.toLocaleString("es");
  $("ips").textContent = data.unique_ips.toLocaleString("es");
  $("findings").textContent = data.report.findings.length;
  $("grade").textContent = data.report.grade;
  $("scope").textContent =
    `Retención: ${data.retention_hours} h · máximo ${data.max_events.toLocaleString("es")} intentos`;
  $("window").textContent =
    `${data.report.started_at.slice(11, 19)} – ${data.report.metadata.window_end.slice(11, 19)} UTC`;
  $("recent").replaceChildren();
  data.recent.forEach((e) => {
    const row = document.createElement("tr");
    [
      e.timestamp.slice(0, 19).replace("T", " "),
      e.ip,
      short(e.username_id),
      short(e.password_id),
      e.client_version,
      short(e.fingerprint),
    ].forEach((value, i) => {
      const cell = element("td", value);
      cell.title = [
        e.timestamp,
        e.ip,
        e.username_id,
        e.password_id,
        e.client_version,
        e.fingerprint,
      ][i];
      row.append(cell);
    });
    $("recent").append(row);
  });
  $("ranking").replaceChildren();
  data.ranking.forEach((r) => {
    const row = document.createElement("tr");
    const label = element("td", `${short(r.username_id)} / ${short(r.password_id)}`);
    label.append(element("small", r.key_day + " · HMAC"));
    row.append(label, element("td", r.count.toLocaleString("es")));
    $("ranking").append(row);
  });
  $("points").replaceChildren();
  $("origins").replaceChildren();
  let unknown = 0;
  data.origins.forEach((o) => {
    const loc = o.location;
    $("origins").append(
      element("span", `${o.ip} · ${o.count}${loc ? " · " + loc.country : " · sin ubicación"}`),
    );
    if (!loc) {
      unknown++;
      return;
    }
    const point = svg("circle", {
      cx: (loc.longitude + 180) * 2,
      cy: (90 - loc.latitude) * 2,
      r: Math.min(14, 3 + Math.log2(o.count + 1)),
    });
    const title = svg("title", {});
    title.textContent = `${o.ip} · ${o.count} intentos · radio aproximado: ${loc.accuracy_km ?? "desconocido"} km`;
    point.append(title);
    $("points").append(point);
  });
  $("geo-note").textContent = data.geoip_enabled
    ? `Ubicación aproximada de la red, no de una persona. ${unknown} de las IPs mostradas sin ubicación. Radio de precisión al señalar un punto.`
    : "Mapa sin geolocalización: configura --geoip-db con una base City .mmdb local. No se consultan APIs externas.";
  $("timeline").replaceChildren();
  const max = Math.max(1, ...data.timeline.map((t) => t.count));
  data.timeline.forEach((t, i) => {
    const height = (t.count / max) * 125;
    const bar = svg("rect", {
      x: (i * 1000) / 60 + 2,
      y: 140 - height,
      width: 12,
      height: Math.max(1, height),
    });
    const title = svg("title", {});
    title.textContent = `${utc(t.epoch)} UTC · ${t.count} intentos`;
    bar.append(title);
    $("timeline").append(bar);
  });
  $("time-start").textContent = utc(data.timeline[0].epoch);
  $("time-end").textContent = utc(data.timeline.at(-1).epoch);
  $("alerts").replaceChildren();
  if (!data.report.findings.length) $("alerts").textContent = "Sin hallazgos en la ventana actual.";
  data.report.findings.forEach((f) => {
    const article = document.createElement("article");
    article.append(element("h3", f.title), element("p", f.description), element("p", f.evidence));
    $("alerts").append(article);
  });
  const s = data.stats;
  $("losses").textContent =
    `Conexiones rechazadas: ${s.rejected_connections ?? 0} · intentos descartados: ${s.dropped_attempts ?? 0} · entradas fuera de límite: ${s.rejected_payloads ?? 0}`;
}
function disconnect() {
  controller?.abort();
  controller = null;
  token = "";
  latest = null;
  $("login").hidden = false;
  $("token").value = "";
  $("export").disabled = true;
  $("disconnect").disabled = true;
  $("status").textContent = "Desconectado";
  ["recent", "ranking", "points", "origins", "timeline", "alerts"].forEach((id) =>
    $(id).replaceChildren(),
  );
  ["total", "ips", "findings", "grade"].forEach((id) => ($(id).textContent = "—"));
}
$("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  controller?.abort();
  token = $("token").value.trim();
  $("token").value = "";
  const current = new AbortController();
  controller = current;
  $("status").textContent = "Conectando…";
  try {
    const response = await fetch("/api/events", {
      headers: { Authorization: `Bearer ${token}` },
      signal: current.signal,
      cache: "no-store",
    });
    if (!response.ok)
      throw new Error(response.status === 401 ? "Token incorrecto" : "Panel no disponible");
    $("login").hidden = true;
    $("disconnect").disabled = false;
    $("export").disabled = false;
    $("status").textContent = "● En directo";
    const reader = response.body.getReader(),
      decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) throw new Error("Servicio desconectado. Vuelve a conectar.");
      buffer += decoder.decode(value, { stream: true });
      let end;
      while ((end = buffer.indexOf("\n\n")) !== -1) {
        const message = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (message.startsWith("data: ")) render(JSON.parse(message.slice(6)));
      }
    }
  } catch (error) {
    if (controller !== current) return;
    disconnect();
    if (error.name !== "AbortError") $("status").textContent = error.message;
  }
});
$("disconnect").addEventListener("click", disconnect);
$("export").addEventListener("click", () => {
  if (!latest) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(latest.report, null, 2)], { type: "application/json;charset=utf-8" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "atalaya-ssh-window.json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
