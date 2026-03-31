// ============================================================
//  UAE Cyber Attack Map — Interactive Threat Intelligence
//  script.js
// ============================================================

"use strict";

// ---- CONFIG ----------------------------------------------------------------
const UAE_CENTER = [24.0, 54.37];   // Abu Dhabi center
const UAE_TARGETS = [
  { name: "Abu Dhabi",  lat: 24.4539, lon: 54.3773, sector: "Government" },
  { name: "Dubai",      lat: 25.2048, lon: 55.2708, sector: "Finance" },
  { name: "Sharjah",   lat: 25.3462, lon: 55.4212, sector: "Telecom" },
  { name: "Ajman",     lat: 25.4052, lon: 55.5136, sector: "Energy" },
  { name: "RAK",       lat: 25.7953, lon: 55.9429, sector: "Infrastructure" },
  { name: "Fujairah",  lat: 25.1288, lon: 56.3265, sector: "Ports" },
];

const ATTACK_SOURCES = [
  { country: "Iran",         flag: "🇮🇷", lat: 32.0,  lon: 53.0,  weight: 28, color: "#ff3c3c" },
  { country: "Russia",       flag: "🇷🇺", lat: 55.75, lon: 37.61, weight: 18, color: "#ff6644" },
  { country: "China",        flag: "🇨🇳", lat: 35.86, lon: 104.1, weight: 14, color: "#ff9900" },
  { country: "North Korea",  flag: "🇰🇵", lat: 40.0,  lon: 127.5, weight: 10, color: "#ff00ff" },
  { country: "Pakistan",     flag: "🇵🇰", lat: 30.3,  lon: 69.3,  weight: 8,  color: "#ffff00" },
  { country: "India",        flag: "🇮🇳", lat: 20.59, lon: 78.96, weight: 6,  color: "#00cfff" },
  { country: "Turkey",       flag: "🇹🇷", lat: 38.96, lon: 35.24, weight: 5,  color: "#bf00ff" },
  { country: "Yemen",        flag: "🇾🇪", lat: 15.55, lon: 48.51, weight: 7,  color: "#ff3c3c" },
  { country: "USA",          flag: "🇺🇸", lat: 37.09, lon:-95.71, weight: 4,  color: "#00cfff" },
  { country: "Germany",      flag: "🇩🇪", lat: 51.16, lon: 10.45, weight: 3,  color: "#39ff14" },
  { country: "Nigeria",      flag: "🇳🇬", lat: 9.08,  lon: 8.67,  weight: 4,  color: "#ff9900" },
  { country: "Brazil",       flag: "🇧🇷", lat:-14.23, lon:-51.93, weight: 2,  color: "#39ff14" },
];

const ATTACK_TYPES = ["DDoS", "Phishing", "Malware", "Ransomware", "APT", "SQLi"];
const TYPE_COLORS  = {
  DDoS:       "#ff3c3c",
  Phishing:   "#ff9900",
  Malware:    "#ff00ff",
  Ransomware: "#00cfff",
  APT:        "#39ff14",
  SQLi:       "#ffff00",
};
const SEVERITIES = ["critical", "high", "medium", "low"];
const SEV_WEIGHTS = [10, 30, 40, 20];   // probability weights

// ---- STATE -----------------------------------------------------------------
let totalAttacks  = 0;
let attacksPerMin = 0;
let attacksThisMin = 0;
let sourceCounts  = {};
let typeCounts    = { DDoS:0, Phishing:0, Malware:0, Ransomware:0, APT:0, SQLi:0 };
let sevCounts     = { critical:0, high:0, medium:0, low:0 };
let activeCountries = new Set();
let map, svgOverlay, svgNS;

// ---- HELPERS ---------------------------------------------------------------
function weightedRandom(items, weights) {
  const total = weights.reduce((a,b) => a+b, 0);
  let r = Math.random() * total;
  for (let i = 0; i < items.length; i++) {
    r -= weights[i];
    if (r <= 0) return items[i];
  }
  return items[items.length - 1];
}

function randomBetween(a, b) {
  return a + Math.random() * (b - a);
}

function fmt2(n) { return String(n).padStart(2,'0'); }

function nowStr() {
  const d = new Date();
  return `${fmt2(d.getHours())}:${fmt2(d.getMinutes())}:${fmt2(d.getSeconds())}`;
}

function severityWeighted() {
  return weightedRandom(SEVERITIES, SEV_WEIGHTS);
}

// ---- CLOCK -----------------------------------------------------------------
function updateClock() {
  const d    = new Date();
  const time = `${fmt2(d.getHours())}:${fmt2(d.getMinutes())}:${fmt2(d.getSeconds())}`;
  const months = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];
  const date = `${fmt2(d.getDate())} ${months[d.getMonth()]} ${d.getFullYear()}`;
  document.getElementById("clock").textContent = time;
  document.getElementById("date").textContent  = date;
}
setInterval(updateClock, 1000);
updateClock();

// ---- MAP INIT --------------------------------------------------------------
function initMap() {
  map = L.map("map", {
    center: UAE_CENTER,
    zoom: 4,
    zoomControl: true,
    attributionControl: true,
  });

  // OpenStreetMap tiles (will be CSS-filtered to dark theme)
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>',
    maxZoom: 18,
  }).addTo(map);

  // UAE target markers
  UAE_TARGETS.forEach(t => {
    const icon = L.divIcon({
      className: "",
      html: `<div class="target-marker" title="${t.name} — ${t.sector}"></div>`,
      iconSize: [16,16],
      iconAnchor: [8,8],
    });
    L.marker([t.lat, t.lon], { icon })
      .bindPopup(`<b>🎯 ${t.name}</b><br>Sector: ${t.sector}<br>Status: <span style="color:#ff3c3c">UNDER ATTACK</span>`)
      .addTo(map);
  });

  // Inject target marker style
  const style = document.createElement("style");
  style.textContent = `
    .target-marker {
      width: 14px; height: 14px;
      background: radial-gradient(circle, #ff3c3c 30%, transparent 70%);
      border: 2px solid #ff3c3c;
      border-radius: 50%;
      box-shadow: 0 0 12px #ff3c3c, 0 0 24px rgba(255,60,60,0.4);
      animation: targetPulse 1.5s ease-in-out infinite;
    }
    @keyframes targetPulse {
      0%, 100% { box-shadow: 0 0 8px #ff3c3c; }
      50%       { box-shadow: 0 0 20px #ff3c3c, 0 0 40px rgba(255,60,60,0.6); }
    }
  `;
  document.head.appendChild(style);

  // SVG overlay for attack lines
  svgNS = "http://www.w3.org/2000/svg";
  const mapPane = map.getPanes().overlayPane;
  const svg = document.createElementNS(svgNS, "svg");
  svg.id = "attackSvg";
  svg.style.cssText = "position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;overflow:visible;z-index:400;";
  mapPane.appendChild(svg);
  svgOverlay = svg;

  // Recalculate on map move/zoom
  map.on("moveend zoomend", redrawLines);
}

// Active lines: [{from, to, color, type, progress, el, particles}]
let activeLines = [];

function latLonToPoint(lat, lon) {
  const p = map.latLngToLayerPoint([lat, lon]);
  return { x: p.x, y: p.y };
}

function redrawLines() {
  // Remove all existing SVG children and redraw
  while (svgOverlay.firstChild) svgOverlay.removeChild(svgOverlay.firstChild);
  activeLines = [];
}

// ---- ANIMATED ATTACK LINE --------------------------------------------------
function fireAttack(source, targetCity, attackType, severity) {
  const target = UAE_TARGETS.find(t => t.name === targetCity) || UAE_TARGETS[0];
  const color  = TYPE_COLORS[attackType] || "#00cfff";

  // Slightly randomize source point for realism
  const srcLat = source.lat + randomBetween(-1.5, 1.5);
  const srcLon = source.lon + randomBetween(-1.5, 1.5);

  const animId = Date.now() + Math.random();

  function draw(progress) {
    if (!svgOverlay) return;

    const sp = latLonToPoint(srcLat, srcLon);
    const ep = latLonToPoint(target.lat, target.lon);

    // Control point for arc
    const cpx = (sp.x + ep.x) / 2 + (ep.y - sp.y) * 0.25;
    const cpy = (sp.y + ep.y) / 2 - Math.abs(ep.x - sp.x) * 0.25;

    // Compute point on quadratic bezier at t=progress
    function bezier(t) {
      const x = (1-t)*(1-t)*sp.x + 2*(1-t)*t*cpx + t*t*ep.x;
      const y = (1-t)*(1-t)*sp.y + 2*(1-t)*t*cpy + t*t*ep.y;
      return {x, y};
    }

    // Remove old element for this animId
    const old = svgOverlay.querySelector(`[data-id="${animId}"]`);
    if (old) svgOverlay.removeChild(old);

    const g = document.createElementNS(svgNS, "g");
    g.setAttribute("data-id", animId);

    // Draw trail path
    const pathD = buildPartialBezierPath(sp, cpx, cpy, ep, Math.min(progress, 1));
    const path = document.createElementNS(svgNS, "path");
    path.setAttribute("d", pathD);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", color);
    path.setAttribute("stroke-width", severity === "critical" ? "2.5" : severity === "high" ? "2" : "1.5");
    path.setAttribute("stroke-opacity", "0.75");
    path.setAttribute("filter", `drop-shadow(0 0 4px ${color})`);
    g.appendChild(path);

    // Draw moving dot (head of the line)
    const pt = bezier(Math.min(progress, 1));
    const dot = document.createElementNS(svgNS, "circle");
    dot.setAttribute("cx", pt.x);
    dot.setAttribute("cy", pt.y);
    dot.setAttribute("r", severity === "critical" ? "5" : "3.5");
    dot.setAttribute("fill", color);
    dot.setAttribute("opacity", "0.95");
    dot.setAttribute("filter", `drop-shadow(0 0 6px ${color})`);
    g.appendChild(dot);

    // Impact flash at end
    if (progress >= 1) {
      const flash = document.createElementNS(svgNS, "circle");
      const ep2 = latLonToPoint(target.lat, target.lon);
      flash.setAttribute("cx", ep2.x);
      flash.setAttribute("cy", ep2.y);
      const r = Math.min(30, (progress - 1) * 150);
      flash.setAttribute("r", r);
      flash.setAttribute("fill", "none");
      flash.setAttribute("stroke", color);
      flash.setAttribute("stroke-width", "1.5");
      flash.setAttribute("opacity", Math.max(0, 1 - (progress - 1) * 3));
      g.appendChild(flash);
    }

    svgOverlay.appendChild(g);
  }

  // Animate
  const duration = randomBetween(1800, 3200);
  const startTime = performance.now();

  function animate(now) {
    const elapsed = now - startTime;
    const progress = elapsed / duration;
    draw(progress);

    if (progress < 1.5) {
      requestAnimationFrame(animate);
    } else {
      // Cleanup
      const el = svgOverlay.querySelector(`[data-id="${animId}"]`);
      if (el) svgOverlay.removeChild(el);
    }
  }
  requestAnimationFrame(animate);
}

// Build path string for partial bezier (0..t)
function buildPartialBezierPath(sp, cpx, cpy, ep, t) {
  // Sample points along the bezier from 0 to t
  const steps = 30;
  let d = "";
  for (let i = 0; i <= steps; i++) {
    const s = (i / steps) * t;
    const x = (1-s)*(1-s)*sp.x + 2*(1-s)*s*cpx + s*s*ep.x;
    const y = (1-s)*(1-s)*sp.y + 2*(1-s)*s*cpy + s*s*ep.y;
    d += (i === 0 ? "M" : "L") + `${x.toFixed(1)} ${y.toFixed(1)} `;
  }
  return d;
}

// ---- SOURCE MARKER ---------------------------------------------------------
const sourceMarkers = {};

function ensureSourceMarker(source) {
  if (sourceMarkers[source.country]) return;
  const icon = L.divIcon({
    className: "",
    html: `<div class="src-marker" style="border-color:${source.color};box-shadow:0 0 8px ${source.color};">${source.flag}</div>`,
    iconSize: [26,26],
    iconAnchor: [13,13],
  });
  const m = L.marker([source.lat, source.lon], { icon })
    .bindPopup(`<b>${source.flag} ${source.country}</b><br>Attacks: <span style="color:${source.color}" id="popup-${source.country}">0</span>`);
  m.addTo(map);
  sourceMarkers[source.country] = m;

  // Inject style once
  if (!document.getElementById("srcMarkerStyle")) {
    const s = document.createElement("style");
    s.id = "srcMarkerStyle";
    s.textContent = `
      .src-marker {
        width:24px; height:24px; border-radius:50%;
        border:2px solid; display:flex; align-items:center; justify-content:center;
        font-size:14px; background:rgba(0,0,0,0.6);
        transition: transform 0.3s;
      }
      .src-marker:hover { transform: scale(1.3); }
    `;
    document.head.appendChild(s);
  }
}

// ---- ATTACK GENERATION -----------------------------------------------------
function generateAttack() {
  const source = weightedRandom(ATTACK_SOURCES, ATTACK_SOURCES.map(s => s.weight));
  const target = UAE_TARGETS[Math.floor(Math.random() * UAE_TARGETS.length)];
  const type   = weightedRandom(ATTACK_TYPES, [30, 20, 18, 12, 10, 10]);
  const sev    = severityWeighted();

  // Update counters
  totalAttacks++;
  attacksThisMin++;
  typeCounts[type]++;
  sevCounts[sev]++;
  sourceCounts[source.country] = (sourceCounts[source.country] || 0) + 1;
  activeCountries.add(source.country);

  // Ensure source marker is on map
  ensureSourceMarker(source);

  // Fire animated line
  fireAttack(source, target.name, type, sev);

  // Update UI
  updateStats();
  addFeedItem(source, target, type, sev);
}

// ---- UI UPDATES ------------------------------------------------------------
function updateStats() {
  // Attack counter
  const el = document.getElementById("attackCount");
  el.textContent = totalAttacks.toLocaleString();

  // Attack rate
  document.getElementById("attackRate").textContent = `+${attacksPerMin} / min`;

  // Type bars
  const maxType = Math.max(...Object.values(typeCounts), 1);
  for (const [type, count] of Object.entries(typeCounts)) {
    const barId = type === "SQLi" ? "SQLi" : type;
    const bar = document.getElementById(`bar-${barId}`);
    const cnt = document.getElementById(`cnt-${barId}`);
    if (bar) bar.style.width = `${(count / maxType) * 100}%`;
    if (cnt) cnt.textContent = count;
  }

  // Severity
  document.getElementById("sev-critical").textContent = sevCounts.critical;
  document.getElementById("sev-high").textContent     = sevCounts.high;
  document.getElementById("sev-medium").textContent   = sevCounts.medium;
  document.getElementById("sev-low").textContent      = sevCounts.low;

  // Threat level
  const critRate = sevCounts.critical / Math.max(totalAttacks, 1);
  const threatPct = Math.min(100, 20 + critRate * 200 + Math.log10(totalAttacks + 1) * 15);
  document.getElementById("threatFill").style.width = `${threatPct}%`;
  let label, color;
  if (threatPct < 35)       { label = "LOW";      color = "#39ff14"; }
  else if (threatPct < 55)  { label = "MODERATE"; color = "#ffff00"; }
  else if (threatPct < 75)  { label = "HIGH";     color = "#ff9900"; }
  else                      { label = "CRITICAL"; color = "#ff3c3c"; }
  const lbl = document.getElementById("threatLabel");
  lbl.textContent = label;
  lbl.style.color = color;
  lbl.style.textShadow = `0 0 12px ${color}`;

  // Top sources
  const sorted = Object.entries(sourceCounts)
    .sort((a,b) => b[1] - a[1])
    .slice(0, 7);
  const sourceEl = document.getElementById("topSources");
  sourceEl.innerHTML = sorted.map(([country, count]) => {
    const src = ATTACK_SOURCES.find(s => s.country === country);
    return `
      <div class="source-item">
        <span class="source-flag">${src?.flag || "🌐"}</span>
        <span class="source-country">${country}</span>
        <span class="source-num">${count}</span>
      </div>
    `;
  }).join("");

  // Footer
  document.getElementById("footerStats").textContent =
    `Monitoring ${totalAttacks.toLocaleString()} attack vectors across ${activeCountries.size} countries`;
}

// ---- FEED ------------------------------------------------------------------
const SECTOR_TARGETS = {
  "Abu Dhabi": "GOV.AE",
  "Dubai":     "DIFC.NET",
  "Sharjah":   "ETISALAT.AE",
  "Ajman":     "DEWA.GOV.AE",
  "RAK":       "RAK.AE",
  "Fujairah":  "PORT.FUJ.AE",
};

function addFeedItem(source, target, type, severity) {
  const feed = document.getElementById("feed");
  const sevColors = { critical:"#ff3c3c", high:"#ff9900", medium:"#ffff00", low:"#39ff14" };
  const ip = `${randomInt(1,254)}.${randomInt(1,254)}.${randomInt(1,254)}.${randomInt(1,254)}`;
  const tgt = SECTOR_TARGETS[target.name] || "UAE.GOV.AE";

  const item = document.createElement("div");
  item.className = "feed-item";
  item.innerHTML = `
    <span class="feed-time">[${nowStr()}]</span>
    <span class="feed-type" style="color:${TYPE_COLORS[type]}">${type}</span>
    <span class="feed-from">${source.flag} ${ip}</span>
    <span class="feed-arrow">→</span>
    <span class="feed-target">${tgt}</span>
    <span style="color:${sevColors[severity]};font-size:9px;margin-left:4px">[${severity.toUpperCase()}]</span>
  `;
  feed.insertBefore(item, feed.firstChild);

  // Keep feed trimmed
  while (feed.children.length > 50) {
    feed.removeChild(feed.lastChild);
  }
}

function randomInt(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}

// ---- ATTACK RATE COUNTER ---------------------------------------------------
setInterval(() => {
  attacksPerMin = attacksThisMin;
  attacksThisMin = 0;
}, 60000);

// ---- BURST SIMULATION (initial load) ---------------------------------------
function burstAttacks(n) {
  let i = 0;
  const interval = setInterval(() => {
    generateAttack();
    i++;
    if (i >= n) clearInterval(interval);
  }, 80);
}

// ---- MAIN LOOP -------------------------------------------------------------
function startAttackLoop() {
  // Variable rate: faster at "peak" times
  function scheduleNext() {
    const delay = randomBetween(400, 2200);
    setTimeout(() => {
      generateAttack();
      scheduleNext();
    }, delay);
  }
  scheduleNext();
}

// ---- BOOT ------------------------------------------------------------------
window.addEventListener("load", () => {
  initMap();
  // Seed initial data (simulate already-running dashboard)
  setTimeout(() => {
    burstAttacks(30);
    setTimeout(() => {
      startAttackLoop();
    }, 3000);
  }, 800);
});
