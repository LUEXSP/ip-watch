const AGENT = "http://127.0.0.1:8790";
let histPage = 0;
const HIST_PER_PAGE = 10;

// ── Utils ────────────────────────────────────────────────
async function api(path, method = "GET", body = null) {
  const headers = await getIPWatchHeaders();
  const opts = { method, cache: "no-store", headers };
  if (body) { opts.body = JSON.stringify(body); opts.headers["Content-Type"] = "application/json"; }
  const r = await fetch(`${AGENT}${path}`, opts);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  const A = 0x1F1E6, u = cc.toUpperCase();
  return String.fromCodePoint(A + u.charCodeAt(0) - 65, A + u.charCodeAt(1) - 65);
}

function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

function ts(epoch) {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleString();
}

function tsShort(epoch) {
  if (!epoch) return "—";
  const d = new Date(epoch * 1000);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function scoreColor(score) {
  if (typeof score !== "number") return "#6b7280";
  if (score >= 40) return "#f87171";
  if (score >= 20) return "#fbbf24";
  return "#34d399";
}

function toast(msg, isErr = false) {
  const el = document.getElementById("toastMsg");
  el.textContent = msg;
  el.className = isErr ? "err" : "ok";
  el.style.display = "block";
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => { el.style.display = "none"; el.style.opacity = "1"; }, 350); }, 3500);
}

function setChip(id, label, val, cls) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = `${label}: ${val}`;
  el.className = "chip " + (cls || "");
}

function setFill(id, pct, color) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = clamp(pct, 0, 100) + "%";
  if (color) el.style.background = color;
}

// ── Status pill ──────────────────────────────────────────
function setOnline(ok) {
  document.getElementById("statusDot").className = "dot " + (ok ? "ok" : "err");
  document.getElementById("statusText").textContent = ok ? "Agent OK" : "Agent OFF";
}

// ── Dashboard ────────────────────────────────────────────
async function loadDash() {
  try {
    const d = await api("/status");
    setOnline(true);

    // IP
    const cc = d.profile?.country_code || "";
    document.getElementById("ipFlag").textContent = flag(cc);
    document.getElementById("ipAddr").textContent = d.ip || "—";

    const loc = [d.profile?.city, d.profile?.region, d.profile?.country].filter(Boolean).join(", ");
    document.getElementById("ipLoc").textContent = loc || "—";
    document.getElementById("ipOrg").textContent = d.profile?.org
      ? `${d.profile.org}${d.profile.asn ? ` · ${d.profile.asn}` : ""}`
      : "—";
    document.getElementById("ipTz").textContent = d.profile?.timezone ? `🕐 ${d.profile.timezone}` : "";
    document.getElementById("ipHostname").textContent = d.profile?.hostname || "";

    const tz = d.profile?.timezone;
    let updStr = "—";
    if (d.last_updated_ts) {
      if (tz) {
        try {
          updStr = new Intl.DateTimeFormat("es", { dateStyle: "short", timeStyle: "medium", timeZone: tz }).format(new Date(d.last_updated_ts * 1000));
        } catch { updStr = ts(d.last_updated_ts); }
      } else {
        updStr = ts(d.last_updated_ts);
      }
    }
    document.getElementById("lastUpdated").textContent = `Actualizado: ${updStr}`;

    // Chips
    const proxy = d.privacy?.proxy?.enabled;
    setChip("chipProxy", "Proxy", proxy === true ? "ON" : proxy === false ? "OFF" : "?",
      proxy === true ? "warn" : proxy === false ? "good" : "");

    const anon = d.privacy?.anonymizer_likely;
    setChip("chipAnon", "Anonymizer", anon === true ? "Likely" : anon === false ? "No" : "?",
      anon ? "warn" : "good");

    const bl = d.fraud?.is_blacklisted_external;
    setChip("chipBL", "Blacklist", bl === true ? "YES" : bl === false ? "No" : "?",
      bl === true ? "bad" : "good");

    const ai = d.system?.ai_friendly;
    setChip("chipAI", "AI", ai ? `${ai.label} (${ai.score})` : "?",
      ai?.label === "YES" ? "good" : ai?.label === "MAYBE" ? "warn" : "bad");

    // Fraud score
    const fs = d.fraud?.fraud_score;
    const risk = d.fraud?.risk;
    document.getElementById("fraudScore").textContent =
      fs !== undefined && fs !== null ? `${fs}/100 ${risk ? `(${risk})` : ""}` : "—";
    document.getElementById("fraudScore").style.color = scoreColor(fs);
    setFill("fraudFill", fs ?? 0, scoreColor(fs));

    const scamA = document.getElementById("scamUrl");
    if (d.fraud?.error) {
      scamA.href = d.fraud?.scamalytics_url || "#";
      scamA.textContent = `Scamalytics: ${d.fraud.error}`;
    } else if (d.fraud?.source) {
      scamA.href = d.fraud.scamalytics_url || "#";
      scamA.textContent = `Scamalytics OK (${d.fraud.source}) ↗`;
    } else if (d.fraud?.scamalytics_url) {
      scamA.href = d.fraud.scamalytics_url;
      scamA.textContent = "Ver reporte Scamalytics ↗";
    } else {
      scamA.href = "#"; scamA.textContent = "Scamalytics no disponible";
    }

    // AbuseIPDB
    const ab = d.abuseipdb;
    if (ab?.score !== undefined) {
      document.getElementById("abuseScore").textContent = `${ab.score}/100`;
      document.getElementById("abuseScore").style.color = scoreColor(ab.score);
      setFill("abuseFill", ab.score, scoreColor(ab.score));
      const parts = [];
      if (ab.isp) parts.push(ab.isp);
      if (ab.total_reports) parts.push(`${ab.total_reports} reportes`);
      document.getElementById("abuseHint").innerHTML =
        `<a href="https://www.abuseipdb.com/check/${d.ip}" target="_blank">Ver en AbuseIPDB ↗</a>` +
        (parts.length ? " · " + parts.join(" · ") : "");
    } else {
      document.getElementById("abuseScore").textContent = "—";
      document.getElementById("abuseHint").textContent = ab?.error === "no_api_key"
        ? "Configura tu API Key de AbuseIPDB en Configuración"
        : "Sin datos";
    }

    // IPQualityScore
    const ipqs = d.ipqualityscore;
    if (ipqs?.score !== undefined && ipqs?.score !== null) {
      document.getElementById("ipqsScore").textContent = `${ipqs.score}/100${ipqs.risk ? ` (${ipqs.risk})` : ""}`;
      document.getElementById("ipqsScore").style.color = scoreColor(ipqs.score);
      setFill("ipqsFill", ipqs.score, scoreColor(ipqs.score));
      const flags = [];
      if (ipqs.proxy) flags.push("proxy");
      if (ipqs.vpn || ipqs.active_vpn) flags.push("vpn");
      if (ipqs.tor || ipqs.active_tor) flags.push("tor");
      if (ipqs.bot_status) flags.push("bot");
      if (ipqs.recent_abuse) flags.push("recent abuse");
      const parts = [];
      if (ipqs.isp) parts.push(ipqs.isp);
      if (ipqs.connection_type) parts.push(ipqs.connection_type);
      if (flags.length) parts.push("Flags: " + flags.join(", "));
      const link = ipqs.lookup_url || `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${d.ip}`;
      document.getElementById("ipqsHint").innerHTML =
        `<a href="${link}" target="_blank">Ver en IPQualityScore ↗</a>` +
        (parts.length ? " · " + parts.join(" · ") : "");
    } else {
      document.getElementById("ipqsScore").textContent = "—";
      setFill("ipqsFill", 0, scoreColor(null));
      document.getElementById("ipqsHint").textContent = ipqs?.error === "no_api_key"
        ? "Configura tu API Key de IPQualityScore en Configuración"
        : (ipqs?.error ? `IPQualityScore: ${ipqs.error}` : "Sin datos");
    }

    // DNS
    document.getElementById("dnsVal").textContent =
      Array.isArray(d.dns) && d.dns.length ? d.dns.slice(0, 2).join(", ") : "—";

    // Browser / OS
    document.getElementById("browserVal").textContent = d.client?.browser || "—";
    document.getElementById("osVal").textContent = d.system?.os
      ? d.system.os.split("-")[0].trim() : "—";

    // AI score
    const aiFull = d.system?.ai_friendly;
    document.getElementById("aiScore").textContent = aiFull ? `${aiFull.score}/100` : "—";
    document.getElementById("aiScore").style.color = scoreColor(aiFull ? 100 - aiFull.score : 50);
    document.getElementById("aiLabel").textContent = aiFull?.reasons?.slice(0, 2).join(" · ") || "—";

    // Proxy detail
    document.getElementById("proxyVal").textContent = proxy === true ? "ON" : proxy === false ? "OFF" : "?";
    document.getElementById("proxyDetail").textContent = d.privacy?.proxy?.value || "—";

    renderNature(d);
    renderBank(d);
    renderLeaks(d);
    renderTunnel(d);

  } catch (e) {
    setOnline(false);
    document.getElementById("ipAddr").textContent = "Sin agente";
    document.getElementById("lastUpdated").textContent = "Agent no disponible";
    console.warn("[Dash]", e);
  }
}

// ── Naturaleza IP + AI-Friendly accionable ───────────────
const NATURE_CLASS = {
  residential: "good", mobile: "good",
  datacenter: "bad", vpn: "bad", tor: "bad",
  unknown: "warn",
};

function renderNature(d) {
  const n = d.nature || {};
  const badge = document.getElementById("natureBadge");
  if (badge) {
    badge.textContent = n.label || "Desconocida";
    badge.className = "chip " + (NATURE_CLASS[n.type] || "warn");
  }
  const conf = document.getElementById("natureConf");
  if (conf) conf.textContent = n.confidence ? `confianza: ${n.confidence}` : "";
  const sig = document.getElementById("natureSignals");
  if (sig) sig.innerHTML = (n.signals || []).map(s => `• ${s}`).join("<br>") || "";

  const ai = d.system?.ai_friendly || {};
  const bs = document.getElementById("aiBigScore");
  if (bs) {
    bs.textContent = (ai.score !== undefined && ai.score !== null) ? `${ai.score}/100 (${ai.label || "?"})` : "—";
    bs.style.color = scoreColor(ai.score !== undefined ? 100 - ai.score : 50);
  }
  setFill("aiBigFill", ai.score ?? 0, scoreColor(ai.score !== undefined ? 100 - ai.score : 50));
  const recs = document.getElementById("aiRecs");
  if (recs) {
    const list = ai.recommendations || [];
    recs.innerHTML = list.length
      ? "<strong>Recomendaciones:</strong><br>" + list.map(r => `→ ${r}`).join("<br>")
      : '<span style="color:var(--good)">Todo en orden: la IP luce apta para servicios de IA.</span>';
  }
}

// ── Riesgo bancario (estimado) ───────────────────────────
const BANK_LEVEL_CLASS = { BAJO: "good", MEDIO: "warn", ALTO: "bad" };

function renderBank(d) {
  const b = d.bank_risk || {};
  const badge = document.getElementById("bankLevel");
  const score = document.getElementById("bankScore");
  const factorsEl = document.getElementById("bankFactors");
  const recsEl = document.getElementById("bankRecs");
  if (!score) return;

  const hasData = typeof b.risk === "number";
  if (badge) {
    badge.textContent = hasData ? `Riesgo ${b.level}` : "Sin datos";
    badge.className = "chip " + (BANK_LEVEL_CLASS[b.level] || "warn");
  }
  if (score) {
    score.textContent = hasData ? `${b.risk}/100` : "—";
    // Escala inversa: riesgo alto = rojo.
    score.style.color = hasData ? scoreColor(b.risk) : "var(--muted)";
  }
  // La barra crece con el riesgo (más llena = peor).
  setFill("bankFill", hasData ? b.risk : 0, hasData ? scoreColor(b.risk) : "var(--muted)");

  if (factorsEl) {
    const f = b.factors || [];
    factorsEl.innerHTML = f.length
      ? f.map(x => `• +${x.delta} <span style="color:var(--muted)">[${x.layer}]</span> ${x.label}`).join("<br>")
      : '<span style="color:var(--good)">Sin banderas de red para banca.</span>';
  }
  if (recsEl) {
    const list = b.recommendations || [];
    recsEl.innerHTML = list.length
      ? "<strong>Recomendaciones:</strong><br>" + list.map(r => `→ ${r}`).join("<br>")
      : "";
  }
  // Reflejar el país esperado configurado, sin pisar lo que el usuario está escribiendo.
  const inp = document.getElementById("expCountry");
  if (inp && document.activeElement !== inp) {
    const cc = d.coherence?.expected_country || "";
    if (cc && inp.value !== cc) inp.value = cc;
  }
}

// ── Fugas WebRTC/DNS + coherencia ────────────────────────
function renderLeaks(d) {
  const leak = d.dns_leak || {};
  const dv = document.getElementById("dnsLeakVal");
  const ds = document.getElementById("dnsLeakSub");
  if (dv) {
    if (leak.error) { dv.textContent = "?"; dv.style.color = "var(--muted)"; }
    else if (leak.leak_suspected) { dv.textContent = "⚠️ Sospechosa"; dv.style.color = "var(--bad)"; }
    else { dv.textContent = "✓ OK"; dv.style.color = "var(--good)"; }
  }
  if (ds) {
    const rs = leak.resolvers || [];
    ds.textContent = rs.length ? rs.map(r => `${r.ip}${r.country_code ? " ("+r.country_code+")" : ""}`).join(", ") : "Resolvers vs país IP";
  }

  const coh = d.coherence || {};
  const cv = document.getElementById("cohVal");
  const cs = document.getElementById("cohSub");
  if (cv) {
    cv.textContent = coh.ok === false ? "⚠️ Incoherente" : coh.ok === true ? "✓ OK" : "—";
    cv.style.color = coh.ok === false ? "var(--bad)" : coh.ok === true ? "var(--good)" : "var(--muted)";
  }
  if (cs) cs.textContent = (coh.issues && coh.issues.length) ? coh.issues.join(" · ")
    : (coh.system_timezone ? `SO: ${coh.system_timezone} · IP: ${coh.ip_timezone || "?"}` : "");
}

// ── Estado del túnel ─────────────────────────────────────
function renderTunnel(d) {
  const t = d.tunnel || {};
  const badge = document.getElementById("tunnelBadge");
  const detail = document.getElementById("tunnelDetail");
  if (!badge) return;
  // Ubicación actual legible: "Florida, Estados Unidos" (sin exponer la IP, que rota).
  const here = [t.current?.region, t.current?.country].filter(Boolean).join(", ")
    || t.current?.country_code || "ubicación desconocida";
  const scopeLabel = { country: "país", region: "estado/región", strict: "IP exacta" }[t.scope] || "país";

  if (!t.pinned) {
    badge.textContent = "Sin fijar";
    badge.className = "chip warn";
    if (detail) detail.textContent = `Ahora en ${here}. Fija el estado actual para vigilar caídas de túnel.`;
    return;
  }
  if (t.ok) {
    badge.textContent = "✓ Protegido";
    badge.className = "chip good";
    if (detail) {
      detail.textContent =
        `Ahora en ${here} · vigilando ${scopeLabel} (${t.expected?.country_code || "?"}). ` +
        `Rotar de IP dentro del mismo ${scopeLabel} no genera alerta.`;
    }
  } else {
    badge.textContent = "⚠️ Cambió";
    badge.className = "chip bad";
    if (detail) detail.innerHTML = `Ahora en ${here}<br>` + (t.issues || []).map(s => `• ${s}`).join("<br>");
  }
}

// ── History ──────────────────────────────────────────────
async function loadHistory() {
  try {
    const offset = histPage * HIST_PER_PAGE;
    const d = await api(`/history?limit=${HIST_PER_PAGE}&offset=${offset}`);
    document.getElementById("histPage").textContent = histPage + 1;
    const container = document.getElementById("histList");
    if (!d.history?.length) {
      container.innerHTML = '<div style="color:var(--muted);font-size:12px;text-align:center;padding:10px">Sin registros</div>';
      return;
    }
    container.innerHTML = d.history.map(h => {
      const sc = typeof h.fraud_score === "number" ? h.fraud_score : null;
      const loc = [h.city, h.country].filter(Boolean).join(", ") || "—";
      return `<div class="hist-item">
        <div>
          <div class="hist-ip">${flag(h.country_code || "")} ${h.ip}</div>
          <div class="hist-loc">${loc} · ${h.org || "—"}</div>
        </div>
        <div>
          <div class="hist-score" style="color:${scoreColor(sc)}">${sc !== null ? sc + "/100" : "—"}</div>
          <div class="hist-time">${tsShort(h.ts)}</div>
        </div>
      </div>`;
    }).join("");
  } catch (e) {
    document.getElementById("histList").innerHTML = `<div style="color:var(--muted)">Error: ${e.message}</div>`;
  }
}

async function loadTrend() {
  try {
    const d = await api("/history/trend?days=7");
    drawTrendChart(d.trend || []);
    const last = d.trend?.[d.trend.length - 1];
    document.getElementById("trendHint").textContent = last
      ? `Último registro: ${last.ip} · Score: ${last.fraud_score ?? "?"} · ${tsShort(last.ts)}`
      : "Sin datos de tendencia";
  } catch (e) {
    document.getElementById("trendHint").textContent = "No se pudo cargar la tendencia";
  }
}

function drawTrendChart(data) {
  const svg = document.getElementById("trendChart");
  svg.innerHTML = "";
  if (!data.length) {
    svg.innerHTML = '<text x="180" y="45" text-anchor="middle" fill="rgba(255,255,255,.3)" font-size="12">Sin datos</text>';
    return;
  }
  const W = 360, H = 80, pad = 10;
  const scores = data.map(d => d.fraud_score ?? 0);
  const minS = 0, maxS = 100;
  const xStep = (W - pad * 2) / Math.max(data.length - 1, 1);

  const toX = (i) => pad + i * xStep;
  const toY = (s) => pad + (1 - (s - minS) / (maxS - minS)) * (H - pad * 2);

  // Grid lines
  [0, 20, 40, 60, 80, 100].forEach(v => {
    const y = toY(v);
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", pad); line.setAttribute("x2", W - pad);
    line.setAttribute("y1", y); line.setAttribute("y2", y);
    line.setAttribute("stroke", "rgba(255,255,255,.07)");
    line.setAttribute("stroke-width", "1");
    svg.appendChild(line);
  });

  // Threshold line at 40
  const tY = toY(40);
  const tLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
  tLine.setAttribute("x1", pad); tLine.setAttribute("x2", W - pad);
  tLine.setAttribute("y1", tY); tLine.setAttribute("y2", tY);
  tLine.setAttribute("stroke", "rgba(248,113,113,.4)");
  tLine.setAttribute("stroke-width", "1");
  tLine.setAttribute("stroke-dasharray", "4,3");
  svg.appendChild(tLine);

  // Area fill
  const points = data.map((d, i) => `${toX(i)},${toY(d.fraud_score ?? 0)}`);
  const areaPath = `M${points[0]} L${points.join(" L")} L${toX(data.length - 1)},${H - pad} L${pad},${H - pad} Z`;
  const area = document.createElementNS("http://www.w3.org/2000/svg", "path");
  area.setAttribute("d", areaPath);
  area.setAttribute("fill", "rgba(96,165,250,.1)");
  svg.appendChild(area);

  // Line
  const linePath = `M${points[0]} L${points.join(" L")}`;
  const lineEl = document.createElementNS("http://www.w3.org/2000/svg", "path");
  lineEl.setAttribute("d", linePath);
  lineEl.setAttribute("fill", "none");
  lineEl.setAttribute("stroke", "#60a5fa");
  lineEl.setAttribute("stroke-width", "2");
  lineEl.setAttribute("stroke-linejoin", "round");
  svg.appendChild(lineEl);

  // Dots
  data.forEach((d, i) => {
    const s = d.fraud_score ?? 0;
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", toX(i));
    circle.setAttribute("cy", toY(s));
    circle.setAttribute("r", "3.5");
    circle.setAttribute("fill", scoreColor(s));
    svg.appendChild(circle);
  });
}

async function loadStats() {
  try {
    const d = await api("/stats");
    document.getElementById("statTotal").textContent = d.total_records ?? "—";
    document.getElementById("statUnique").textContent = d.unique_ips ?? "—";
    document.getElementById("statAvg").textContent = d.avg_fraud_score !== null ? d.avg_fraud_score : "—";
    document.getElementById("statMax").textContent = d.max_fraud_score ?? "—";
  } catch { /* silencioso */ }
}

// ── Speedtest ────────────────────────────────────────────
let speedtestRunning = false;

async function runSpeedtest() {
  if (speedtestRunning) return;
  speedtestRunning = true;
  const btn = document.getElementById("btnSpeedtest");
  btn.textContent = "⏳ Ejecutando... (~1 min)";
  btn.disabled = true;
  document.getElementById("spErrorBox").style.display = "none";
  ["spPing","spDown","spUp"].forEach(id => { document.getElementById(id).textContent = "..."; });
  document.getElementById("spServer").textContent = "Conectando con servidor...";

  try {
    const d = await api("/speedtest");
    if (d.ok) {
      document.getElementById("spPing").textContent = d.ping ?? "—";
      document.getElementById("spDown").textContent = d.download ?? "—";
      document.getElementById("spUp").textContent = d.upload ?? "—";
      document.getElementById("spServer").textContent = [d.server, d.sponsor].filter(Boolean).join(" · ") || "—";
      toast("Speedtest completado");
      loadSpeedHistory();
    } else {
      // Mostrar box de instalación si es que falta speedtest-cli
      const errorMsg = d.error || "Error en speedtest";
      if (errorMsg.includes("no encontrado") || errorMsg.includes("not found") || errorMsg.includes("No such file")) {
        document.getElementById("spErrorBox").style.display = "block";
      }
      document.getElementById("spServer").textContent = errorMsg;
      ["spPing","spDown","spUp"].forEach(id => { document.getElementById(id).textContent = "—"; });
      toast(errorMsg, true);
    }
  } catch (e) {
    toast("Error: " + e.message, true);
    document.getElementById("spServer").textContent = "Error de conexión con el agente";
    ["spPing","spDown","spUp"].forEach(id => { document.getElementById(id).textContent = "—"; });
  }
  speedtestRunning = false;
  btn.textContent = "▶ Iniciar Speedtest";
  btn.disabled = false;
}

async function loadSpeedHistory() {
  try {
    const d = await api("/speedtest/history");
    const list = document.getElementById("speedHistList");
    if (!d.history?.length) {
      list.innerHTML = '<div style="color:var(--muted);font-size:12px;text-align:center;padding:10px">Sin historial</div>';
      return;
    }
    list.innerHTML = d.history.map(h => `
      <div class="hist-item">
        <div>
          <div style="font-size:12px;font-weight:700">↓ ${h.download ?? "?"}  ↑ ${h.upload ?? "?"}  Mbps</div>
          <div style="font-size:11px;color:var(--muted)">${h.server || "—"} · IP: ${h.ip || "?"}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:13px;font-weight:800;color:var(--accent)">${h.ping ?? "?"}ms</div>
          <div style="font-size:10px;color:var(--muted)">${tsShort(h.ts)}</div>
        </div>
      </div>`).join("");
  } catch { /* silencioso */ }
}

// ── Automation ───────────────────────────────────────────
async function loadAutomation() {
  try {
    const cfg = await api("/config");
    const hooks = cfg.config?.webhooks || [];
    document.getElementById("webhookList").innerHTML = hooks.length
      ? hooks.map(h => `<div style="font-family:monospace;font-size:11px;padding:3px 0;border-bottom:1px solid var(--line2)">${h}</div>`).join("")
      : '<div style="color:var(--muted)">Sin webhooks configurados</div>';

    const sched = cfg.config?.scheduler || [];
    document.getElementById("schedulerList").innerHTML = sched.length
      ? sched.map(t => `<div style="padding:5px 0;border-bottom:1px solid var(--line2)">
          <strong>${t.name}</strong> · ${t.action} · cada ${t.every_seconds}s
        </div>`).join("")
      : '<div style="color:var(--muted)">Sin tareas programadas</div>';
  } catch { /* silencioso */ }

  // Scheduler log
  try {
    const d = await api("/scheduler/log?limit=10");
    document.getElementById("schedulerLog").innerHTML = d.log?.length
      ? d.log.map(r => `<div style="padding:4px 0;border-bottom:1px solid var(--line2)">
          <span style="color:${r.success ? "var(--good)" : "var(--bad)"}">${r.success ? "✓" : "✗"}</span>
          ${r.task_name} · ${r.action} · <span style="color:var(--muted)">${tsShort(r.ts)}</span>
        </div>`).join("")
      : '<div style="color:var(--muted)">Sin registros</div>';
  } catch { /* silencioso */ }
}

// ── Logs ─────────────────────────────────────────────────
async function loadLogs() {
  try {
    const d = await api("/logs?limit=150");
    document.getElementById("logBox").textContent = d.logs?.length
      ? d.logs.join("\n")
      : "Sin logs recientes.";
    document.getElementById("logBox").scrollTop = 0;
  } catch {
    document.getElementById("logBox").textContent = "Error conectando con el agente.";
  }
}

async function loadWebhookLog() {
  try {
    const d = await api("/webhook/log?limit=15");
    document.getElementById("webhookLog").innerHTML = d.log?.length
      ? d.log.map(r => `<div style="padding:4px 0;border-bottom:1px solid var(--line2);font-size:11px">
          <span style="color:${r.success ? "var(--good)" : "var(--bad)"}">${r.success ? "✓" : "✗"}</span>
          ${r.event_type} → <span style="font-family:monospace">${r.url}</span>
          <span style="color:var(--muted)"> [${r.status_code}] ${tsShort(r.ts)}</span>
        </div>`).join("")
      : '<div style="color:var(--muted)">Sin registros</div>';
  } catch { /* silencioso */ }
}

// ── Notification settings ────────────────────────────────
async function refreshVoiceStatus() {
  const el = document.getElementById("voiceStatus");
  if (!el) return;
  try {
    const response = await chrome.runtime.sendMessage({ type: "GET_VOICE_STATUS" });
    const status = response?.status || {};
    const state = status.state || "IDLE";
    const queued = Number(status.queued || 0);
    const suffix = status.lastError ? ` — Error: ${status.lastError}` :
      status.lastEvent ? ` — ${status.lastEvent}` : "";
    el.textContent = `Voz: ${state}${queued ? ` | Cola: ${queued}` : ""}${suffix}`;
    el.style.color = state === "ERROR" ? "#f87171" : state === "SPEAKING" ? "#fbbf24" : "var(--muted)";
  } catch (error) {
    el.textContent = `Voz: sin respuesta — ${error.message}`;
    el.style.color = "#f87171";
  }
}

async function loadNotifSettings() {
  const { notificationsEnabled = true, intervalSeconds = 60, ttsEnabled = true } =
    await chrome.storage.sync.get({ notificationsEnabled: true, intervalSeconds: 60, ttsEnabled: true });
  toggleSwitch("swNotif", notificationsEnabled);
  toggleSwitch("swTts", ttsEnabled);
  document.getElementById("notifInterval").value = intervalSeconds;
}

function toggleSwitch(id, state) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle("on", !!state);
}

function isSwitchOn(id) {
  return document.getElementById(id)?.classList.contains("on");
}

// ── Actions ──────────────────────────────────────────────
async function sendClientInfo() {
  try {
    const ua = navigator.userAgent;
    let browser = "Unknown";
    if (ua.includes("Chrome") && !ua.includes("Edg")) browser = "Chrome";
    else if (ua.includes("Firefox")) browser = "Firefox";
    else if (ua.includes("Edg")) browser = "Edge";
    const vm = ua.match(/(Chrome|Firefox|Edg|Safari)\/(\d+)/);
    const version = vm ? vm[2] : "";
    let timezone = "";
    try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { /* noop */ }
    const payload = {
      ua,
      browser: version ? `${browser} ${version}` : browser,
      language: navigator.language || "",
      languages: Array.isArray(navigator.languages) ? navigator.languages.slice(0, 6) : [],
      timezone,
    };
    // WebRTC lo mide el navegador; lo enviamos para el score de riesgo bancario.
    try {
      const wr = await testWebRTCLeak();
      payload.webrtc = { leak: !!wr.leak, ip: wr.ip || null, reason: wr.reason || null };
    } catch { /* silencioso */ }
    await api("/client", "POST", payload);
  } catch { /* silencioso */ }
}

function isPrivateIP(ip) {
  // IPs privadas/locales — NO son leak, son normales
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fc|fd)/.test(ip);
}

async function testWebRTCLeak() {
  // Obtener IP pública actual para comparar
  let publicIP = null;
  try {
    const d = await api("/status");
    publicIP = d.ip || null;
  } catch { /* sin agente, comparamos solo contra privadas */ }

  return new Promise(resolve => {
    const pc = new RTCPeerConnection({ iceServers: [] });
    const ipsFound = [];
    pc.createDataChannel("");
    pc.createOffer().then(o => pc.setLocalDescription(o));
    pc.onicecandidate = e => {
      if (e.candidate) {
        const m = /([0-9]{1,3}\.){3}[0-9]{1,3}/.exec(e.candidate.candidate);
        if (m) {
          const ip = m[0];
          if (!ipsFound.includes(ip)) ipsFound.push(ip);
          // Solo es leak real si es la IP pública o una IP no-privada desconocida
          if (publicIP && ip === publicIP) {
            resolve({ leak: true, ip, reason: "IP pública real expuesta" });
          }
        }
      } else {
        // Sin más candidatos — revisar si alguna no-privada apareció
        const nonPrivate = ipsFound.filter(ip => !isPrivateIP(ip));
        if (nonPrivate.length > 0 && !publicIP) {
          resolve({ leak: true, ip: nonPrivate[0], reason: "IP no-privada detectada" });
        } else {
          // Solo IPs locales (192.168.x.x, 10.x.x.x) — esto es NORMAL con mDNS activo
          resolve({ leak: false, ips: ipsFound });
        }
      }
    };
    setTimeout(() => {
      const nonPrivate = ipsFound.filter(ip => !isPrivateIP(ip));
      if (nonPrivate.length > 0) {
        resolve({ leak: true, ip: nonPrivate[0], reason: "IP no-privada detectada" });
      } else {
        resolve({ leak: false, ips: ipsFound });
      }
    }, 3000);
  });
}

async function exportJSON() {
  try {
    const [status, history] = await Promise.all([api("/status"), api("/history?limit=200")]);
    const blob = new Blob([JSON.stringify({ status, history, exportTime: Date.now() }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const d = new Date();
    const ts2 = `${d.getFullYear()}-${d.getMonth()+1}-${d.getDate()}_${d.getHours()}-${d.getMinutes()}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = `ipwatch_${ts2}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Export iniciado");
  } catch (e) {
    toast("Error exportando: " + e.message, true);
  }
}

async function rotateIP() {
  toast("Solicitando rotación de IP...");
  try {
    const d = await api("/rotate_ip", "POST");
    if (d.ok) {
      toast("✓ " + (d.message || "IP rotada"));
    } else {
      const isConfigError = d.error?.includes("no configurado") || d.error?.includes("Configuración");
      if (isConfigError) {
        toast("⚙️ StarVPN: configurá email y token en Opciones (clic derecho → Opciones)", true);
      } else {
        toast("✗ " + (d.error || "Error"), true);
      }
    }
  } catch (e) {
    toast("Error: " + e.message, true);
  }
}

// ── Tab system ───────────────────────────────────────────
const tabLoaders = {
  dash: loadDash,
  history: async () => { await Promise.all([loadHistory(), loadTrend(), loadStats()]); },
  speed: async () => {
    // Chequear si speedtest-cli está disponible
    try {
      const d = await api("/speedtest/history");
      document.getElementById("spErrorBox").style.display = "none";
    } catch { /* silencioso */ }
    await loadSpeedHistory();
  },
  auto: async () => { await loadAutomation(); await loadNotifSettings(); },
  logs: async () => { await Promise.all([loadLogs(), loadWebhookLog()]); }
};

let currentTab = "dash";

function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === `tab-${name}`));
  currentTab = name;
  if (tabLoaders[name]) tabLoaders[name]();
}

// ── Init ─────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Tab clicks
  document.querySelectorAll(".tab").forEach(t => {
    t.addEventListener("click", () => switchTab(t.dataset.tab));
  });

  // Dashboard buttons
  document.getElementById("statusPill").addEventListener("click", loadDash);
  document.getElementById("btnRefresh").addEventListener("click", async () => {
    toast("Actualizando...");
    try { await api("/refresh", "POST"); setTimeout(loadDash, 1500); } catch (e) { toast(e.message, true); }
  });
  document.getElementById("btnToast").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "FORCE_TOAST" });
    toast("Toast enviado");
  });
  document.getElementById("btnWebRTC").addEventListener("click", async () => {
    const result = await testWebRTCLeak();
    if (result.leak) {
      toast(`⚠️ Fuga WebRTC real: ${result.ip} — ${result.reason}`, true);
    } else {
      const localNote = result.ips?.length
        ? ` (IPs locales normales: ${result.ips.join(", ")})`
        : "";
      toast(`✅ Sin fuga WebRTC${localNote}`, false);
    }
  });
  document.getElementById("btnExport").addEventListener("click", exportJSON);
  document.getElementById("btnRotate").addEventListener("click", rotateIP);

  // Probar fugas (WebRTC en el navegador + refrescar análisis DNS del agente)
  document.getElementById("btnLeakTest").addEventListener("click", async () => {
    const wv = document.getElementById("webrtcVal");
    const ws = document.getElementById("webrtcSub");
    if (wv) { wv.textContent = "Probando..."; wv.style.color = "var(--muted)"; }
    const result = await testWebRTCLeak();
    if (wv) {
      if (result.leak) {
        wv.textContent = "⚠️ Fuga"; wv.style.color = "var(--bad)";
        if (ws) ws.textContent = `${result.ip} — ${result.reason}`;
      } else {
        wv.textContent = "✓ OK"; wv.style.color = "var(--good)";
        if (ws) ws.textContent = result.ips?.length ? `Locales: ${result.ips.join(", ")}` : "Sin fuga";
      }
    }
    // Forzar refresh del agente para recalcular DNS/coherencia
    try { await api("/refresh", "POST"); setTimeout(loadDash, 1500); } catch { /* silencioso */ }
  });

  // Vigilancia de túnel
  document.getElementById("btnTunnelPin").addEventListener("click", async () => {
    try {
      const d = await api("/tunnel/pin", "POST");
      toast(d.ok ? "📌 Estado del túnel fijado" : "✗ " + (d.error || "Error"), !d.ok);
      loadDash();
    } catch (e) { toast(e.message, true); }
  });
  document.getElementById("btnTunnelClear").addEventListener("click", async () => {
    try {
      const d = await api("/tunnel/clear", "POST");
      toast(d.ok ? "Vigilancia de túnel limpiada" : "✗ Error", !d.ok);
      loadDash();
    } catch (e) { toast(e.message, true); }
  });
  // Guardar país esperado (para el score de riesgo bancario)
  document.getElementById("btnSaveCountry").addEventListener("click", async () => {
    const cc = (document.getElementById("expCountry").value || "").trim().toUpperCase();
    if (cc && !/^[A-Z]{2}$/.test(cc)) { toast("Usa un código ISO-2, p.ej. VE", true); return; }
    try {
      await api("/config", "POST", { expected_country: cc });
      toast(cc ? `País esperado: ${cc}` : "País esperado borrado (auto)");
      await api("/refresh", "POST");
      setTimeout(loadDash, 1500);
    } catch (e) { toast(e.message, true); }
  });
  document.getElementById("btnSyncTz").addEventListener("click", async () => {
    try {
      const d = await api("/set_timezone", "POST");
      toast(d.ok ? `✓ Timezone: ${d.result?.windows || "OK"}` : "✗ " + (d.error || "Error"), !d.ok);
    } catch (e) { toast(e.message, true); }
  });

  // History buttons
  document.getElementById("btnHistReload").addEventListener("click", loadHistory);
  document.getElementById("btnTrendReload").addEventListener("click", loadTrend);
  document.getElementById("btnHistPrev").addEventListener("click", () => {
    if (histPage > 0) { histPage--; loadHistory(); }
  });
  document.getElementById("btnHistNext").addEventListener("click", () => {
    histPage++; loadHistory();
  });

  // Speedtest
  document.getElementById("btnSpeedtest").addEventListener("click", runSpeedtest);
  document.getElementById("btnSpeedHist").addEventListener("click", loadSpeedHistory);

  // Automation
  document.getElementById("swNotif").addEventListener("click", () => {
    const next = !isSwitchOn("swNotif");
    toggleSwitch("swNotif", next);
    chrome.storage.sync.set({ notificationsEnabled: next });
    chrome.runtime.sendMessage({ type: "UPDATE_NOTIFICATION_SETTINGS" });
  });
  document.getElementById("swTts").addEventListener("click", () => {
    const next = !isSwitchOn("swTts");
    toggleSwitch("swTts", next);
    chrome.storage.sync.set({ ttsEnabled: next });
  });
  document.getElementById("btnSaveNotif").addEventListener("click", async () => {
    let v = parseInt(document.getElementById("notifInterval").value);
    if (isNaN(v)) v = 60;
    v = Math.max(15, Math.min(3600, v));
    document.getElementById("notifInterval").value = v;
    await chrome.storage.sync.set({ intervalSeconds: v });
    chrome.runtime.sendMessage({ type: "UPDATE_NOTIFICATION_SETTINGS" });
    toast(`Intervalo guardado: ${v}s`);
  });
  document.getElementById("btnTestNotif").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "FORCE_TOAST" });
    toast("Notificación enviada");
  });
  document.getElementById("btnTestVoice").addEventListener("click", async () => {
    const response = await chrome.runtime.sendMessage({
      type: "TEST_VOICE",
      text: "Prueba de voz de IP Watch. El sistema de voz está funcionando correctamente."
    });
    toast(response?.ok ? "Prueba de voz enviada" : `Error de voz: ${response?.error || "desconocido"}`, !response?.ok);
    setTimeout(refreshVoiceStatus, 250);
  });
  document.getElementById("btnResetStream").addEventListener("click", async () => {
    chrome.runtime.sendMessage({ type: "RESET_EVENT_STREAM" });
    toast("Stream de eventos reseteado");
  });
  document.getElementById("btnRotate2").addEventListener("click", rotateIP);

  // Logs
  document.getElementById("btnClearLogs").addEventListener("click", loadLogs);

  // Messages from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "IP_CHANGED" && currentTab === "dash") {
      setTimeout(loadDash, 500);
    }
    if (msg.type === "VOICE_STATUS") {
      refreshVoiceStatus();
    }
  });

  refreshVoiceStatus();
  setInterval(refreshVoiceStatus, 3000);

  // Initial load
  sendClientInfo();
  loadDash();
  loadNotifSettings();

  // Auto-refresh every 10s on active tab
  setInterval(() => {
    if (currentTab === "dash") loadDash();
    else if (currentTab === "logs") loadLogs();
  }, 10000);
});
