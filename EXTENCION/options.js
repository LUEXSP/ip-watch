const AGENT = "http://127.0.0.1:8790";

async function api(path, method = "GET", body = null) {
  const headers = await getIPWatchHeaders();
  const opts = { method, cache: "no-store", headers };
  if (body) { opts.body = JSON.stringify(body); opts.headers["Content-Type"] = "application/json"; }
  const r = await fetch(`${AGENT}${path}`, opts);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function loadLocalTokenField() {
  const token = await getIPWatchToken();
  const el = document.getElementById("localAuthToken");
  if (el) el.value = token || "";
}

async function saveLocalTokenField() {
  const token = document.getElementById("localAuthToken")?.value.trim() || "";
  await saveIPWatchToken(token);
  msg("✓ Token local guardado en la extensión");
}

function msg(text, isErr = false) {
  const el = document.getElementById("msg");
  el.textContent = text;
  el.className = isErr ? "err" : "ok";
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 5000);
}

function sw(id, on) {
  document.getElementById(id)?.classList.toggle("on", !!on);
}
function isSw(id) {
  return document.getElementById(id)?.classList.contains("on");
}

let currentConfig = {};
let webhooks = [];

async function loadConfig() {
  try {
    const d = await api("/config");
    currentConfig = d.config || {};
    webhooks = [...(currentConfig.webhooks || [])];

    // Fill fields
    document.getElementById("abuseKey").value = currentConfig.abuseipdb_api_key || "";
    document.getElementById("ipqsKey").value = currentConfig.ipqualityscore_api_key || "";
    document.getElementById("ipqsStrictness").value = currentConfig.ipqualityscore_strictness ?? 1;
    document.getElementById("scamUser").value = currentConfig.scamalytics_user || "";
    document.getElementById("scamKey").value = currentConfig.scamalytics_api_key || "";
    document.getElementById("starEmail").value = currentConfig.starvpn_email || "";
    document.getElementById("starToken").value = currentConfig.starvpn_token || "";
    document.getElementById("checkInterval").value = currentConfig.check_interval_seconds || 120;
    document.getElementById("fraudThreshold").value = currentConfig.notify_on_fraud_above ?? 40;
    document.getElementById("scriptPath").value = currentConfig.script_on_ip_change || "";
    document.getElementById("expCountry").value = (currentConfig.expected_country || "").toUpperCase();
    document.getElementById("tunnelScope").value = currentConfig.tunnel_watch_scope || "country";
    sw("swAutoTz", currentConfig.auto_tz);
    sw("swTunnel", currentConfig.using_tunnel);

    renderWebhooks();
    renderScheduler();
  } catch (e) {
    msg("No se pudo conectar con el agente: " + e.message, true);
  }
}

function renderWebhooks() {
  const el = document.getElementById("webhookList");
  if (!webhooks.length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:4px 0">Sin webhooks configurados.</div>';
    return;
  }
  el.innerHTML = webhooks.map((url, i) => `
    <div class="webhook-item">
      <span>${url}</span>
      <button class="btn danger" data-idx="${i}" style="padding:4px 10px;font-size:12px" onclick="removeWebhook(${i})">✕</button>
    </div>
  `).join("");
}

function renderScheduler() {
  const el = document.getElementById("schedList");
  const sched = currentConfig.scheduler || [];
  if (!sched.length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:13px">Sin tareas programadas. Agrégatelas editando el JSON.</div>';
    return;
  }
  el.innerHTML = sched.map(t => `
    <div class="sched-item">
      <strong>${t.name}</strong>
      <span class="tag">${t.action}</span>
      <span style="color:var(--muted);font-size:12px"> · cada ${t.every_seconds}s</span>
    </div>
  `).join("");
}

window.removeWebhook = function(idx) {
  webhooks.splice(idx, 1);
  renderWebhooks();
};

async function saveConfig() {
  const cc = (document.getElementById("expCountry").value || "").trim().toUpperCase();
  if (cc && !/^[A-Z]{2}$/.test(cc)) {
    msg("País esperado inválido. Usa un código ISO-2, p.ej. VE", true);
    return;
  }
  const newCfg = {
    abuseipdb_api_key: document.getElementById("abuseKey").value.trim(),
    ipqualityscore_api_key: document.getElementById("ipqsKey").value.trim(),
    ipqualityscore_strictness: parseInt(document.getElementById("ipqsStrictness").value) || 1,
    scamalytics_user: document.getElementById("scamUser").value.trim(),
    scamalytics_api_key: document.getElementById("scamKey").value.trim(),
    starvpn_email: document.getElementById("starEmail").value.trim(),
    starvpn_token: document.getElementById("starToken").value.trim(),
    check_interval_seconds: parseInt(document.getElementById("checkInterval").value) || 120,
    notify_on_fraud_above: parseInt(document.getElementById("fraudThreshold").value) ?? 40,
    script_on_ip_change: document.getElementById("scriptPath").value.trim(),
    expected_country: cc,
    tunnel_watch_scope: document.getElementById("tunnelScope").value || "country",
    using_tunnel: isSw("swTunnel"),
    auto_tz: isSw("swAutoTz"),
    webhooks: webhooks
  };
  try {
    const d = await api("/config", "POST", newCfg);
    if (d.ok) {
      currentConfig = d.config;
      msg("✓ Configuración guardada correctamente");
    } else {
      msg("Error guardando: " + (d.error || "desconocido"), true);
    }
  } catch (e) {
    msg("Error: " + e.message, true);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadLocalTokenField();
  document.getElementById("btnSaveLocalToken")?.addEventListener("click", async () => {
    await saveLocalTokenField();
    await loadConfig();
  });
  loadConfig();

  document.getElementById("swAutoTz").addEventListener("click", () => {
    document.getElementById("swAutoTz").classList.toggle("on");
  });

  document.getElementById("swTunnel").addEventListener("click", () => {
    document.getElementById("swTunnel").classList.toggle("on");
  });

  document.getElementById("btnAddWebhook").addEventListener("click", () => {
    const url = document.getElementById("newWebhook").value.trim();
    if (!url || !url.startsWith("http")) {
      msg("URL inválida. Debe empezar con http:// o https://", true);
      return;
    }
    if (webhooks.includes(url)) { msg("Este webhook ya existe", true); return; }
    webhooks.push(url);
    document.getElementById("newWebhook").value = "";
    renderWebhooks();
  });

  document.getElementById("btnTestWebhook").addEventListener("click", async () => {
    if (!webhooks.length) { msg("No hay webhooks configurados", true); return; }
    try {
      const d = await api("/webhook/test", "POST", { url: webhooks[0] });
      msg(d.ok ? "✓ Webhook de prueba enviado" : "✗ " + (d.error || "Error"), !d.ok);
    } catch (e) {
      msg("Error: " + e.message, true);
    }
  });

  document.getElementById("btnSave").addEventListener("click", saveConfig);
  document.getElementById("btnReload").addEventListener("click", loadConfig);
});
