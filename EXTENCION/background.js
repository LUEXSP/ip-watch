importScripts("auth.js");
const AGENT = "http://127.0.0.1:8790";
const POLL_MS = 5000;
let periodicInterval = null;
let eventLoopStarted = false;
let eventPollRunning = false;

// ── Voice Engine v2 ─────────────────────────────────────
const voiceQueue = [];
let voiceSpeaking = false;
let voiceRetryTimer = null;
let voiceStatus = {
  state: "IDLE",
  queued: 0,
  lastText: "",
  lastEvent: "",
  lastError: "",
  updatedAt: 0
};

async function persistVoiceStatus(patch = {}) {
  voiceStatus = { ...voiceStatus, ...patch, queued: voiceQueue.length, updatedAt: Date.now() };
  try {
    await chrome.storage.local.set({ ipWatchVoiceStatus: voiceStatus });
    chrome.runtime.sendMessage({ type: "VOICE_STATUS", status: voiceStatus }).catch(() => {});
  } catch (_) {}
}

function isTerminalVoiceEvent(type) {
  return ["end", "interrupted", "cancelled", "error"].includes(type);
}

// Windows suele traer solo voces en inglés: pedir lang "es-ES" sin voz española
// instalada deja el TTS en silencio. Elegimos una voz que exista de verdad.
function listVoices() {
  return new Promise(resolve => {
    try {
      chrome.tts.getVoices(v => resolve(Array.isArray(v) ? v : []));
    } catch (_) {
      resolve([]);
    }
  });
}

async function pickVoice(preferredLang = "es-ES") {
  const voices = await listVoices();
  const names = voices.map(v => `${v.voiceName || "?"} (${v.lang || "?"})`);
  if (!voices.length) return { chosen: null, match: "no_voices", names };

  const want = String(preferredLang).toLowerCase();
  const base = want.split("-")[0];
  const exact = voices.find(v => (v.lang || "").toLowerCase() === want);
  const sameLang = voices.find(v => (v.lang || "").toLowerCase().startsWith(base));
  const chosen = exact || sameLang || voices[0];
  return {
    chosen,
    match: exact ? "exact" : sameLang ? "same_language" : "other_language",
    names
  };
}

function speakOptions(pick, item) {
  const opts = {
    rate: Number(item.rate || 0.9),
    pitch: 1,
    volume: 1,
    enqueue: false
  };
  // Si hay una voz concreta, la fijamos: mezclar lang con una voz de otro idioma falla.
  if (pick.chosen?.voiceName) opts.voiceName = pick.chosen.voiceName;
  else opts.lang = item.lang || "es-ES";
  return opts;
}

async function processVoiceQueue() {
  if (voiceSpeaking || voiceQueue.length === 0) {
    await persistVoiceStatus();
    return;
  }

  const item = voiceQueue.shift();
  voiceSpeaking = true;
  await persistVoiceStatus({
    state: "SPEAKING",
    lastText: item.text,
    lastEvent: "starting",
    lastError: ""
  });

  const pick = await pickVoice(item.lang || "es-ES");
  if (!pick.chosen) {
    voiceSpeaking = false;
    await persistVoiceStatus({
      state: "ERROR",
      lastEvent: "no_voices",
      lastError: "El sistema no tiene ninguna voz TTS instalada."
    });
    return;
  }
  await persistVoiceStatus({
    voice: pick.chosen.voiceName || "",
    voiceLang: pick.chosen.lang || "",
    voiceMatch: pick.match
  });

  try {
    chrome.tts.speak(item.text, {
      ...speakOptions(pick, item),
      onEvent: async (event) => {
        const type = event?.type || "unknown";
        await persistVoiceStatus({
          lastEvent: type,
          lastError: type === "error" ? (event?.errorMessage || "TTS error") : ""
        });

        if (!isTerminalVoiceEvent(type)) return;

        voiceSpeaking = false;

        if (type === "error" && item.retries < 1) {
          voiceQueue.unshift({ ...item, retries: item.retries + 1 });
          await persistVoiceStatus({ state: "RETRYING" });
          clearTimeout(voiceRetryTimer);
          voiceRetryTimer = setTimeout(processVoiceQueue, 500);
          return;
        }

        await persistVoiceStatus({ state: voiceQueue.length ? "QUEUED" : "IDLE" });
        setTimeout(processVoiceQueue, 150);
      }
    });
  } catch (error) {
    voiceSpeaking = false;
    await persistVoiceStatus({ state: "ERROR", lastEvent: "exception", lastError: error.message });
    setTimeout(processVoiceQueue, 300);
  }
}

async function enqueueVoice(text, options = {}) {
  const clean = String(text || "").trim();
  if (!clean) return { ok: false, error: "Texto vacío" };

  // Evita repetir exactamente el mismo anuncio si el evento llega duplicado.
  const duplicate = voiceQueue.some(item => item.text === clean) ||
    (voiceSpeaking && voiceStatus.lastText === clean);
  if (duplicate) {
    await persistVoiceStatus({ lastEvent: "duplicate_skipped" });
    return { ok: true, skipped: true };
  }

  // Mantiene una cola corta; para cambios rápidos interesa anunciar lo más reciente.
  if (voiceQueue.length >= 5) voiceQueue.shift();
  voiceQueue.push({
    text: clean,
    lang: options.lang || "es-ES",
    rate: options.rate || 0.9,
    retries: 0
  });
  await persistVoiceStatus({ state: voiceSpeaking ? "QUEUED" : "READY", lastEvent: "queued" });
  processVoiceQueue();
  return { ok: true, queued: voiceQueue.length };
}

// Prueba real: resuelve cuando el motor TTS termina o falla, no cuando se encola.
// Antes devolvía "ok" al encolar, así que el popup salía en verde aunque no sonara nada.
async function testVoice(text) {
  const pick = await pickVoice("es-ES");
  if (!pick.chosen) {
    return {
      ok: false,
      error: "El sistema no tiene ninguna voz TTS instalada (instala un paquete de voz en Windows).",
      voices: pick.names
    };
  }

  await stopVoice(true);
  const info = { voice: pick.chosen.voiceName || "", lang: pick.chosen.lang || "", match: pick.match, voices: pick.names };

  return new Promise(resolve => {
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      persistVoiceStatus({
        state: result.ok ? "IDLE" : "ERROR",
        lastEvent: result.ok ? "test_end" : "test_failed",
        lastError: result.ok ? "" : result.error,
        voice: info.voice,
        voiceLang: info.lang,
        voiceMatch: info.match
      });
      resolve({ ...info, ...result });
    };
    const timer = setTimeout(() => finish({
      ok: false,
      error: "El motor TTS no respondió. Revisa el volumen del sistema y la salida de audio."
    }), 15000);

    try {
      chrome.tts.speak(text, {
        ...speakOptions(pick, { rate: 0.9 }),
        onEvent: (event) => {
          const type = event?.type;
          if (type === "error") {
            finish({ ok: false, error: event?.errorMessage || "Error del motor TTS" });
          } else if (type === "end") {
            finish({ ok: true, spoke: true });
          } else if (type === "interrupted" || type === "cancelled") {
            finish({ ok: false, error: `Reproducción ${type} por otra app o pestaña` });
          }
        }
      });
    } catch (error) {
      finish({ ok: false, error: error.message });
    }
  });
}

async function stopVoice(clearQueue = true) {
  clearTimeout(voiceRetryTimer);
  if (clearQueue) voiceQueue.length = 0;
  voiceSpeaking = false;
  try { chrome.tts.stop(); } catch (_) {}
  await persistVoiceStatus({ state: "IDLE", lastEvent: "stopped", lastError: "" });
}

// ── Badge ────────────────────────────────────────────────
async function updateBadge() {
  try {
    const data = await fetchJSON(`${AGENT}/status`);
    const score = data.fraud?.fraud_score;
    const text = (score !== undefined && score !== null) ? String(score) : "?";
    const color = score >= 40 ? "#fb7185" : score >= 20 ? "#fbbf24" : "#2dd4bf";
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
  } catch {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#6b7280" });
  }
}

// ── Toast notification ───────────────────────────────────
async function showToast() {
  try {
    const data = await fetchJSON(`${AGENT}/status`);
    const ip = data.ip || "?";
    const score = data.fraud?.fraud_score ?? "?";
    const risk = data.fraud?.risk || "?";
    const city = data.profile?.city || "";
    const region = data.profile?.region || "";
    const country = data.profile?.country || "";
    const location = [city, region, country].filter(Boolean).join(", ") || "Ubicación desconocida";
    const proxy = data.privacy?.proxy?.enabled === true ? " | Proxy: ON" : "";
    const abuse = data.abuseipdb?.score !== undefined ? ` | Abuse: ${data.abuseipdb.score}` : "";

    const id = `toast_${Date.now()}`;
    chrome.notifications.create(id, {
      type: "basic",
      iconUrl: "icon128.png",
      title: `IP Watch — ${ip}`,
      message: `Fraude: ${score}/100 (${risk})\n${location}${proxy}${abuse}`,
      priority: 0,
      requireInteraction: false
    });
    setTimeout(() => chrome.notifications.clear(id), 8000);
  } catch {
    // Agente no disponible — silencioso, es esperado al arrancar
  }
}

// ── IP Change notification (con TTS) ────────────────────
async function notifyIPChange(payload) {
  const ip = payload.ip || "?";
  const score = payload.fraud?.fraud_score ?? "?";
  const risk = payload.fraud?.risk || "?";
  const city = payload.profile?.city || "";
  const region = payload.profile?.region || "";
  const country = payload.profile?.country || "";
  const countryCode = (payload.profile?.country_code || "").toUpperCase();
  const abuseScore = payload.abuseipdb?.score ?? null;

  // Un exit residencial rota de IP sin que nada se rompa: solo avisamos cuando cambia
  // la ubicación relevante según el alcance configurado (por defecto, el país).
  const scope = payload.tunnel?.scope || "country";
  const prev = await chrome.storage.local.get({ lastAnnouncedCountry: "", lastAnnouncedRegion: "" });
  const countryChanged = Boolean(countryCode) && Boolean(prev.lastAnnouncedCountry)
    && countryCode !== prev.lastAnnouncedCountry;
  const regionChanged = Boolean(region) && Boolean(prev.lastAnnouncedRegion)
    && region !== prev.lastAnnouncedRegion;
  const firstRun = !prev.lastAnnouncedCountry;

  let shouldNotify;
  if (scope === "strict") shouldNotify = true;
  else if (scope === "region") shouldNotify = firstRun || countryChanged || regionChanged;
  else shouldNotify = firstRun || countryChanged;

  // Siempre guardamos la ubicación y la IP para no re-anunciar y para el badge.
  await chrome.storage.local.set({
    lastAnnouncedIp: ip,
    lastAnnouncedAt: Date.now(),
    lastAnnouncedCountry: countryCode || prev.lastAnnouncedCountry,
    lastAnnouncedRegion: region || prev.lastAnnouncedRegion
  });

  // Mandar al popup si está abierto (siempre: la UI debe reflejar la IP nueva).
  chrome.runtime.sendMessage({ type: "IP_CHANGED", payload }).catch(() => {});

  if (!shouldNotify) return;

  const where = [region, country].filter(Boolean).join(", ") || countryCode || "ubicación desconocida";
  let msg = `Ahora en ${where}`;
  if (city) msg += ` (${city})`;
  msg += `\nFraude: ${score}/100 (${risk})`;
  if (abuseScore !== null) msg += ` · AbuseIPDB: ${abuseScore}/100`;

  const id = `change_${Date.now()}`;
  chrome.notifications.create(id, {
    type: "basic",
    iconUrl: "icon128.png",
    title: `📍 Ubicación de salida: ${where}`,
    message: msg,
    priority: 2,
    requireInteraction: false
  });
  setTimeout(() => chrome.notifications.clear(id), 10000);

  // TTS — Voice Engine v2: cola, deduplicación, retry y diagnóstico.
  const { ttsEnabled = true } = await chrome.storage.sync.get({ ttsEnabled: true });
  if (ttsEnabled) {
    await enqueueVoice(
      `Tu salida ahora es ${where}. Puntuación de fraude ${score}.`,
      { lang: "es-ES", rate: 0.9 }
    );
  }
}

// ── Tunnel alert (kill-switch informativo, con TTS) ──────
async function notifyTunnelAlert(payload) {
  const issues = Array.isArray(payload?.issues) ? payload.issues : [];
  const cur = payload?.current || {};
  const where = [cur.region, cur.country].filter(Boolean).join(", ") || cur.country_code || "";
  const id = `tunnel_${Date.now()}`;
  chrome.notifications.create(id, {
    type: "basic",
    iconUrl: "icon128.png",
    title: where ? `🛡️ Alerta de túnel — ahora en ${where}` : `🛡️ Alerta de túnel`,
    message: issues.length ? issues.join("\n") : "El estado protegido de tu IP cambió.",
    priority: 2,
    requireInteraction: true
  });

  const { ttsEnabled = true } = await chrome.storage.sync.get({ ttsEnabled: true });
  if (ttsEnabled) {
    await enqueueVoice(
      "Atención. El estado protegido de tu IP cambió. Posible caída de túnel.",
      { lang: "es-ES", rate: 0.95 }
    );
  }
  chrome.runtime.sendMessage({ type: "TUNNEL_ALERT", payload }).catch(() => {});
}

// ── High fraud alert ─────────────────────────────────────
function notifyHighFraud(payload) {
  const id = `fraud_${Date.now()}`;
  chrome.notifications.create(id, {
    type: "basic",
    iconUrl: "icon128.png",
    title: `⚠️ Alerta: Fraude alto detectado`,
    message: `IP: ${payload.ip}\nFraud score: ${payload.fraud_score} (umbral: ${payload.threshold})`,
    priority: 2,
    requireInteraction: true
  });
}

// ── Periodic notifications ───────────────────────────────
async function startPeriodic() {
  const { notificationsEnabled = true, intervalSeconds = 60 } =
    await chrome.storage.sync.get({ notificationsEnabled: true, intervalSeconds: 60 });
  if (periodicInterval) clearInterval(periodicInterval);
  if (notificationsEnabled) {
    periodicInterval = setInterval(showToast, intervalSeconds * 1000);
  }
}

// ── Fetch helper ─────────────────────────────────────────
async function fetchJSON(url) {
  const r = await fetch(url, { cache: "no-store", headers: await getIPWatchHeaders() });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── Event stream + fallback de IP actual ────────────────
async function processAgentEventsOnce() {
  if (eventPollRunning) return;
  eventPollRunning = true;

  try {
    const stored = await chrome.storage.local.get({
      lastEventId: 0,
      lastEventStreamId: "",
      lastAnnouncedIp: ""
    });

    let after = Number(stored.lastEventId || 0);
    let data = await fetchJSON(`${AGENT}/events?after=${after}`);

    // El agente crea un stream nuevo cada vez que reinicia. Si cambió,
    // el lastEventId anterior ya no es válido y hay que empezar desde cero.
    if (data.stream_id && data.stream_id !== stored.lastEventStreamId) {
      after = 0;
      await chrome.storage.local.set({
        lastEventId: 0,
        lastEventStreamId: data.stream_id
      });
      data = await fetchJSON(`${AGENT}/events?after=0`);
    }

    for (const ev of data.events || []) {
      after = Math.max(after, Number(ev.id || 0));

      if (ev.type === "IP_CHANGED") {
        const eventIp = ev.payload?.ip || "";
        const latest = await chrome.storage.local.get({ lastAnnouncedIp: "" });

        if (eventIp && eventIp !== latest.lastAnnouncedIp) {
          await notifyIPChange(ev.payload);
          await updateBadge();
        }
      } else if (ev.type === "HIGH_FRAUD_SCORE") {
        notifyHighFraud(ev.payload);
      } else if (ev.type === "TUNNEL_ALERT") {
        await notifyTunnelAlert(ev.payload);
      }
    }

    await chrome.storage.local.set({
      lastEventId: after,
      lastEventStreamId: data.stream_id || stored.lastEventStreamId || ""
    });
  } catch (error) {
    console.debug('[IP Watch] Event poll no disponible:', error?.message || error);
  } finally {
    eventPollRunning = false;
  }
}

async function verifyCurrentIpFallback() {
  try {
    const data = await fetchJSON(`${AGENT}/status`);
    const currentIp = String(data?.ip || "").trim();
    if (!currentIp) return;

    const stored = await chrome.storage.local.get({ lastAnnouncedIp: "" });

    // Primera ejecución: establecer referencia sin anunciar una falsa "IP cambiada".
    if (!stored.lastAnnouncedIp) {
      await chrome.storage.local.set({ lastAnnouncedIp: currentIp });
      return;
    }

    // Si el stream perdió el evento o el service worker estuvo suspendido,
    // esta comparación recupera el anuncio del cambio real.
    if (currentIp !== stored.lastAnnouncedIp) {
      await notifyIPChange(data);
      await updateBadge();
    }
  } catch (error) {
    console.debug('[IP Watch] Fallback IP no disponible:', error?.message || error);
  }
}

async function pollAgentNow() {
  await processAgentEventsOnce();
  await verifyCurrentIpFallback();
}

async function eventLoop() {
  if (eventLoopStarted) return;
  eventLoopStarted = true;

  while (true) {
    await pollAgentNow();
    await new Promise(resolve => setTimeout(resolve, POLL_MS));
  }
}

// ── Init ─────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  startPeriodic();
  chrome.alarms.create("keepalive", { periodInMinutes: 0.5 });
  // Dar 3s al agente para iniciar antes del primer chequeo
  setTimeout(() => { updateBadge(); showToast(); }, 3000);
  eventLoop();
});

chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create("keepalive", { periodInMinutes: 0.5 });
  startPeriodic();
  setTimeout(updateBadge, 2000);
  eventLoop();
});

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "keepalive") {
    updateBadge();
    pollAgentNow();
    (async () => {
      try {
        await fetch(`${AGENT}/health`, { headers: await getIPWatchHeaders() });
      } catch (_) {}
    })();
  }
});

// ── Messages from popup / options ────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "UPDATE_NOTIFICATION_SETTINGS") {
    startPeriodic();
    sendResponse({ ok: true });
  }
  if (msg.type === "FORCE_TOAST") {
    showToast();
    sendResponse({ ok: true });
  }
  if (msg.type === "RESET_EVENT_STREAM") {
    chrome.storage.local.set({ lastEventId: 0, lastEventStreamId: "" });
    sendResponse({ ok: true });
  }
  if (msg.type === "SHOW_NOTIFICATION") {
    const id = `manual_${Date.now()}`;
    chrome.notifications.create(id, {
      type: "basic",
      iconUrl: "icon128.png",
      title: msg.title || "IP Watch",
      message: msg.message || "",
      priority: msg.priority || 1,
      requireInteraction: msg.sticky || false
    });
    setTimeout(() => chrome.notifications.clear(id), msg.duration || 8000);
    sendResponse({ ok: true });
  }
  if (msg.type === "TEST_VOICE") {
    testVoice(msg.text || "Prueba de voz de IP Watch. El sistema de voz está funcionando.")
      .then(sendResponse)
      .catch(error => sendResponse({ ok: false, error: error.message }));
  }
  if (msg.type === "LIST_VOICES") {
    listVoices()
      .then(voices => sendResponse({
        ok: true,
        voices: voices.map(v => `${v.voiceName || "?"} (${v.lang || "?"})`)
      }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
  }
  if (msg.type === "GET_VOICE_STATUS") {
    chrome.storage.local.get({ ipWatchVoiceStatus: voiceStatus })
      .then(data => sendResponse({ ok: true, status: data.ipWatchVoiceStatus }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
  }
  if (msg.type === "STOP_VOICE") {
    stopVoice(true)
      .then(() => sendResponse({ ok: true }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
  }
  return true;
});

// Iniciar el loop
eventLoop();
