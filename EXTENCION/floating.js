const AGENT = "http://127.0.0.1:8790";

function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return "";
  const A = 0x1F1E6, u = cc.toUpperCase();
  return String.fromCodePoint(A + u.charCodeAt(0) - 65, A + u.charCodeAt(1) - 65);
}

function scoreClass(score) {
  if (typeof score !== "number") return "";
  if (score >= 40) return "high";
  if (score >= 20) return "med";
  return "low";
}

async function fetchStatus() {
  try {
    const res = await fetch(`${AGENT}/status`, { cache: "no-store", headers: await getIPWatchHeaders() });
    const data = await res.json();
    const ip = data.ip || "?";
    const cc = data.profile?.country_code || "";
    const city = data.profile?.city || "";
    const country = data.profile?.country || "";
    const loc = [flagEmoji(cc), [city, country].filter(Boolean).join(", ")].filter(Boolean).join(" ") || "—";

    document.getElementById("fIp").textContent = ip;
    document.getElementById("fLoc").textContent = loc;

    const fs = data.fraud?.fraud_score;
    const fEl = document.getElementById("fScore");
    fEl.textContent = fs !== undefined ? `${fs}/100` : "—";
    fEl.className = "badge " + scoreClass(fs);

    const ab = data.abuseipdb?.score;
    const aEl = document.getElementById("fAbuse");
    aEl.textContent = ab !== undefined ? `${ab}/100` : "—";
    aEl.className = "badge " + scoreClass(ab);

    const proxy = data.privacy?.proxy?.enabled;
    document.getElementById("fProxy").textContent = proxy === true ? "ON" : proxy === false ? "OFF" : "?";
    document.getElementById("fProxy").style.color = proxy === true ? "#fbbf24" : "#34d399";
  } catch {
    document.getElementById("fIp").textContent = "Agent offline";
    document.getElementById("fLoc").textContent = "—";
  }
}

document.getElementById("closeBtn").addEventListener("click", () => {
  chrome.windows.getCurrent(win => chrome.windows.remove(win.id));
});

document.getElementById("rotateBtn").addEventListener("click", async () => {
  const btn = document.getElementById("rotateBtn");
  btn.textContent = "⏳...";
  btn.disabled = true;
  try {
    const res = await fetch(`${AGENT}/rotate_ip`, { method: "POST", cache: "no-store", headers: await getIPWatchHeaders() });
    const d = await res.json();
    btn.textContent = d.ok ? "✓ Rotado" : "✗ Error";
  } catch {
    btn.textContent = "✗ Sin agente";
  }
  setTimeout(() => { btn.textContent = "🔃 Rotar IP"; btn.disabled = false; }, 3000);
});

fetchStatus();
setInterval(fetchStatus, 5000);
