---
name: testing-ip-watch
description: How to run and test the IP Watch Chrome MV3 extension + local Python agent end-to-end.
---

# Testing IP Watch (extension + local agent)

The app is a Chrome MV3 extension (`EXTENCION/`) + a local Python agent (`agent.py`) serving `http://127.0.0.1:8790`. The popup polls the agent for IP quality data.

## Run the agent
- `cd <repo> && python3 agent.py` (needs internet — fetches public IP/profile). Listens on 127.0.0.1:8790.
- `/health` needs no auth; `/status`, `/config`, `/tunnel/pin`, `/tunnel/clear`, etc. require header `X-IPWatch-Token: <local_auth_token>`.
- The token is `ip_watch_config.json` → `local_auth_token`.

## Token pairing (important shortcut)
- The extension `auth.js` fallback token is `IPWATCH_LOCAL_TOKEN_CHANGE_ME`. If `ip_watch_config.json` still has that same value, the popup authorizes with NO manual pairing. Otherwise, save the real token via the Options page (`options.html`) field, or set `ipwatch_local_auth_token` in chrome.storage.local.

## Load the extension
- `chrome://extensions` → enable Developer mode → Load unpacked → select the `EXTENCION/` folder.
- GTK file picker tip: the location bar (Ctrl+L) keeps navigating *into* folders. Instead click "Home" in the left pane to force the list to render, then double-click through directories and single-click + "Open" the target folder.
- Best way to test/inspect console: open the popup as a full tab at `chrome-extension://<ID>/popup.html` (ID shown on the extensions page). This keeps it from auto-closing and lets `browser_console` read its context.

## What to verify (v2.4.0 features)
- **Naturaleza de la IP** card: badge (Datacenter/Hosting on an AWS VM), `confianza: N`, signals, AI-Friendly Score bar + recommendations.
- **Privacidad nativa** card: WebRTC leak (button "🔍 Probar fugas"), DNS leak, timezone coherence (VM is usually UTC → shows "⚠️ Incoherente" vs a US IP tz).
- **Vigilancia del túnel**: "📌 Fijar estado actual" → POST /tunnel/pin → badge "✓ Protegido"; "Limpiar" → POST /tunnel/clear → "Sin fijar".
- **💾 Export** button (in the footer button row, scroll down): downloads `ipwatch_*.json` (status+history+exportTime) via anchor+blob. Verify file lands in `~/Downloads`.

## v2.5.0 — Bank-risk card ("¿Cómo te vería un banco/fintech?")
- Renders below the AI-Friendly card. Inverse scale: 0 = low risk, 100 = high (opposite of AI-Friendly). Backend `compute_bank_risk()` in agent.py; factors sum deltas per layer (Red/Reputación/Coherencia/Fingerprint). Datacenter IP = +25 Red. Levels: ≥60 ALTO, ≥25 MEDIO, else BAJO.
- `#expCountry` input + `#btnSaveCountry` "Guardar": POSTs `/config {expected_country}` (ISO-2, validated `^[A-Z]{2}$` client-side), then `/refresh`. A mismatch vs the IP country adds "+20 [Coherencia] País esperado ≠ país de la IP". Empty value clears it (toast "borrado (auto)").
- After editing code, RELOAD the extension (chrome://extensions → reload icon) AND restart the agent so both pick up the new version.
- GOTCHA: the agent persists `client` state (browser language/timezone/webrtc from the last `/client` POST) in `ip_watch_state.json`. Stale values from a prior session can briefly show phantom coherence factors (e.g. a es-VE language flag) until the freshly-opened popup re-posts real `navigator` values. Reset `expected_country`/state for a clean baseline if needed.
- Launching the agent in background: `(python3 agent.py &)` from a one-shot exec shell gets reaped. Use `setsid nohup python3 agent.py >/tmp/agent.log 2>&1 </dev/null & disown` so it survives.

## Devin Secrets Needed
- None. `ip_watch_config.json` ships with working Scamalytics/AbuseIPDB keys. IPQualityScore key is empty (that card shows "Configura tu API Key" — expected).
