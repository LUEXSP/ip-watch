# IP Watch v2.5.0 — Test Plan (PR #1, bank-risk feature)

Setup done (not in plan): agent v2.5.0 running on 127.0.0.1:8790, extension reloaded, token = fallback. Popup opened as full tab.

Code refs: popup.js renderBank (257-296), btnSaveCountry (830-839); agent.py compute_bank_risk (1056-1154), compute_coherence (990-1044).

## Test 1 — Bank-risk card renders with inverse-lens factors
Open popup, scroll to "¿Cómo te vería un banco/fintech?" card (below AI-Friendly).
- PASS: `#bankLevel` = "Riesgo MEDIO" (or ALTO), `#bankScore` ≈ "49/100" (non-zero), `#bankFill` bar filled/red, `#bankFactors` lists "+25 [Red] IP de datacenter/hosting" among factors, `#bankRecs` shows a residential-exit recommendation. Bank score must be visibly WORSE than AI-Friendly (55/100 MAYBE) — i.e. flags a datacenter IP that AI-Friendly treats as merely MAYBE.
- FAIL: card missing, "Sin datos", score "—", or no datacenter factor.

## Test 2 — Expected-country mismatch raises score with new factor
In the card's "País real esperado (ISO-2)" input (`#expCountry`), type `VE`, click "Guardar" (`#btnSaveCountry`).
- PASS: toast "País esperado: VE"; after refresh the `#bankFactors` list gains "+20 [Coherencia] País esperado ≠ país de la IP" and `#bankScore` rises by 20 (≈49→69, level → ALTO). Coherence card issue mentions "País esperado (VE) no coincide con el país de la IP (US)".
- FAIL: no new factor, score unchanged, or no toast.

## Test 3 — Invalid input rejected
Type `X` in `#expCountry`, click Guardar.
- PASS: toast "Usa un código ISO-2, p.ej. VE"; NO /config POST (score/factors unchanged; still shows VE factor from Test 2).
- FAIL: accepts "X" / saves / clears prior value.

## Test 4 — Clearing expected country drops the factor
Clear `#expCountry` (empty), click Guardar.
- PASS: toast "País esperado borrado (auto)"; after refresh the "País esperado ≠ país de la IP" factor is GONE and `#bankScore` drops back (≈49), level → MEDIO.
- FAIL: factor persists or score stays elevated.

## Test 5 — Regression: no JS console errors, other cards/tabs intact
Throughout, keep popup DevTools console open.
- PASS: AI-Friendly, WebRTC/DNS/tunnel cards, export, Historial & Speed tabs still render; zero uncaught console errors.
- FAIL: any uncaught error.
