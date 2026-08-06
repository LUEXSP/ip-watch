# IP Watch v2.5.0 — Test Report (PR #1, bank-risk feature)

**Branch:** `devin/1785694259-ip-quality-monitor` · commit `05d17b1` (v2.5.0)
**How tested:** Restarted the local Python agent (v2.5.0, 127.0.0.1:8790), reloaded the `EXTENCION/` extension in Chrome (now shows 2.5.0 with "Riesgo bancario estimado" in its description), and drove the new bank-risk card end-to-end in the popup (opened as a full tab for console inspection). VM public IP is an AWS datacenter IP (100.23.34.160). Completed the full test procedure; **all 5 checks passed with zero JS console errors.**

---

## Test 1 — Bank-risk card renders with inverse-lens factors ✅ PASS
The new **"¿Cómo te vería un banco/fintech?"** card appears directly below the AI-Friendly card:
- Badge = **Riesgo MEDIO**, subtitle "Escala inversa: 0 = riesgo bajo"
- **Riesgo bancario 49/100** with a filled bar
- Factors: `+25 [Red] IP de datacenter/hosting`, `+12 [Coherencia] Idioma del navegador ≠ país de la IP`, `+12 [Coherencia] Zona horaria incoherente con la IP`
- Recommendation: "Un banco marca datacenter/hosting como alto riesgo: usa un exit residencial."
- Inverse lens confirmed: the same datacenter IP that AI-Friendly rates **55/100 MAYBE** is flagged as a real **risk** by the bank lens.

![Bank-risk card baseline 49/100 MEDIO](https://app.devin.ai/attachments/66c11f4f-3f58-4642-8ce5-ca423a263a6d/ss_e3b02c8c.png)

## Test 2 — Expected-country mismatch raises score with the new factor ✅ PASS
Typed `VE` in "País real esperado (ISO-2)" and clicked Guardar:
- Toast **"País esperado: VE"**
- New factor **`+20 [Coherencia] País esperado ≠ país de la IP`** appeared; score rose **49 → 57**
- Coherence card now reads "País esperado (VE) no coincide con el país de la IP (US)."
- Verified in agent state: `risk 57 MEDIO`, `country_match: False`.

![After saving VE — new país factor, 57/100](https://app.devin.ai/attachments/78ec2592-d564-4b0e-96b6-a2c70e459b64/ss_3c26fb49.png)

> **Note (not a bug):** My plan predicted ~69/ALTO, but the score went 49→57 and stayed MEDIO. Reason: the baseline "+12 idioma" factor was based on *stale* client state (es-VE) left over in the agent from a prior session. On this popup load the extension re-posted the real browser locale (`en-US`, tz `UTC`), which is language-coherent with the US IP, so the idioma factor resolved at the same time the país factor was added (net +8). The feature behaved correctly — the new expected-country factor appeared and the score rose.

## Test 3 — Invalid non-ISO-2 value rejected ✅ PASS
Typed `X`, clicked Guardar:
- Toast **"Usa un código ISO-2, p.ej. VE"**
- Score stayed **57**, VE factor unchanged; agent `/config` still had `expected_country = VE` — the invalid value was **not** saved and did not clobber the prior value.

![Invalid "X" rejected with toast](https://app.devin.ai/attachments/87752696-a726-4aff-8e8b-09f0a7a98c31/ss_6e4a6fd5.png)

## Test 4 — Clearing expected country drops the factor ✅ PASS
Cleared the field, clicked Guardar:
- Toast **"País esperado borrado (auto)"**
- The "País esperado ≠ país de la IP" factor is **gone**; score dropped **57 → 37**; coherence card no longer mentions expected country; factors back to `+25 datacenter` + `+12 timezone`.

![After clearing — país factor gone, 37/100](https://app.devin.ai/attachments/a44ad4dd-e1ce-41ad-9318-54e4e5204658/ss_d3f0d04b.png)

## Test 5 — Regression: no JS console errors, other cards/tabs intact ✅ PASS
- AI-Friendly, WebRTC/DNS/tunnel cards, Historial (trend + 504-record list) and Speed tabs all render.
- Popup DevTools console showed only my own diagnostic log — **zero uncaught errors** across card render, save/reject/clear country, and tab switches.

---

## Escalations / notes
- No functional bugs found. All new v2.5.0 behavior verified against the golden path.
- The only surprise was the stale-client-state effect described in Test 2 (baseline briefly showed a phantom es-VE language factor before the popup refreshed client data). It self-corrects on popup load and is not a defect, but worth being aware of if you ever seed/persist `client` state between sessions.
