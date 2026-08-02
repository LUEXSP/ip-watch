IP Watch v2.1 Security Build

Cambios principales:
- Credenciales removidas del código y del config incluido.
- Token local entre extensión y agente: EXTENCION/auth.js + ip_watch_config.json.
- CORS cerrado a extensiones del navegador y localhost.
- /config devuelve secretos enmascarados.
- Permiso downloads eliminado del manifest.
- Loop duplicado del background corregido.

Instalación rápida:
1) Ejecuta start_agent.bat o: python agent.py
2) En Chrome/Edge: Extensiones > Modo desarrollador > Cargar descomprimida > carpeta EXTENCION.
3) Abre Opciones y agrega tus API keys/StarVPN si deseas.

IMPORTANTE:
No compartas EXTENCION/auth.js ni ip_watch_config.json si contienen tu token/API keys.
Si vas a compartir la extensión, borra esos dos archivos o usa ip_watch_config.example.json.

---
HOTFIX v2.1.1 - Scamalytics API/CAPTCHA
- Scamalytics ahora usa SOLO el endpoint API directo configurado con user/key.
- Se eliminó el fallback por scraping HTML de scamalytics.com/ip/<ip>, porque esa ruta puede activar Cloudflare/CAPTCHA.
- Si Scamalytics devuelve HTML, Cloudflare o CAPTCHA, el agente lo marca como error controlado y deja que AbuseIPDB funcione como fallback.
- El dashboard ya no debe romperse ni guardar resultados HTML como fraud score válido.

---
IP Watch v2.2 - IPQualityScore
- Nuevo campo en Configuración: IPQualityScore API Key.
- Nuevo campo: IPQualityScore Strictness (0-3, recomendado 1).
- Nuevo score visible en el popup: IPQualityScore.
- IPQualityScore ahora también influye en AI Friendly Score.
- Endpoint de prueba local: /ipqualityscore/test?ip=1.2.3.4 (requiere X-IPWatch-Token).


=== v2.2.1 Token Fix ===
Si ves 401 Unauthorized en DevTools, abre Opciones de la extensión y pega el mismo valor de local_auth_token que tienes en ip_watch_config.json.
Luego presiona "Guardar token local en la extensión", guarda/recarga y vuelve a probar.
