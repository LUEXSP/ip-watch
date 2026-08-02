IP Watch v2.3.1 — Voice Event Fix

Correcciones:
- Detecta reinicios del agente mediante stream_id.
- Reinicia correctamente lastEventId cuando cambia el stream.
- Verifica la IP actual como respaldo si se pierde un evento.
- Poll de respaldo mediante chrome.alarms cada 30 segundos.
- Evita anuncios duplicados con lastAnnouncedIp.

Instalación:
1. Reemplaza la extensión por la carpeta EXTENCION de este paquete.
2. Sustituye agent.py y reinicia INICIADOR.BAT/agent.py.
3. En chrome://extensions pulsa Recargar.
4. Usa Probar voz y luego cambia la IP.
