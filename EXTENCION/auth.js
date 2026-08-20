// IP Watch local auth helper.
// Fallback usado si todavía no has guardado un token desde Opciones.
const IPWATCH_TOKEN = "IPWATCH_LOCAL_TOKEN_CHANGE_ME";

async function getIPWatchToken() {
  try {
    const data = await chrome.storage.local.get(["ipwatch_local_auth_token"]);
    return (data.ipwatch_local_auth_token || IPWATCH_TOKEN || "").trim();
  } catch (e) {
    return (IPWATCH_TOKEN || "").trim();
  }
}

async function getIPWatchHeaders(extra = {}) {
  const token = await getIPWatchToken();
  const headers = { ...extra };
  if (token) headers["X-IPWatch-Token"] = token;
  return headers;
}

async function saveIPWatchToken(token) {
  await chrome.storage.local.set({ ipwatch_local_auth_token: (token || "").trim() });
}
