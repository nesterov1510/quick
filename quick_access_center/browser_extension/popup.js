"use strict";

const SCRIPT_ID = "quick-dashboard-bridge";
const connectButton = document.getElementById("connect");
const panelLabel = document.getElementById("panel");
const statusLabel = document.getElementById("status");
const siteList = document.getElementById("sites");
let activeTab = null;
let configuredOrigin = "";
let targetSites = [];

function setStatus(message, type = "") {
  statusLabel.textContent = message;
  statusLabel.className = type;
}

function panelPattern(origin) {
  const url = new URL(origin);
  const local = url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname);
  if (url.protocol !== "https:" && !local) {
    throw new Error("Для удалённой панели требуется HTTPS. HTTP допускается только на этом компьютере.");
  }
  // Chrome match patterns cannot contain a port. The bridge ALSO checks the
  // exact saved origin (including port) before it does anything.
  return `${url.protocol}//${url.hostname}/*`;
}

// Twin of background.js: a private *domain name* is not accepted because it
// can resolve anywhere.
function isPrivateHost(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost") return true;
  const parts = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (parts) {
    const [a, b] = [Number(parts[1]), Number(parts[2])];
    if (parts.slice(1).some(part => Number(part) > 255)) return false;
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  return host === "::1" || /^(fc|fd)[0-9a-f]{2}:/.test(host);
}

// Login pages of the allowlist: HTTPS, or plain HTTP inside a private network
// when that entry opted in. Chrome match patterns ignore the port; the service
// worker still compares the exact URL before releasing anything.
function sitePattern(origin) {
  const url = new URL(origin);
  if (url.protocol === "https:") return `https://${url.hostname}/*`;
  if (url.protocol === "http:" && isPrivateHost(url.hostname)) return `http://${url.hostname}/*`;
  throw new Error(`Адрес сервиса должен быть HTTPS: ${origin}`);
}

function renderSites() {
  if (!siteList) return;
  siteList.textContent = "";
  for (const site of targetSites) {
    const item = document.createElement("li");
    const mark = site.permitted ? "✅" : "⛔";
    item.textContent = `${mark} ${site.name} — ${site.login_url}` +
      (site.insecure ? " · http, пароль идёт открытым текстом" : "");
    siteList.append(item);
  }
  if (!targetSites.length) {
    const item = document.createElement("li");
    item.textContent = "Список сервисов не прочитан (sites.json / sites.local.json).";
    siteList.append(item);
  }
}

async function loadSites() {
  try {
    const response = await chrome.runtime.sendMessage({type: "LIST_SITES"});
    targetSites = response?.ok && Array.isArray(response.sites) ? response.sites : [];
  } catch {
    targetSites = [];
  }
  renderSites();
}

async function showConfiguration() {
  const {panelOrigin} = await chrome.storage.local.get("panelOrigin");
  configuredOrigin = panelOrigin || "";
  panelLabel.textContent = configuredOrigin || "Панель пока не подключена";
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  activeTab = tab || null;
  connectButton.disabled = !activeTab?.url;
  await loadSites();
}

async function alreadyPermitted(origins) {
  const granted = new Set();
  for (const origin of origins) {
    try {
      if (await chrome.permissions.contains({origins: [origin]})) granted.add(origin);
    } catch {
      // Treat an unsupported query as "not granted"; the request below decides.
    }
  }
  return granted;
}

connectButton.addEventListener("click", async () => {
  if (!activeTab?.url || !activeTab?.id) return;
  let url;
  let pattern;
  try {
    url = new URL(activeTab.url);
    if (url.pathname !== "/" || url.search || url.hash) {
      throw new Error("Сначала откройте главную страницу панели Quick Access (без фильтров).");
    }
    pattern = panelPattern(url.origin);
  } catch (error) {
    setStatus(error.message, "error");
    return;
  }

  // One prompt for the panel and for every login page the extension may fill.
  const wanted = [pattern];
  for (const site of targetSites) {
    try {
      const patternForSite = sitePattern(new URL(site.login_url).origin);
      if (!wanted.includes(patternForSite)) wanted.push(patternForSite);
    } catch {
      // A site entry without a usable HTTPS origin is skipped.
    }
  }

  connectButton.disabled = true;
  setStatus("Запрашиваем разрешение для панели и сервисов автовхода…");
  let verified = false;
  let grantedBefore = new Set();
  try {
    grantedBefore = await alreadyPermitted(wanted);
    // Must be called directly from the button's user gesture.
    if (!await chrome.permissions.request({origins: wanted})) {
      throw new Error("Разрешение не выдано. Подключение отменено.");
    }
    const [proof] = await chrome.scripting.executeScript({
      target: {tabId: activeTab.id},
      func: () => document.querySelector('meta[name="quick-access-autologin"]')?.content === "1"
    });
    if (!proof?.result) {
      throw new Error("На вкладке нет открытой панели Quick Access. Войдите в неё и обновите страницу.");
    }
    verified = true;

    const {panelOrigin: previous} = await chrome.storage.local.get("panelOrigin");
    const existing = await chrome.scripting.getRegisteredContentScripts({ids: [SCRIPT_ID]});
    if (existing.length) {
      await chrome.scripting.unregisterContentScripts({ids: [SCRIPT_ID]});
    }
    await chrome.scripting.registerContentScripts([{
      id: SCRIPT_ID,
      matches: [pattern],
      js: ["bridge.js"],
      runAt: "document_start",
      allFrames: false,
      persistAcrossSessions: true
    }]);
    await chrome.storage.local.set({panelOrigin: url.origin});
    // Registers target.js for the newly permitted login pages.
    await chrome.runtime.sendMessage({type: "REGISTER_TARGETS"});
    if (previous && previous !== url.origin) {
      const oldPattern = panelPattern(previous);
      if (oldPattern !== pattern) await chrome.permissions.remove({origins: [oldPattern]});
    }
    configuredOrigin = url.origin;
    panelLabel.textContent = url.origin;
    setStatus("Подключено. Вкладка панели обновится; войдите в Vault и нажмите карточку ⚡.", "success");
    await chrome.tabs.reload(activeTab.id);
    await loadSites();
  } catch (error) {
    // Don't retain host access granted for an unrelated or logged-out page.
    if (!verified) {
      const revoke = wanted.filter(origin => !grantedBefore.has(origin) && origin !== configuredOriginPattern());
      for (const origin of revoke) {
        await chrome.permissions.remove({origins: [origin]}).catch(() => {});
      }
    }
    setStatus(error.message || "Не удалось подключить панель.", "error");
  } finally {
    connectButton.disabled = false;
  }
});

function configuredOriginPattern() {
  try {
    return configuredOrigin ? panelPattern(configuredOrigin) : "";
  } catch {
    return "";
  }
}

showConfiguration().catch(() => setStatus("Не удалось проверить настройки расширения.", "error"));
