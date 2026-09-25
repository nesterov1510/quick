"use strict";

const SCRIPT_ID = "quick-dashboard-bridge";
const connectButton = document.getElementById("connect");
const panelLabel = document.getElementById("panel");
const statusLabel = document.getElementById("status");
let activeTab = null;
let configuredOrigin = "";

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

async function showConfiguration() {
  const {panelOrigin} = await chrome.storage.local.get("panelOrigin");
  configuredOrigin = panelOrigin || "";
  panelLabel.textContent = configuredOrigin || "Панель пока не подключена";
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  activeTab = tab || null;
  connectButton.disabled = !activeTab?.url;
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

  connectButton.disabled = true;
  setStatus("Запрашиваем разрешение для выбранной панели…");
  let verified = false;
  try {
    // Must be called directly from the button's user gesture.
    if (!await chrome.permissions.request({origins: [pattern]})) {
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
    if (previous && previous !== url.origin) {
      const oldPattern = panelPattern(previous);
      if (oldPattern !== pattern) await chrome.permissions.remove({origins: [oldPattern]});
    }
    configuredOrigin = url.origin;
    panelLabel.textContent = url.origin;
    setStatus("Подключено. Вкладка панели обновится; войдите в Vault и нажмите карточку ⚡.", "success");
    await chrome.tabs.reload(activeTab.id);
  } catch (error) {
    // Don't retain host access granted for an unrelated or logged-out page.
    if (!verified && url.origin !== configuredOrigin) {
      await chrome.permissions.remove({origins: [pattern]}).catch(() => {});
    }
    setStatus(error.message || "Не удалось подключить панель.", "error");
  } finally {
    connectButton.disabled = false;
  }
});

showConfiguration().catch(() => setStatus("Не удалось проверить настройки расширения.", "error"));
