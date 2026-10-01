"use strict";

const ACTIVITY_LOGIN_URL = "https://msb-activity.meryosab.com/login";
const ACTIVITY_ORIGIN = new URL(ACTIVITY_LOGIN_URL).origin;
const PENDING_TTL_MS = 45_000;
const KEY_PREFIX = "pending-login:";
const pendingTakes = new Set();

function tabKey(tabId) {
  return `${KEY_PREFIX}${tabId}`;
}

function isTopFrame(sender) {
  return sender?.id === chrome.runtime.id &&
    Number.isInteger(sender.tab?.id) && sender.frameId === 0;
}

function isPanelSender(sender, panelOrigin) {
  if (!isTopFrame(sender) || !panelOrigin) return false;
  try {
    const page = new URL(sender.url);
    return page.origin === panelOrigin && page.pathname === "/";
  } catch {
    return false;
  }
}

function isTargetSender(sender) {
  if (!isTopFrame(sender)) return false;
  try {
    const page = new URL(sender.url);
    return page.origin === ACTIVITY_ORIGIN &&
      (page.pathname === "/login" || page.pathname === "/login/") &&
      !page.search && !page.hash;
  } catch {
    return false;
  }
}

async function openLogin(message, sender) {
  const {panelOrigin} = await chrome.storage.local.get("panelOrigin");
  if (!isPanelSender(sender, panelOrigin) || message.login_url !== ACTIVITY_LOGIN_URL ||
      typeof message.username !== "string" || !message.username || message.username.length > 1024 ||
      typeof message.password !== "string" || !message.password || message.password.length > 4096) {
    return {ok: false};
  }

  let tab;
  try {
    // Set up the one-use secret BEFORE navigating: the login content script
    // cannot race ahead of storage. session storage stays in browser memory,
    // never syncs or persists to disk like storage.local.
    tab = await chrome.tabs.create({url: "about:blank", active: true});
    const expiresAt = Date.now() + PENDING_TTL_MS;
    await chrome.storage.session.set({
      [tabKey(tab.id)]: {username: message.username, password: message.password, expiresAt}
    });
    await chrome.alarms.create(tabKey(tab.id), {when: expiresAt});
    await chrome.tabs.update(tab.id, {url: ACTIVITY_LOGIN_URL});
    return {ok: true};
  } catch {
    if (tab?.id !== undefined) {
      await chrome.storage.session.remove(tabKey(tab.id)).catch(() => {});
      await chrome.alarms.clear(tabKey(tab.id)).catch(() => {});
      await chrome.tabs.remove(tab.id).catch(() => {});
    }
    return {ok: false};
  }
}

async function takeLogin(sender) {
  if (!isTargetSender(sender)) return {ok: false};
  const key = tabKey(sender.tab.id);
  // Two content scripts can race: serialize consumption before the first
  // asynchronous storage read, then delete the entry before replying.
  if (pendingTakes.has(key)) return {ok: false};
  pendingTakes.add(key);
  try {
    const entry = (await chrome.storage.session.get(key))[key];
    await chrome.storage.session.remove(key);
    await chrome.alarms.clear(key);
    if (!entry || Date.now() > entry.expiresAt) return {ok: false};
    return {ok: true, username: entry.username, password: entry.password};
  } finally {
    pendingTakes.delete(key);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "OPEN_LOGIN" && message?.type !== "TAKE_LOGIN") return;
  const action = message.type === "OPEN_LOGIN"
    ? openLogin(message, sender)
    : takeLogin(sender);
  action.then(sendResponse).catch(() => sendResponse({ok: false}));
  return true; // Chrome keeps the message channel open while the Promise resolves.
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name.startsWith(KEY_PREFIX)) chrome.storage.session.remove(alarm.name).catch(() => {});
});
chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.session.remove(tabKey(tabId)).catch(() => {});
  chrome.alarms.clear(tabKey(tabId)).catch(() => {});
});
