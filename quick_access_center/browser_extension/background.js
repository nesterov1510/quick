"use strict";

// Single source of truth for the extension side of auto login: the exact
// HTTPS login URLs listed in sites.json / sites.local.json. A password is only
// ever released to one of these pages, in the tab opened by a card click.
const BUILT_IN_SITES = [{name: "MSB Activity", login_url: "https://msb-activity.meryosab.com/login"}];
const SITES_FILES = ["sites.json", "sites.local.json"];
const PENDING_TTL_MS = 45_000;
const KEY_PREFIX = "pending-login:";
const TARGET_SCRIPT_ID = "quick-login-target";
const pendingTakes = new Set();
let allowedTargets = [];
let targetsReady = null;

function tabKey(tabId) {
  return `${KEY_PREFIX}${tabId}`;
}

// Private network literals only: a private domain name could resolve anywhere
// and would quietly turn the opt-in into "any HTTP site".
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

// Mirrors vault_control/autologin.py: exact URL, no userinfo, query or
// fragment, so a lookalike domain or a redirect parameter never matches.
// Plain HTTP is accepted only for a private address that opted in explicitly.
function canonicalTargetUrl(raw, allowInsecure = false) {
  let page;
  try {
    page = new URL(String(raw || ""));
  } catch {
    return null;
  }
  if (!page.hostname || page.username || page.password) return null;
  if (page.search || page.hash) return null;
  const insecure = page.protocol === "http:" && allowInsecure && isPrivateHost(page.hostname);
  if (page.protocol !== "https:" && !insecure) return null;
  const path = page.pathname || "/";
  return {url: `${page.origin}${path}`, origin: page.origin, path, insecure};
}

function selector(site, key) {
  const value = site?.[key];
  return typeof value === "string" ? value.trim() : "";
}

async function readSitesFile(name) {
  try {
    const response = await fetch(chrome.runtime.getURL(name), {cache: "no-store"});
    if (!response.ok) return [];
    const data = await response.json();
    return Array.isArray(data?.sites) ? data.sites : [];
  } catch {
    return []; // a missing or broken file must never widen the allowlist
  }
}

async function loadTargets() {
  const sites = [...BUILT_IN_SITES];
  for (const name of SITES_FILES) sites.push(...await readSitesFile(name));

  const targets = [];
  for (const site of sites) {
    const page = canonicalTargetUrl(site?.login_url, site?.allow_insecure === true);
    if (!page || targets.some(item => item.url === page.url)) continue;
    targets.push({
      ...page,
      name: typeof site?.name === "string" && site.name.trim() ? site.name.trim() : page.url,
      usernameSelector: selector(site, "username_selector"),
      passwordSelector: selector(site, "password_selector"),
      submitSelector: selector(site, "submit_selector")
    });
  }
  allowedTargets = targets;
  return targets;
}

// The service worker can wake up on a message before sites.json is read, so
// every credential decision waits for the allowlist instead of racing it.
function ensureTargetsLoaded() {
  if (!targetsReady) {
    targetsReady = loadTargets().catch(() => { allowedTargets = []; });
  }
  return targetsReady;
}

// Lookup accepts a private HTTP URL syntactically; whether such an entry is
// allowed at all was decided per site in loadTargets (allow_insecure).
function findTargetByUrl(url) {
  const page = canonicalTargetUrl(url, true);
  return page ? allowedTargets.find(item => item.url === page.url) || null : null;
}

// Chrome match patterns must not contain a port: they cover every port of the
// host. The exact URL (port included) is still checked before a credential is
// released, so a broader injection point does not widen the allowlist.
function hostPattern(target) {
  const url = new URL(target.url);
  return `${url.protocol}//${url.hostname}/*`;
}

function contentScriptMatches(targets) {
  const matches = new Set();
  for (const target of targets) {
    const url = new URL(target.url);
    const base = `${url.protocol}//${url.hostname}`;
    matches.add(`${base}${target.path}`);
    if (target.path !== "/" && !target.path.endsWith("/")) matches.add(`${base}${target.path}/`);
  }
  return [...matches];
}

async function ensureTargetScripts() {
  const permitted = [];
  for (const pattern of [...new Set(allowedTargets.map(hostPattern))]) {
    try {
      if (await chrome.permissions.contains({origins: [pattern]})) permitted.push(pattern);
    } catch {
      // Without host access the page simply keeps its normal manual login.
    }
  }

  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ids: [TARGET_SCRIPT_ID]});
    if (existing.length) await chrome.scripting.unregisterContentScripts({ids: [TARGET_SCRIPT_ID]});
    const matches = contentScriptMatches(allowedTargets.filter(item => permitted.includes(hostPattern(item))));
    if (!matches.length) return 0;
    await chrome.scripting.registerContentScripts([{
      id: TARGET_SCRIPT_ID,
      matches,
      js: ["target.js"],
      runAt: "document_idle",
      allFrames: false,
      persistAcrossSessions: true
    }]);
    return matches.length;
  } catch {
    return 0;
  }
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

// Extension pages (popup) have no tab; everything else must come from a page.
function isExtensionPageSender(sender) {
  return sender?.id === chrome.runtime.id && sender.tab === undefined;
}

function targetFromSender(sender) {
  if (!isTopFrame(sender)) return null;
  try {
    const page = new URL(sender.url);
    if (page.search || page.hash) return null;
  } catch {
    return null;
  }
  return findTargetByUrl(sender.url);
}

async function listSites() {
  await ensureTargetsLoaded();
  const sites = [];
  for (const target of allowedTargets) {
    let permitted = false;
    try {
      permitted = await chrome.permissions.contains({origins: [hostPattern(target)]});
    } catch {
      permitted = false;
    }
    sites.push({name: target.name, login_url: target.url, permitted, insecure: !!target.insecure});
  }
  return {ok: true, sites};
}

async function openLogin(message, sender) {
  const {panelOrigin} = await chrome.storage.local.get("panelOrigin");
  await ensureTargetsLoaded();
  const target = findTargetByUrl(message.login_url);
  if (!isPanelSender(sender, panelOrigin) || !target ||
      typeof message.username !== "string" || !message.username || message.username.length > 1024 ||
      typeof message.password !== "string" || !message.password || message.password.length > 4096) {
    return {ok: false};
  }

  let permitted = false;
  try {
    permitted = await chrome.permissions.contains({origins: [hostPattern(target)]});
  } catch {
    permitted = false;
  }
  if (!permitted) return {ok: false, error: "no_host_permission"};

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
    await ensureTargetScripts();
    await chrome.tabs.update(tab.id, {url: target.url});
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
  await ensureTargetsLoaded();
  if (!targetFromSender(sender)) return {ok: false};
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

// The content script never stores the allowlist: it asks, and the answer is
// derived from sender.url, not from anything the page can claim.
async function targetCheck(sender) {
  await ensureTargetsLoaded();
  const target = targetFromSender(sender);
  if (!target) return {ok: false};
  return {
    ok: true,
    login_url: target.url,
    username_selector: target.usernameSelector,
    password_selector: target.passwordSelector,
    submit_selector: target.submitSelector
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const actions = {
    OPEN_LOGIN: () => openLogin(message, sender),
    TAKE_LOGIN: () => takeLogin(sender),
    TARGET_CHECK: () => targetCheck(sender),
    LIST_SITES: () => isExtensionPageSender(sender) ? listSites() : Promise.resolve({ok: false}),
    REGISTER_TARGETS: async () => {
      if (!isExtensionPageSender(sender)) return {ok: false};
      targetsReady = loadTargets().catch(() => { allowedTargets = []; });
      await targetsReady;
      return {ok: true, registered: await ensureTargetScripts()};
    }
  };
  const action = actions[message?.type];
  if (!action) return;
  Promise.resolve()
    .then(action)
    .then(sendResponse)
    .catch(() => sendResponse({ok: false}));
  return true; // Chrome keeps the message channel open while the Promise resolves.
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name.startsWith(KEY_PREFIX)) chrome.storage.session.remove(alarm.name).catch(() => {});
});
chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.session.remove(tabKey(tabId)).catch(() => {});
  chrome.alarms.clear(tabKey(tabId)).catch(() => {});
});
function refreshTargets() {
  targetsReady = null;
  return ensureTargetsLoaded().then(ensureTargetScripts).catch(() => {});
}

for (const event of [chrome.runtime.onInstalled, chrome.runtime.onStartup]) {
  event?.addListener?.(refreshTargets);
}
refreshTargets();
