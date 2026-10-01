"use strict";

// Only a login page named by the extension's own allowlist receives a one-use
// credential, and only when it was opened by clicking an opted-in card in the
// configured Quick panel. The allowlist stays in the service worker, which
// answers from sender.url: the page can neither read nor widen it.
(async () => {
  if (window.top !== window) return;

  let config;
  try {
    config = await chrome.runtime.sendMessage({type: "TARGET_CHECK"});
  } catch {
    return;
  }
  if (!config?.ok) return;

  function usable(input) {
    return !!input && !input.disabled && !input.readOnly && !input.hidden;
  }

  function query(scope, selector) {
    try {
      return selector ? scope.querySelector(selector) : null;
    } catch {
      return null; // a broken selector in sites.local.json must not throw
    }
  }

  function pickPassword() {
    if (config.password_selector) {
      const picked = query(document, config.password_selector);
      return picked && picked.tagName === "INPUT" && picked.type === "password" && usable(picked)
        ? picked
        : null; // an explicit selector that does not resolve is never guessed around
    }
    const passwords = [...document.querySelectorAll('input[type="password"]')]
      .filter(input => usable(input));
    return passwords.length === 1 ? passwords[0] : null;
  }

  function pickUsername(form, candidates) {
    if (config.username_selector) {
      const picked = query(document, config.username_selector);
      if (!picked || picked.tagName !== "INPUT" || picked.form !== form || !usable(picked)) return null;
      return ["text", "email", "tel"].includes(picked.type) ? picked : null;
    }
    const named = candidates.filter(input =>
      /^(username|user|login|email|identifier)$/i.test(input.name || input.id || "") ||
      /^(username|email)$/.test(input.autocomplete || ""));
    return named.length === 1 ? named[0] : candidates.length === 1 ? candidates[0] : null;
  }

  function loginForm() {
    const password = pickPassword();
    if (!password) return null;
    const form = password.form;
    if (!form) return null;
    const submit = config.submit_selector
      ? query(form, config.submit_selector)
      : form.querySelector('button[type="submit"], input[type="submit"]');
    if (submit?.disabled) return null;
    try {
      // A submit button's formaction/formmethod can override the form. Resolve
      // relative actions against document.baseURI (which may contain <base>).
      const method = (submit?.getAttribute?.("formmethod") || form.method).toUpperCase();
      const rawAction = submit?.getAttribute?.("formaction") || form.getAttribute("action");
      const action = new URL(rawAction || location.href, rawAction ? document.baseURI : location.href);
      if (method !== "POST" || action.origin !== location.origin ||
          action.username || action.password || action.protocol !== "https:") return null;
    } catch { return null; }

    const inputs = [...form.querySelectorAll("input")];
    const candidates = inputs.filter(input =>
      ["text", "email", "tel"].includes(input.type) && usable(input));
    const username = pickUsername(form, candidates);
    if (!username) return null;
    return {form, username, password, submit};
  }

  function setValue(input, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", {bubbles: true}));
    input.dispatchEvent(new Event("change", {bubbles: true}));
  }

  async function fillAndSubmit(fields) {
    try {
      const credential = await chrome.runtime.sendMessage({type: "TAKE_LOGIN"});
      if (!credential?.ok || !fields.password.isConnected || !fields.username.isConnected) return;
      setValue(fields.username, credential.username);
      setValue(fields.password, credential.password);
      // requestSubmit runs validation and the page's submit handlers (unlike
      // form.submit()) while retaining hidden CSRF fields loaded by that site.
      fields.form.requestSubmit(fields.submit || undefined);
    } catch {
      // An unavailable/mismatched form stays open for manual login.
    }
  }

  let started = false;
  const tryStart = () => {
    if (started) return true;
    const fields = loginForm();
    if (!fields) return false;
    started = true;
    fillAndSubmit(fields);
    return true;
  };
  if (tryStart()) return;
  // Covers forms rendered after DOMContentLoaded (without widening the URL
  // allowlist or keeping a credential in persistent extension storage).
  const observer = new MutationObserver(() => { if (tryStart()) observer.disconnect(); });
  observer.observe(document.documentElement, {childList: true, subtree: true});
  setTimeout(() => observer.disconnect(), 20_000);
})();
