"use strict";

// Only the real Activity login page receives a one-use credential, and only
// when opened by clicking an opted-in card in the configured Quick panel.
(() => {
  if (window.top !== window || location.origin !== "https://msb-activity.meryosab.com" ||
      !["/login", "/login/"].includes(location.pathname)) return;

  function loginForm() {
    const passwords = [...document.querySelectorAll('input[type="password"]')]
      .filter(input => !input.disabled && !input.readOnly && !input.hidden);
    if (passwords.length !== 1) return null;
    const password = passwords[0];
    const form = password.form;
    if (!form) return null;
    const submit = form.querySelector('button[type="submit"], input[type="submit"]');
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
      ["text", "email", "tel"].includes(input.type) &&
      !input.disabled && !input.readOnly && !input.hidden);
    const named = candidates.filter(input =>
      /^(username|user|login|email|identifier)$/i.test(input.name || input.id || "") ||
      /^(username|email)$/.test(input.autocomplete || ""));
    const username = named.length === 1 ? named[0] : candidates.length === 1 ? candidates[0] : null;
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
