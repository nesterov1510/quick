"use strict";

// Runs in Chrome's isolated world, not in the Quick Access page's JavaScript.
// Credentials are never posted to window, put into the DOM or sent in a URL.
(async () => {
  const {panelOrigin} = await chrome.storage.local.get("panelOrigin");
  if (!panelOrigin || location.origin !== panelOrigin || location.pathname !== "/") return;
  let busy = false;

  function notify(text) {
    const toast = document.createElement("div");
    toast.textContent = text;
    toast.setAttribute("role", "status");
    Object.assign(toast.style, {
      position: "fixed", top: "16px", right: "16px", zIndex: "2147483647",
      padding: "12px 16px", maxWidth: "330px", borderRadius: "8px",
      background: "#223147", color: "#ffffff", font: "13px system-ui, sans-serif",
      boxShadow: "0 8px 28px rgba(0,0,0,.45)"
    });
    (document.body || document.documentElement).append(toast);
    setTimeout(() => toast.remove(), 3800);
  }

  function cardId(target) {
    if (!(target instanceof Element) || document.body?.classList.contains("reorder-mode")) return null;
    const card = target.closest('.mini-card[data-auto-login="1"]');
    if (card) {
      if (target.closest("button, a, input, textarea, select, form")) return null;
      return /^\d+$/.test(card.dataset.id || "") ? card.dataset.id : null;
    }
    const open = target.closest("a#modalOpen");
    if (!open || !document.getElementById("modalBackdrop")?.classList.contains("show")) return null;
    const url = new URL(open.href, location.href);
    const match = url.origin === location.origin && url.pathname.match(/^\/open\/(\d+)$/);
    if (!match) return null;
    const cardForModal = document.querySelector(`.mini-card[data-id="${match[1]}"][data-auto-login="1"]`);
    return cardForModal ? match[1] : null;
  }

  async function start(id) {
    const token = document.querySelector('meta[name="quick-autologin-vault-csrf"]')?.content;
    if (!token) {
      notify("Сначала разблокируйте Vault; затем повторно нажмите карточку.");
      location.assign("/vault/login?next=%2F");
      return;
    }
    try {
      const response = await fetch(`/vault/app/${id}/autologin`, {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        body: new URLSearchParams({csrf_token: token}).toString()
      });
      if (response.redirected && new URL(response.url).pathname === "/vault/login") {
        notify("Время сеанса Vault истекло. Войдите снова и нажмите карточку.");
        location.assign("/vault/login?next=%2F");
        return;
      }
      if (response.status === 401 || response.status === 403) {
        notify("Сначала войдите в Quick Access и повторите попытку.");
        location.assign("/access-control?next=%2F");
        return;
      }
      if (response.status === 400) {
        notify("Защитный токен устарел. Обновите страницу и нажмите карточку снова.");
        return;
      }
      if (!response.headers.get("content-type")?.includes("application/json")) {
        notify("Нет ответа от Vault. Обновите страницу и повторите попытку.");
        return;
      }
      const data = await response.json();
      if (!response.ok || data?.ok !== true) {
        notify("Автовход не настроен. Проверьте ссылку и галочку доступа в Vault.");
        return;
      }
      const result = await chrome.runtime.sendMessage({
        type: "OPEN_LOGIN", login_url: data.login_url,
        username: data.username, password: data.password
      });
      if (!result?.ok) {
        notify(result?.error === "no_host_permission"
          ? "Расширению не выдан доступ к этому сервису. Откройте значок расширения и подключите панель ещё раз."
          : "Не удалось открыть форму входа. Проверьте настройки расширения.");
      }
    } catch {
      notify("Автовход не удался. Проверьте соединение и повторите попытку.");
    }
  }

  function intercept(event) {
    if (!event.isTrusted || event.defaultPrevented ||
        event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    if (event.type === "click" && event.button !== 0) return;
    if (event.type === "keydown" && event.key !== "Enter" && event.key !== " ") return;
    const id = cardId(event.target);
    if (!id) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (busy) return;
    busy = true;
    start(id).finally(() => { busy = false; });
  }

  // Capture precedes the dashboard's regular click/key handlers, which retain
  // their normal open-only behavior when the extension is not connected.
  document.addEventListener("click", intercept, true);
  document.addEventListener("keydown", intercept, true);
})();
