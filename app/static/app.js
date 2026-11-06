"use strict";
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  if (window.htmx) {
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
    window.htmx.on("htmx:configRequest", (event) => {
      if (csrf) event.detail.headers["X-CSRF-Token"] = csrf;
    });
  }
  document.addEventListener("htmx:confirm", (event) => {
    const form = event.detail?.elt;
    const message = form instanceof HTMLFormElement ? form.dataset.confirm : "";
    if (!message) return;
    event.preventDefault();
    if (window.confirm(message)) event.detail.issueRequest(true);
  });
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.hasAttribute("hx-post")) return;
    const message = form.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });
  // Failed htmx actions (409 busy, 422 invalid) return the error page; show its message inline.
  document.addEventListener("htmx:beforeSwap", (event) => {
    const xhr = event.detail.xhr;
    if (!xhr || xhr.status < 400) return;
    let message = "The request could not be completed.";
    try {
      const doc = new DOMParser().parseFromString(xhr.responseText || "", "text/html");
      const text = doc.querySelector(".auth-card p")?.textContent?.trim();
      if (text) message = text;
    } catch (_) { /* keep default */ }
    const box = document.createElement("div");
    box.className = "alert alert-error";
    box.setAttribute("role", "alert");
    box.textContent = message;
    event.detail.shouldSwap = false;
    const target = event.detail.target;
    if (target) target.replaceChildren(box);
  });
  // Copy buttons for one-time secrets.
  document.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-copy]") : null;
    if (!button) return;
    const source = document.getElementById(button.dataset.copy || "");
    if (!source || !navigator.clipboard) return;
    navigator.clipboard.writeText(source.textContent || "").then(() => {
      const label = button.lastChild;
      if (label && label.nodeType === Node.TEXT_NODE) {
        const previous = label.textContent;
        label.textContent = "Copied";
        setTimeout(() => { label.textContent = previous; }, 1500);
      }
    }).catch(() => {});
  });
  const consoleRoot = document.querySelector("[data-socket]");
  const openButton = document.querySelector("[data-console-open]");
  if (!consoleRoot || !openButton) return;
  openButton.addEventListener("click", () => {
    if (!window.Terminal) {
      showError("The local terminal client did not load. Refresh the page and try again.");
      return;
    }
    const placeholder = consoleRoot.querySelector(".console-placeholder");
    if (placeholder) placeholder.remove();
    const term = new window.Terminal({ cursorBlink: true, convertEol: true, fontFamily: '"SFMono-Regular", Consolas, monospace', fontSize: 13, theme: { background: "#0a0c0e", foreground: "#e9edf1", cursor: "#2f6bd6" } });
    term.open(consoleRoot);
    const fit = window.FitAddon ? new window.FitAddon.FitAddon() : null;
    if (fit) { term.loadAddon(fit); fit.fit(); }
    const socketPath = consoleRoot.dataset.socket;
    if (!socketPath || !/^\/ws\/machines\/vm-[a-z0-9]{5}\/console$/.test(socketPath)) {
      term.dispose(); showError("This machine does not have a valid console address."); return;
    }
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${scheme}//${window.location.host}${socketPath}`);
    socket.binaryType = "arraybuffer";
    socket.addEventListener("open", () => { term.writeln("\x1b[36mSecure console connected.\x1b[0m"); if (fit) fit.fit(); term.focus(); });
    socket.addEventListener("message", (event) => {
      if (event.data instanceof ArrayBuffer) term.write(new Uint8Array(event.data));
      else term.write(String(event.data));
    });
    socket.addEventListener("close", () => term.writeln("\r\n\x1b[90mConsole connection closed.\x1b[0m"));
    socket.addEventListener("error", () => term.writeln("\r\n\x1b[31mUnable to connect to the machine console.\x1b[0m"));
    term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(new TextEncoder().encode(data));
    });
    window.addEventListener("resize", () => { if (fit) fit.fit(); }, { passive: true });
  }, { once: true });
  function showError(message) {
    const notice = document.createElement("p");
    notice.className = "console-error";
    notice.setAttribute("role", "alert");
    notice.textContent = message;
    consoleRoot.replaceChildren(notice);
  }
})();

