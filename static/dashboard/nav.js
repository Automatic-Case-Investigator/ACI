// Boosted navigation — a small custom client router for the ACI dashboard.
//
// Same-origin GET navigations (nav-drawer links, stat cards, segment filters,
// "all …" links, and GET search forms) are intercepted, fetched in the
// background, and the <main class="page"> region is swapped in place — no full
// reload, so the header, nav drawer, theme, and scroll context survive.
//
// Around every swap it calls window.ACIApp.teardown()/init() (see app.js) so
// per-page timers and the session WebSocket are released and re-attached
// cleanly. The session/chatbox page is intentionally excluded (its links carry
// data-no-boost) so its stateful client always starts on a fresh document.
//
// Any failure (non-OK status, network error, cross-origin redirect, or a
// response without <main class="page">) falls back to a hard load so the user
// is never left on a half-swapped page.
(function () {
  "use strict";

  if (!window.history || !window.history.pushState || !window.DOMParser) return;

  history.scrollRestoration = "manual";

  const scrollByUrl = new Map();
  let controller = null;
  let navToken = 0;

  // ── progress affordance ──────────────────────────────────────────────────────
  function setBusy(on) {
    const main = document.querySelector("main.page");
    if (main) main.setAttribute("aria-busy", on ? "true" : "false");
    document.body.classList.toggle("nav-loading", on);
  }

  // ── interception predicates ──────────────────────────────────────────────────
  function isModifiedClick(e) {
    return e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey;
  }

  function boostableLink(a) {
    if (!a || a.target === "_blank" || a.hasAttribute("download")) return null;
    if (a.hasAttribute("data-no-boost") || a.closest("[data-no-boost]")) return null;
    const href = a.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) return null;
    let url;
    try { url = new URL(a.href, location.href); } catch (_) { return null; }
    if (url.origin !== location.origin) return null;
    // Pure same-page hash links (e.g. the settings rail) are handled natively.
    if (url.pathname === location.pathname && url.search === location.search && url.hash) return null;
    return url;
  }

  // ── the swap ─────────────────────────────────────────────────────────────────
  function reexecuteScripts(root) {
    root.querySelectorAll("script").forEach((old) => {
      const fresh = document.createElement("script");
      for (const attr of old.attributes) fresh.setAttribute(attr.name, attr.value);
      fresh.textContent = old.textContent;
      old.replaceWith(fresh);
    });
  }

  function updateChrome(doc) {
    const title = doc.querySelector("title");
    if (title) document.title = title.textContent;

    const nextSub = doc.querySelector(".subtitle");
    const curSub = document.querySelector(".subtitle");
    if (nextSub && curSub) curSub.textContent = nextSub.textContent;

    // The nav drawer lives outside <main class="page">, so copy the server's
    // active-item decision (nav-on) by matching hrefs.
    const nextNav = Array.from(doc.querySelectorAll(".nav-item"));
    document.querySelectorAll(".nav-item").forEach((cur) => {
      const match = nextNav.find((n) => n.getAttribute("href") === cur.getAttribute("href"));
      cur.classList.toggle("nav-on", !!(match && match.classList.contains("nav-on")));
    });
  }

  function applySwap(doc) {
    const nextMain = doc.querySelector("main.page");
    const curMain = document.querySelector("main.page");
    if (!nextMain || !curMain) return false;

    if (window.ACIApp && typeof window.ACIApp.teardown === "function") window.ACIApp.teardown();
    curMain.innerHTML = nextMain.innerHTML;
    reexecuteScripts(curMain);
    updateChrome(doc);
    if (window.ACIApp && typeof window.ACIApp.init === "function") window.ACIApp.init();
    return true;
  }

  function restoreScroll(url, isPop) {
    if (isPop) {
      const y = scrollByUrl.get(url);
      window.scrollTo(0, typeof y === "number" ? y : 0);
      return;
    }
    const hash = new URL(url, location.href).hash;
    if (hash) {
      const target = document.getElementById(hash.slice(1));
      if (target) { target.scrollIntoView(); return; }
    }
    window.scrollTo(0, 0);
  }

  function focusMain() {
    const main = document.querySelector("main.page");
    if (!main) return;
    main.setAttribute("tabindex", "-1");
    try { main.focus({ preventScroll: true }); } catch (_) { main.focus(); }
  }

  // ── navigate ─────────────────────────────────────────────────────────────────
  async function navigate(url, opts) {
    const options = opts || {};
    const isPop = !!options.isPop;
    const token = ++navToken;

    // Remember where we were so Back can restore the scroll position.
    if (!isPop) {
      scrollByUrl.set(location.href, window.scrollY);
    }

    if (controller) controller.abort();
    controller = new AbortController();
    setBusy(true);

    let response;
    try {
      response = await fetch(url, {
        headers: { "X-Requested-With": "fetch" },
        signal: controller.signal,
        credentials: "same-origin",
      });
    } catch (err) {
      if (err && err.name === "AbortError") return; // superseded by a newer nav
      setBusy(false);
      location.assign(url);
      return;
    }

    if (token !== navToken) return; // a newer navigation won

    // Cross-origin redirect (e.g. a login page) or an error → hard load.
    if (!response.ok || new URL(response.url).origin !== location.origin) {
      setBusy(false);
      location.assign(url);
      return;
    }

    let html;
    try { html = await response.text(); } catch (_) { setBusy(false); location.assign(url); return; }
    if (token !== navToken) return;

    const doc = new DOMParser().parseFromString(html, "text/html");
    const finalUrl = response.url || url; // follow same-origin redirects

    if (!applySwap(doc)) {
      setBusy(false);
      location.assign(finalUrl);
      return;
    }

    if (!isPop) history.pushState({ url: finalUrl }, "", finalUrl);
    restoreScroll(isPop ? url : finalUrl, isPop);
    focusMain();
    setBusy(false);
  }

  // ── listeners ────────────────────────────────────────────────────────────────
  document.addEventListener("click", (e) => {
    if (isModifiedClick(e)) return;
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a) return;
    const url = boostableLink(a);
    if (!url) return;
    e.preventDefault();
    if (url.href === location.href) return;
    navigate(url.href, { push: true });
  });

  // GET search / filter forms — submit without a reload.
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!form || form.method.toLowerCase() !== "get") return;
    if (form.hasAttribute("data-no-boost") || form.closest("[data-no-boost]")) return;
    let action;
    try { action = new URL(form.getAttribute("action") || location.href, location.href); } catch (_) { return; }
    if (action.origin !== location.origin) return;
    e.preventDefault();
    const params = new URLSearchParams(new FormData(form));
    action.search = params.toString();
    navigate(action.href, { push: true });
  });

  window.addEventListener("popstate", () => {
    navigate(location.href, { isPop: true });
  });

  // Seed the initial history entry so the first Back has a url to work with.
  history.replaceState({ url: location.href }, "", location.href);
})();
