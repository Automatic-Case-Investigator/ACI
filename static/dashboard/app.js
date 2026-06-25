// Live dashboard client. Opens a WebSocket to the session consumer and swaps
// server-rendered HTML frames into the log / side-panel / status regions.
//
// Rendering tracks (sprint B):
//   • analyst questions + orchestrator answers render as chat bubbles (B1)
//   • consecutive sub-agent (triage/investigation) events group into collapsible
//     agent boxes keyed by run id (B2)
//   • the footer shows an idle/active activity line (B3)
//   • investigation details live in a right-side tab panel (B4)
(function () {
  "use strict";
  function renderStaticMarkdown() {
    if (typeof marked === "undefined") return;
    document.querySelectorAll(".report-body.markdown-body").forEach((body) => {
      if (body.dataset.markdownRendered === "1") return;
      body.innerHTML = marked.parse(body.textContent || "", { breaks: true });
      body.dataset.markdownRendered = "1";
    });
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#39;",
    })[ch]);
  }

  function dashboardActivePage(target) {
    const params = new URLSearchParams(location.search);
    const pageParam = target.dataset.pageParam || "rp";
    const page = Number(params.get(pageParam) || 1);
    return Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
  }

  function renderDashboardActivePager(pager, total, page, pageSize, pageParam) {
    if (!pager) return;
    const pages = Math.ceil(total / pageSize);
    if (pages <= 1) {
      pager.innerHTML = "";
      pager.hidden = true;
      return;
    }
    const current = Math.min(Math.max(page, 1), pages);
    function href(nextPage) {
      const params = new URLSearchParams(location.search);
      params.set(pageParam, String(nextPage));
      return `${location.pathname}?${params.toString()}`;
    }
    const nums = Array.from({ length: pages }, (_, idx) => {
      const n = idx + 1;
      return n === current
        ? `<span class="pager-num pager-cur" aria-current="page">${n}</span>`
        : `<a class="pager-num" href="${escapeHTML(href(n))}">${n}</a>`;
    }).join("");
    pager.hidden = false;
    pager.innerHTML = `
      <nav class="pager" aria-label="Pagination">
        ${current > 1
          ? `<a class="pager-step" href="${escapeHTML(href(current - 1))}" rel="prev">&lsaquo; Prev</a>`
          : `<span class="pager-step pager-off">&lsaquo; Prev</span>`}
        <span class="pager-nums">${nums}</span>
        ${current < pages
          ? `<a class="pager-step" href="${escapeHTML(href(current + 1))}" rel="next">Next &rsaquo;</a>`
          : `<span class="pager-step pager-off">Next &rsaquo;</span>`}
      </nav>
    `;
  }

  function renderDashboardActiveRuns(runs) {
    const target = document.getElementById("active-runs");
    if (!target) return;
    const allRuns = Array.isArray(runs) ? runs : [];
    const pageSize = Math.max(1, Number(target.dataset.pageSize || 8) || 8);
    const pageParam = target.dataset.pageParam || "rp";
    const page = dashboardActivePage(target);
    const params = new URLSearchParams(location.search);
    const query = (params.get("rq") || "").trim().toLowerCase();
    const searchActive = Boolean(query);
    const filteredRuns = query
      ? allRuns.filter((run) => [
        run.run_id,
        run.short_id,
        run.agent_name,
        run.case_id,
        run.question,
        run.status,
      ].some((field) => String(field || "").toLowerCase().includes(query)))
      : allRuns;
    const pages = Math.max(1, Math.ceil(filteredRuns.length / pageSize));
    const current = Math.min(page, pages);
    const visible = filteredRuns.slice((current - 1) * pageSize, current * pageSize);

    if (!visible.length) {
      target.innerHTML = `<tr><td colspan="4" class="muted">${
        searchActive ? "no active runs match this search" : "nothing awaiting inference right now"
      }</td></tr>`;
    } else {
      target.innerHTML = visible.map((run, idx) => {
        const question = run.question || run.case_id || "";
        const status = run.status || "running";
        return `
          <tr style="--i: ${idx}">
            <td class="mono">${escapeHTML(run.short_id || String(run.run_id || "").slice(0, 8))}</td>
            <td class="cell-q">
              <span class="strong">${escapeHTML(run.agent_name || "agent")}</span>
              <span class="muted tiny">${escapeHTML(question)}</span>
            </td>
            <td class="cell-prog"><span class="prog" title="${escapeHTML(status)}"><span class="prog-bar"></span></span></td>
            <td class="muted mono">${escapeHTML(run.age || "")}</td>
          </tr>
        `;
      }).join("");
    }

    renderDashboardActivePager(
      document.getElementById("active-runs-pager"),
      filteredRuns.length,
      current,
      pageSize,
      pageParam
    );
  }

  function bindDashboardIndex() {
    const target = document.getElementById("active-runs");
    if (!target) return null;
    let inFlight = false;
    async function refreshActiveRuns() {
      if (inFlight) return;
      inFlight = true;
      try {
        const response = await fetch("/api/agent/runs/active/", {
          headers: { "Accept": "application/json" },
          cache: "no-store",
        });
        if (!response.ok) return;
        const payload = await response.json();
        renderDashboardActiveRuns(payload.runs);
      } catch (_) {
        // Keep the server-rendered table if the transient refresh fails.
      } finally {
        inFlight = false;
      }
    }
    function onVisibility() {
      if (!document.hidden) refreshActiveRuns();
    }
    refreshActiveRuns();
    const timer = setInterval(refreshActiveRuns, 5000);
    document.addEventListener("visibilitychange", onVisibility);
    return function teardownDashboardIndex() {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }

  // ── Runs page: partial table auto-refresh ───────────────────────────────────
  // Mirrors bindDashboardIndex but reuses the router's full-page parse: fetch the
  // current URL, lift out the runs <tbody>, and swap only that — preserving the
  // seg-bar, search box, and filter chips. No new server endpoint required.
  function bindRunsRefresh() {
    if (!document.querySelector(".runs-toolbar")) return null;
    const tbody = document.getElementById("runs-tbody");
    if (!tbody) return null;
    let inFlight = false;
    async function refreshRuns() {
      if (inFlight || document.hidden) return;
      // Don't clobber a mid-typed search or an in-progress row selection.
      const active = document.activeElement;
      if (active && active.closest && active.closest(".settings-section")) return;
      if (document.querySelector("[data-bulk-item]:checked")) return;
      inFlight = true;
      try {
        const response = await fetch(location.href, {
          headers: { "X-Requested-With": "fetch" },
          cache: "no-store",
        });
        if (!response.ok) return;
        const doc = new DOMParser().parseFromString(await response.text(), "text/html");
        const next = doc.getElementById("runs-tbody");
        const current = document.getElementById("runs-tbody");
        if (next && current) current.innerHTML = next.innerHTML;
      } catch (_) {
        // Keep the existing rows if the transient refresh fails.
      } finally {
        inFlight = false;
      }
    }
    const timer = setInterval(refreshRuns, 5000);
    function onVisibility() {
      if (!document.hidden) refreshRuns();
    }
    document.addEventListener("visibilitychange", onVisibility);
    return function teardownRunsRefresh() {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }

  // ── toasts: auto-dismiss server-rendered messages ──────────────────────────
  function bindToasts() {
    const list = document.querySelector(".settings-msgs");
    if (!list) return null;
    const timers = [];
    list.querySelectorAll(".settings-msg").forEach((msg, idx) => {
      // Errors linger longer so they're not missed.
      const ttl = msg.classList.contains("error") ? 8000 : 4000;
      timers.push(setTimeout(() => {
        msg.classList.add("toast-out");
        timers.push(setTimeout(() => msg.remove(), 320));
      }, ttl + idx * 150));
    });
    return function teardownToasts() {
      timers.forEach(clearTimeout);
    };
  }

  // ── bulk selection (checkbox lists: runs, live sessions) ────────────────────
  // Row checkboxes associate with their form via the HTML `form="..."` attribute,
  // so they live in a swappable <tbody> while the submit lives in a toolbar form.
  // Change events are delegated on document so rows swapped in by the runs
  // auto-refresh stay wired without re-binding.
  function bindBulkSelect() {
    const forms = Array.from(document.querySelectorAll("form[data-bulk]"));
    if (!forms.length) return null;
    const cleanups = [];
    forms.forEach((form) => {
      const id = form.id;
      const items = () => Array.from(document.querySelectorAll('[data-bulk-item][form="' + id + '"]'));
      const all = document.querySelector('[data-bulk-all][data-bulk-for="' + id + '"]');
      const bar = document.querySelector('[data-bulk-bar][data-bulk-for="' + id + '"]');
      const count = bar ? bar.querySelector("[data-bulk-count]") : null;

      function refresh() {
        const list = items();
        const checked = list.filter((c) => c.checked);
        if (count) count.textContent = String(checked.length);
        if (bar) bar.hidden = checked.length === 0;
        if (all) {
          all.checked = list.length > 0 && checked.length === list.length;
          all.indeterminate = checked.length > 0 && checked.length < list.length;
        }
      }
      function onAll() { items().forEach((c) => { c.checked = all.checked; }); refresh(); }
      function onChange(e) {
        if (e.target && e.target.matches && e.target.matches('[data-bulk-item][form="' + id + '"]')) refresh();
      }
      function onSubmit(e) {
        const n = items().filter((c) => c.checked).length;
        if (n === 0) { e.preventDefault(); return; }
        if (!window.confirm("Delete " + n + " selected item(s)? This cannot be undone.")) e.preventDefault();
      }
      if (all) all.addEventListener("change", onAll);
      document.addEventListener("change", onChange);
      form.addEventListener("submit", onSubmit);
      cleanups.push(() => {
        if (all) all.removeEventListener("change", onAll);
        document.removeEventListener("change", onChange);
        form.removeEventListener("submit", onSubmit);
      });
      refresh();
    });
    return function teardownBulkSelect() { cleanups.forEach((fn) => fn()); };
  }

  // ── session client (full page load only — excluded from boosted nav) ─────────
  // Returns a teardown closure (or null on non-session pages) so the router can
  // close the WebSocket and clear timers when the analyst navigates away.
  function initSession() {
  const sid = window.ACI_SESSION_ID;
  if (!sid || !document.getElementById("log")) return null;

  const log = document.getElementById("log");
  const activityEl = document.getElementById("activity");
  const cols = document.getElementById("cols");
  const statusEl = document.getElementById("status");
  const queueEl = document.getElementById("queue");
  const boardPanelEl = document.getElementById("board-panel");
  const verdictPanelEl = document.getElementById("verdict-panel");
  const sidePanelEl = document.getElementById("side-panel");
  const sidePanelToggleEl = document.getElementById("side-panel-toggle");
  const sidePanelCloseEl = document.getElementById("side-panel-close");
  const sidePanelResizeEl = document.getElementById("side-panel-resize");
  const mobileViewSwitch = document.getElementById("mobile-view-switch");
  const spinnerCharEl = document.getElementById("spinner-char");
  const idleDotEl = document.getElementById("idle-dot");
  const activityTextEl = document.getElementById("activity-text");
  const askBtn = document.getElementById("ask-btn");
  const ctxArc = document.getElementById("ctx-arc");
  const ctxRing = document.getElementById("ctx-ring");
  const ctxTitle = document.getElementById("ctx-title");
  const CTX_CIRC = 87.96; // 2π × 14
  let ws;
  const SIDE_PANEL_WIDTH_KEY = `aci:${sid}:side-panel-width`;

  const AGENT_NAME = { tri: "triage", inv: "investigation", orch: "orchestrator" };
  const ACTOR_LABEL = {
    orch: "orchestrator thinking",
    inv: "investigation running",
    tri: "triage running",
  };

  // ── context ring ────────────────────────────────────────────────────────────
  function ctxAge(ts) {
    if (!ts) return "";
    const secs = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (secs < 5) return " · just now";
    if (secs < 60) return ` · ${secs}s ago`;
    if (secs < 3600) return ` · ${Math.round(secs / 60)}m ago`;
    return ` · ${Math.round(secs / 3600)}h ago`;
  }

  function updateCtx(tokens, limit, source, runId, ts) {
    if (!ctxArc || !limit) return;
    const frac = Math.min(tokens / limit, 1);
    ctxArc.style.strokeDashoffset = (CTX_CIRC * (1 - frac)).toFixed(2);
    const pct = Math.round(frac * 100);
    ctxArc.style.stroke = frac < 0.7 ? "var(--result)" : frac < 0.9 ? "var(--call)" : "var(--error)";
    if (ctxTitle) {
      const who = source ? `${source}${runId ? ` ${String(runId).slice(0, 8)}` : ""}: ` : "";
      ctxTitle.textContent =
        `${who}${tokens.toLocaleString()} / ${limit.toLocaleString()} tokens (${pct}%)${ctxAge(ts)}`;
    }
  }

  function initCtx() {
    if (!ctxRing) return;
    const tokens = Number(ctxRing.dataset.ctxTokens || 0);
    const limit = Number(ctxRing.dataset.ctxLimit || 0);
    const ts = Number(ctxRing.dataset.ctxTs || 0) || null;
    updateCtx(tokens, limit, ctxRing.dataset.ctxSource || "", ctxRing.dataset.ctxRunId || "", ts);
  }

  // ── spinner / idle / stop-button (B3) ───────────────────────────────────────
  const SPIN_CHARS = ["|", "/", "-", "\\"];
  let spinIdx = 0;
  let spinTimer = null;

  function setProcessing(active, source) {
    if (active) {
      if (idleDotEl) idleDotEl.hidden = true;
      if (spinnerCharEl) spinnerCharEl.hidden = false;
      if (activityTextEl) activityTextEl.textContent = (ACTOR_LABEL[source] || "working") + "…";
      if (!spinTimer) {
        spinTimer = setInterval(() => {
          spinIdx = (spinIdx + 1) % SPIN_CHARS.length;
          if (spinnerCharEl) spinnerCharEl.textContent = SPIN_CHARS[spinIdx];
        }, 150);
      }
      if (atBottom()) scrollBottom();
      if (askBtn) {
        askBtn.textContent = "stop";
        askBtn.type = "button"; // bypass required-field validation
        askBtn.onclick = () => send({ action: "stop" });
      }
    } else {
      if (spinnerCharEl) spinnerCharEl.hidden = true;
      if (idleDotEl) idleDotEl.hidden = false;
      if (activityTextEl) activityTextEl.textContent = "ready";
      clearInterval(spinTimer);
      spinTimer = null;
      if (askBtn) {
        askBtn.textContent = "ask";
        askBtn.type = "submit";
        askBtn.onclick = null;
      }
    }
  }

  // ── helpers ─────────────────────────────────────────────────────────────────
  function atBottom() {
    if (!log) return false;
    return log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  }
  function scrollBottom() {
    if (log) log.scrollTop = log.scrollHeight;
  }
  function send(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  }
  function parseFragment(html) {
    const t = document.createElement("template");
    t.innerHTML = (html || "").trim();
    return t.content;
  }
  function parseHTML(html) {
    return parseFragment(html).firstElementChild;
  }
  function emptySidePanelText(text) {
    const div = document.createElement("div");
    div.className = "side-empty muted";
    div.textContent = text;
    return div;
  }
  function appendLogChild(node) {
    if (!log || !node) return;
    if (activityEl && activityEl.parentElement === log) {
      log.insertBefore(node, activityEl);
    } else {
      log.appendChild(node);
    }
  }

  function isMobileLayout() {
    return window.matchMedia && window.matchMedia("(max-width: 760px)").matches;
  }

  function clampSidePanelWidth(width) {
    const min = 300;
    if (!cols || isMobileLayout()) return width;
    const available = cols.clientWidth || window.innerWidth || 0;
    const max = Math.max(min, Math.min(720, available - 360));
    return Math.min(Math.max(width, min), max);
  }

  function setSidePanelWidth(width, persist) {
    if (!sidePanelEl || isMobileLayout()) return;
    const next = clampSidePanelWidth(width);
    sidePanelEl.style.setProperty("--side-panel-width", `${Math.round(next)}px`);
    if (persist) localStorage.setItem(SIDE_PANEL_WIDTH_KEY, String(Math.round(next)));
  }

  function restoreSidePanelWidth() {
    const stored = Number(localStorage.getItem(SIDE_PANEL_WIDTH_KEY));
    if (Number.isFinite(stored) && stored > 0) setSidePanelWidth(stored, false);
  }

  function setSidePanelOpen(open) {
    if (!sidePanelEl) return;
    sidePanelEl.classList.toggle("open", open);
    sidePanelEl.setAttribute("aria-hidden", open ? "false" : "true");
    if (cols) cols.classList.toggle("side-panel-open", open);
    if (sidePanelToggleEl) sidePanelToggleEl.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function setSideTab(name) {
    if (!sidePanelEl) return;
    sidePanelEl.querySelectorAll("[data-side-tab]").forEach((button) => {
      const active = button.dataset.sideTab === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    });
    sidePanelEl.querySelectorAll("[data-side-pane]").forEach((pane) => {
      pane.classList.toggle("active", pane.dataset.sidePane === name);
    });
  }

  // Named so the session teardown can remove it (anonymous window listeners leak
  // across a boosted navigation away from the session page).
  function onSidePanelWindowResize() {
    if (!sidePanelEl) return;
    const current = sidePanelEl.getBoundingClientRect().width;
    if (current > 0) setSidePanelWidth(current, false);
  }

  function bindSidePanel() {
    if (!sidePanelEl) return;
    restoreSidePanelWidth();
    if (sidePanelToggleEl) {
      sidePanelToggleEl.onclick = () => setSidePanelOpen(!sidePanelEl.classList.contains("open"));
    }
    if (sidePanelCloseEl) {
      sidePanelCloseEl.onclick = () => setSidePanelOpen(false);
    }
    sidePanelEl.querySelectorAll("[data-side-tab]").forEach((button) => {
      button.onclick = () => setSideTab(button.dataset.sideTab);
    });
    if (sidePanelResizeEl) {
      sidePanelResizeEl.addEventListener("pointerdown", (event) => {
        if (isMobileLayout()) return;
        event.preventDefault();
        const startX = event.clientX;
        const startWidth = sidePanelEl.getBoundingClientRect().width;
        sidePanelEl.classList.add("resizing");
        document.body.classList.add("resizing-side-panel");
        sidePanelResizeEl.setPointerCapture?.(event.pointerId);
        const onMove = (moveEvent) => {
          setSidePanelWidth(startWidth + (startX - moveEvent.clientX), true);
        };
        const onUp = () => {
          sidePanelEl.classList.remove("resizing");
          document.body.classList.remove("resizing-side-panel");
          window.removeEventListener("pointermove", onMove);
          window.removeEventListener("pointerup", onUp);
          window.removeEventListener("pointercancel", onUp);
        };
        window.addEventListener("pointermove", onMove);
        window.addEventListener("pointerup", onUp);
        window.addEventListener("pointercancel", onUp);
      });
    }
    window.addEventListener("resize", onSidePanelWindowResize);
  }

  // Apply the "selected" class to the button matching `verdict` (resolving the
  // confirm button against the agent verdict). The server renders this on every
  // status frame; this is only needed for the optimistic click-time update.
  function highlightFeedback(fb, verdict) {
    if (!fb) return;
    const card = fb.closest(".verdict-card");
    const agentVerdict = card ? (card.getAttribute("data-verdict-value") || "") : "";
    fb.querySelectorAll(".fb-btn").forEach((b) => {
      const bv = b.getAttribute("data-verdict");
      // Confirm wins when the analyst verdict equals the agent verdict; a dispute
      // button highlights only when the analyst chose a value differing from it,
      // so a confirmed fp/tp never lights up two buttons. Mirrors _verdict.html.
      const selected = bv === "confirm"
        ? (!!agentVerdict && agentVerdict === verdict)
        : (bv === verdict && verdict !== agentVerdict);
      b.classList.toggle("fb-selected", selected);
    });
  }

  function updateStatusPanel(html) {
    const fragment = parseFragment(html);
    const statusbar = fragment.querySelector(".statusbar");
    const verdict = fragment.querySelector(".verdict-card");
    if (statusEl && statusbar) {
      statusEl.innerHTML = "";
      statusEl.appendChild(statusbar);
    } else if (statusEl) {
      statusEl.innerHTML = html;
    }
    if (verdictPanelEl) {
      verdictPanelEl.innerHTML = "";
      if (verdict) {
        verdictPanelEl.appendChild(verdict);
      } else {
        verdictPanelEl.appendChild(emptySidePanelText("no verdict yet"));
      }
    }
  }

  function updateInvestigationPanel(html, showQueue) {
    const fragment = parseFragment(html);
    const queue = fragment.querySelector(".queue");
    // The board panel can contain multiple sections (findings + threat intel).
    const boards = fragment.querySelectorAll(".board");
    if (queueEl) {
      queueEl.innerHTML = "";
      queueEl.appendChild(queue || emptySidePanelText("no tasks yet"));
    }
    if (boardPanelEl) {
      boardPanelEl.innerHTML = "";
      if (boards.length) {
        boards.forEach((b) => boardPanelEl.appendChild(b));
      } else {
        boardPanelEl.appendChild(emptySidePanelText("no board entries yet"));
      }
    }
    bindQueue();
    if (sidePanelEl) sidePanelEl.classList.toggle("has-work", !!showQueue);
  }

  // ── log placement: bubbles flat, sub-agent traces grouped into boxes (B1/B2) ──
  let currentBox = null; // { run, body }
  let currentStream = null; // { key, node, body, raw }
  const intentStreams = new Map(); // run/source/sequence -> { node, body, raw }

  function openBox(run, src) {
    const box = document.createElement("details");
    box.className = "agent-box";
    box.open = true;
    box.dataset.run = run;
    const head = document.createElement("summary");
    head.className = "agent-box-head src-" + src;
    head.textContent = `${AGENT_NAME[src] || src} · ${String(run).slice(0, 8)}`;
    const body = document.createElement("div");
    body.className = "agent-box-body";
    box.appendChild(head);
    box.appendChild(body);
    appendLogChild(box);
    return { run, body };
  }

  function renderMarkdown(node) {
    if (!node || !node.classList) return;
    const body = node.classList.contains("bubble-assistant")
      ? node.querySelector(".bubble-body")
      : node.querySelector(".markdown-body");
    if (!body || typeof marked === "undefined") return;
    body.innerHTML = marked.parse(body.textContent, { breaks: true });
    body.dataset.markdownRendered = "1";
  }

  function appendStreamChunk(meta, fallbackNode) {
    if (!log) return;
    const src = meta.source || (fallbackNode && fallbackNode.dataset && fallbackNode.dataset.src) || "orch";
    const run = meta.run_id || (fallbackNode && fallbackNode.dataset && fallbackNode.dataset.run) || "";
    const delta = meta.detail || (fallbackNode && fallbackNode.dataset && fallbackNode.dataset.delta) || "";
    if (!delta) return;

    const key = `${src}:${run || "session"}`;
    if (!currentStream || currentStream.key !== key) {
      const node = document.createElement("div");
      node.className = "bubble bubble-assistant bubble-streaming";
      node.dataset.src = src;
      node.dataset.run = run;
      const body = document.createElement("div");
      body.className = "bubble-body";
      node.appendChild(body);
      appendLogChild(node);
      currentBox = null;
      currentStream = { key, node, body, raw: "" };
    }
    currentStream.raw += delta;
    if (typeof marked !== "undefined") {
      currentStream.body.innerHTML = marked.parse(currentStream.raw, { breaks: true });
    } else {
      currentStream.body.textContent = currentStream.raw;
    }
  }

  function finalizeStream(meta) {
    if (!currentStream) return false;
    const src = meta.source || "orch";
    const run = meta.run_id || "";
    const key = `${src}:${run || "session"}`;
    if (currentStream.key !== key) return false;
    const finalText = meta.detail || currentStream.raw;
    currentStream.raw = finalText;
    currentStream.node.classList.remove("bubble-streaming");
    currentStream.node.dataset.seq = meta.seq || currentStream.node.dataset.seq || "";
    if (typeof marked !== "undefined") {
      currentStream.body.innerHTML = marked.parse(finalText, { breaks: true });
    } else {
      currentStream.body.textContent = finalText;
    }
    currentStream = null;
    return true;
  }

  function intentKey(meta) {
    const src = meta.source || "orch";
    const run = meta.run_id || "session";
    const sequence = (meta.metadata && meta.metadata.intent_sequence) || meta.intent_sequence || "";
    return `${src}:${run}:${sequence}`;
  }

  function traceParent(run, src) {
    if (run && (src === "inv" || src === "tri")) {
      if (!currentBox || currentBox.run !== run) currentBox = openBox(run, src);
      return currentBox.body;
    }
    currentBox = null;
    return log;
  }

  function appendIntentChunk(meta) {
    if (!log) return;
    const delta = meta.detail || "";
    if (!delta) return;
    const key = intentKey(meta);
    let stream = intentStreams.get(key);
    if (!stream) {
      const node = document.createElement("div");
      node.className = "logline ev-intent intent-streaming";
      node.dataset.run = meta.run_id || "";
      node.dataset.src = meta.source || "orch";
      node.dataset.kind = "intent_delta";
      node.dataset.intent = (meta.metadata && meta.metadata.intent_sequence) || "";
      const glyph = document.createElement("span");
      glyph.className = "glyph";
      glyph.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>';
      glyph.title = "Public reasoning summary";
      const body = document.createElement("span");
      body.className = "line-body summary-only intent-body";
      node.appendChild(glyph);
      node.appendChild(body);
      const parent = traceParent(meta.run_id || "", meta.source || "orch");
      if (parent === log) appendLogChild(node);
      else parent.appendChild(node);
      stream = { node, body, raw: "" };
      intentStreams.set(key, stream);
    }
    stream.raw += delta;
    if (typeof marked !== "undefined") {
      stream.body.innerHTML = marked.parse(stream.raw, { breaks: true });
    } else {
      stream.body.textContent = stream.raw;
    }
  }

  function finalizeIntent(meta, node) {
    const key = intentKey(meta);
    const stream = intentStreams.get(key);
    if (!stream) return false;
    renderMarkdown(node);
    stream.node.replaceWith(node);
    intentStreams.delete(key);
    return true;
  }

  function clearStreamIfFinal(node) {
    if (!node || !node.dataset || !currentStream) return;
    const kind = node.dataset.kind || "";
    const src = node.dataset.src || "";
    const run = node.dataset.run || "";
    const same = currentStream.key === `${src}:${run || "session"}`;
    if (same && kind !== "stream") currentStream = null;
  }

  function placeLine(node) {
    if (!node || !log) return;
    if (node.classList && node.classList.contains("stream-fragment")) {
      appendStreamChunk({}, node);
      return;
    }
    // Defense-in-depth against duplicates: a persisted event carries a per-session
    // seq. If a node with that seq is already in the log (e.g. it was rendered
    // server-side and the stream re-pushed it), skip it instead of painting twice.
    const seq = node.dataset && node.dataset.seq;
    if (seq && log.querySelector(`[data-seq="${seq}"]`)) return;
    const isBubble = node.classList && node.classList.contains("bubble");
    const run = node.dataset ? node.dataset.run : "";
    const src = node.dataset ? node.dataset.src : "";
    const groupable = !isBubble && run && (src === "inv" || src === "tri");
    if (groupable) {
      if (!currentBox || currentBox.run !== run) currentBox = openBox(run, src);
      currentBox.body.appendChild(node);
    } else {
      currentBox = null;
      appendLogChild(node);
    }
    clearStreamIfFinal(node);
    renderMarkdown(node);
  }

  // Re-group the server-rendered (flat) initial events into boxes/bubbles.
  function regroupInitial() {
    if (!log) return;
    const nodes = Array.from(log.children).filter((node) => node !== activityEl);
    log.innerHTML = "";
    if (activityEl) log.appendChild(activityEl);
    currentBox = null;
    nodes.forEach(placeLine);
    scrollBottom();
  }

  // ── edit dialog ─────────────────────────────────────────────────────────────
  function bindEditDialog() {
    const dialog = document.getElementById("task-edit-dialog");
    if (!dialog) return;
    document.getElementById("task-edit-form").onsubmit = () => {
      send({
        action: "edit",
        task_id: document.getElementById("edit-task-id").value,
        title: document.getElementById("edit-task-title").value.trim(),
        description: document.getElementById("edit-task-desc").value.trim(),
        priority: document.getElementById("edit-task-priority").value,
      });
    };
    document.getElementById("edit-cancel").onclick = () => dialog.close();
  }

  function openEditDialog(taskId, title, description, priority) {
    const dialog = document.getElementById("task-edit-dialog");
    if (!dialog) return;
    document.getElementById("edit-task-id").value = taskId;
    document.getElementById("edit-task-title").value = title;
    document.getElementById("edit-task-desc").value = description;
    document.getElementById("edit-task-priority").value = priority;
    dialog.showModal();
  }

  // ── queue bindings ──────────────────────────────────────────────────────────
  function bindQueue() {
    if (!queueEl) return;
    queueEl.querySelectorAll("[data-action]").forEach((el) => {
      if (el.tagName === "FORM") {
        el.onsubmit = (e) => {
          e.preventDefault();
          const fd = new FormData(el);
          send({ action: "add", title: fd.get("title"), priority: fd.get("priority") });
          el.reset();
        };
      } else {
        el.onclick = () => {
          const action = el.dataset.action;
          const task = el.dataset.task;
          if (action === "del") {
            send({ action: "del", task_id: task });
          } else if (action === "move") {
            const row = el.closest("[data-index]");
            const idx = parseInt((row && row.dataset.index) || "1", 10);
            const pos = el.dataset.dir === "up" ? idx - 1 : idx + 1;
            send({ action: "move", task_id: task, position: pos });
          } else if (action === "edit") {
            const row = el.closest("tr");
            const title = el.dataset.title || row.querySelector(".title-text")?.textContent?.trim() || "";
            const desc = row.querySelector(".task-desc-body")?.textContent?.trim() || "";
            const pri = el.dataset.priority || row.querySelector(".pri")?.textContent?.trim() || "50";
            openEditDialog(task, title, desc, pri);
          }
        };
      }
    });
  }

  // ── ask / stop form ─────────────────────────────────────────────────────────
  function bindAskForm() {
    const form = document.getElementById("ask-follow-up");
    if (!form) return;
    form.onsubmit = (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const question = (fd.get("question") || "").trim();
      if (question) {
        send({ action: "ask", question });
        form.reset();
      }
    };
  }

  function setMobileView(view) {
    if (!cols || !mobileViewSwitch) return;
    const queueAvailable = !cols.classList.contains("no-queue");
    const next = view === "queue" && queueAvailable ? "queue" : "activity";
    cols.classList.toggle("mobile-show-activity", next === "activity");
    cols.classList.toggle("mobile-show-queue", next === "queue");
    mobileViewSwitch.querySelectorAll("[data-view]").forEach((button) => {
      const active = button.dataset.view === next;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function bindMobileViewSwitch() {
    if (!mobileViewSwitch) return;
    mobileViewSwitch.querySelectorAll("[data-view]").forEach((button) => {
      button.onclick = () => setMobileView(button.dataset.view);
    });
  }

  // ── WebSocket ───────────────────────────────────────────────────────────────
  // Highest persisted-event id already shown. Seeds from the server-rendered
  // page so the stream resumes after the initial events (no duplicate first
  // bubble) and advances as new events arrive so reconnects don't replay.
  let lastCursor = Number(window.ACI_CURSOR) || 0;

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws/runs/${sid}/?after=${lastCursor}`);
    ws.onmessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch (_) { return; }

      if (m.type === "log" && log) {
        if (m.id && m.id > lastCursor) lastCursor = m.id;
        const stick = atBottom();
        if (m.kind === "stream") {
          appendStreamChunk(m, null);
        } else if (m.kind === "intent_delta") {
          appendIntentChunk(m);
        } else if (m.kind === "answer" && finalizeStream(m)) {
          // Final answer already visible as a streaming bubble; just remove the caret.
        } else {
          const node = parseHTML(m.html);
          if (!(m.kind === "intent" && finalizeIntent(m, node))) placeLine(node);
        }
        if (stick) scrollBottom();
      } else if (m.type === "status" && statusEl) {
        updateStatusPanel(m.html);
        setProcessing(!!m.processing, m.processing_source || m.ctx_source);
        if (m.ctx_limit) updateCtx(m.ctx_tokens || 0, m.ctx_limit, m.ctx_source, m.ctx_run_id, m.ctx_ts);
      } else if (m.type === "queue" && queueEl) {
        updateInvestigationPanel(m.html, m.show_queue);
        if (cols) cols.classList.toggle("no-queue", !m.show_queue);
        if (mobileViewSwitch) mobileViewSwitch.classList.toggle("no-queue", !m.show_queue);
        if (!m.show_queue) setMobileView("activity");
      }
    };
    ws.onclose = () => setTimeout(connect, 1000);
  }

  // ── verdict feedback ────────────────────────────────────────────────────────
  function getCookie(name) {
    const m = document.cookie.match("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)");
    return m ? m.pop() : "";
  }

  function bindFeedback() {
    const feedbackRoot = sidePanelEl || statusEl;
    if (!feedbackRoot) return;
    feedbackRoot.addEventListener("click", (e) => {
      const btn = e.target.closest(".fb-btn");
      if (!btn) return;
      const card = btn.closest(".verdict-card");
      const fbDiv = btn.closest(".verdict-feedback");
      const runId = card && card.getAttribute("data-run-id");
      if (!runId) return;
      let verdict = btn.getAttribute("data-verdict");
      if (verdict === "confirm") verdict = card.getAttribute("data-verdict-value") || "";
      if (!verdict) return;
      const setVerdict = (v) => {
        if (!fbDiv) return;
        highlightFeedback(fbDiv, v);
        fbDiv.dataset.analystVerdict = v;
      };
      const prevVerdict = fbDiv ? (fbDiv.dataset.analystVerdict || "") : "";
      setVerdict(verdict); // optimistic
      fetch(`/api/agent/runs/${runId}/feedback/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": getCookie("csrftoken") },
        body: JSON.stringify({ analyst_verdict: verdict }),
      })
        .then((r) => {
          const ack = card.querySelector(".fb-ack");
          if (!r.ok) {
            setVerdict(prevVerdict);
            if (ack) { ack.hidden = false; ack.textContent = "failed"; }
            return;
          }
          if (ack) {
            ack.hidden = false;
            ack.textContent = "saved";
            setTimeout(() => { ack.hidden = true; }, 2000);
          }
        })
        .catch(() => setVerdict(prevVerdict));
    });
  }

  regroupInitial();
  initCtx();
  bindQueue();
  bindAskForm();
  bindMobileViewSwitch();
  bindSidePanel();
  bindEditDialog();
  bindFeedback();
  connect();

  return function teardownSession() {
    if (ws) {
      ws.onclose = null; // stop the auto-reconnect
      try { ws.close(); } catch (_) {}
    }
    clearInterval(spinTimer);
    spinTimer = null;
    window.removeEventListener("resize", onSidePanelWindowResize);
  };
  }

  // ── lifecycle registry ───────────────────────────────────────────────────────
  // The boosted-nav router (nav.js) calls ACIApp.teardown() before swapping page
  // content and ACIApp.init() after, so per-page bindings re-attach cleanly and
  // timers/sockets from the previous page are released.
  let _teardowns = [];

  function initApp() {
    renderStaticMarkdown();
    [bindDashboardIndex(), bindRunsRefresh(), bindToasts(), bindBulkSelect(), initSession()].forEach((fn) => {
      if (typeof fn === "function") _teardowns.push(fn);
    });
  }

  function teardownApp() {
    _teardowns.forEach((fn) => { try { fn(); } catch (_) {} });
    _teardowns = [];
  }

  window.ACIApp = { init: initApp, teardown: teardownApp };
  initApp();
})();
