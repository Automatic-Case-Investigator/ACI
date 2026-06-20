// Live dashboard client. Opens a WebSocket to the session consumer and swaps
// server-rendered HTML frames into the log / queue / status regions.
//
// Rendering tracks (sprint B):
//   • analyst questions + orchestrator answers render as chat bubbles (B1)
//   • consecutive sub-agent (triage/investigation) events group into collapsible
//     agent boxes keyed by run id (B2)
//   • the footer shows an idle/active activity line (B3)
//   • the queue column appears only when investigation has work (B4)
(function () {
  "use strict";
  const sid = window.ACI_SESSION_ID;
  if (!sid) return;

  const log = document.getElementById("log");
  const cols = document.getElementById("cols");
  const statusEl = document.getElementById("status");
  const queueEl = document.getElementById("queue");
  const mobileViewSwitch = document.getElementById("mobile-view-switch");
  const spinnerCharEl = document.getElementById("spinner-char");
  const idleDotEl = document.getElementById("idle-dot");
  const activityTextEl = document.getElementById("activity-text");
  const askBtn = document.getElementById("ask-btn");
  const ctxArc = document.getElementById("ctx-arc");
  const ctxTitle = document.getElementById("ctx-title");
  const CTX_CIRC = 87.96; // 2π × 14
  let ws;

  const AGENT_NAME = { tri: "triage", inv: "investigation", orch: "orchestrator" };
  const ACTOR_LABEL = {
    orch: "orchestrator thinking",
    inv: "investigation running",
    tri: "triage running",
  };

  // ── context ring ────────────────────────────────────────────────────────────
  function updateCtx(tokens, limit, source, runId) {
    if (!ctxArc || !limit) return;
    const frac = Math.min(tokens / limit, 1);
    ctxArc.style.strokeDashoffset = (CTX_CIRC * (1 - frac)).toFixed(2);
    const pct = Math.round(frac * 100);
    ctxArc.style.stroke = frac < 0.7 ? "var(--result)" : frac < 0.9 ? "var(--call)" : "var(--error)";
    if (ctxTitle) {
      const who = source ? `${source}${runId ? ` ${String(runId).slice(0, 8)}` : ""}: ` : "";
      ctxTitle.textContent = `${who}${tokens.toLocaleString()} / ${limit.toLocaleString()} tokens (${pct}%)`;
    }
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
        askBtn.textContent = "■ stop";
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
  function parseHTML(html) {
    const t = document.createElement("template");
    t.innerHTML = (html || "").trim();
    return t.content.firstElementChild;
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
    log.appendChild(box);
    return { run, body };
  }

  function renderMarkdown(node) {
    if (!node || !node.classList) return;
    const body = node.classList.contains("bubble-assistant")
      ? node.querySelector(".bubble-body")
      : node.querySelector(".markdown-body");
    if (!body || typeof marked === "undefined") return;
    body.innerHTML = marked.parse(body.textContent, { breaks: true });
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
      log.appendChild(node);
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
      glyph.textContent = "»";
      glyph.title = "Public reasoning summary";
      const body = document.createElement("span");
      body.className = "line-body summary-only intent-body";
      node.appendChild(glyph);
      node.appendChild(body);
      traceParent(meta.run_id || "", meta.source || "orch").appendChild(node);
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
      log.appendChild(node);
    }
    clearStreamIfFinal(node);
    renderMarkdown(node);
  }

  // Re-group the server-rendered (flat) initial events into boxes/bubbles.
  function regroupInitial() {
    if (!log) return;
    const nodes = Array.from(log.children);
    log.innerHTML = "";
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
        statusEl.innerHTML = m.html;
        setProcessing(!!m.processing, m.ctx_source);
        if (m.ctx_limit) updateCtx(m.ctx_tokens || 0, m.ctx_limit, m.ctx_source, m.ctx_run_id);
      } else if (m.type === "queue" && queueEl) {
        queueEl.innerHTML = m.html;
        bindQueue();
        if (cols) cols.classList.toggle("no-queue", !m.show_queue);
        if (mobileViewSwitch) mobileViewSwitch.classList.toggle("no-queue", !m.show_queue);
        if (!m.show_queue) setMobileView("activity");
      }
    };
    ws.onclose = () => setTimeout(connect, 1000);
  }

  regroupInitial();
  bindQueue();
  bindAskForm();
  bindMobileViewSwitch();
  bindEditDialog();
  connect();
})();
