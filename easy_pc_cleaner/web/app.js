(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const state = { server: null, plan: null, busy: new Set() };
  const token = document.querySelector('meta[name="api-token"]')?.content || "";

  function text(value, fallback = "—") {
    if (value === null || value === undefined || value === "") return fallback;
    return String(value);
  }

  function bytes(value) {
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let index = 0;
    let result = number;
    while (result >= 1024 && index < units.length - 1) { result /= 1024; index += 1; }
    return `${result >= 10 || index === 0 ? result.toFixed(0) : result.toFixed(1)} ${units[index]}`;
  }

  function date(value) {
    if (!value) return "No report yet";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? text(value) : parsed.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function el(tag, options = {}) {
    const node = document.createElement(tag);
    if (options.className) node.className = options.className;
    if (options.text !== undefined) node.textContent = text(options.text, "");
    if (options.scope) node.scope = options.scope;
    return node;
  }

  function message(value, kind = "success") {
    const target = $("notice");
    target.textContent = text(value, "Ready.");
    target.hidden = false;
    target.classList.toggle("is-error", kind === "error");
  }

  function clearMessage() {
    const target = $("notice");
    target.hidden = true;
    target.textContent = "";
    target.classList.remove("is-error");
  }

  function setBusy(button, active, label) {
    if (!button) return;
    if (active) {
      state.busy.add(button);
      button.dataset.label = button.textContent;
      button.textContent = label || "Working…";
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    } else {
      state.busy.delete(button);
      if (button.dataset.label) button.textContent = button.dataset.label;
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  function headers() {
    const result = { Accept: "application/json" };
    if (token && token !== "__EPC_TOKEN__") result["X-Easy-PC-Token"] = token;
    return result;
  }

  async function api(path, options = {}) {
    const init = { method: options.method || "GET", headers: headers() };
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch {
      throw new Error("The local service is not reachable. Start Easy PC Cleaner and refresh this page.");
    }
    let payload = null;
    try { payload = await response.json(); } catch { /* server status below is enough */ }
    if (!response.ok) {
      const detail = payload && typeof payload.error === "string" ? payload.error : `Local service returned ${response.status}.`;
      throw new Error(detail);
    }
    return payload || {};
  }

  function summaryValue(report, keys, fallback = "—") {
    const source = report && typeof report.summary === "object" ? report.summary : report || {};
    for (const key of keys) if (source[key] !== undefined && source[key] !== null) return source[key];
    return fallback;
  }

  function describeReport(report) {
    if (!report || typeof report !== "object") return "No details available.";
    const kind = text(report.kind || report.type || report.status, "Local report");
    const deleted = summaryValue(report, ["deletedFiles", "deletedCount"], null);
    const released = summaryValue(report, ["deletedBytes", "candidateBytes"], null);
    if (deleted !== null && released !== null) return `${kind}: ${deleted} file(s), ${bytes(released)}.`;
    if (report.summary && typeof report.summary === "string") return `${kind}: ${report.summary}`;
    return kind;
  }

  function updateState(server) {
    state.server = server || {};
    const autopilot = state.server.autopilot || {};
    const policy = state.server.policy || {};
    const age = policy.minAgeDays ?? policy.min_age_days ?? 7;
    const configuredBytes = Number(policy.max_delete_bytes);
    const cap = policy.maxDeleteMiB ?? (Number.isFinite(configuredBytes) ? configuredBytes / (1024 * 1024) : 512);
    const interval = autopilot.intervalMinutes ?? 90;
    $("connection-status").textContent = `Local service · ${text(state.server.platform, "ready")}`;
    document.querySelector(".connection")?.classList.add("is-ready");
    $("policy-age").textContent = `${age} day${Number(age) === 1 ? "" : "s"}`;
    $("policy-limit").textContent = Number.isFinite(Number(cap)) ? `${Math.round(Number(cap))} MiB` : text(cap);
    $("review-count").textContent = text(state.server.pendingReviewCount ?? 0);
    $("autopilot-interval").textContent = `Every ${interval} minutes`;
    $("autopilot-description").textContent = autopilot.npmVerify
      ? "Stale-temp cleanup plus official npm verification / garbage collection. Full package purges stay manual."
      : "When enabled, it runs the same limited stale-temp policy and saves a local report.";
    const autopilotChip = $("autopilot-chip");
    const enabled = Boolean(autopilot.enabled);
    autopilotChip.textContent = enabled ? "Enabled" : "Off";
    autopilotChip.classList.toggle("chip-muted", !enabled);
    $("autopilot-button").textContent = enabled ? "Pause autopilot" : "Enable autopilot";
    const report = state.server.lastReport;
    $("last-report").textContent = report ? date(report.createdAt) : "No report yet";
    $("last-report-detail").textContent = report ? describeReport(report) : "Run a scan to create a reviewable cleanup plan.";
    const available = new Map((Array.isArray(state.server.tools) ? state.server.tools : []).map((item) => [item.id, item.available !== false]));
    document.querySelectorAll("[data-cache-tool]").forEach((button) => {
      const tool = button.dataset.cacheTool;
      const supported = available.size === 0 || available.get(tool) !== false;
      button.disabled = !supported || state.busy.has(button);
      button.title = supported ? "" : "This tool is not available on this computer.";
    });
  }

  function renderPlan(plan) {
    state.plan = plan || null;
    const hasPlan = Boolean(plan && typeof plan === "object");
    $("scan-empty").hidden = hasPlan;
    $("scan-results").hidden = !hasPlan;
    const eligibleCount = plan?.summary?.candidateCount ?? plan?.summary?.candidateFiles ?? plan?.candidates?.length ?? 0;
    $("clean-button").disabled = !hasPlan || Number(eligibleCount) === 0;
    if (!hasPlan) return;
    const summary = plan.summary && typeof plan.summary === "object" ? plan.summary : {};
    const candidates = Array.isArray(plan.candidates) ? plan.candidates : [];
    const count = summary.candidateCount ?? summary.candidateFiles ?? candidates.length;
    const candidateBytes = summary.candidateBytes ?? candidates.reduce((total, item) => total + Number(item?.size ?? item?.metadata?.size ?? 0), 0);
    $("candidate-count").textContent = text(count, "0");
    $("candidate-bytes").textContent = bytes(candidateBytes);
    $("scan-boundaries").textContent = "Stale temp only";
    const truncated = summary.truncated ? `Scan stopped at ${text(summary.truncated)}; this is a bounded partial plan.` : "Only current eligible items appear below.";
    const skippedCount = Array.isArray(plan.skipped) ? plan.skipped.length : (summary.skipped && typeof summary.skipped === "object" ? Object.values(summary.skipped).reduce((sum, value) => sum + Number(value || 0), 0) : 0);
    $("scan-note").textContent = skippedCount ? `${truncated} ${skippedCount} item(s) were skipped by safeguards.` : truncated;
    const body = $("candidate-list");
    body.replaceChildren();
    candidates.slice(0, 12).forEach((candidate) => {
      const row = el("tr");
      const path = el("td", { className: "candidate-path", text: candidate.path || "Local temporary file" });
      const category = el("td", { text: candidate.category || candidate.rootLabel || "Temporary" });
      const size = el("td", { text: bytes(candidate.size ?? candidate.metadata?.size) });
      const automaticEligible = candidate.automaticEligible ?? candidate.automatic ?? false;
      const eligible = el("td", { className: automaticEligible ? "eligible" : "not-eligible", text: automaticEligible ? "Yes" : "Review" });
      row.append(path, category, size, eligible);
      body.append(row);
    });
    $("candidate-more").textContent = candidates.length > 12 ? `${candidates.length - 12} additional candidate(s) remain in the current local plan.` : "";
  }

  function renderReports(payload) {
    const reports = Array.isArray(payload?.reports) ? payload.reports : [];
    const target = $("report-list");
    target.replaceChildren();
    if (reports.length === 0) {
      target.append(el("p", { className: "subtle", text: "No local reports yet." }));
      return;
    }
    reports.slice(0, 12).forEach((report) => {
      const article = el("article", { className: "report-item" });
      article.append(
        el("h3", { text: text(report.kind || report.type || "Local activity", "Local activity") }),
        el("p", { text: describeReport(report) }),
        el("p", { className: "report-time", text: date(report.createdAt) })
      );
      target.append(article);
    });
  }

  async function refreshState(showSuccess = false) {
    const response = await api("/api/state");
    updateState(response);
    if (showSuccess) message("Local status refreshed.");
  }

  async function refreshReports() {
    const response = await api("/api/reports");
    renderReports(response);
  }

  async function scan(button) {
    clearMessage();
    setBusy(button, true, "Scanning…");
    try {
      const response = await api("/api/scan", { method: "POST", body: {} });
      renderPlan(response.plan);
      const count = response?.plan?.summary?.candidateCount ?? response?.plan?.summary?.candidateFiles ?? response?.plan?.candidates?.length ?? 0;
      const partial = Boolean(response?.plan?.summary?.truncated);
      message(`${partial ? "Bounded scan paused at its safety limit" : "Scan complete"}. ${count} eligible temporary file(s) found; ${count ? "review the plan before cleaning" : "nothing is selected for cleanup"}.`);
    } catch (error) {
      renderPlan(null);
      message(error.message, "error");
    } finally { setBusy(button, false); }
  }

  async function clean() {
    if (!state.plan?.id) { message("Run a new scan before cleaning.", "error"); return; }
    const confirmation = window.prompt("Type CLEAN STALE TEMP to clean only the displayed stale temporary-file plan.");
    if (confirmation === null) { message("Cleanup cancelled. Nothing changed."); return; }
    if (confirmation !== "CLEAN STALE TEMP") { message("Cleanup was not run because the confirmation phrase did not match.", "error"); return; }
    const button = $("clean-button");
    clearMessage();
    setBusy(button, true, "Cleaning…");
    try {
      const response = await api("/api/clean", { method: "POST", body: { planId: state.plan.id, confirm: "CLEAN STALE TEMP" } });
      state.plan = null;
      renderPlan(null);
      message(describeReport(response.report || response));
      await Promise.all([refreshState(), refreshReports()]);
    } catch (error) {
      message(error.message, "error");
    } finally { setBusy(button, false); }
  }

  async function cacheTask(button) {
    const tool = button.dataset.cacheTool;
    const confirmation = window.prompt(`Type RUN CACHE TASK to run the selected ${tool} task using its official tool.`);
    if (confirmation === null) { message("Cache task cancelled. Nothing changed."); return; }
    if (confirmation !== "RUN CACHE TASK") { message("Cache task was not run because the confirmation phrase did not match.", "error"); return; }
    clearMessage();
    setBusy(button, true, "Running…");
    try {
      const response = await api("/api/cache", { method: "POST", body: { tool, confirm: "RUN CACHE TASK" } });
      message(describeReport(response.report || response));
      await Promise.all([refreshState(), refreshReports()]);
    } catch (error) {
      message(error.message, "error");
    } finally { setBusy(button, false); updateState(state.server); }
  }

  async function toggleAutopilot() {
    const autopilot = state.server?.autopilot || {};
    const next = !Boolean(autopilot.enabled);
    if (next && !window.confirm(`Enable the local 90-minute scheduler for stale temporary files${autopilot.npmVerify ? " plus official npm verification / garbage collection" : ""}? A local report is saved after every run. Full purges remain manual.`)) return;
    const button = $("autopilot-button");
    clearMessage();
    setBusy(button, true, next ? "Enabling…" : "Pausing…");
    try {
      const response = await api("/api/autopilot", { method: "POST", body: { enabled: next, confirm: "ENABLE AUTOPILOT" } });
      if (state.server) state.server.autopilot = { ...(state.server.autopilot || {}), ...response };
      updateState(state.server);
      message(next ? "Autopilot is enabled for the local stale-temp policy." : "Autopilot is paused. No scheduled cleanup will run.");
      await refreshState();
    } catch (error) {
      message(error.message, "error");
    } finally { setBusy(button, false); updateState(state.server); }
  }

  async function openTrash() {
    const button = $("trash-button");
    clearMessage();
    setBusy(button, true, "Opening…");
    try {
      await api("/api/trash", { method: "POST", body: { action: "open" } });
      message("The system Trash / Recycle Bin was opened. Review it and empty it yourself if you choose.");
    } catch (error) {
      message(error.message, "error");
    } finally { setBusy(button, false); }
  }

  function inventorySummary(report) {
    if (!report || typeof report !== "object") return "Inventory completed. Review the local report for details.";
    const summary = report.summary && typeof report.summary === "object" ? report.summary : report;
    const files = summary.fileCount ?? summary.files ?? summary.scannedFiles;
    const total = summary.totalBytes ?? summary.bytes ?? summary.scannedBytes;
    const duplicates = summary.duplicateGroups ?? summary.duplicates;
    const pieces = ["Read-only inventory completed"];
    if (files !== undefined) pieces.push(`${files} file(s)`);
    if (total !== undefined) pieces.push(bytes(total));
    if (duplicates !== undefined) pieces.push(`${duplicates} duplicate group(s)`);
    return pieces.join(" · ");
  }

  async function inventory(event) {
    event.preventDefault();
    const path = $("inventory-path").value.trim();
    if (!path) { message("Enter one local folder path to inventory.", "error"); $("inventory-path").focus(); return; }
    const button = $("inventory-button");
    const result = $("inventory-result");
    clearMessage();
    setBusy(button, true, "Inventorying…");
    result.hidden = true;
    try {
      const response = await api("/api/inventory", { method: "POST", body: { path, duplicates: $("duplicates-check").checked } });
      result.textContent = inventorySummary(response.report || response);
      result.hidden = false;
      message("Read-only inventory completed. No files were changed.");
      await refreshReports();
    } catch (error) {
      result.textContent = error.message;
      result.hidden = false;
      message(error.message, "error");
    } finally { setBusy(button, false); }
  }

  function bind() {
    $("scan-button").addEventListener("click", (event) => scan(event.currentTarget));
    $("rescan-button").addEventListener("click", (event) => scan(event.currentTarget));
    $("clean-button").addEventListener("click", clean);
    $("trash-button").addEventListener("click", openTrash);
    $("autopilot-button").addEventListener("click", toggleAutopilot);
    $("inventory-form").addEventListener("submit", inventory);
    $("refresh-button").addEventListener("click", async (event) => {
      setBusy(event.currentTarget, true, "Refreshing…");
      try { await refreshState(true); } catch (error) { message(error.message, "error"); } finally { setBusy(event.currentTarget, false); }
    });
    $("reports-refresh").addEventListener("click", async (event) => {
      setBusy(event.currentTarget, true, "Refreshing…");
      try { await refreshReports(); message("Recent local reports refreshed."); } catch (error) { message(error.message, "error"); } finally { setBusy(event.currentTarget, false); }
    });
    document.querySelectorAll("[data-cache-tool]").forEach((button) => button.addEventListener("click", () => cacheTask(button)));
  }

  async function initialize() {
    bind();
    try {
      const results = await Promise.all([refreshState(), refreshReports()]);
      return results;
    } catch (error) {
      $("connection-status").textContent = "Local service unavailable";
      document.querySelector(".connection")?.classList.remove("is-ready");
      message(error.message, "error");
      $("report-list").replaceChildren(el("p", { className: "subtle", text: "Reports will appear once the local service is running." }));
    }
  }

  void initialize();
})();
