"use strict";

const MAX_ARCHIVE_BYTES = 25 * 1024 * 1024;
const state = { file: null, result: null, filter: "all", controller: null };

const byId = (id) => document.getElementById(id);
const fileInput = byId("fileInput");
const dropZone = byId("dropZone");
const scanButton = byId("scanButton");
const cancelButton = byId("cancelButton");
const statusLine = byId("statusLine");
const progress = byId("progress");
const resultsSection = byId("results");
const findingList = byId("findingList");
const exportButton = byId("exportButton");

function setStatus(message, tone = "") {
  statusLine.textContent = message;
  statusLine.className = "status-line" + (tone ? " " + tone : "");
}

function humanBytes(value) {
  if (value < 1024) return value + " B";
  if (value < 1024 * 1024) return (value / 1024).toFixed(1) + " KB";
  return (value / (1024 * 1024)).toFixed(1) + " MB";
}

function chooseFile(file) {
  if (!file || state.controller) return;
  if (!file.name.toLowerCase().endsWith(".zip")) {
    setStatus("Choose a .zip archive. Other file types are not accepted.", "error");
    return;
  }
  if (file.size === 0) {
    setStatus("The selected archive is empty.", "error");
    return;
  }
  if (file.size > MAX_ARCHIVE_BYTES) {
    setStatus("The archive exceeds the 25 MB limit.", "error");
    return;
  }
  state.file = file;
  byId("fileName").textContent = file.name;
  byId("fileSize").textContent = humanBytes(file.size);
  byId("fileRow").hidden = false;
  scanButton.disabled = false;
  resultsSection.hidden = true;
  setStatus("Archive selected. Ready for a local scan.");
}

function clearFile() {
  if (state.controller) return;
  state.file = null;
  fileInput.value = "";
  byId("fileRow").hidden = true;
  scanButton.disabled = true;
  setStatus("Waiting for a project archive.");
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function renderSummary(result) {
  const grid = byId("summaryGrid");
  grid.replaceChildren();
  const summary = result.summary || {};
  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    const cell = element("div", "summary-cell " + severity);
    cell.append(element("span", "summary-count", summary[severity] || 0));
    cell.append(element("span", "summary-label", severity));
    grid.append(cell);
  }
}

function renderProjectMap(projectMap) {
  const stats = byId("projectMapStats");
  const modules = byId("projectMapModules");
  stats.replaceChildren();
  modules.replaceChildren();

  if (!projectMap || !projectMap.summary) {
    byId("projectMapMeta").textContent = "Python structure index unavailable.";
    stats.append(element("div", "empty-state", "No Python project map was returned."));
    return;
  }

  const summary = projectMap.summary;
  byId("projectMapMeta").textContent =
    (projectMap.scanned_files || 0) + " Python files inspected · " +
    (projectMap.warnings || []).length + " mapping warnings";

  for (const [label, key] of [
    ["Modules", "modules"],
    ["Classes", "classes"],
    ["Functions", "functions"],
    ["Call sites", "calls"],
    ["Imports", "imports"],
    ["Internal links", "dependency_edges"],
    ["Cross-file calls", "cross_file_calls"],
    ["Cycle groups", "circular_dependency_groups"]
  ]) {
    const tile = element("div", "project-map-stat");
    tile.append(element("span", "project-map-count", summary[key] || 0));
    tile.append(element("span", "project-map-label", label));
    stats.append(tile);
  }

  const indexed = projectMap.modules || [];
  if (!indexed.length) {
    modules.append(element("div", "empty-state", "No parseable Python modules were found in this archive."));
    return;
  }

  const heading = element("div", "project-map-list-heading", "INDEXED MODULES");
  modules.append(heading);
  const visible = indexed.slice(0, 12);
  for (const module of visible) {
    const row = element("div", "project-module");
    const name = element("strong", "project-module-name", module.path || module.module);
    const counts = element("span", "project-module-counts",
      (module.symbols || []).filter(item => item.kind === "class").length + " classes · " +
      (module.symbols || []).filter(item => item.kind === "function" || item.kind === "async_function").length + " functions · " +
      (module.calls || []).length + " calls");
    row.append(name, counts);
    modules.append(row);
  }
  if (indexed.length > visible.length) {
    modules.append(element("div", "project-map-more",
      "And " + (indexed.length - visible.length) + " more module(s). Export JSON for the full index."));
  }

  const dependencies = projectMap.dependencies || [];
  modules.append(element("div", "project-map-list-heading", "INTERNAL DEPENDENCIES"));
  if (!dependencies.length) {
    modules.append(element("div", "empty-state", "No imports resolved to another indexed Python module."));
  } else {
    for (const dependency of dependencies.slice(0, 24)) {
      const row = element("div", "project-dependency");
      const relation = dependency.resolution === "possible_submodule" ? "possible submodule" : "direct import";
      row.append(element("strong", "project-dependency-path",
        dependency.source_module + " → " + dependency.target_module));
      row.append(element("span", "project-dependency-meta",
        "line " + dependency.line + " · " + relation));
      modules.append(row);
    }
    if (dependencies.length > 24) {
      modules.append(element("div", "project-map-more",
        "And " + (dependencies.length - 24) + " more dependency edge(s). Export JSON for the full graph."));
    }
  }

  const crossCalls = projectMap.cross_file_calls || [];
  modules.append(element("div", "project-map-list-heading", "CROSS-FILE CALLS"));
  if (!crossCalls.length) {
    modules.append(element("div", "empty-state", "No calls could be resolved confidently across indexed modules."));
  } else {
    for (const call of crossCalls.slice(0, 24)) {
      const row = element("div", "project-dependency");
      row.append(element("strong", "project-dependency-path",
        call.source_module + "." + call.caller + " → " + call.target_module + "." + call.target_symbol));
      const resolution = call.resolution === "direct" ? "direct import" :
        call.resolution === "possible_submodule" ? "possible submodule" : "ambiguous import";
      row.append(element("span", "project-dependency-meta",
        "line " + call.line + " · " + resolution));
      modules.append(row);
    }
    if (crossCalls.length > 24) {
      modules.append(element("div", "project-map-more",
        "And " + (crossCalls.length - 24) + " more cross-file call(s). Export JSON for the full graph."));
    }
  }

  const cycles = projectMap.circular_dependencies || [];
  modules.append(element("div", "project-map-list-heading", "CIRCULAR IMPORT GROUPS"));
  if (!cycles.length) {
    modules.append(element("div", "empty-state", "No circular import groups were found."));
  } else {
    for (const cycle of cycles.slice(0, 16)) {
      const row = element("div", "project-dependency");
      row.append(element("strong", "project-dependency-path", cycle.modules.join(" ↔ ")));
      const details = cycle.resolution === "direct" ? "definite cycle" : "possible cycle";
      row.append(element("span", "project-dependency-meta",
        details + " · " + cycle.edge_count + " edge(s)" +
        (cycle.possible_edges ? " · " + cycle.possible_edges + " uncertain" : "")));
      for (const edge of (cycle.edges || []).slice(0, 8)) {
        const imported = edge.imported_name ? " " + edge.imported_name : "";
        row.append(element("span", "project-dependency-meta",
          edge.source_module + " → " + edge.target_module +
          " · line " + edge.line + " · " + edge.import_kind + imported));
      }
      if ((cycle.edges || []).length > 8) {
        row.append(element("span", "project-dependency-meta",
          "And " + ((cycle.edges || []).length - 8) + " more import edge(s)."));
      }
      modules.append(row);
    }
    if (cycles.length > 16) {
      modules.append(element("div", "project-map-more",
        "And " + (cycles.length - 16) + " more circular group(s). Export JSON for the full index."));
    }
  }

  if ((projectMap.warnings || []).length) {
    modules.append(element("div", "project-map-warning",
      (projectMap.warnings || []).length + " module warning(s). Check the scan warnings below."));
  }
}

function renderFinding(finding) {
  const card = element("article", "finding-card " + finding.severity);
  const top = element("div", "finding-top");
  top.append(element("span", "finding-rule", finding.rule_id));
  top.append(element("span", "severity " + finding.severity, finding.severity));
  card.append(top);
  card.append(element("h3", "", finding.title));
  card.append(element("div", "finding-location", finding.path + ":" + finding.line + ":" + finding.column));
  card.append(element("p", "finding-message", finding.message));
  card.append(element("div", "evidence-label", "REDACTED SOURCE EVIDENCE"));
  card.append(element("pre", "evidence", finding.evidence || "No snippet available"));
  const fix = element("div", "remediation");
  fix.append(element("strong", "", "REMEDIATION"));
  fix.append(document.createTextNode(" " + finding.remediation));
  card.append(fix);
  return card;
}

function renderFindings() {
  findingList.replaceChildren();
  if (!state.result) return;
  const all = state.result.findings || [];
  const visible = state.filter === "all" ? all : all.filter((item) => item.severity === state.filter);
  if (!visible.length) {
    findingList.append(element("div", "empty-state", all.length ? "No findings match this filter." : "No findings matched the current rules. This is not a security certification."));
    return;
  }
  for (const finding of visible) findingList.append(renderFinding(finding));
}

function renderWarnings(errors) {
  const box = byId("warnings");
  box.replaceChildren();
  box.hidden = !errors || !errors.length;
  if (!box.hidden) {
    box.append(element("strong", "", "Scan warnings"));
    const list = document.createElement("ul");
    for (const error of errors) list.append(element("li", "", error));
    box.append(list);
  }
}

function showResult(result) {
  state.result = result;
  state.filter = "all";
  byId("scanMeta").textContent = (result.scanned_files || 0) + " files analyzed · " + (result.skipped_files || 0) + " skipped";
  renderSummary(result);
  renderProjectMap(result.project_map);
  renderFindings();
  renderWarnings(result.errors || []);
  for (const button of byId("filters").querySelectorAll("button")) {
    const active = button.dataset.filter === "all";
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }
  resultsSection.hidden = false;
  resultsSection.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

async function runScan() {
  if (!state.file || state.controller) return;
  state.controller = new AbortController();
  scanButton.disabled = true;
  cancelButton.hidden = false;
  progress.hidden = false;
  dropZone.setAttribute("aria-disabled", "true");
  byId("removeFile").disabled = true;
  setStatus("Scanning locally. Uploaded source files are not executed.");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/zip" },
      body: state.file,
      signal: state.controller.signal,
      cache: "no-store",
      credentials: "same-origin",
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Scan request failed (" + response.status + ").");
    showResult(payload);
    setStatus("Scan complete. Review each finding and validate it in context.", "success");
  } catch (error) {
    if (error.name === "AbortError") {
      setStatus("Scan cancelled. No report was saved.");
    } else {
      setStatus(error.message || "The local scan failed.", "error");
    }
  } finally {
    state.controller = null;
    scanButton.disabled = !state.file;
    cancelButton.hidden = true;
    progress.hidden = true;
    dropZone.removeAttribute("aria-disabled");
    byId("removeFile").disabled = false;
  }
}

function cancelScan() {
  if (state.controller) state.controller.abort();
}

function exportReport() {
  if (!state.result) return;
  const blob = new Blob([JSON.stringify(state.result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "aegisforge-report.json";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

dropZone.addEventListener("click", () => { if (!state.controller) fileInput.click(); });
dropZone.addEventListener("keydown", (event) => {
  if (!state.controller && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    fileInput.click();
  }
});
dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  if (state.controller) return;
  dropZone.classList.add("dragging");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));
dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragging");
  if (!state.controller) chooseFile(event.dataTransfer.files && event.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => chooseFile(fileInput.files && fileInput.files[0]));
byId("removeFile").addEventListener("click", clearFile);
scanButton.addEventListener("click", runScan);
cancelButton.addEventListener("click", cancelScan);
exportButton.addEventListener("click", exportReport);
byId("filters").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-filter]");
  if (!button) return;
  state.filter = button.dataset.filter;
  for (const item of byId("filters").querySelectorAll("button")) {
    const active = item === button;
    item.classList.toggle("active", active);
    item.setAttribute("aria-pressed", active ? "true" : "false");
  }
  renderFindings();
});
