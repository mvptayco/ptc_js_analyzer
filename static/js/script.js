
/* ===========================
   CONFIG: Backend endpoints
=========================== */
const API = {
  analyze: "/api/analyze",   // unified endpoint (JSON or file upload)
};

/* ===========================
   Helpers
=========================== */
const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

function show(el) { el?.classList.remove("hidden"); }
function hide(el) { el?.classList.add("hidden"); }
function setText(el, text) { if (el) el.textContent = text; }

function showError(msg) {
  const error = $("error");
  if (!error) return;
  setText(error, msg);
  show(error);
}

function clearError() {
  const error = $("error");
  if (!error) return;
  setText(error, "");
  hide(error);
}

/* ===========================
   Safe masking (don’t display full secrets)
=========================== */
function maskSecret(value) {
  if (!value || typeof value !== "string") return "";
  return value.trim(); // User requested full display
}

function normalizeList(list) {
  if (!Array.isArray(list)) return [];
  return list.filter(x => x !== null && x !== undefined);
}


/* ============ PROGRESS LOG ============ */
const STAGES = [
  { text: "Initializing analysis...", icon: "fas fa-sync" },
  { text: "API Keys analysis in progress...", icon: "fas fa-key" },
  { text: "Credential patterns detected...", icon: "fas fa-user-lock" },
  { text: "Extracting emails...", icon: "fas fa-envelope" },
  { text: "Checking for XSS vulnerabilities...", icon: "fas fa-triangle-exclamation" },
  { text: "Mapping XSS functions...", icon: "fas fa-brain" },
  { text: "Discovering API endpoints...", icon: "fas fa-link" },
  { text: "Parsing parameters...", icon: "fas fa-puzzle-piece" },
  { text: "Enumerating paths & directories...", icon: "fas fa-folder-open" },
  { text: "Collecting comments...", icon: "fas fa-comment-dots" },
  { text: "Aggregating results (All)...", icon: "fas fa-chart-bar" }
];

let progressInterval = null;

function startProgressLog(containerId = "progress-log") {
  const log = $(containerId);
  if (!log) return;
  
  log.innerHTML = "";
  log.classList.remove("hidden");
  
  let i = 0;
  
  // Clear any existing interval
  if (progressInterval) clearInterval(progressInterval);
  
  // Show first item immediately
  addProgressItem(log, STAGES[0]);
  i++;

  progressInterval = setInterval(() => {
    if (i >= STAGES.length) {
      clearInterval(progressInterval);
      return;
    }
    addProgressItem(log, STAGES[i]);
    i++;
  }, 2000); // Add new item every 2000ms
}

function stopProgressLog() {
  if (progressInterval) clearInterval(progressInterval);
  // Try both possible containers
  ["progress-log", "progress-log-results"].forEach(id => {
      const log = $(id);
      if (!log) return;
      
      // Instead of filling the rest, just show completion
      // This makes the log length depend on the actual analysis time
      addProgressItem(log, { text: "Analysis complete!", icon: "fas fa-check-circle" }, true);
  });
}

function addProgressItem(container, stage, instant = false) {
  const div = document.createElement("div");
  div.className = "progress-item";
  div.innerHTML = `<i class="${stage.icon}" aria-hidden="true"></i> <span>${stage.text}</span>`;
  if (instant) div.style.animation = "none";
  div.style.opacity = "1";
  div.style.transform = "translateY(0)";
  
  // Highlight previous items as done, make this one active
  const prev = container.lastElementChild;
  if (prev) {
     prev.classList.remove("active");
     prev.style.color = "var(--muted)"; // dimmed
  }
  div.classList.add("active");
  container.appendChild(div);
  
  // Scroll to bottom
  container.scrollTop = container.scrollHeight;

  // SYNC: Update the main loading text to match current stage
  // This ensures the spinner text doesn't get stuck on "Analyzing URL..."
  const loadingText = $("loading-text");
  if (loadingText) loadingText.textContent = stage.text;

  const resultsLoader = document.querySelector(".results-loading span");
  if (resultsLoader) resultsLoader.textContent = stage.text;
}

/* ===========================
   Loading UI (modal OR results)
=========================== */
function setLoading(on, text = "Analyzing...") {
  const analyzerModal = $("analyzerModal");
  const analyzerOpen = analyzerModal && !analyzerModal.classList.contains("hidden");

  // Modal loading elements
  const loading = $("loading");
  const loadingText = $("loading-text");
  const progressLog = $("progress-log");

  // Results area
  const results = $("results");
  const findings = $("findings-content");

  if (analyzerOpen) {
    if (!loading) return;
    if (loadingText) loadingText.textContent = text;
    
    if (on) {
        show(loading);
        startProgressLog("progress-log");
    } else {
        stopProgressLog();
        hide(loading);
        if (progressLog) hide(progressLog);
    }
    return;
  }

  // Show busy in results section
  if (results) {
    results.classList.remove("hidden");
    results.setAttribute("aria-busy", on ? "true" : "false");
  }
  if (!findings) return;

  if (on) {
    findings.innerHTML = `
      <div class="results-loading" role="status" aria-live="polite">
        <i class="fas fa-spinner fa-spin" aria-hidden="true"></i>
        <span>${text}</span>
      </div>
      <div id="progress-log-results" class="progress-log"></div>
    `;
    startProgressLog("progress-log-results");
  } else {
    const spinner = findings.querySelector(".results-loading");
    if (spinner) spinner.remove();
  }
}

/* ===========================
   UX: jump to results
=========================== */
function jumpToResults(message = "Analyzing...") {
  const results = $("results");
  results?.classList.remove("hidden");
  results?.setAttribute("aria-busy", "true");
  setLoading(true, message);
  results?.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ===========================
   Theme Toggle
=========================== */
(function initTheme(){
  const html = document.documentElement;
  const icon = $("themeIcon");

  const stored = localStorage.getItem("theme");
  if (stored) html.setAttribute("data-theme", stored);

  function updateIcon() {
    const theme = html.getAttribute("data-theme");
    if (!icon) return;
    icon.className = theme === "light" ? "fas fa-moon" : "fas fa-sun";
  }
  updateIcon();

  $("themeToggle")?.addEventListener("click", () => {
    html.classList.add("theme-animating");
    const current = html.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    updateIcon();
    window.setTimeout(() => html.classList.remove("theme-animating"), 300);
  });
})();

/* ===========================
   Modal open/close
=========================== */
function openModal(modalId) {
  const modal = $(modalId);
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
}

function closeModal(modalId) {
  const modal = $(modalId);
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

/* Close modal on overlay/close button click */
document.addEventListener("click", (e) => {
  const closeTarget = e.target.closest("[data-close='true']");
  if (!closeTarget) return;

  const modal = e.target.closest(".modal");
  if (!modal) return;

  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
});

/* Close modals on ESC */
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;

  const analyzer = $("analyzerModal");
  if (analyzer && !analyzer.classList.contains("hidden")) closeModal("analyzerModal");

  const email = $("emailModal");
  if (email && !email.classList.contains("hidden")) closeModal("emailModal");
});

/* Open Analyzer Modal */
$("openAnalyzerBtn")?.addEventListener("click", () => {
  clearError();
  openModal("analyzerModal");
});

/* Email Modal */
$("contactBtn")?.addEventListener("click", () => openModal("emailModal"));

$("copyEmailBtn")?.addEventListener("click", async () => {
  const emailInput = $("contactEmail");
  const toast = $("copyToast");
  if (!emailInput) return;

  try {
    await navigator.clipboard.writeText(emailInput.value);
    if (toast) {
      toast.classList.remove("hidden");
      setTimeout(() => toast.classList.add("hidden"), 1400);
    }
  } catch {
    emailInput.select();
    document.execCommand("copy");
  }
});

/* ===========================
   Tabs
=========================== */
function switchTab(tabName) {
  $$(".tab-btn").forEach(btn => {
    const active = btn.dataset.tab === tabName;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });

  $$(".tab-content").forEach(panel => {
    panel.classList.add("hidden");
    panel.classList.remove("active");
  });

  const panel = document.getElementById(`${tabName}-tab`);
  if (panel) {
    panel.classList.remove("hidden");
    panel.classList.add("active");
    panel.focus?.();
  }
}

document.addEventListener("click", (e) => {
  const tabBtn = e.target.closest(".tab-btn");
  if (!tabBtn) return;
  e.preventDefault();
  switchTab(tabBtn.dataset.tab);
});

/* ===========================
   Clear Inputs
=========================== */
$("clearInputsBtn")?.addEventListener("click", () => {
  const jsUrl = $("jsUrl");
  const multipleUrls = $("multipleUrls");
  const urlFile = $("urlFile");
  const fileName = $("fileName");
  const analyzeFileBtn = $("analyzeFileBtn");
  // apiKeyInput removed

  if (jsUrl) jsUrl.value = "";
  if (multipleUrls) multipleUrls.value = "";
  if (urlFile) urlFile.value = "";
  // apiKeyInput removed

  if (fileName) { fileName.textContent = ""; fileName.classList.add("hidden"); }
  if (analyzeFileBtn) {
    analyzeFileBtn.disabled = true;
    analyzeFileBtn.setAttribute("aria-disabled","true");
  }

  clearError();
});

/* Enable file analyze button on file select */
$("urlFile")?.addEventListener("change", (e) => {
  const file = e.target.files?.[0];
  const fileName = $("fileName");
  const analyzeFileBtn = $("analyzeFileBtn");

  if (!file) {
    if (fileName) { fileName.textContent = ""; fileName.classList.add("hidden"); }
    if (analyzeFileBtn) { analyzeFileBtn.disabled = true; analyzeFileBtn.setAttribute("aria-disabled","true"); }
    return;
  }

  if (fileName) { fileName.textContent = `Selected: ${file.name}`; fileName.classList.remove("hidden"); }
  if (analyzeFileBtn) { analyzeFileBtn.disabled = false; analyzeFileBtn.setAttribute("aria-disabled","false"); }
});

/* ===========================
   ✅ Close modal immediately when Analyze clicked
=========================== */
function attachPreAnalyzeClose(buttonId, message) {
  const btn = $(buttonId);
  if (!btn) return;

  btn.addEventListener("click", () => {
    clearError();
    closeModal("analyzerModal");
    jumpToResults(message);
  }, true); // capture phase
}
attachPreAnalyzeClose("analyzeBtn", "Analyzing URL...");
attachPreAnalyzeClose("analyzeMultipleBtn", "Analyzing all URLs...");
attachPreAnalyzeClose("analyzeFileBtn", "Analyzing file...");

/* ===========================
   Rendering: Files + Results + Stats + Filters
=========================== */
let CURRENT_RESULTS = [];        // all files results from backend
let CURRENT_FILE_ID = null;      // selected file_id
let CURRENT_FILTER = "all";

function setStat(id, value) {
  const el = $(id);
  if (el) el.textContent = String(value ?? 0);
}

function computeTotals(results) {
  const all = (k) => results.reduce((acc, r) => acc + normalizeList(r[k]).length, 0);

  return {
    api_keys: all("api_keys"),
    credentials: all("credentials"),
    emails: all("emails"),
    xss: all("xss_vulnerabilities"),
    endpoints: all("api_endpoints"),
    recommendations: all("recommendations")
  };
}

function renderStats(results) {
  const t = computeTotals(results);
  setStat("stat-api-keys", t.api_keys);
  setStat("stat-credentials", t.credentials);
  setStat("stat-emails", t.emails);
  setStat("stat-xss", t.xss);
  setStat("stat-endpoints", t.endpoints);
  setStat("stat-recommendations", t.recommendations);
}

function renderFilesGrid(results) {
  const grid = $("files-grid");
  const section = $("files-section");
  if (!grid || !section) return;

  grid.innerHTML = "";

  results.forEach((r) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn-secondary";
    btn.style.width = "100%";
    btn.style.justifyContent = "space-between";

    const errorCount = normalizeList(r.errors).length;
    const label = r.url || `File ${r.file_id}`;
    const status = errorCount ? `${errorCount} error(s)` : "OK";

    btn.innerHTML = `
      <span style="display:flex; gap:10px; align-items:center;">
        <i class="fas fa-file-code" aria-hidden="true"></i>
        <span style="text-align:left; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width: 520px;">
          ${label}
        </span>
      </span>
      <span style="color:${errorCount ? "#ffb1b1" : "var(--muted)"}; font-weight:900;">
        ${status}
      </span>
    `;

    btn.addEventListener("click", () => {
      CURRENT_FILE_ID = r.file_id;
      renderSelectedFile();
    });

    grid.appendChild(btn);
  });

  section.style.display = results.length ? "" : "";
}

function renderFindingItem(item, mask = false) {
  if (typeof item !== "object" || !item) {
    return `<span>${escapeHtml(String(item))}</span>`;
  }

  // Extract common fields
  const type = item.type || "Finding";
  const line = item.line || item.line_number || item.lineno;
  
  // Determine main content (value/match/parameter)
  let content = item.match || item.parameter || item.value || item.key || item.url || item.path || item.comment || "";
  let contentLabel = "";

  if (item.parameter) contentLabel = "Parameter";
  else if (item.match) contentLabel = "Match";
  else if (item.url) contentLabel = "URL";
  else if (item.path) contentLabel = "Path";

  // Mask if needed
  if (mask && (item.match || item.key || item.value || item.token)) {
    content = maskSecret(content);
  }

  // Fallback if content is empty but we have a raw object
  if (!content && typeof item === "object") {
    // Try to JSON stringify if it's not a known structure
    try { content = JSON.stringify(item); } catch { content = String(item); }
  }

  const lineHtml = line ? `<span class="meta-tag"><i class="fas fa-list-ol"></i> Line ${line}</span>` : "";
  const typeHtml = type ? `<span class="meta-tag"><i class="fas fa-tag"></i> ${type}</span>` : "";
  
  const confidence = item.confidence || "";
  let confidenceHtml = "";
  if (confidence) {
    const confLower = confidence.toLowerCase();
    let icon = "fa-info-circle";
    if (confLower === "high") icon = "fa-exclamation-circle";
    else if (confLower === "medium") icon = "fa-exclamation-triangle";
    
    confidenceHtml = `<span class="meta-tag confidence-${confLower}"><i class="fas ${icon}"></i> ${confidence}</span>`;
  }

  return `
    <div class="finding-content">
      ${contentLabel ? `<div class="finding-content-label">${escapeHtml(contentLabel)}</div>` : ""}
      <div class="finding-content-text">${escapeHtml(content)}</div>
    </div>
    <div class="finding-meta">
      ${confidenceHtml}
      ${typeHtml}
      ${lineHtml}
    </div>
  `;
}

function buildFindingGroup(title, iconClass, items, {mask=false} = {}) {
  const safeItems = normalizeList(items);
  if (safeItems.length === 0) return "";

  const listItems = safeItems.map(v => {
    // Use .finding-item div structure directly
    return `<div class="finding-item">${renderFindingItem(v, mask)}</div>`;
  }).join("");

  return `
    <div class="finding-group">
      <h3 class="finding-title"><i class="${iconClass}" aria-hidden="true"></i> ${title} <span class="count">(${safeItems.length})</span></h3>
      <div class="finding-list">${listItems}</div>
    </div>
  `;
}

function buildRecommendationsGroup(items) {
  const safeItems = normalizeList(items);
  if (safeItems.length === 0) return "";
  
  const listItems = safeItems.map(item => {
    let priorityClass = "confidence-low";
    const p = (item.priority || "").toLowerCase();
    if (p === "critical") priorityClass = "confidence-critical"; 
    else if (p === "high") priorityClass = "confidence-high";
    else if (p === "medium") priorityClass = "confidence-medium";
    
    return `
      <div class="finding-item recommendation-item">
        <div class="finding-content">
            <div class="finding-content-label">${escapeHtml(item.category || 'Security')}</div>
            <div class="finding-content-text" style="font-weight:bold; color:var(--text-primary);">${escapeHtml(item.title)}</div>
            <div class="finding-desc" style="margin-top:5px; color:var(--muted); line-height:1.4;">${escapeHtml(item.description)}</div>
        </div>
        <div class="finding-meta">
            <span class="meta-tag ${priorityClass}"><i class="fas fa-shield-alt"></i> ${escapeHtml(item.priority)} Priority</span>
        </div>
      </div>
    `;
  }).join("");

  return `
    <div class="finding-group">
      <h3 class="finding-title"><i class="fas fa-shield-halved" aria-hidden="true"></i> Security Recommendations <span class="count">(${safeItems.length})</span></h3>
      <div class="finding-list">${listItems}</div>
    </div>
  `;
}

function renderServerInfoGroup(file) {
    let html = "";
    
    // Server Info
    if (file.server_info) {
        html += `
        <div class="finding-group">
            <h3 class="finding-title"><i class="fas fa-server"></i> Server Information</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        <div class="finding-content-label">Server Header</div>
                        <div class="finding-content-text">${escapeHtml(file.server_info.server_header || 'Unknown')}</div>
                        ${file.server_info.type ? `<div style="margin-top:5px; font-size:0.9em; color:var(--muted);">Type: ${escapeHtml(file.server_info.type)}</div>` : ''}
                        ${file.server_info.x_powered_by ? `<div style="margin-top:5px; font-size:0.9em; color:#ffb1b1;">X-Powered-By: ${escapeHtml(file.server_info.x_powered_by)}</div>` : ''}
                    </div>
                </div>
            </div>
        </div>`;
    }
    
    // IP Address
    if (file.ip_address) {
         html += `
        <div class="finding-group">
            <h3 class="finding-title"><i class="fas fa-network-wired"></i> IP Address</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        <div class="finding-content-text">${escapeHtml(file.ip_address)}</div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    // Cloudflare
    if (file.cloudflare_analysis && file.cloudflare_analysis.is_present) {
        const details = normalizeList(file.cloudflare_analysis.details).map(d => `<div><i class="fas fa-check" style="color:var(--accent); font-size:0.8em;"></i> ${escapeHtml(d)}</div>`).join("");
         html += `
        <div class="finding-group">
            <h3 class="finding-title"><i class="fab fa-cloudflare"></i> Cloudflare Analysis</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        <div class="finding-content-text" style="color:#F48120; font-weight:bold; margin-bottom:5px;">Cloudflare Protected</div>
                        <div style="font-size:0.9em;">${details}</div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    // Rate Limit
    if (file.rate_limit_info && file.rate_limit_info.is_present) {
        const details = normalizeList(file.rate_limit_info.details).map(d => `<div><i class="fas fa-info-circle" style="color:var(--accent); font-size:0.8em;"></i> ${escapeHtml(d)}</div>`).join("");
         html += `
        <div class="finding-group">
            <h3 class="finding-title"><i class="fas fa-tachometer-alt"></i> Rate Limiting</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        <div class="finding-content-label">Provider: ${escapeHtml(file.rate_limit_info.provider)}</div>
                        <div class="finding-content-text" style="color:#F48120; font-weight:bold; margin-bottom:5px;">Rate Limiting Detected</div>
                        <div style="font-size:0.9em;">${details}</div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    // CSP
    if (file.csp_info) {
        const weaknesses = normalizeList(file.csp_info.weaknesses).map(w => `<div style="color:#ffb1b1; margin-top:3px;"><i class="fas fa-times-circle"></i> ${escapeHtml(w)}</div>`).join("");
        
         html += `
        <div class="finding-group">
            <h3 class="finding-title"><i class="fas fa-shield-virus"></i> Content Security Policy</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        ${weaknesses ? `<div style="margin-bottom:10px; font-weight:bold; color:#ffb1b1;">Weaknesses Detected:</div>${weaknesses}` : '<div style="color:var(--accent); font-weight:bold;"><i class="fas fa-check-circle"></i> CSP looks good!</div>'}
                        <div style="margin-top:10px; font-size:0.85em; opacity:0.7; word-break:break-all; font-family:monospace; background:rgba(0,0,0,0.2); padding:5px; border-radius:4px;">${escapeHtml(file.csp_info.raw)}</div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    return html || `<div class="helper-note"><i class="fas fa-circle-info"></i> No server information available.</div>`;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function applyFilterToFile(file) {
  const f = CURRENT_FILTER;

  const groups = {
    api_keys: () => buildFindingGroup("API Keys", "fas fa-key", file.api_keys, { mask: true }),
    credentials: () => buildFindingGroup("Credentials", "fas fa-lock", file.credentials, { mask: true }),
    emails: () => buildFindingGroup("Emails", "fas fa-envelope", file.emails, { mask: false }),
    xss: () => buildFindingGroup("XSS Vulnerabilities", "fas fa-triangle-exclamation", file.xss_vulnerabilities, { mask: false }),
    xss_functions: () => buildFindingGroup("XSS Functions", "fas fa-bug", file.xss_functions, { mask: false }),
    api_endpoints: () => buildFindingGroup("API Endpoints", "fas fa-code-branch", file.api_endpoints, { mask: false }),
    parameters: () => buildFindingGroup("Parameters", "fas fa-sliders", file.parameters, { mask: false }),
    paths: () => buildFindingGroup("Paths/Directories", "fas fa-folder-open", file.paths_directories, { mask: false }),
    comments: () => buildFindingGroup("Comments", "fas fa-comment-dots", file.interesting_comments, { mask: false }),
    errors: () => buildFindingGroup("Errors", "fas fa-circle-xmark", file.errors, { mask: false }),
    server_info: () => renderServerInfoGroup(file),
    recommendations: () => buildRecommendationsGroup(file.recommendations)
  };

  if (f === "all") {
    return (
      groups.api_keys() +
      groups.credentials() +
      groups.emails() +
      groups.xss() +
      groups.xss_functions() +
      groups.api_endpoints() +
      groups.server_info() +
      groups.recommendations() +
      groups.parameters() +
      groups.paths() +
      groups.comments() +
      groups.errors()
    ) || `<div class="helper-note"><i class="fas fa-circle-info"></i> No findings for this file.</div>`;
  }

  // map HTML filters to groups
  if (groups[f]) {
    return groups[f]() || `<div class="helper-note"><i class="fas fa-circle-info"></i> No findings for this filter.</div>`;
  }

  return `<div class="helper-note"><i class="fas fa-circle-info"></i> Unknown filter.</div>`;
}

function renderSelectedFile() {
  const findings = $("findings-content");
  const backBtn = $("backToFiles");
  if (!findings) return;

  const file = CURRENT_RESULTS.find(r => r.file_id === CURRENT_FILE_ID) || CURRENT_RESULTS[0];
  if (!file) {
    findings.innerHTML = `<div class="helper-note"><i class="fas fa-circle-info"></i> No results yet.</div>`;
    return;
  }

  // show back button when a file is selected
  if (backBtn) show(backBtn);

  findings.innerHTML = `
    <div class="file-header" style="margin-bottom:10px; color:var(--muted); font-weight:900;">
      <i class="fas fa-file-code" aria-hidden="true"></i>
      <span style="margin-left:8px;">${escapeHtml(file.url || `File ${file.file_id}`)}</span>
    </div>
    ${applyFilterToFile(file)}
  `;
}

function renderOverviewAllFiles() {
  const findings = $("findings-content");
  const backBtn = $("backToFiles");
  if (!findings) return;

  // hide back button in overview mode
  if (backBtn) hide(backBtn);

  // Show a condensed overview: totals + per file quick summary
  const blocks = CURRENT_RESULTS.map(file => {
    const k = normalizeList(file.api_keys).length;
    const c = normalizeList(file.credentials).length;
    const e = normalizeList(file.emails).length;
    const x = normalizeList(file.xss_vulnerabilities).length;
    const ep = normalizeList(file.api_endpoints).length;

    return `
      <div class="stat-card" style="margin-bottom:10px; cursor:pointer;" data-file="${file.file_id}">
        <i class="fas fa-file-code" aria-hidden="true"></i>
        <div style="flex:1;">
          <div style="font-weight:900; margin-bottom:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            ${escapeHtml(file.url || `File ${file.file_id}`)}
          </div>
          <div style="color:var(--muted); font-weight:850; font-size:.9rem;">
            Keys: ${k} • Creds: ${c} • Emails: ${e} • XSS: ${x} • Endpoints: ${ep}
          </div>
        </div>
      </div>
    `;
  }).join("");

  findings.innerHTML = blocks || `<div class="helper-note"><i class="fas fa-circle-info"></i> No results yet.</div>`;

  // click overview card -> open file view
  findings.querySelectorAll("[data-file]").forEach(el => {
    el.addEventListener("click", () => {
      CURRENT_FILE_ID = Number(el.getAttribute("data-file"));
      renderSelectedFile();
    });
  });
}

/* Back to Files button (go back to overview) */
$("backToFiles")?.addEventListener("click", () => {
  CURRENT_FILE_ID = null;
  renderOverviewAllFiles();
});

/* Filters */
$$(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    CURRENT_FILTER = btn.dataset.filter || "all";

    // re-render current view
    if (CURRENT_FILE_ID) renderSelectedFile();
    else renderOverviewAllFiles();
  });
});

/* ===========================
   Analyze handlers (calls backend)
=========================== */
// API Key removed as per user request

async function postJSON(url, bodyObj) {
  const headers = {
    "Content-Type": "application/json"
  };
  
  const res = await fetch(url, {
    method: "POST",
    headers: headers,
    body: JSON.stringify(bodyObj)
  });

  // Handle errors
  if (!res.ok) {
    const text = await res.text();
    // Try to parse JSON error message first
    try {
        const json = JSON.parse(text);
        throw new Error(json.message || json.error || `Request failed: ${res.status}`);
    } catch (e) {
        if (e.message && e.message !== "Unexpected end of JSON input") throw e;
        throw new Error(text || `Request failed: ${res.status}`);
    }
  }
  return res.json();
}

async function postFile(url, file) {
  const fd = new FormData();
  fd.append("file", file);
  
  const headers = {};

  const res = await fetch(url, {
    method: "POST",
    headers: headers,
    body: fd
  });

  if (!res.ok) {
    const text = await res.text();
    // Try to parse JSON error message first
    try {
        const json = JSON.parse(text);
        throw new Error(json.message || json.error || `Request failed: ${res.status}`);
    } catch (e) {
        if (e.message && e.message !== "Unexpected end of JSON input") throw e;
        throw new Error(text || `Request failed: ${res.status}`);
    }
  }
  return res.json();
}

/* Single URL */
$("analyzeBtn")?.addEventListener("click", async () => {
  clearError();

  const jsUrl = $("jsUrl")?.value?.trim();
  if (!jsUrl) return showError("Please enter a JavaScript URL.");

  try {
    setLoading(true, "Analyzing URL...");
    const data = await postJSON(API.analyze, { url: jsUrl });

    CURRENT_RESULTS = Array.isArray(data.results) ? data.results : [];
    CURRENT_FILE_ID = null;
    window.CURRENT_SESSION_ID = data.session_id;

    renderFilesGrid(CURRENT_RESULTS);
    renderStats(CURRENT_RESULTS);
    renderOverviewAllFiles();

    setLoading(false);
    $("results")?.setAttribute("aria-busy", "false");
  } catch (err) {
    setLoading(false);
    $("results")?.setAttribute("aria-busy", "false");
    showError(err.message || "Analysis failed.");
  }
});

/* Multiple URLs */
$("analyzeMultipleBtn")?.addEventListener("click", async () => {
  clearError();

  const raw = $("multipleUrls")?.value || "";
  const urls = raw.split("\n").map(x => x.trim()).filter(Boolean);
  if (!urls.length) return showError("Please enter at least one URL.");

  try {
    setLoading(true, "Analyzing all URLs...");
    const data = await postJSON(API.analyze, { urls });

    CURRENT_RESULTS = Array.isArray(data.results) ? data.results : [];
    CURRENT_FILE_ID = null;
    window.CURRENT_SESSION_ID = data.session_id;

    renderFilesGrid(CURRENT_RESULTS);
    renderStats(CURRENT_RESULTS);
    renderOverviewAllFiles();

    setLoading(false);
    $("results")?.setAttribute("aria-busy", "false");
  } catch (err) {
    setLoading(false);
    $("results")?.setAttribute("aria-busy", "false");
    showError(err.message || "Analysis failed.");
  }
});

/* File upload */
$("analyzeFileBtn")?.addEventListener("click", async () => {
  clearError();

  const file = $("urlFile")?.files?.[0];
  if (!file) return showError("Please choose a file first.");

  try {
    setLoading(true, "Analyzing file...");
    const data = await postFile(API.analyze, file);

    CURRENT_RESULTS = Array.isArray(data.results) ? data.results : [];
    CURRENT_FILE_ID = null;
    window.CURRENT_SESSION_ID = data.session_id;

    renderFilesGrid(CURRENT_RESULTS);
    renderStats(CURRENT_RESULTS);
    renderOverviewAllFiles();

    setLoading(false);
    $("results")?.setAttribute("aria-busy", "false");
  } catch (err) {
    setLoading(false);
    $("results")?.setAttribute("aria-busy", "false");
    showError(err.message || "Analysis failed.");
  }
});


/* function formatFinding removed */

/* ============ CHAT WIDGET ============ */
document.addEventListener('DOMContentLoaded', () => {
  const chatToggleBtn = $('chatToggleBtn');
  const chatWindow = $('chatWindow');
  const chatCloseBtn = $('chatCloseBtn');
  const chatMessages = $('chatMessages');
  const chatInput = $('chatInput');
  const chatSendBtn = $('chatSendBtn');

  if (!chatToggleBtn || !chatWindow) return;

  // Toggle chat window
  chatToggleBtn.addEventListener('click', () => {
    chatWindow.classList.toggle('hidden');
    if (!chatWindow.classList.contains('hidden') && chatInput) {
      chatInput.focus();
    }
  });

  // Close chat window
  chatCloseBtn?.addEventListener('click', () => {
    chatWindow.classList.add('hidden');
  });

  // Send message function
  const sendMessage = async () => {
    const text = chatInput.value.trim();
    if (!text) return;

    // Add user message
    addMessage(text, 'user');
    chatInput.value = '';

    // Show typing indicator
    const typingId = addMessage("Thinking...", 'bot typing');

    try {
      // Find session ID from global results or DOM
      // Assuming session ID is not explicitly stored in global var, 
      // but we can try to infer or send empty. 
      // For best results, app.py uses session to context.
      // We will look for a session ID if available, else standard chat.
      // Note: In this simple implementation, the backend updates context 
      // based on whatever session_id is passed. 
      // We'll grab the first session ID from the results if available.
      
      // Attempt to get session ID from URL or hidden field if stored.
      // Since we don't store it globally in script.js, let's look at CURRENT_RESULTS?
      // CURRENT_RESULTS is an array of files. We need the session key.
      // We'll rely on the backend's in-memory storage. 
      // Since we don't have the session ID handy in a variable, we'll try to get it.
      // Actually, app.py returns session_id in the /analyze response.
      // We should store it.
      
      // Fallback: If we can't find session ID, the chat engine will just use generic knowledge.
      const sessionId = window.CURRENT_SESSION_ID || null;

      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, session_id: sessionId })
      });
      
      const data = await response.json();
      
      // Remove typing indicator
      const typingEl = document.querySelector('.message.typing');
      if (typingEl) typingEl.remove();
      
      addMessage(data.response || "I couldn't process that.", 'bot');
      
    } catch (err) {
      const typingEl = document.querySelector('.message.typing');
      if (typingEl) typingEl.remove();
      addMessage("Sorry, I encountered an error connecting to the server.", 'bot');
    }
  };

  // Add message to chat
  const addMessage = (text, sender) => {
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${sender}`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.innerHTML = text.replace(/\n/g, '<br>');
    
    msgDiv.appendChild(contentDiv);
    chatMessages.appendChild(msgDiv);
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    return msgDiv;
  };

  // Send button click
  chatSendBtn?.addEventListener('click', sendMessage);

  // Enter key in input
  chatInput?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      sendMessage();
    }
  });
});