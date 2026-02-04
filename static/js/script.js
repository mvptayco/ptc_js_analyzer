
/* ===========================
   Anti-Inspect Measures (REMOVED)
=========================== */
// document.addEventListener('contextmenu', (e) => e.preventDefault());
// document.addEventListener('keydown', (e) => {
//   if (e.key === 'F12' || 
//       (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key)) || 
//       (e.ctrlKey && e.key === 'u')) {
//     e.preventDefault();
//     return false;
//   }
// });

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
  
  // Scroll to bottom smoothly for the "moving up" effect
    // container.scrollTop = container.scrollHeight;
    container.scrollTo({
      top: container.scrollHeight,
      behavior: 'smooth'
    });

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
// EXPOSE GLOBALLY for inline onclicks
window.openModal = function(modalId) {
  const modal = $(modalId);
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
};

window.closeModal = function(modalId) {
  const modal = $(modalId);
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
};

/* Close modal on overlay/close button click */
document.addEventListener("DOMContentLoaded", () => {
  // Bind class-based listeners as backup
  const closeBtns = document.querySelectorAll(".modal-close, [data-close='true']");
  closeBtns.forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      // Find modal
      const modal = btn.closest(".modal");
      if (modal) {
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
        document.body.classList.remove("modal-open");
      }
    });
  });
});

// Capture phase listener (Nuclear option for stubborn events)
window.addEventListener("click", (e) => {
  const closeTarget = e.target.closest("[data-close='true']");
  if (!closeTarget) return;

  const modal = closeTarget.closest(".modal");
  if (!modal) return;

  // If we found a modal and a close target, close it!
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}, true); // Use capture phase!

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
  const directoryHtml = item.directory ? `<span class="meta-tag"><i class="fas fa-folder"></i> Directory: ${item.directory}</span>` : "";
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
      ${Array.isArray(item.related_endpoints) && item.related_endpoints.length ? `
        <div class="finding-related" style="margin-top:8px;">
          <div class="finding-content-label">Related Endpoints</div>
          <ul style="margin:6px 0 0; padding-left:18px; color:var(--muted);">
            ${item.related_endpoints.slice(0,3).map(ep => `<li>${escapeHtml(((ep.method || '') + ' ' + (ep.path || '')).trim())}</li>`).join("")}
          </ul>
        </div>
      ` : ""}
    </div>
    <div class="finding-meta">
      ${confidenceHtml}
      ${typeHtml}
      ${lineHtml}
      ${directoryHtml}
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
            <h3 class="finding-title"><i class="fas fa-hand-paper"></i> Rate Limiting</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        <div class="finding-content-text" style="color:#00ff9d; font-weight:bold; margin-bottom:5px;">Rate Limiting Detected</div>
                        <div style="font-size:0.9em;">${details}</div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    // CSP
    if (file.csp_info) {
        let cspHtml = "";
        if (file.csp_info.is_present) {
             cspHtml = `<div class="finding-content-text" style="color:#00ff9d; font-weight:bold; margin-bottom:5px;">CSP Present</div>`;
        } else {
             cspHtml = `<div class="finding-content-text" style="color:#ffb1b1; font-weight:bold; margin-bottom:5px;">CSP Missing</div>`;
        }
        
        if (file.csp_info.raw) {
            cspHtml += `<div style="font-size:0.9em; word-break:break-all; margin-top:5px; padding:5px; background:rgba(0,0,0,0.3); border-radius:4px;">${escapeHtml(file.csp_info.raw)}</div>`;
        }

        html += `
        <div class="finding-group">
            <h3 class="finding-title"><i class="fas fa-shield-virus"></i> Content Security Policy</h3>
            <div class="finding-list">
                <div class="finding-item">
                    <div class="finding-content">
                        ${cspHtml}
                    </div>
                </div>
            </div>
        </div>`;
    }

    return html;
}


function renderSelectedFile() {
  const container = $("findings-content");
  const section = $("results");
  if (!container || !section) return;

  const file = CURRENT_RESULTS.find(r => r.file_id === CURRENT_FILE_ID);
  if (!file) {
    container.innerHTML = "<p>File result not found.</p>";
    return;
  }
  
  // Show back button
  $("backToFiles")?.classList.remove("hidden");
  $("files-section")?.classList.add("hidden");
  
  // Ensure results section is visible
  section.classList.remove("hidden");
  section.setAttribute("aria-busy", "false");

  // Build HTML
  let html = "";
  
  const showAll = CURRENT_FILTER === "all";

  // Errors (Always show if present, or maybe only on 'all'?)
  // Usually errors are important enough to show on 'all' or if we had an 'errors' tab.
  // Let's show them on 'all' for now.
  if (showAll) {
    const errs = normalizeList(file.errors);
    if (errs.length > 0) {
      html += `
        <div class="finding-group error-group">
          <h3 class="finding-title error-title"><i class="fas fa-exclamation-triangle"></i> Errors</h3>
          <div class="finding-list">
            ${errs.map(e => `<div class="finding-item error-item">${escapeHtml(e)}</div>`).join("")}
          </div>
        </div>
      `;
    }
  }
  
  // Recommendations
  if (showAll || CURRENT_FILTER === "recommendations") {
      html += buildRecommendationsGroup(file.recommendations);
  }
  
  // Server/IP/CSP info
  if (showAll || CURRENT_FILTER === "server_info") {
      html += renderServerInfoGroup(file);
  }

  // Security Findings
  if (showAll || CURRENT_FILTER === "api_keys") 
      html += buildFindingGroup("API Keys", "fas fa-key", file.api_keys, {mask:false});
      
  if (showAll || CURRENT_FILTER === "credentials")
      html += buildFindingGroup("Credentials", "fas fa-user-lock", file.credentials, {mask:false});
      
  if (showAll || CURRENT_FILTER === "emails")
      html += buildFindingGroup("Emails", "fas fa-envelope", file.emails, {mask:false});
      
  if (showAll || CURRENT_FILTER === "xss")
      html += buildFindingGroup("XSS Vulnerabilities", "fas fa-bug", file.xss_vulnerabilities);
      
  if (showAll || CURRENT_FILTER === "xss_functions")
      html += buildFindingGroup("XSS Sinks/Sources", "fas fa-code", file.xss_functions);
      
  if (showAll || CURRENT_FILTER === "api_endpoints")
      html += buildFindingGroup("API Endpoints", "fas fa-link", file.api_endpoints);
      
  if (showAll || CURRENT_FILTER === "parameters")
      html += buildFindingGroup("Parameters", "fas fa-puzzle-piece", file.parameters);
      
  if (showAll || CURRENT_FILTER === "paths")
      html += buildFindingGroup("Paths & Directories", "fas fa-folder-open", file.paths_directories);
      
  if (showAll || CURRENT_FILTER === "comments")
      html += buildFindingGroup("Interesting Comments", "fas fa-comment-dots", file.interesting_comments);

  if (!html) {
    html = "<p style='padding:1rem; color:var(--muted);'>No findings for this category.</p>";
  }

  container.innerHTML = html;
  
  // Scroll to results
  // Only scroll if we are not already there (to avoid annoying jumps when switching filters)
  // But maybe we should just scroll to top of results container?
  // section.scrollIntoView({ behavior: "smooth" }); // user might find this annoying if they just clicked a filter

}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


/* ===========================
   Main Analysis Logic
=========================== */
async function performAnalysis(payload, isFile = false) {
  setLoading(true, "Initializing analysis...");
  CURRENT_RESULTS = [];
  CURRENT_FILE_ID = null;
  $("files-grid").innerHTML = "";
  $("findings-content").innerHTML = "";
  $("backToFiles")?.classList.add("hidden");
  
  try {
    let res;
    if (isFile) {
      // payload is FormData
      res = await fetch(API.analyze, {
        method: "POST",
        headers: { "Accept": "application/json" },
        body: payload
      });
    } else {
      // payload is JSON object
      res = await fetch(API.analyze, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        body: JSON.stringify(payload)
      });
    }

    if (!res.ok) {
        if (res.status === 429) {
             // Redirect to rate limit page so user sees the HTML
             window.location.href = "/rate-limited";
             throw new Error("Rate limit exceeded. Redirecting...");
        }
        const errData = await res.json();
        throw new Error(errData.error || "Analysis failed");
    }

    const data = await res.json();
    setLoading(false);
    
    // Close modal now that analysis is done
    closeModal("analyzerModal");

    // Save global results
    CURRENT_RESULTS = data.results || [];
    window.CURRENT_RESULTS = CURRENT_RESULTS; // Expose for chat context

    if (CURRENT_RESULTS.length === 0) {
        $("files-section").classList.remove("hidden");
        const noResultsMsg = "<div style='padding:2rem; text-align:center; color:var(--muted);'><i class='fas fa-search' style='font-size:2rem; margin-bottom:1rem; opacity:0.5;'></i><p>No results returned from analysis.</p></div>";
        $("files-grid").innerHTML = noResultsMsg;
        
        // Also show in findings content to be sure
        $("findings-content").innerHTML = noResultsMsg;
        $("results").classList.remove("hidden"); // Ensure results section is shown for empty message
        
        $("files-section").scrollIntoView({ behavior: "smooth" });
        return;
    }

    // Render stats
    renderStats(CURRENT_RESULTS);

    // Render files grid
    renderFilesGrid(CURRENT_RESULTS);

    // Auto-select if only 1 file
    if (CURRENT_RESULTS.length === 1) {
      CURRENT_FILE_ID = CURRENT_RESULTS[0].file_id;
      renderSelectedFile();
    } else {
       // Show files list
       $("files-section").classList.remove("hidden");
       $("files-section").scrollIntoView({ behavior: "smooth" });
    }

  } catch (err) {
    setLoading(false);
    showError(err.message);
  }
}

/* ===========================
   Event Listeners
=========================== */

/* Ensure DOM is loaded before attaching listeners */
document.addEventListener('DOMContentLoaded', () => {

  /* Helper to close modal and show results */
  function prepareAnalysisUI(message) {
    clearError();
    // Keep modal open to show loading state inside it
    setLoading(true, message);
  }

  /* Filters */
  const filterBtns = document.querySelectorAll(".filter-btn");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      // Update active state
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      
      // Update filter
      CURRENT_FILTER = btn.dataset.filter || "all";
      
      // Re-render
      renderSelectedFile();
    });
  });

  /* Single URL */
  const analyzeBtn = $("analyzeBtn");
  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", () => {
      const url = $("jsUrl").value.trim();
      if (!url) { 
        showError("Please enter a URL"); 
        return; 
      }
      
      prepareAnalysisUI("Analyzing URL...");
      performAnalysis({ url: url });
    });
  }

  /* Multiple URLs */
  const analyzeMultipleBtn = $("analyzeMultipleBtn");
  if (analyzeMultipleBtn) {
    analyzeMultipleBtn.addEventListener("click", () => {
      const raw = $("multipleUrls").value.trim();
      if (!raw) { showError("Please enter URLs"); return; }
      
      const urls = raw.split(/[\r\n,]+/).map(u => u.trim()).filter(Boolean);
      if (!urls.length) { showError("No valid URLs found"); return; }
      
      prepareAnalysisUI("Analyzing all URLs...");
      performAnalysis({ urls: urls });
    });
  }

  /* File Upload */
  const analyzeFileBtn = $("analyzeFileBtn");
  if (analyzeFileBtn) {
    analyzeFileBtn.addEventListener("click", () => {
      const fileInput = $("urlFile");
      const file = fileInput.files?.[0];
      if (!file) { showError("Please select a file"); return; }

      const formData = new FormData();
      formData.append("file", file);
      
      prepareAnalysisUI("Analyzing file...");
      performAnalysis(formData, true);
    });
  }

  /* Back to files button */
  const backToFiles = $("backToFiles");
  if (backToFiles) {
    backToFiles.addEventListener("click", () => {
      $("files-section").classList.remove("hidden");
      $("findings-content").innerHTML = ""; // clear details
      $("backToFiles").classList.add("hidden");
      $("files-section").scrollIntoView({ behavior: "smooth" });
    });
  }

  /* Prevent form submission and trigger analyze */
  const singleUrlForm = $("singleUrlForm");
  if (singleUrlForm) {
    singleUrlForm.addEventListener("submit", (e) => {
      e.preventDefault();
      $("analyzeBtn")?.click();
    });
  }
});

/* ============ CHAT WIDGET ============ */
document.addEventListener('DOMContentLoaded', () => {
  // Store system instruction
  let systemInstruction = "";

  // Fetch system instruction on load
  fetch('/api/chat/config')
      .then(res => res.json())
      .then(data => {
          systemInstruction = data.system_instruction || "";
      })
      .catch(err => console.error("Failed to load chat config", err));

  const chatToggleBtn = $('chatToggleBtn');
  const chatWindow = $('chatWindow');
  const chatCloseBtn = $('chatCloseBtn');
  const chatMessages = $('chatMessages');
  const chatInput = $('chatInput');
  const chatSendBtn = $('chatSendBtn');
  const chatInputArea = document.querySelector('.chat-input-area');

  if (!chatToggleBtn || !chatWindow) return;

  // Add Model Selector
  const modelSelect = document.createElement('select');
  modelSelect.id = 'chatModelSelect';
  modelSelect.className = 'chat-model-select';
  modelSelect.innerHTML = `
      <option value="gpt-4o">GPT-4o (Best)</option>
      <option value="claude-3-5-sonnet">Claude 3.5 Sonnet</option>
      <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
      <option value="gpt-4o-mini">GPT-4o Mini (Fast)</option>
  `;
  // Style the selector - Moved to style.css
  // Object.assign(modelSelect.style, ... );
  
  // Insert before input area (not inside it, to avoid breaking flex row)
  if (chatInputArea && chatInputArea.parentNode) {
      // Create a wrapper for padding/spacing if needed
      const wrapper = document.createElement('div');
      wrapper.style.padding = "0 12px";
      wrapper.style.background = "rgba(255,255,255,0.02)";
      wrapper.appendChild(modelSelect);
      chatInputArea.parentNode.insertBefore(wrapper, chatInputArea);
  }

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
    
    // Get selected model
    const selectedModel = modelSelect.value || 'gpt-4o-mini';

    try {
      // Build context from analysis results
      let context = "";
      if (window.CURRENT_RESULTS && window.CURRENT_RESULTS.length > 0) {
          context = "\n\n[System Context - Current Analysis Findings]:\n";
          window.CURRENT_RESULTS.forEach(file => {
               context += `File: ${file.url || 'Uploaded File'}\n`;
               
               const findings = [];
               if (file.api_keys && file.api_keys.length) {
                   findings.push(`- API Keys (${file.api_keys.length}): ${file.api_keys.map(k => k.value || k.match).join(', ').substring(0, 100)}...`);
               }
               if (file.credentials && file.credentials.length) {
                   findings.push(`- Credentials (${file.credentials.length}): ${file.credentials.map(c => c.value || c.match).join(', ').substring(0, 100)}...`);
               }
               if (file.xss_vulnerabilities && file.xss_vulnerabilities.length) {
                   findings.push(`- XSS Vulnerabilities (${file.xss_vulnerabilities.length}) found.`);
               }
               if (file.recommendations && file.recommendations.length) {
                   findings.push(`- Recommendations: ${file.recommendations.map(r => r.title).join('; ')}`);
               }
               
               if(findings.length > 0) {
                   context += findings.join("\n") + "\n";
               } else {
                   context += "No significant security issues found.\n";
               }
          });
          context += "\nPlease use these findings to answer the user's questions comprehensively.";
      }

      // Prepare messages for Puter.js
      const messages = [
          { role: 'system', content: systemInstruction },
          { role: 'user', content: context ? (text + context) : text }
      ];

      // Remove typing indicator before streaming starts
      const typingEl = document.querySelector('.message.typing');
      if (typingEl) typingEl.remove();

      // Create bot message container
      const botMsgDiv = addMessage("", 'bot');
      const contentDiv = botMsgDiv.querySelector('.message-content');
      let fullResponse = "";

      // Use Puter.js with streaming
      const response = await puter.ai.chat(messages, { 
          model: selectedModel,
          stream: true 
      });

      for await (const part of response) {
          if (part?.text) {
              fullResponse += part.text;
              contentDiv.innerHTML = fullResponse.replace(/\n/g, '<br>');
              chatMessages.scrollTop = chatMessages.scrollHeight;
          }
      }
      
    } catch (err) {
      console.error(err);
      const typingEl = document.querySelector('.message.typing');
      if (typingEl) typingEl.remove();
      
      // If we already have a partial response, don't show error, just log it. 
      // Otherwise show error.
      const lastMsg = chatMessages.lastElementChild;
      if (!lastMsg || !lastMsg.classList.contains('bot') || lastMsg.textContent.trim() === "") {
          addMessage("Sorry, I encountered an error connecting to the AI service (Puter.js).", 'bot');
      }
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
