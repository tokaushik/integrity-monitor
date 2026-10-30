const stateStore = {
  sealValid: true,
  checkedAt: null,
  counts: { total: 0, intact: 0, modified: 0, renamed: 0, missing: 0 },
  files: [],
  audit: [],
  selectedPath: null,
  activeView: "inspector",
  activeFilter: "all",
};

const els = {
  sealStamp: document.getElementById("seal-stamp"),
  sealBanner: document.getElementById("seal-alert-banner"),
  liveWatch: document.getElementById("live-watch-checkbox"),
  btnCheckAll: document.getElementById("btn-check-all"),
  pathInput: document.getElementById("path-input"),
  btnAddPath: document.getElementById("btn-add-path"),
  btnBrowseFile: document.getElementById("btn-browse-file"),
  btnBrowseFolder: document.getElementById("btn-browse-folder"),
  btnResetDb: document.getElementById("btn-reset-db"),
  statusNotice: document.getElementById("status-notice"),
  tabCountTotal: document.getElementById("tab-count-total"),
  cntAll: document.getElementById("cnt-all"),
  cntOk: document.getElementById("cnt-ok"),
  cntFlagged: document.getElementById("cnt-flagged"),
  registryList: document.getElementById("registry-list"),
  inspectionStage: document.getElementById("inspection-stage"),
  viewInspector: document.getElementById("view-inspector"),
  viewLedger: document.getElementById("view-ledger"),
  viewAudit: document.getElementById("view-audit"),
  ledgerScanMeta: document.getElementById("ledger-scan-meta"),
  ledgerTableWrap: document.getElementById("ledger-table-wrap"),
  auditTableWrap: document.getElementById("audit-table-wrap"),
};

let pollTimer = null;

function setNotice(text, isError = false) {
  els.statusNotice.textContent = text;
  els.statusNotice.classList.toggle("is-error", isError);
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function formatBytes(bytes) {
  if (bytes == null) return "N/A";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function parentFolderLabel(fullPath) {
  if (!fullPath) return "";
  const sep = fullPath.includes("\\") ? "\\" : "/";
  const parts = fullPath.split(sep);
  parts.pop();
  return parts.slice(-2).join(sep) || fullPath;
}

function effectiveStatus(fileItem, sealValid) {
  const raw = fileItem.status || "INTACT";
  if (!sealValid && raw === "INTACT") {
    return "UNTRUSTED";
  }
  return raw;
}

function shortTagText(status) {
  if (status === "INTACT") return "Intact";
  if (status === "MODIFIED") return "Changed";
  if (status === "RENAMED") return "Renamed";
  if (status === "MISSING") return "Missing";
  if (status === "UNTRUSTED") return "Tampered DB";
  return status;
}

function stampLabel(status) {
  if (status === "INTACT") return "Intact · Verified";
  if (status === "MODIFIED") return "Modified · Hash Mismatch";
  if (status === "RENAMED") return "Moved / Renamed";
  if (status === "MISSING") return "Missing / Deleted";
  if (status === "UNTRUSTED") return "Untrusted · DB Tampered";
  return status;
}

async function apiCall(url, method = "GET", payload = null) {
  const opts = { method, headers: {} };
  if (payload !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(payload);
  }
  const resp = await fetch(url, opts);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || `HTTP ${resp.status}`);
  }
  return data;
}

/* Render 64-char SHA-256 in readable 8-char groups, highlighting changed digits */
function renderDigestWords(hashStr, compareAgainst = null) {
  if (!hashStr || hashStr.length !== 64) {
    return `<span style="color:var(--vermilion-ink)">Unavailable (file not found at path)</span>`;
  }

  const words = [];
  for (let w = 0; w < 8; w++) {
    const start = w * 8;
    const slice = hashStr.slice(start, start + 8);
    let charsHtml = "";

    if (compareAgainst && compareAgainst.length === 64) {
      for (let i = 0; i < 8; i++) {
        const ch = escapeHtml(slice[i]);
        if (slice[i] !== compareAgainst[start + i]) {
          charsHtml += `<span class="hex-diff">${ch}</span>`;
        } else {
          charsHtml += ch;
        }
      }
    } else {
      charsHtml = escapeHtml(slice);
    }

    words.push(`<span class="hex-word"><span>${charsHtml}</span></span>`);
  }
  return words.join("");
}

function countChangedNibbles(hashA, hashB) {
  if (!hashA || !hashB || hashA.length !== 64 || hashB.length !== 64) return null;
  let diff = 0;
  for (let i = 0; i < 64; i++) {
    if (hashA[i] !== hashB[i]) diff++;
  }
  return diff;
}

/* Main UI Render */
function renderAll() {
  // Seal tag
  if (stateStore.sealValid) {
    els.sealStamp.className = "seal-tag seal-valid";
    els.sealStamp.textContent = "Baseline: Protected";
    els.sealBanner.classList.add("hidden");
  } else {
    els.sealStamp.className = "seal-tag seal-broken";
    els.sealStamp.textContent = "Baseline: Tampered!";
    els.sealBanner.classList.remove("hidden");
  }

  // Counts
  const total = stateStore.files.length;
  const okCount = stateStore.files.filter(
    (f) => effectiveStatus(f, stateStore.sealValid) === "INTACT"
  ).length;
  const flaggedCount = total - okCount;

  els.tabCountTotal.textContent = total;
  els.cntAll.textContent = total;
  els.cntOk.textContent = okCount;
  els.cntFlagged.textContent = flaggedCount;

  // Keep selectedPath valid
  if (total === 0) {
    stateStore.selectedPath = null;
  } else if (!stateStore.files.some((f) => f.path === stateStore.selectedPath)) {
    stateStore.selectedPath = stateStore.files[0].path;
  }

  renderRegistryList();
  renderInspectionSheet();
  renderLedgerTable();
  renderAuditTable();
}

function renderRegistryList() {
  const filtered = stateStore.files.filter((f) => {
    const st = effectiveStatus(f, stateStore.sealValid);
    if (stateStore.activeFilter === "verified") return st === "INTACT";
    if (stateStore.activeFilter === "flagged") return st !== "INTACT";
    return true;
  });

  if (!filtered.length) {
    els.registryList.innerHTML = `<div class="rail-empty">No matching files in this view.</div>`;
    return;
  }

  els.registryList.innerHTML = filtered
    .map((item) => {
      const st = effectiveStatus(item, stateStore.sealValid);
      const isSelected = item.path === stateStore.selectedPath;
      return `
        <div class="registry-item ${isSelected ? "selected" : ""}" data-select-path="${escapeHtml(item.path)}">
          <div class="reg-row-top">
            <span class="reg-filename">${escapeHtml(item.file_name)}</span>
            <span class="mini-tag tag-${escapeHtml(st)}">${shortTagText(st)}</span>
          </div>
          <div class="reg-dir">${escapeHtml(parentFolderLabel(item.path))}</div>
        </div>
      `;
    })
    .join("");
}

function renderInspectionSheet() {
  const file = stateStore.files.find((f) => f.path === stateStore.selectedPath);
  if (!file) {
    els.inspectionStage.innerHTML = `
      <div class="empty-sheet">
        <div class="empty-code">GETTING STARTED</div>
        <h2>Select a File to Start Monitoring</h2>
        <p>
          Click <strong>Select File...</strong> above to generate and save a file's reference SHA-256 hash.
          Whenever you check the file later, this tool generates a new hash and shows whether the file
          is intact, modified, renamed, or deleted.
        </p>
      </div>
    `;
    return;
  }

  const st = effectiveStatus(file, stateStore.sealValid);
  const refHash = file.reference_hash;
  const curHash = file.current_hash;

  // Digest comparison summary note
  let digestNote = "Current hash matches the saved reference hash — file is untouched.";
  if (st === "MODIFIED" && curHash) {
    const diffNibbles = countChangedNibbles(refHash, curHash);
    digestNote = `Hashes do not match (${diffNibbles} of 64 characters changed — highlighted in red above).`;
  } else if (st === "RENAMED" && file.moved_to) {
    digestNote = `Same SHA-256 hash was found under a new filename: ${file.moved_to}`;
  } else if (st === "MISSING") {
    digestNote = "File could not be found at its monitored location.";
  } else if (st === "UNTRUSTED") {
    digestNote = "Warning: baseline.json was edited outside this tool, so stored hashes cannot be trusted.";
  }

  const sizeDeltaText =
    file.size_delta > 0
      ? `+${file.size_delta.toLocaleString()} bytes`
      : file.size_delta < 0
      ? `${file.size_delta.toLocaleString()} bytes`
      : "Unchanged";

  // Block matrix HTML
  let blockMatrixHtml = `<p class="sec-note">Part-by-part view unavailable (file is empty or missing).</p>`;
  const br = file.block_report;
  if (br && Array.isArray(br.segments) && br.segments.length > 0) {
    const stateLabels = {
      intact: "Unchanged",
      modified: "Changed",
      appended: "Added",
      truncated: "Removed",
    };
    const cells = br.segments
      .map((seg) => {
        const tag = stateLabels[seg.state] || seg.state;
        return `
          <div class="blk-cell blk-${escapeHtml(seg.state)}">
            <div class="blk-top">
              <span>Part ${seg.index}</span>
              <span class="blk-state">${escapeHtml(tag)}</span>
            </div>
            <div class="blk-range">Bytes ${seg.start_byte.toLocaleString()}–${seg.end_byte.toLocaleString()}</div>
          </div>
        `;
      })
      .join("");
    blockMatrixHtml = `<div class="block-matrix">${cells}</div>`;
  }

  const findingTone =
    st === "INTACT" ? "" : st === "RENAMED" ? "finding-warn" : "finding-alert";

  const acceptBtn =
    file.status === "MODIFIED" && stateStore.sealValid
      ? `<button class="btn btn-ochre btn-sm" data-file-action="rebaseline" data-path="${escapeHtml(file.path)}">Save as New Baseline</button>`
      : "";

  els.inspectionStage.innerHTML = `
    <article class="inspection-sheet">
      <div class="sheet-top">
        <div>
          <div class="sheet-file-kicker">File Integrity Report</div>
          <h2 class="sheet-file-title">${escapeHtml(file.file_name)}</h2>
          <div class="sheet-file-path">${escapeHtml(file.path)}</div>
        </div>
        <div class="stamp-box stamp-${escapeHtml(st)}">${stampLabel(st)}</div>
      </div>

      <div class="sheet-meta-bar">
        <div class="meta-specs">
          <span>Saved Size: <strong>${formatBytes(file.reference_size)}</strong></span>
          <span>Current Size: <strong>${file.current_size != null ? formatBytes(file.current_size) : "N/A"}</strong></span>
          <span>Size Change: <strong>${escapeHtml(sizeDeltaText)}</strong></span>
          <span>Last Checked: <strong>${escapeHtml(file.checked_at || "-")}</strong></span>
        </div>
        <div class="sheet-actions">
          <button class="btn btn-paper btn-sm" data-file-action="check" data-path="${escapeHtml(file.path)}">Check Now</button>
          ${acceptBtn}
          <button class="btn btn-danger-outline btn-sm" data-file-action="remove" data-path="${escapeHtml(file.path)}">Remove</button>
        </div>
      </div>

      <!-- Section 1: SHA-256 Comparison -->
      <div class="sheet-section">
        <div class="sec-heading">
          <span class="sec-title">SHA-256 Hash Comparison</span>
          <span class="sec-note">Generated with Python hashlib.sha256()</span>
        </div>

        <div class="digest-grid">
          <div class="digest-row">
            <div class="digest-label">Saved Hash</div>
            <div class="digest-words">${renderDigestWords(refHash, null)}</div>
          </div>
          <div class="digest-row">
            <div class="digest-label">Current Hash</div>
            <div class="digest-words">${renderDigestWords(curHash, st === "MODIFIED" ? refHash : null)}</div>
          </div>
        </div>

        <div class="digest-summary-bar">
          <span>${escapeHtml(digestNote)}</span>
        </div>
      </div>

      <!-- Section 2: File Parts Map -->
      <div class="sheet-section">
        <div class="sec-heading">
          <span class="sec-title">Where the File Changed (File Split into Equal Parts)</span>
          <span class="sec-note">${br ? `Each part covers ~${br.block_size.toLocaleString()} bytes from start to end` : ""}</span>
        </div>
        ${blockMatrixHtml}
      </div>

      <!-- Section 3: Summary -->
      <div class="sheet-section">
        <div class="sec-heading">
          <span class="sec-title">Integrity Summary</span>
        </div>
        <div class="finding-box ${findingTone}">
          ${escapeHtml(file.diagnosis || "Reference baseline recorded.")}
        </div>
      </div>
    </article>
  `;
}

function renderLedgerTable() {
  if (stateStore.checkedAt) {
    els.ledgerScanMeta.textContent = `Last full verification: ${stateStore.checkedAt}`;
  }
  if (!stateStore.files.length) {
    els.ledgerTableWrap.innerHTML = `<div class="rail-empty">No files currently monitored.</div>`;
    return;
  }

  const rows = stateStore.files
    .map((f, idx) => {
      const st = effectiveStatus(f, stateStore.sealValid);
      const refShort = f.reference_hash ? f.reference_hash.slice(0, 16) + "…" : "-";
      const curShort = f.current_hash ? f.current_hash.slice(0, 16) + "…" : "MISSING";
      return `
        <tr>
          <td class="mono-cell">${idx + 1}</td>
          <td>
            <strong>${escapeHtml(f.file_name)}</strong>
            <div class="reg-dir">${escapeHtml(f.path)}</div>
          </td>
          <td><span class="mini-tag tag-${escapeHtml(st)}">${escapeHtml(st)}</span></td>
          <td class="mono-cell">${escapeHtml(refShort)}</td>
          <td class="mono-cell">${escapeHtml(curShort)}</td>
          <td class="mono-cell">${formatBytes(f.current_size ?? f.reference_size)}</td>
          <td>${escapeHtml(f.diagnosis || "")}</td>
          <td>
            <button class="btn btn-paper btn-sm" data-inspect-jump="${escapeHtml(f.path)}">Inspect</button>
          </td>
        </tr>
      `;
    })
    .join("");

  els.ledgerTableWrap.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>#</th>
          <th>File</th>
          <th>Status</th>
          <th>Reference SHA-256</th>
          <th>Current SHA-256</th>
          <th>Size</th>
          <th>Finding</th>
          <th>Sheet</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderAuditTable() {
  if (!stateStore.audit.length) {
    els.auditTableWrap.innerHTML = `<div class="rail-empty">Audit trail is empty.</div>`;
    return;
  }

  const rows = stateStore.audit
    .map((ev) => {
      const isAlert = ev.event === "INTEGRITY_ALERT";
      const tagClass = isAlert ? "tag-MODIFIED" : "tag-INTACT";
      return `
        <tr>
          <td class="mono-cell">${escapeHtml(ev.timestamp)}</td>
          <td><span class="mini-tag ${tagClass}">${escapeHtml(ev.event)}</span></td>
          <td><strong>${escapeHtml(ev.file_name)}</strong></td>
          <td>${escapeHtml(ev.details)}</td>
        </tr>
      `;
    })
    .join("");

  els.auditTableWrap.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Event Type</th>
          <th>Target File</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

/* API Workflows */
async function loadState(scan = false) {
  try {
    const data = await apiCall(`/api/state?scan=${scan ? "1" : "0"}`);
    stateStore.sealValid = data.seal_valid;
    stateStore.checkedAt = data.checked_at || stateStore.checkedAt;
    stateStore.counts = data.counts || stateStore.counts;
    stateStore.files = data.files || [];
    stateStore.audit = data.audit || [];
    renderAll();
  } catch (err) {
    setNotice(err.message, true);
  }
}

async function registerTarget(rawPath) {
  const cleaned = rawPath.trim();
  if (!cleaned) {
    setNotice("Provide a file or directory path first.", true);
    return;
  }
  try {
    setNotice("Computing SHA-256 baseline...");
    const res = await apiCall("/api/add", "POST", { path: cleaned });
    els.pathInput.value = "";
    if (res.mode === "directory") {
      setNotice(`Registered ${res.added_count} file(s) from folder.`);
    } else if (res.record) {
      stateStore.selectedPath = res.record.path;
      setNotice(`Baseline recorded for ${res.record.file_name}`);
    }
    await loadState(false);
  } catch (err) {
    setNotice(err.message, true);
  }
}

/* View Tab Switching */
document.querySelectorAll(".view-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    stateStore.activeView = tab.dataset.view;
    document.querySelectorAll(".view-tab").forEach((b) => b.classList.toggle("active", b === tab));
    els.viewInspector.classList.toggle("hidden", stateStore.activeView !== "inspector");
    els.viewLedger.classList.toggle("hidden", stateStore.activeView !== "ledger");
    els.viewAudit.classList.toggle("hidden", stateStore.activeView !== "audit");
  });
});

/* Registry Filter Buttons */
document.querySelectorAll(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    stateStore.activeFilter = btn.dataset.filter;
    document.querySelectorAll(".filter-btn").forEach((b) => b.classList.toggle("active", b === btn));
    renderRegistryList();
  });
});

/* Select File in Left Rail */
els.registryList.addEventListener("click", (e) => {
  const row = e.target.closest("[data-select-path]");
  if (!row) return;
  stateStore.selectedPath = row.dataset.selectPath;
  renderRegistryList();
  renderInspectionSheet();
});

/* Jump from Summary Ledger Table to Inspector Sheet */
els.ledgerTableWrap.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-inspect-jump]");
  if (!btn) return;
  stateStore.selectedPath = btn.dataset.inspectJump;
  document.querySelector('.view-tab[data-view="inspector"]').click();
  renderAll();
});

/* Per-File Inspection Actions */
els.inspectionStage.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-file-action]");
  if (!btn) return;
  const action = btn.dataset.fileAction;
  const target = btn.dataset.path;
  btn.disabled = true;

  try {
    if (action === "check") {
      const res = await apiCall("/api/check", "POST", { path: target });
      setNotice(`${res.result.file_name}: ${res.result.status}`);
      await loadState(false);
    } else if (action === "rebaseline") {
      await apiCall("/api/rebaseline", "POST", { path: target });
      setNotice("Reference SHA-256 updated.");
      await loadState(false);
    } else if (action === "remove") {
      await apiCall("/api/remove", "POST", { path: target });
      setNotice("File removed from baseline.");
      await loadState(false);
    }
  } catch (err) {
    setNotice(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

/* Toolbar & Registration Controls */
els.btnCheckAll.addEventListener("click", async () => {
  els.btnCheckAll.disabled = true;
  try {
    setNotice("Re-hashing all monitored files...");
    const data = await apiCall("/api/check-all", "POST");
    stateStore.sealValid = data.seal_valid;
    stateStore.checkedAt = data.checked_at;
    stateStore.counts = data.counts;
    stateStore.files = data.files || [];
    stateStore.audit = data.audit || [];
    renderAll();
    setNotice(`Scan finished at ${data.checked_at}`);
  } catch (err) {
    setNotice(err.message, true);
  } finally {
    els.btnCheckAll.disabled = false;
  }
});

els.btnAddPath.addEventListener("click", () => registerTarget(els.pathInput.value));
els.pathInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") registerTarget(els.pathInput.value);
});

els.btnBrowseFile.addEventListener("click", async () => {
  els.btnBrowseFile.disabled = true;
  try {
    setNotice("Waiting for file selection dialog...");
    const res = await apiCall("/api/browse-file", "POST");
    if (res.path) {
      await registerTarget(res.path);
    } else {
      setNotice("Selection cancelled.");
    }
  } catch (err) {
    setNotice(err.message, true);
  } finally {
    els.btnBrowseFile.disabled = false;
  }
});

els.btnBrowseFolder.addEventListener("click", async () => {
  els.btnBrowseFolder.disabled = true;
  try {
    setNotice("Waiting for folder selection dialog...");
    const res = await apiCall("/api/browse-folder", "POST");
    if (res.path) {
      await registerTarget(res.path);
    } else {
      setNotice("Selection cancelled.");
    }
  } catch (err) {
    setNotice(err.message, true);
  } finally {
    els.btnBrowseFolder.disabled = false;
  }
});

els.btnResetDb.addEventListener("click", async () => {
  if (!confirm("Clear all tracked files and initialize a fresh sealed baseline?")) return;
  try {
    await apiCall("/api/reset", "POST");
    setNotice("Baseline database reset.");
    await loadState(false);
  } catch (err) {
    setNotice(err.message, true);
  }
});

els.liveWatch.addEventListener("change", () => {
  if (els.liveWatch.checked) {
    loadState(true);
    pollTimer = setInterval(() => loadState(true), 3000);
    setNotice("Auto-Poll active (every 3s)");
  } else {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    setNotice("Auto-Poll paused");
  }
});

// Initial fetch
loadState(true);
