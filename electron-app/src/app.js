/* ═══════════════════════════════════════════════════════════
   VulnScan5G — Frontend Application Logic (v2)
   Fixed: file browse, fix results display, detail modal,
   LLM toggle disable, confidence colors, export paths
   ═══════════════════════════════════════════════════════════ */

const API = 'http://127.0.0.1:8765';
let currentResult = null;
let allFindings = [];
let allRules = [];
let fixesData = null;
let scanPollInterval = null;
let llmAvailable = false;

// ─── Navigation ─────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => navigateTo(btn.dataset.page));
});

function navigateTo(page) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`[data-page="${page}"]`).classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`page-${page}`).classList.add('active');
    if (page === 'rules' && allRules.length === 0) loadRules();
    if (page === 'settings') checkLLMStatus();
}

// ─── API Helper ─────────────────────────────────────────────
async function api(endpoint, options = {}) {
    try {
        const res = await fetch(`${API}${endpoint}`, {
            headers: { 'Content-Type': 'application/json' },
            ...options,
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        return await res.json();
    } catch (e) {
        if (e.message.includes('Failed to fetch') || e.message.includes('NetworkError')) {
            throw new Error('Server not running. Please restart the application.');
        }
        throw e;
    }
}

// ─── Browse Folder & File ───────────────────────────────────
async function browseFolder() {
    const path = await _selectFolder();
    if (path) document.getElementById('scan-path').value = path;
}

async function browseFile() {
    const path = await _selectFile();
    if (path) document.getElementById('scan-path').value = path;
}

async function browseFolderQuick() {
    const path = await _selectFolder();
    if (path) document.getElementById('quick-path').value = path;
}

async function browseFileQuick() {
    const path = await _selectFile();
    if (path) document.getElementById('quick-path').value = path;
}

async function _selectFolder() {
    if (window.electronAPI) {
        return await window.electronAPI.selectFolder();
    }
    return prompt('Enter folder path:');
}

async function _selectFile() {
    if (window.electronAPI) {
        return await window.electronAPI.selectFile();
    }
    return prompt('Enter file path:');
}

// ─── Quick Scan ─────────────────────────────────────────────
function startQuickScan() {
    const path = document.getElementById('quick-path').value;
    if (!path) { showToast('Please select a folder or file first!'); return; }
    document.getElementById('scan-path').value = path;
    navigateTo('scan');
    startScan();
}

// ─── Start Scan ─────────────────────────────────────────────
async function startScan() {
    const target = document.getElementById('scan-path').value;
    if (!target) { showToast('Please select a target folder or file!'); return; }

    const useLlm = document.getElementById('opt-llm').checked;
    const doFix = document.getElementById('opt-fix').checked;
    const severity = document.getElementById('opt-severity').value;
    const model = document.getElementById('setting-model')?.value || null;

    // Show progress
    document.getElementById('scan-progress').classList.remove('hidden');
    document.getElementById('scan-results').classList.add('hidden');
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="progress-spinner"></span> Scanning...';

    const progressBar = document.getElementById('progress-bar');
    progressBar.style.width = '10%';

    try {
        await api('/scan', {
            method: 'POST',
            body: JSON.stringify({ target, min_severity: severity, use_llm: useLlm, do_fix: doFix, model_name: model }),
        });

        let progress = 10;
        const stages = [
            'Stage 1: Loading files...',
            'Stage 2: Extracting metadata...',
            'Stage 3: Running detectors (regex, AST, tree-sitter)...',
            'Stage 4: Merging & scoring findings...',
            useLlm ? 'Stage 5: LLM reasoning...' : null,
            doFix ? 'Stage 6: Generating auto-fixes...' : null,
            'Stage 7: Building report...',
        ].filter(Boolean);
        let stageIdx = 0;

        scanPollInterval = setInterval(async () => {
            try {
                const status = await api('/scan/status');

                if (progress < 88) {
                    progress += 2 + Math.random() * 4;
                    progressBar.style.width = `${Math.min(progress, 88)}%`;
                }

                // Cycle through stage messages
                const detail = document.getElementById('progress-detail');
                if (status.running) {
                    if (stageIdx < stages.length) {
                        detail.textContent = stages[stageIdx];
                        if (progress > (stageIdx + 1) * (80 / stages.length)) stageIdx++;
                    }
                } else {
                    clearInterval(scanPollInterval);
                    progressBar.style.width = '100%';
                    detail.textContent = 'Scan complete!';

                    if (status.error) {
                        throw new Error(status.error);
                    }

                    setTimeout(() => displayResults(status.result, doFix, target), 500);
                }
            } catch (e) {
                clearInterval(scanPollInterval);
                showToast(`Scan error: ${e.message}`);
                resetScanUI();
            }
        }, 800);

    } catch (e) {
        showToast(`Failed to start scan: ${e.message}`);
        resetScanUI();
    }
}

function resetScanUI() {
    document.getElementById('scan-progress').classList.add('hidden');
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
    document.getElementById('progress-bar').style.width = '0%';
}

// ─── Display Results ────────────────────────────────────────
function displayResults(result, didFix, target) {
    currentResult = result;
    fixesData = null;
    const summary = result.summary;
    const findings = result.findings || [];
    allFindings = findings;

    document.getElementById('scan-progress').classList.add('hidden');
    document.getElementById('scan-results').classList.remove('hidden');
    resetScanUI();

    // Severity counts with animation
    animateCount('cnt-critical', summary.critical || 0);
    animateCount('cnt-high', summary.high || 0);
    animateCount('cnt-medium', summary.medium || 0);
    animateCount('cnt-low', summary.low || 0);
    animateCount('cnt-info', summary.info || 0);

    // Meta info
    document.getElementById('meta-files').textContent = summary.files_scanned || 0;
    document.getElementById('meta-duration').textContent = (summary.duration_seconds || 0).toFixed(2);
    document.getElementById('meta-total').textContent = summary.total_findings || 0;

    // File filter dropdown
    const fileFilter = document.getElementById('findings-file-filter');
    fileFilter.innerHTML = '<option value="all">All Files</option>';
    const files = [...new Set(findings.map(f => f.file_path))].sort();
    files.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f;
        opt.textContent = basename(f);
        fileFilter.appendChild(opt);
    });

    renderFindings(findings);

    // Load fixes if auto-fix was enabled
    if (didFix) {
        loadFixes();
    } else {
        // Hide fix panel
        const fixPanel = document.getElementById('fix-results');
        if (fixPanel) fixPanel.classList.add('hidden');
        document.getElementById('meta-fixed').classList.add('hidden');
        document.getElementById('meta-fixed-dir').classList.add('hidden');
    }
}

// ─── Load Fixes from /fixes endpoint ────────────────────────
async function loadFixes() {
    try {
        const data = await api('/fixes');
        fixesData = data;

        // Update meta bar
        const fixedEl = document.getElementById('meta-fixed');
        const fixedCountEl = document.getElementById('meta-fixed-count');
        const fixedDirEl = document.getElementById('meta-fixed-dir');
        const fixedPathEl = document.getElementById('meta-fixed-path');

        fixedCountEl.textContent = data.total_files || 0;
        fixedEl.classList.remove('hidden');
        fixedPathEl.textContent = data.fixed_dir || 'fixed_output/';
        fixedDirEl.classList.remove('hidden');

        // Re-render findings with fix info
        renderFindings(allFindings);

        // Render fix panel
        renderFixPanel(data);

    } catch (e) {
        console.error('Failed to load fixes:', e);
    }
}

function renderFixPanel(data) {
    let fixPanel = document.getElementById('fix-results');
    if (!fixPanel) {
        fixPanel = document.createElement('div');
        fixPanel.id = 'fix-results';
        fixPanel.className = 'card';
        // Insert after findings table
        const container = document.querySelector('.findings-table-container');
        container.parentElement.insertBefore(fixPanel, container.nextSibling);
    }

    if (!data.fixes || data.fixes.length === 0) {
        fixPanel.innerHTML = '<div class="empty-state"><span class="empty-icon">🔧</span><p>No fixes were generated.</p></div>';
        fixPanel.classList.remove('hidden');
        return;
    }

    fixPanel.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
            <h3 style="font-size:16px;font-weight:700;margin:0">🔧 Auto-Fix Results — ${data.total_files} file(s) patched</h3>
            <div style="display:flex;gap:8px">
                <button class="btn btn-secondary" id="btn-save-fixes" onclick="saveFixesTo()" style="font-size:13px">
                    📁 Save To...
                </button>
                <button class="btn btn-primary" id="btn-apply-fixes" onclick="applyFixes()" style="font-size:13px">
                    ✅ Apply to Source
                </button>
            </div>
        </div>
        <div style="font-size:12px;color:#9898b0;margin-bottom:6px">
            📂 Fixed copies at: <code style="color:#64ffda">${esc(data.fixed_dir)}</code>
        </div>
        <div style="font-size:11px;color:#5a5a7a;margin-bottom:16px">
            📁 <strong>Save To</strong> — choose any folder to copy fixed files &nbsp;|&nbsp;
            ✅ <strong>Apply to Source</strong> — replace originals (<code>.bak</code> backup created)
        </div>
        <div id="apply-result" class="hidden" style="margin-bottom:12px"></div>
        ${data.fixes.map(f => `
            <div class="fix-file-card" style="background:#161625;border:1px solid rgba(255,255,255,0.06);border-radius:10px;padding:14px;margin-bottom:10px">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
                    <span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64ffda">${esc(f.filename)}</span>
                    <span style="font-size:11px">
                        <span style="color:#00e676">+${f.additions}</span>
                        <span style="color:#ff4757;margin-left:6px">-${f.deletions}</span>
                    </span>
                </div>
                <div style="font-size:10px;color:#5a5a7a;margin-bottom:6px">${esc(f.original_path)}</div>
                <pre style="background:#0f0f1a;border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:10px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#e8e8f0;overflow-x:auto;margin:0;white-space:pre-wrap;max-height:200px;overflow-y:auto">${formatDiff(f.diff)}</pre>
            </div>
        `).join('')}
    `;
    fixPanel.classList.remove('hidden');
}

async function applyFixes() {
    const btn = document.getElementById('btn-apply-fixes');
    const resultDiv = document.getElementById('apply-result');
    btn.disabled = true;
    btn.textContent = '⏳ Applying...';

    try {
        const data = await api('/fixes/apply', { method: 'POST' });
        resultDiv.classList.remove('hidden');

        if (data.total_applied > 0) {
            resultDiv.innerHTML = `
                <div style="background:rgba(0,230,118,0.1);border:1px solid rgba(0,230,118,0.3);border-radius:8px;padding:12px">
                    <div style="font-weight:600;color:#00e676;margin-bottom:6px">✅ ${data.total_applied} file(s) updated successfully!</div>
                    ${data.applied.map(a => `
                        <div style="font-size:11px;color:#9898b0;margin-top:2px">
                            • <code style="color:#64ffda">${esc(a.filename)}</code> → original replaced (backup: <code>${esc(a.filename)}.bak</code>)
                        </div>
                    `).join('')}
                    ${data.total_errors > 0 ? `
                        <div style="color:#ff4757;margin-top:8px;font-size:11px">⚠️ ${data.total_errors} error(s):
                            ${data.errors.map(e => `<div>• ${esc(e.filename)}: ${esc(e.error)}</div>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
            btn.textContent = '✅ Applied!';
            showToast(`✅ ${data.total_applied} file(s) patched. Backups created as .bak`);
        } else {
            resultDiv.innerHTML = `<div style="color:#ff4757;font-size:12px">❌ No files could be applied. ${data.errors.map(e => e.error).join(', ')}</div>`;
            btn.textContent = '❌ Failed';
            btn.disabled = false;
        }
    } catch (e) {
        btn.textContent = '❌ Retry';
        btn.disabled = false;
        showToast(`❌ Apply failed: ${e.message}`);
    }
}

async function saveFixesTo() {
    // Open native folder picker
    let savePath = null;
    if (window.electronAPI && window.electronAPI.selectSaveFolder) {
        savePath = await window.electronAPI.selectSaveFolder();
    } else {
        savePath = prompt('Enter folder path to save fixed files:');
    }
    if (!savePath) return;

    const btn = document.getElementById('btn-save-fixes');
    const resultDiv = document.getElementById('apply-result');
    btn.disabled = true;
    btn.textContent = '⏳ Saving...';

    try {
        const data = await api('/fixes/save', {
            method: 'POST',
            body: JSON.stringify({ output_dir: savePath }),
        });
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = `
            <div style="background:rgba(100,255,218,0.1);border:1px solid rgba(100,255,218,0.3);border-radius:8px;padding:12px">
                <div style="font-weight:600;color:#64ffda;margin-bottom:6px">📁 ${data.total_saved} file(s) saved!</div>
                <div style="font-size:11px;color:#9898b0">
                    Location: <code style="color:#64ffda">${esc(data.output_dir)}</code>
                </div>
                ${data.saved.map(s => `
                    <div style="font-size:11px;color:#9898b0;margin-top:2px">• ${esc(s.filename)}</div>
                `).join('')}
            </div>
        `;
        btn.textContent = '📁 Save To...';
        btn.disabled = false;
        showToast(`✅ ${data.total_saved} fixed file(s) saved to ${savePath}`);
    } catch (e) {
        btn.textContent = '📁 Save To...';
        btn.disabled = false;
        showToast(`❌ Save failed: ${e.message}`);
    }
}
function formatDiff(diff) {
    if (!diff) return '(no changes)';
    return diff.split('\n').map(line => {
        if (line.startsWith('+') && !line.startsWith('+++')) {
            return `<span style="color:#00e676">${esc(line)}</span>`;
        } else if (line.startsWith('-') && !line.startsWith('---')) {
            return `<span style="color:#ff4757">${esc(line)}</span>`;
        } else if (line.startsWith('@@')) {
            return `<span style="color:#a78bfa">${esc(line)}</span>`;
        }
        return esc(line);
    }).join('\n');
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 15));
    const timer = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current;
        if (current >= target) clearInterval(timer);
    }, 40);
}

// ─── Render Findings Table ──────────────────────────────────
function renderFindings(findings) {
    const tbody = document.getElementById('findings-tbody');
    const noFindings = document.getElementById('no-findings');

    if (findings.length === 0) {
        tbody.innerHTML = '';
        noFindings.classList.remove('hidden');
        return;
    }

    noFindings.classList.add('hidden');
    tbody.innerHTML = findings.map((f, idx) => {
        const sev = (f.severity || 'medium').toLowerCase();
        const conf = Math.round((f.confidence || 0) * 100);
        const confClass = conf >= 80 ? 'conf-high' : conf >= 60 ? 'conf-med-high' : conf >= 40 ? 'conf-med' : 'conf-low';
        const fname = basename(f.file_path);
        const hasFixFile = fixesData && fixesData.fixes && fixesData.fixes.some(fx => fx.filename === fname);

        return `
            <tr onclick="showFindingDetail(${idx})">
                <td class="file-cell" title="${esc(f.file_path)}">${esc(fname)}</td>
                <td class="line-cell">${f.line || 0}</td>
                <td><span class="rule-cwe">${esc(f.cwe_id || 'N/A')}</span></td>
                <td><span class="severity-badge ${sev}">${sev}</span></td>
                <td>
                    <div class="confidence-bar"><div class="confidence-fill ${confClass}" style="width:${conf}%"></div></div>
                    <span style="font-size:10px;color:#9898b0;margin-left:4px">${conf}%</span>
                </td>
                <td style="max-width:250px">${esc(truncate(f.description, 80))}</td>
                <td style="font-size:11px;color:#5a5a7a">${esc(f.detector || '')}</td>
                <td>${hasFixFile
                    ? '<span class="fix-badge fixed">✓ Fixed</span>'
                    : (f.recommendation ? '<span class="fix-badge no-fix">Rec.</span>' : '<span style="color:#5a5a7a">—</span>')
                }</td>
            </tr>
        `;
    }).join('');
}

// ─── Finding Detail Modal ───────────────────────────────────
function showFindingDetail(idx) {
    const f = allFindings[idx];
    if (!f) return;

    const sev = (f.severity || 'medium').toLowerCase();
    const conf = Math.round((f.confidence || 0) * 100);

    let html = `
        <div class="modal-row">
            <div class="modal-section">
                <div class="modal-label">File</div>
                <div class="modal-value" style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64ffda">${esc(f.file_path)}</div>
            </div>
            <div class="modal-section" style="flex:0 0 80px">
                <div class="modal-label">Line</div>
                <div class="modal-value" style="font-family:'JetBrains Mono',monospace">${f.line}</div>
            </div>
        </div>

        <div class="modal-row">
            <div class="modal-section">
                <div class="modal-label">Severity</div>
                <div class="modal-value"><span class="severity-badge ${sev}">${sev}</span></div>
            </div>
            <div class="modal-section">
                <div class="modal-label">CWE</div>
                <div class="modal-value"><span class="rule-cwe">${esc(f.cwe_id || 'N/A')}</span></div>
            </div>
            <div class="modal-section">
                <div class="modal-label">Confidence</div>
                <div class="modal-value">${conf}%</div>
            </div>
            <div class="modal-section">
                <div class="modal-label">Detector</div>
                <div class="modal-value">${esc(f.detector || 'N/A')}</div>
            </div>
        </div>

        <div class="modal-section">
            <div class="modal-label">Rule</div>
            <div class="modal-value">${esc(f.rule_id || '')} — ${esc(f.vuln_type || '')}</div>
        </div>

        <div class="modal-section">
            <div class="modal-label">Description</div>
            <div class="modal-value">${esc(f.description)}</div>
        </div>

        <div class="modal-section">
            <div class="modal-label">Recommendation</div>
            <div class="modal-value">${esc(f.recommendation || 'No specific recommendation')}</div>
        </div>
    `;

    // Snippet (code context)
    if (f.snippet) {
        html += `
            <div class="modal-section">
                <div class="modal-label">Code Context</div>
                <div class="modal-code">${esc(f.snippet)}</div>
            </div>
        `;
    }

    // LLM analysis
    if (f.llm_confirmed !== null && f.llm_confirmed !== undefined) {
        html += `
            <div class="modal-section">
                <div class="modal-label">🧠 LLM Analysis</div>
                <div class="modal-value">
                    <strong>${f.llm_confirmed ? '✅ Confirmed' : '❌ Rejected'}</strong>
                    (confidence: ${Math.round((f.llm_confidence || 0) * 100)}%)
                </div>
                ${f.llm_explanation ? `<div class="modal-value" style="margin-top:4px;color:#9898b0">${esc(f.llm_explanation)}</div>` : ''}
            </div>
        `;
    }

    // Auto-fix — check fixesData for this file's diff
    const fname = basename(f.file_path);
    const fileFix = fixesData && fixesData.fixes && fixesData.fixes.find(fx => fx.filename === fname);
    if (fileFix) {
        html += `
            <div class="modal-section">
                <div class="modal-label">🔧 Auto-Fix Applied (+${fileFix.additions} -${fileFix.deletions})</div>
                <pre class="modal-code" style="white-space:pre-wrap">${formatDiff(fileFix.diff)}</pre>
            </div>
        `;
    } else if (f.llm_fix) {
        html += `
            <div class="modal-section">
                <div class="modal-label">🔧 Auto-Fix Applied</div>
                <div class="modal-code">${esc(f.llm_fix)}</div>
            </div>
        `;
    }

    document.getElementById('modal-title').textContent = `${f.cwe_id || 'Finding'} — ${basename(f.file_path)}:${f.line}`;
    document.getElementById('modal-body').innerHTML = html;
    document.getElementById('finding-modal').classList.remove('hidden');
}

function closeFindingModal(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('finding-modal').classList.add('hidden');
}

// Close modal on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.getElementById('finding-modal').classList.add('hidden');
    }
});

// ─── Filter Findings ────────────────────────────────────────
function filterFindings() {
    const search = document.getElementById('findings-search').value.toLowerCase();
    const sevFilter = document.getElementById('findings-severity-filter').value;
    const fileFilter = document.getElementById('findings-file-filter').value;

    let filtered = allFindings;
    if (sevFilter !== 'all') filtered = filtered.filter(f => (f.severity || '').toLowerCase() === sevFilter);
    if (fileFilter !== 'all') filtered = filtered.filter(f => f.file_path === fileFilter);
    if (search) {
        filtered = filtered.filter(f =>
            (f.description || '').toLowerCase().includes(search) ||
            (f.file_path || '').toLowerCase().includes(search) ||
            (f.cwe_id || '').toLowerCase().includes(search) ||
            (f.rule_id || '').toLowerCase().includes(search) ||
            (f.recommendation || '').toLowerCase().includes(search)
        );
    }
    renderFindings(filtered);
}

// ─── Export ──────────────────────────────────────────────────
async function exportJSON() {
    if (!currentResult) { showToast('No scan results to export'); return; }
    try {
        const target = currentResult.summary.target.replace(/\\/g, '/');
        const dir = target.endsWith('/') ? target : target.substring(0, target.lastIndexOf('/') + 1);
        const outPath = dir + 'vulnscan5g_report.json';
        await api('/report/json', { method: 'POST', body: JSON.stringify({ output_path: outPath }) });
        showToast(`✅ JSON saved: ${outPath}`);
    } catch (e) { showToast(`Export failed: ${e.message}`); }
}

async function exportHTML() {
    if (!currentResult) { showToast('No scan results to export'); return; }
    try {
        const target = currentResult.summary.target.replace(/\\/g, '/');
        const dir = target.endsWith('/') ? target : target.substring(0, target.lastIndexOf('/') + 1);
        const outPath = dir + 'vulnscan5g_report.html';
        await api('/report/html', { method: 'POST', body: JSON.stringify({ output_path: outPath }) });
        showToast(`✅ HTML saved: ${outPath}`);
    } catch (e) { showToast(`Export failed: ${e.message}`); }
}

// ─── Rules ──────────────────────────────────────────────────
async function loadRules() {
    try {
        const data = await api('/rules');
        allRules = Array.isArray(data) ? data : (data.rules || []);
        renderRules(allRules);
    } catch (e) {
        document.getElementById('rules-grid').innerHTML = `
            <div class="empty-state"><span class="empty-icon">⚠️</span><p>Failed to load rules: ${esc(e.message)}</p></div>
        `;
    }
}

function renderRules(rules) {
    document.getElementById('rules-grid').innerHTML = rules.map(r => {
        const sev = (r.severity || 'medium').toLowerCase();
        return `
            <div class="rule-card">
                <div class="rule-header">
                    <span class="rule-name">${esc(r.name || r.id)}</span>
                    <span class="rule-cwe">${esc(r.cwe_id || '')}</span>
                </div>
                <div class="rule-desc">${esc(r.description || '')}</div>
                <div class="rule-meta">
                    <span class="severity-badge ${sev}">${sev}</span>
                    <span style="color:#5a5a7a;font-size:11px">${esc(r.id || '')}</span>
                    ${r.recommendation ? `<span style="color:#9898b0;font-size:11px;margin-left:auto">💡 ${esc(truncate(r.recommendation, 50))}</span>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function filterRules() {
    const q = document.getElementById('rules-search').value.toLowerCase();
    if (!q) { renderRules(allRules); return; }
    renderRules(allRules.filter(r =>
        (r.name || '').toLowerCase().includes(q) ||
        (r.cwe_id || '').toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q) ||
        (r.id || '').toLowerCase().includes(q)
    ));
}

// ─── LLM Status ─────────────────────────────────────────────
async function checkLLMStatus() {
    try {
        const data = await api('/llm/status');
        llmAvailable = data.available;
        updateLLMUI(data.available);
    } catch (e) {
        llmAvailable = false;
        updateLLMUI(false);
    }
}

function updateLLMUI(online) {
    // Sidebar indicator
    const dot = document.getElementById('llm-dot');
    const label = document.getElementById('llm-label');
    dot.className = online ? 'llm-dot online' : 'llm-dot offline';
    label.textContent = online ? 'LLM Online' : 'LLM Offline';

    // LLM toggle
    const llmToggle = document.getElementById('toggle-llm');
    if (online) {
        llmToggle.classList.remove('disabled');
        llmToggle.title = '';
    } else {
        llmToggle.classList.add('disabled');
        document.getElementById('opt-llm').checked = false;
        llmToggle.title = 'Set up Ollama in Settings first';
    }

    // Warning banner
    const warning = document.getElementById('llm-warning');
    if (online) {
        warning.classList.add('hidden');
    } else {
        warning.classList.remove('hidden');
    }

    // Settings page status
    if (online) {
        setStepDone('step-install-status', 'btn-install-ollama');
        setStepDone('step-verify-status', 'btn-verify');
    }
}

function setStepDone(statusId, btnId) {
    const status = document.getElementById(statusId);
    const btn = document.getElementById(btnId);
    if (status) status.textContent = '✅ Ready';
    if (btn) { btn.textContent = '✅ Done'; btn.disabled = true; }
}

// ─── Ollama Install ─────────────────────────────────────────
async function installOllama() {
    const btn = document.getElementById('btn-install-ollama');
    const status = document.getElementById('step-install-status');

    // First check if already installed
    btn.disabled = true;
    btn.textContent = '🔍 Checking...';
    status.textContent = '⏳ Checking...';

    try {
        const check = await api('/ollama/check');
        if (check.installed) {
            btn.textContent = '✅ Already Installed';
            status.textContent = `✅ Installed (${check.version || 'detected'})`;
            showToast('✅ Ollama is already installed!');
            return;
        }
    } catch (e) { /* not installed, continue */ }

    // Start download
    btn.textContent = '⏳ Downloading (~100MB)...';
    status.textContent = '⏳ Downloading installer...';

    try {
        await api('/ollama/install', { method: 'POST' });

        // Poll install status
        const pollInstall = setInterval(async () => {
            try {
                const s = await api('/ollama/install/status');
                if (s.running) {
                    if (s.stage === 'downloading') {
                        status.textContent = '⏳ Downloading OllamaSetup.exe (~100MB)...';
                    } else if (s.stage === 'launching') {
                        status.textContent = '⏳ Launching installer...';
                    }
                } else {
                    clearInterval(pollInstall);
                    if (s.done) {
                        btn.textContent = '✅ Installer Launched';
                        status.textContent = '✅ Setup wizard opened — complete the installation!';
                        showToast('✅ Ollama installer launched! Follow the setup wizard on screen.');
                    } else if (s.error) {
                        btn.textContent = '❌ Retry';
                        btn.disabled = false;
                        status.textContent = `❌ ${s.error}`;
                        showToast(`❌ Install failed: ${s.error}`);
                    }
                }
            } catch {
                clearInterval(pollInstall);
            }
        }, 2000);

    } catch (e) {
        btn.textContent = '❌ Retry';
        btn.disabled = false;
        status.textContent = `❌ ${e.message}`;
        showToast(`❌ Install failed: ${e.message}`);
    }
}

// ─── Model Selection ────────────────────────────────────────
function onModelChange() {
    const select = document.getElementById('setting-model');
    const hint = document.getElementById('model-size-hint');
    const sizes = {
        'deepseek-coder:6.7b': '~4GB download, runs on 8GB+ RAM',
        'deepseek-coder:1.3b': '~800MB download, runs on 4GB+ RAM',
        'deepseek-coder:33b': '~19GB download, runs on 32GB+ RAM',
        'codellama:7b': '~4GB download, runs on 8GB+ RAM',
        'codellama:13b': '~7GB download, runs on 16GB+ RAM',
        'codellama:34b': '~19GB download, runs on 32GB+ RAM',
        'qwen2.5-coder:7b': '~4.5GB download, runs on 8GB+ RAM',
        'qwen2.5-coder:14b': '~9GB download, runs on 16GB+ RAM',
        'qwen2.5-coder:1.5b': '~1GB download, runs on 4GB+ RAM',
        'starcoder2:7b': '~4GB download, runs on 8GB+ RAM',
        'starcoder2:3b': '~2GB download, runs on 4GB+ RAM',
        'starcoder2:15b': '~9GB download, runs on 16GB+ RAM',
        'llama3.1:8b': '~4.7GB download, runs on 8GB+ RAM',
        'llama3.1:70b': '~40GB download, runs on 64GB+ RAM',
        'mistral:7b': '~4GB download, runs on 8GB+ RAM',
        'mixtral:8x7b': '~26GB download, runs on 48GB+ RAM',
        'gemma2:9b': '~5.4GB download, runs on 8GB+ RAM',
        'gemma2:27b': '~16GB download, runs on 32GB+ RAM',
        'phi3:medium': '~8GB download, runs on 16GB+ RAM',
        'phi3:mini': '~2.3GB download, runs on 4GB+ RAM',
        'command-r:35b': '~20GB download, runs on 32GB+ RAM',
        'tinyllama:1.1b': '~640MB download, runs on 2GB+ RAM',
    };
    hint.textContent = sizes[select.value] || '';
}

function getSelectedModel() {
    return document.getElementById('setting-model').value;
}

async function pullModel() {
    const model = getSelectedModel();
    if (!model) return;

    const btn = document.getElementById('btn-pull-model');
    const progressDiv = document.getElementById('pull-progress');
    const progressBar = document.getElementById('pull-progress-bar');
    const detail = document.getElementById('pull-detail');

    btn.disabled = true;
    btn.textContent = `⏳ Pulling ${model}...`;
    progressDiv.classList.remove('hidden');
    progressBar.style.width = '0%';
    document.getElementById('step-pull-status').textContent = `⏳ Downloading ${model}...`;

    try {
        await api('/ollama/pull', { method: 'POST', body: JSON.stringify({ model }) });
        const pollPull = setInterval(async () => {
            try {
                const status = await api('/ollama/pull/status');
                if (status.running) {
                    detail.textContent = status.output || `Downloading ${model}...`;
                    const match = (status.output || '').match(/(\d+)%/);
                    if (match) progressBar.style.width = match[1] + '%';
                } else {
                    clearInterval(pollPull);
                    progressBar.style.width = '100%';
                    if (status.output && status.output.toLowerCase().includes('error')) {
                        detail.textContent = status.output;
                        btn.textContent = '❌ Retry';
                        btn.disabled = false;
                        document.getElementById('step-pull-status').textContent = `❌ ${status.output}`;
                        showToast(`❌ Pull failed: ${status.output}`);
                    } else {
                        detail.textContent = `✅ ${model} ready!`;
                        btn.textContent = `✅ ${model} Downloaded`;
                        document.getElementById('step-pull-status').textContent = `✅ ${model} downloaded`;
                        showToast(`✅ Model ${model} is ready!`);
                    }
                }
            } catch { clearInterval(pollPull); }
        }, 2000);
    } catch (e) {
        btn.textContent = '❌ Retry';
        btn.disabled = false;
        progressDiv.classList.add('hidden');
        document.getElementById('step-pull-status').textContent = `❌ ${e.message}`;
        showToast(`❌ Pull failed: ${e.message}`);
    }
}

async function verifyLLM() {
    const btn = document.getElementById('btn-verify');
    btn.disabled = true;
    btn.textContent = '🧪 Testing...';
    document.getElementById('step-verify-status').textContent = '⏳ Verifying...';
    try {
        const data = await api('/llm/status');
        if (data.available) {
            btn.textContent = '✅ Verified';
            document.getElementById('step-verify-status').textContent = '✅ Connected & Ready!';
            updateLLMUI(true);
        } else {
            throw new Error('Ollama not responding');
        }
    } catch (e) {
        btn.textContent = '❌ Retry';
        btn.disabled = false;
        document.getElementById('step-verify-status').textContent = `❌ ${e.message}`;
        updateLLMUI(false);
    }
}

// ─── Toast Notification ─────────────────────────────────────
function showToast(msg) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.style.cssText = `
            position:fixed; bottom:24px; right:24px;
            background:#1e1e32; border:1px solid rgba(255,255,255,0.1);
            color:#e8e8f0; padding:12px 20px; border-radius:10px;
            font-size:13px; z-index:3000; max-width:400px;
            box-shadow:0 8px 30px rgba(0,0,0,0.5);
            transform:translateY(100px); opacity:0;
            transition:all 0.3s ease;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    requestAnimationFrame(() => {
        toast.style.transform = 'translateY(0)';
        toast.style.opacity = '1';
    });
    setTimeout(() => {
        toast.style.transform = 'translateY(100px)';
        toast.style.opacity = '0';
    }, 3500);
}

// ─── Utility ────────────────────────────────────────────────
function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}

function basename(p) {
    return (p || '').split(/[/\\]/).pop() || p;
}

function truncate(s, max) {
    if (!s) return '';
    return s.length > max ? s.substring(0, max) + '...' : s;
}

// ─── Init ───────────────────────────────────────────────────
async function init() {
    try {
        await api('/health');
        console.log('✅ Server connected');
    } catch {
        console.warn('⚠️ Server not available yet');
    }
    checkLLMStatus();
}

document.addEventListener('DOMContentLoaded', init);
