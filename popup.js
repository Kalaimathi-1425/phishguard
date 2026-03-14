const API = 'http://localhost:8000/scan';

async function checkAPI() {
  try {
    const res = await fetch('http://localhost:8000/health');
    if (res.ok) {
      document.getElementById('statusDot').className = 'status-dot online';
      document.getElementById('apiStatusText').textContent = 'API: connected ✓';
      return true;
    }
  } catch(e) {}
  document.getElementById('statusDot').className = 'status-dot offline';
  document.getElementById('apiStatusText').textContent = 'API: offline — start server!';
  return false;
}

async function scanURL() {
  const input = document.getElementById('urlInput');
  const url   = input.value.trim();
  if (!url) { input.focus(); return; }
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="loading"><span></span><span></span><span></span></span>';
  try {
    const res  = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    showResult(data);
  } catch(e) {
    showResult({ url, verdict: 'ERROR', risk: 'UNKNOWN', phishing_probability: 0, flags: ['API not reachable'] });
  } finally {
    btn.disabled = false;
    btn.textContent = 'SCAN';
  }
}

function showResult(data) {
  const prob    = (data.phishing_probability || 0) * 100;
  const verdict = data.verdict;
  const risk    = data.risk;
  const row     = document.getElementById('verdictRow');
  row.className = 'result-verdict ' + (verdict === 'SAFE' ? 'safe' : risk === 'MEDIUM' ? 'warn' : 'phish');
  const text    = document.getElementById('verdictText');
  text.textContent = verdict;
  text.style.color = verdict === 'SAFE' ? '#22c55e' : risk === 'HIGH' ? '#ef4444' : '#f59e0b';
  document.getElementById('verdictSub').textContent = 'Risk: ' + risk + ' | ' + prob.toFixed(1) + '%';
  const fill = document.getElementById('probFill');
  fill.style.background = prob > 70 ? '#ef4444' : prob > 40 ? '#f59e0b' : '#22c55e';
  setTimeout(() => { fill.style.width = prob + '%'; }, 50);
  const flags = data.flags || [];
  const flagsEl = document.getElementById('flagsList');
  if (flags.length && verdict !== 'SAFE') {
    flagsEl.innerHTML = flags.slice(0, 3).map(f =>
      `<div class="flag-item"><div class="flag-dot"></div><span>${f}</span></div>`
    ).join('');
  } else {
    flagsEl.innerHTML = '';
  }
  document.getElementById('resultBox').classList.add('show');
}

async function checkCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs[0]) return;
  const url    = tabs[0].url;
  const urlEl  = document.getElementById('currentUrl');
  const resEl  = document.getElementById('currentResult');
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    urlEl.textContent = 'Chrome internal page';
    resEl.textContent = 'Not applicable';
    resEl.style.color = '#64748b';
    return;
  }
  urlEl.textContent  = url.length > 50 ? url.substring(0, 50) + '...' : url;
  resEl.innerHTML    = '<span class="loading"><span></span><span></span><span></span></span> Scanning...';
  try {
    const res  = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    const prob = ((data.phishing_probability || 0) * 100).toFixed(1);
    if (data.verdict === 'PHISHING') {
      resEl.textContent = data.risk + ' RISK — ' + prob + '% phishing probability';
      resEl.style.color = data.risk === 'HIGH' ? '#ef4444' : '#f59e0b';
    } else {
      resEl.textContent = 'SAFE — ' + prob + '% phishing probability';
      resEl.style.color = '#22c55e';
    }
  } catch(e) {
    resEl.textContent = 'API offline — cannot check';
    resEl.style.color = '#64748b';
  }
}

function loadStats() {
  chrome.storage.local.get(['totalScanned','totalPhishing','totalSafe','recentScans'], (res) => {
    document.getElementById('totalScanned').textContent  = res.totalScanned  || 0;
    document.getElementById('totalPhishing').textContent = res.totalPhishing || 0;
    document.getElementById('totalSafe').textContent     = res.totalSafe     || 0;
    const scans  = res.recentScans || [];
    const listEl = document.getElementById('historyList');
    if (!scans.length) {
      listEl.innerHTML = '<div class="empty">No scans yet</div>';
      return;
    }
    listEl.innerHTML = scans.slice(0, 6).map(s => {
      const cls = s.verdict === 'SAFE' ? 'safe' : s.risk === 'HIGH' ? 'phish' : 'warn';
      const dot = s.verdict === 'SAFE' ? '#22c55e' : s.risk === 'HIGH' ? '#ef4444' : '#f59e0b';
      const url = s.url.length > 35 ? s.url.substring(0, 35) + '...' : s.url;
      return `<div class="hist-item">
        <div class="hist-dot" style="background:${dot}"></div>
        <div class="hist-url" title="${s.url}">${url}</div>
        <span class="hist-badge badge-${cls}">${s.verdict}</span>
        <span class="hist-time">${s.time || ''}</span>
      </div>`;
    }).join('');
  });
}

function openDashboard() {
  chrome.tabs.create({ url: 'http://localhost:8000/dashboard' });
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') scanURL();
});

checkAPI();
checkCurrentTab();
loadStats();

