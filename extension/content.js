let warningShown = false;

// Listen for warning message from background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'SHOW_WARNING' && !warningShown) {
    showWarningOverlay(message.data);
  }
});

// Check links on hover
document.addEventListener('mouseover', (e) => {
  const link = e.target.closest('a');
  if (!link || !link.href) return;
  const url = link.href;
  if (!url.startsWith('http')) return;

  if (link.getAttribute('data-phishguard')) return;
  link.setAttribute('data-phishguard', 'checking');

  chrome.runtime.sendMessage({ action: 'CHECK_URL', url }, (response) => {
    if (chrome.runtime.lastError) return;
    if (!response || !response.result) return;
    const result = response.result;
    if (result.verdict === 'PHISHING') {
      link.style.outline = result.risk === 'HIGH'
        ? '2px solid #ef4444'
        : '2px solid #f59e0b';
      link.style.outlineOffset = '2px';
      link.title = 'PhishGuard WARNING: '
        + result.verdict + ' — '
        + (result.phishing_probability * 100).toFixed(0)
        + '% phishing probability';
      link.setAttribute('data-phishguard', 'phishing');
    } else {
      link.setAttribute('data-phishguard', 'safe');
    }
  });
});

// Intercept clicks on dangerous links
document.addEventListener('click', (e) => {
  const link = e.target.closest('a');
  if (!link || !link.href) return;
  const url = link.href;
  if (!url.startsWith('http')) return;

  const status = link.getAttribute('data-phishguard');
  if (status === 'phishing') {
    e.preventDefault();
    e.stopPropagation();
    chrome.runtime.sendMessage({ action: 'CHECK_URL', url }, (response) => {
      if (response && response.result) {
        showWarningOverlay(response.result);
      }
    });
  }
}, true);

function showWarningOverlay(data) {
  if (warningShown) return;
  warningShown = true;

  const existing = document.getElementById('phishguard-overlay');
  if (existing) existing.remove();

  const prob   = ((data.phishing_probability || 0) * 100).toFixed(1);
  const flags  = (data.flags || []).slice(0, 4);
  const isHigh = data.risk === 'HIGH';

  const overlay = document.createElement('div');
  overlay.id = 'phishguard-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.88);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Courier New', monospace;
    animation: pgFadeIn 0.3s ease;
  `;

  overlay.innerHTML = `
    <style>
      @keyframes pgFadeIn {
        from { opacity: 0; }
        to   { opacity: 1; }
      }
      @keyframes pgSlideIn {
        from { transform: translateY(-20px); opacity: 0; }
        to   { transform: translateY(0);     opacity: 1; }
      }
      #phishguard-card {
        animation: pgSlideIn 0.3s ease;
      }
      #phishguard-back:hover    { opacity: 0.85 !important; }
      #phishguard-proceed:hover { background: rgba(239,68,68,0.15) !important; }
    </style>

    <div id="phishguard-card" style="
      background: #0a0e1a;
      border: 2px solid ${isHigh ? '#ef4444' : '#f59e0b'};
      border-radius: 16px;
      padding: 2rem;
      max-width: 520px;
      width: 90%;
      color: #e2e8f0;
    ">

      <!-- Header -->
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:1.5rem">
        <div style="
          width:52px;height:52px;
          background:${isHigh ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)'};
          border-radius:12px;
          display:flex;align-items:center;justify-content:center;
          font-size:26px;flex-shrink:0
        ">&#x1F6E1;</div>
        <div>
          <div style="
            font-size:1.2rem;font-weight:bold;
            letter-spacing:3px;
            color:${isHigh ? '#ef4444' : '#f59e0b'}
          ">PHISHING DETECTED</div>
          <div style="font-size:0.72rem;color:#64748b;margin-top:3px;letter-spacing:1px">
            PhishGuard Security Warning
          </div>
        </div>
      </div>

      <!-- URL Box -->
      <div style="
        background:#1a2235;
        border:1px solid rgba(99,179,237,0.15);
        border-radius:8px;
        padding:10px 14px;
        margin-bottom:1.25rem;
        word-break:break-all;
        font-size:0.78rem;
        color:#94a3b8;
        line-height:1.5
      ">${data.url}</div>

      <!-- Risk + Probability -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:1.25rem">
        <div style="
          background:#1a2235;border-radius:8px;
          padding:12px;text-align:center;
          border:1px solid rgba(99,179,237,0.1)
        ">
          <div style="
            font-size:1.3rem;font-weight:bold;
            color:${isHigh ? '#ef4444' : '#f59e0b'}
          ">${data.risk}</div>
          <div style="font-size:0.62rem;color:#64748b;letter-spacing:1px;margin-top:3px">
            RISK LEVEL
          </div>
        </div>
        <div style="
          background:#1a2235;border-radius:8px;
          padding:12px;text-align:center;
          border:1px solid rgba(99,179,237,0.1)
        ">
          <div style="
            font-size:1.3rem;font-weight:bold;
            color:${isHigh ? '#ef4444' : '#f59e0b'}
          ">${prob}%</div>
          <div style="font-size:0.62rem;color:#64748b;letter-spacing:1px;margin-top:3px">
            PHISHING PROBABILITY
          </div>
        </div>
      </div>

      <!-- Reasons -->
      ${flags.length ? `
        <div style="margin-bottom:1.25rem">
          <div style="
            font-size:0.65rem;letter-spacing:2px;
            color:#ef4444;text-transform:uppercase;
            margin-bottom:8px
          ">&#x25BA; Why this is dangerous</div>
          ${flags.map(f => `
            <div style="
              display:flex;align-items:flex-start;gap:8px;
              padding:8px 10px;
              background:rgba(239,68,68,0.07);
              border:1px solid rgba(239,68,68,0.2);
              border-radius:6px;margin-bottom:5px
            ">
              <div style="
                width:5px;height:5px;border-radius:50%;
                background:#ef4444;flex-shrink:0;margin-top:5px
              "></div>
              <div style="font-size:0.73rem;color:#e2e8f0;line-height:1.4">${f}</div>
            </div>
          `).join('')}
        </div>
      ` : ''}

      <!-- Buttons -->
      <div style="display:flex;gap:10px">
        <button id="phishguard-back" style="
          flex:2;
          background:#3b82f6;border:none;
          border-radius:10px;padding:13px;
          color:white;
          font-family:'Courier New',monospace;
          font-size:0.8rem;letter-spacing:1px;
          cursor:pointer;font-weight:bold;
          transition:opacity 0.2s
        ">&#x25C4; GO BACK (SAFE)</button>

        <button id="phishguard-proceed" style="
          flex:1;
          background:transparent;
          border:1px solid rgba(239,68,68,0.4);
          border-radius:10px;padding:13px;
          color:#ef4444;
          font-family:'Courier New',monospace;
          font-size:0.72rem;letter-spacing:1px;
          cursor:pointer;
          transition:background 0.2s
        ">Proceed anyway</button>
      </div>

      <!-- Footer -->
      <div style="
        text-align:center;margin-top:1.25rem;
        font-size:0.62rem;color:#334155;letter-spacing:1px
      ">
        PHISHGUARD EXTENSION &#x25BA; PROTECTING YOU FROM PHISHING
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // GO BACK button
  document.getElementById('phishguard-back').addEventListener('click', () => {
    overlay.remove();
    warningShown = false;
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://google.com';
    }
  });

  // Proceed anyway button
  document.getElementById('phishguard-proceed').addEventListener('click', () => {
    if (confirm('WARNING: This site has been flagged as phishing. Proceed at your own risk?')) {
      overlay.remove();
      warningShown = false;
      chrome.runtime.sendMessage({
        action: 'PROCEED_ANYWAY',
        url: window.location.href
      });
    }
  });

  // Click outside to dismiss
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      overlay.remove();
      warningShown = false;
    }
  });
}

