const API_URL = 'http://localhost:8000/scan';

const SAFE_DOMAINS = [
  'google.com','youtube.com','facebook.com','twitter.com',
  'instagram.com','linkedin.com','github.com','microsoft.com',
  'apple.com','amazon.com','wikipedia.org','reddit.com',
  'netflix.com','stackoverflow.com','localhost'
];

const cache = {};

async function checkURL(url) {
  if (!url || url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url.startsWith('about:') ||
      url.startsWith('file://')) {
    return null;
  }

  if (cache[url]) return cache[url];

  try {
    const hostname = new URL(url).hostname.replace('www.', '');
    if (SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d))) {
      const result = { verdict: 'SAFE', risk: 'LOW', phishing_probability: 0, flags: [], url };
      cache[url] = result;
      return result;
    }
  } catch(e) { return null; }

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    cache[url] = data;

    chrome.storage.local.get(['totalScanned','totalPhishing','totalSafe'], (res) => {
      const total    = (res.totalScanned  || 0) + 1;
      const phishing = (res.totalPhishing || 0) + (data.verdict === 'PHISHING' ? 1 : 0);
      const safe     = (res.totalSafe     || 0) + (data.verdict === 'SAFE'     ? 1 : 0);
      chrome.storage.local.set({ totalScanned: total, totalPhishing: phishing, totalSafe: safe });
    });

    chrome.storage.local.get(['recentScans'], (res) => {
      const scans = res.recentScans || [];
      scans.unshift({
        url: data.url,
        verdict: data.verdict,
        risk: data.risk,
        probability: data.phishing_probability,
        time: new Date().toLocaleTimeString()
      });
      if (scans.length > 20) scans.pop();
      chrome.storage.local.set({ recentScans: scans });
    });

    return data;
  } catch(e) {
    console.log('PhishGuard API not reachable:', e);
    return null;
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'loading' || !tab.url) return;
  if (tab.url.startsWith('chrome://') ||
      tab.url.startsWith('chrome-extension://')) return;

  const result = await checkURL(tab.url);
  if (!result) return;

  if (result.verdict === 'PHISHING') {
    if (result.risk === 'HIGH') {
      chrome.action.setBadgeText({ text: '!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
    } else {
      chrome.action.setBadgeText({ text: '?', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
    }
    chrome.tabs.sendMessage(tabId, {
      action: 'SHOW_WARNING',
      data: result
    }).catch(() => {});
  } else {
    chrome.action.setBadgeText({ text: '', tabId });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'CHECK_URL') {
    checkURL(message.url).then(result => {
      sendResponse({ result });
    });
    return true;
  }
  if (message.action === 'GET_STATS') {
    chrome.storage.local.get(['totalScanned','totalPhishing','totalSafe','recentScans'], (res) => {
      sendResponse(res);
    });
    return true;
  }
  if (message.action === 'PROCEED_ANYWAY') {
    chrome.storage.local.get(['allowedUrls'], (res) => {
      const allowed = res.allowedUrls || [];
      allowed.push(message.url);
      chrome.storage.local.set({ allowedUrls: allowed });
    });
  }
});

