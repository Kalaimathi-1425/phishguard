chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!url.startsWith("http")) return;

  try {
    const response = await fetch("https://your-api.com/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await response.json();

    if (data.verdict === "PHISHING") {
      // Show warning notification
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "⚠ PhishGuard Warning",
        message: `PHISHING DETECTED!\n${url}\nRisk: ${data.risk}`
      });

      // Block the page
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(url)}&risk=${data.risk}`
        )
      });
    }
  } catch(e) {
    console.log("PhishGuard check failed:", e);
  }
});
