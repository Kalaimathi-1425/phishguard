async function scan() {
  const url    = document.getElementById("url").value;
  const result = document.getElementById("result");
  result.textContent = "Scanning...";
  result.style.display = "block";

  try {
    const res  = await fetch("https://your-api.com/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    const safe = data.verdict === "SAFE";

    result.className = safe ? "safe" : "phish";
    result.innerHTML = `
      <strong>${safe ? "✓ SAFE" : "⚠ PHISHING"}</strong><br/>
      Risk: ${data.risk}<br/>
      Probability: ${(data.phishing_probability * 100).toFixed(1)}%
      ${data.flags?.length ?
        "<br/><br/>Flags:<br/>" +
        data.flags.map(f => "• " + f).join("<br/>") : ""}
    `;
  } catch(e) {
    result.textContent = "Error connecting to API";
  }
}

// Auto-scan current tab
chrome.tabs.query({active:true, currentWindow:true}, tabs => {
  document.getElementById("url").value = tabs[0].url;
});
