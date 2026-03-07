// ─── PhishGuard Background Service Worker ───────────────────────────────────

const DEFAULT_API_BASE = "http://localhost:8000";
let apiBase = DEFAULT_API_BASE;

// Load saved API base on startup
chrome.storage.local.get(["apiBase"], (res) => {
  if (res.apiBase) apiBase = res.apiBase;
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.apiBase) apiBase = changes.apiBase.newValue;
});

// ─── Cache: url → { status, reason, checkedAt } ─────────────────────────────
const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCached(url) {
  const entry = cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.checkedAt > CACHE_TTL_MS) {
    cache.delete(url);
    return null;
  }
  return entry;
}

// ─── Core: Check URL against PhishGuard backend ──────────────────────────────
async function checkUrl(url) {
  const cached = getCached(url);
  if (cached) return cached;

  try {
    const response = await fetch(`${apiBase}/analyze/quick-check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    const result = {
      status: data.is_malicious ? "dangerous" : "safe",
      reason: data.reason || data.message || "",
      score: data.score ?? null,
      categories: data.categories || [],
      checkedAt: Date.now(),
    };

    cache.set(url, result);
    return result;
  } catch (err) {
    return {
      status: "error",
      reason: `Could not reach PhishGuard backend: ${err.message}`,
      checkedAt: Date.now(),
    };
  }
}

// ─── Core: Check QR image URL ─────────────────────────────────────────────────
async function checkQr(imageUrl) {
  const cached = getCached("qr:" + imageUrl);
  if (cached) return cached;

  try {
    const response = await fetch(`${apiBase}/analyze/check-qr`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image_url: imageUrl }),
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    const result = {
      status: data.is_malicious ? "dangerous" : data.decoded_url ? "safe" : "no-qr",
      reason: data.reason || data.message || "",
      decodedUrl: data.decoded_url || null,
      checkedAt: Date.now(),
    };

    cache.set("qr:" + imageUrl, result);
    return result;
  } catch (err) {
    return {
      status: "error",
      reason: `QR check failed: ${err.message}`,
      checkedAt: Date.now(),
    };
  }
}

// ─── Badge helpers ────────────────────────────────────────────────────────────
function setBadge(tabId, count) {
  if (count > 0) {
    chrome.action.setBadgeText({ text: String(count), tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
  } else {
    chrome.action.setBadgeText({ text: "", tabId });
  }
}

// ─── Context Menu ─────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-check-link",
    title: "🛡️ Check link with PhishGuard",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "phishguard-check-image",
    title: "🔍 Scan image for QR code",
    contexts: ["image"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "phishguard-check-link" && info.linkUrl) {
    const result = await checkUrl(info.linkUrl);
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_CONTEXT_RESULT",
      url: info.linkUrl,
      result,
    });
  }
  if (info.menuItemId === "phishguard-check-image" && info.srcUrl) {
    const result = await checkQr(info.srcUrl);
    chrome.tabs.sendMessage(tab.id, {
      type: "SHOW_CONTEXT_RESULT",
      url: info.srcUrl,
      result,
      isQr: true,
    });
  }
});

// ─── Message handler from content.js / popup.js ───────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CHECK_URL") {
    checkUrl(msg.url).then(sendResponse);
    return true; // async
  }
  if (msg.type === "CHECK_QR") {
    checkQr(msg.imageUrl).then(sendResponse);
    return true;
  }
  if (msg.type === "SET_BADGE") {
    setBadge(sender.tab?.id, msg.count);
    return false;
  }
  if (msg.type === "GET_API_BASE") {
    sendResponse({ apiBase });
    return false;
  }
});

// ─── Intercept Chrome's "dangerous site" navigation ──────────────────────────
// When Chrome flags a page, we also send it to PhishGuard for our own analysis
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const url = details.url;
  if (!url.startsWith("http")) return;

  const result = await checkUrl(url);
  if (result.status === "dangerous") {
    // Notify the tab's content script to show a warning overlay
    chrome.tabs.sendMessage(details.tabId, {
      type: "PHISHGUARD_BLOCK_WARNING",
      url,
      result,
    }).catch(() => {}); // tab may not have content script yet

    setBadge(details.tabId, 1);

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ PhishGuard Alert",
      message: `Dangerous link detected!\n${url.slice(0, 80)}`,
      priority: 2,
    });
  }
});
