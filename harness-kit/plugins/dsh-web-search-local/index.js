/**
 * Local web search for DSH.
 * 1) SearXNG JSON at SEARXNG_URL (default http://127.0.0.1:8888)
 * 2) DuckDuckGo HTML fallback — no API key
 * Provider id: local-ddg (Harness searchProvider pin).
 */
export const name = "dsh-web-search-local";
export const inject = ["web"];

const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const DDG_HTML = "https://html.duckduckgo.com/html/";

function decodeHref(href) {
  try {
    const u = new URL(href, DDG_HTML);
    const uddg = u.searchParams.get("uddg");
    if (uddg) return decodeURIComponent(uddg);
    if (u.hostname.endsWith("duckduckgo.com") && u.pathname.startsWith("/l/")) {
      const inner = u.searchParams.get("uddg");
      if (inner) return decodeURIComponent(inner);
    }
    return u.href;
  } catch {
    return href;
  }
}

function parseHtml(html, max) {
  const sources = [];
  const seen = new Set();
  const blockRe = /<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  const snippetRe = /class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/(?:a|td|span|div)>/gi;
  const snippets = [];
  let sm;
  while ((sm = snippetRe.exec(html))) {
    snippets.push(stripTags(sm[1]));
  }
  let m;
  let i = 0;
  while ((m = blockRe.exec(html))) {
    const url = decodeHref(m[1].replace(/&amp;/g, "&"));
    if (!url.startsWith("http") || seen.has(url)) continue;
    if (url.includes("duckduckgo.com/y.js")) continue;
    seen.add(url);
    sources.push({
      url,
      title: stripTags(m[2]).slice(0, 200) || url,
      ...(snippets[i] ? { snippet: snippets[i].slice(0, 400) } : {}),
    });
    i += 1;
    if (sources.length >= max) break;
  }
  return sources;
}

function stripTags(s) {
  return s
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function searxSearch(query, maxResults, signal) {
  const base = (process.env.SEARXNG_URL || "http://127.0.0.1:8888").replace(/\/$/, "");
  const url = `${base}/search?${new URLSearchParams({
    q: query,
    format: "json",
    language: "en",
    safesearch: "0",
  })}`;
  const res = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json", "User-Agent": UA },
    signal,
  });
  if (!res.ok) throw new Error(`SearXNG ${res.status}`);
  const data = await res.json();
  const seen = new Set();
  const sources = [];
  for (const r of data.results || []) {
    const href = r.url || r.href;
    if (!href || seen.has(href)) continue;
    seen.add(href);
    const engine = r.engine || (Array.isArray(r.engines) ? r.engines.join(",") : "");
    const snippet = [engine ? `[${engine}]` : "", r.content || r.snippet || ""].filter(Boolean).join(" ").slice(0, 400);
    sources.push({
      url: href,
      title: (r.title || href).slice(0, 200),
      ...(snippet ? { snippet } : {}),
    });
    if (sources.length >= maxResults) break;
  }
  if (!sources.length) throw new Error("SearXNG returned no results");
  return sources;
}

async function ddgSearch(query, maxResults, signal) {
  const url = `${DDG_HTML}?${new URLSearchParams({ q: query, kl: "us-en" })}`;
  const headers = {
    "User-Agent": UA,
    Accept: "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: "https://html.duckduckgo.com/",
  };
  let res = await fetch(url, { method: "GET", headers, signal, redirect: "follow" });
  if (!res.ok) {
    const body = new URLSearchParams({ q: query, b: "", l: "us-en" });
    res = await fetch(DDG_HTML, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal,
      redirect: "follow",
    });
  }
  if (!res.ok) {
    throw new Error(`DuckDuckGo HTML ${res.status}`);
  }
  const html = await res.text();
  return parseHtml(html, maxResults);
}

export function apply(ctx) {
  ctx.web.registerSearchProvider({
    id: "local-ddg",
    available() {
      return true;
    },
    async search(request, signal) {
      const max = Math.max(1, request.maxResults ?? 8);
      try {
        const sources = await searxSearch(request.query, max, signal);
        return { sources, truncated: false, content: "source: searxng" };
      } catch {
        const sources = await ddgSearch(request.query, max, signal);
        return { sources, truncated: false, content: "source: duckduckgo-html" };
      }
    },
  });
}
