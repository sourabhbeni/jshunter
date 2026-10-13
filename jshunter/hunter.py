"""Core hunter: discover JS files on a target, download, scan for secrets + endpoints.

Passive recon only: plain GET requests, no form submissions, no auth bypass.
Only run against targets you are authorized to test (your own assets,
a bug-bounty scope that allows it, or a lab).
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import requests

from .patterns import scan_text
from .endpoints import extract_endpoints, extract_sourcemap_urls

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_JS = 40
DEFAULT_MAX_BYTES = 2_000_000  # 2 MB per file cap

HEADERS = {"User-Agent": "jshunter/0.1 (bug-bounty recon; passive only)"}


class _ScriptSrcParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for k, v in attrs:
                if k == "src" and v:
                    self.srcs.append(v)


def discover_js_urls(page_url, session, timeout=DEFAULT_TIMEOUT):
    """Fetch a page and return absolute JS URLs from <script src> tags."""
    resp = session.get(page_url, timeout=timeout, headers=HEADERS)
    resp.raise_for_status()
    parser = _ScriptSrcParser()
    parser.feed(resp.text)
    base = "{0.scheme}://{0.netloc}".format(urlparse(page_url))
    urls = []
    for src in parser.srcs:
        abs_url = urljoin(base + "/", src)
        # stay on the same host (avoid pulling third-party libs for secret scanning)
        if urlparse(abs_url).netloc == urlparse(page_url).netloc:
            urls.append(abs_url)
    # dedupe, preserve order
    return list(dict.fromkeys(urls))


def fetch_text(session, url, timeout=DEFAULT_TIMEOUT, max_bytes=DEFAULT_MAX_BYTES):
    """GET a URL, return text (truncated at max_bytes). Returns None on failure."""
    try:
        resp = session.get(url, timeout=timeout, headers=HEADERS, stream=True)
        resp.raise_for_status()
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        raw = b"".join(chunks)[:max_bytes]
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def hunt(target_url, max_js=DEFAULT_MAX_JS, include_sourcemaps=True,
         timeout=DEFAULT_TIMEOUT, session=None):
    """Run the full hunt against one page URL.

    Returns a report dict:
      {target, js_files: [{url, secrets:[...], endpoints:[...], sourcemaps:[...]}],
       summary: {files_scanned, secrets_found, endpoints_found, by_severity:{...}}}
    """
    session = session or requests.Session()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    js_urls = discover_js_urls(target_url, session, timeout=timeout)[:max_js]

    files = []
    by_severity = {}
    n_secrets = 0
    n_endpoints = 0

    for js_url in js_urls:
        text = fetch_text(session, js_url, timeout=timeout)
        if text is None:
            files.append({"url": js_url, "error": "fetch failed", "secrets": [],
                          "endpoints": [], "sourcemaps": []})
            continue
        secrets = scan_text(text)
        endpoints = extract_endpoints(text)
        sourcemaps = extract_sourcemap_urls(text, js_url) if include_sourcemaps else []

        # redact full secret values from the per-file listing is NOT done here;
        # callers that render reports should use 'preview'. Full values are kept
        # so the operator can verify findings against the target.
        for s in secrets:
            by_severity[s["severity"]] = by_severity.get(s["severity"], 0) + 1
        n_secrets += len(secrets)
        n_endpoints += len(endpoints)
        files.append({"url": js_url, "secrets": secrets, "endpoints": endpoints,
                      "sourcemaps": sourcemaps, "bytes": len(text)})

    return {
        "target": target_url,
        "tool": "jshunter/0.1",
        "js_files": files,
        "summary": {
            "pages_crawled": 1,
            "files_scanned": len([f for f in files if "error" not in f]),
            "files_failed": len([f for f in files if "error" in f]),
            "secrets_found": n_secrets,
            "endpoints_found": n_endpoints,
            "by_severity": by_severity,
        },
    }
