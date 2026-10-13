"""Endpoint extraction from JavaScript sources.

Finds API paths, absolute URLs, GraphQL endpoints, and websocket URLs
that reveal hidden attack surface.
"""
import re

# fetch("/api/users"), axios.post('/v1/login'), $.ajax({url: ...}), open("GET", ...)
_FETCH_CALL = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete|request)|\$\.(?:ajax|get|post)|"""
    r"""xmlhttp\.open|open)\s*\(\s*['"`]([^'"`]{1,200})['"`]""",
    re.IGNORECASE,
)

# any quoted string that looks like an API-ish path
_QUOTED_PATH = re.compile(r"""['"`](/(?:api|v\d|graphql|rest|internal|admin|debug)[A-Za-z0-9\-_/{}:?=&%.]*)['"`]""")

# absolute URLs (http/https/ws)
_ABSOLUTE_URL = re.compile(r"""['"`](https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200}|wss?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200})['"`]""")

# string concat building paths: "/api/" + version + "/users"
_CONCAT_PATH = re.compile(r"""['"](/[A-Za-z0-9\-_]{1,40}/)['"]\s*\+""")

GRAPHQL_HINTS = ("graphql", "/gql")


def extract_endpoints(js_text):
    """Return sorted unique list of endpoint dicts: {value, kind}."""
    found = {}

    def add(value, kind):
        value = value.strip()
        if not value or len(value) > 200:
            return
        # skip junk
        if value in ("/", "//"):
            return
        key = (value, kind)
        if key not in found:
            found[key] = {"value": value, "kind": kind}

    for m in _FETCH_CALL.finditer(js_text):
        add(m.group(1), "fetch-call")
    for m in _QUOTED_PATH.finditer(js_text):
        v = m.group(1)
        kind = "graphql" if any(h in v.lower() for h in GRAPHQL_HINTS) else "api-path"
        add(v, kind)
    for m in _ABSOLUTE_URL.finditer(js_text):
        v = m.group(1)
        # skip common third-party CDNs to keep the signal on first-party surface
        low = v.lower()
        if any(cdn in low for cdn in ("googleapis.com", "gstatic.com", "cloudflare.com",
                                      "jsdelivr.net", "unpkg.com", "facebook.net",
                                      "googletagmanager", "hotjar.com", "stripe.com/js")):
            continue
        add(v, "absolute-url")
    for m in _CONCAT_PATH.finditer(js_text):
        add(m.group(1) + "<concat>", "partial-path")

    return sorted(found.values(), key=lambda e: (e["kind"], e["value"]))


def extract_sourcemap_urls(js_text, js_url):
    """Find sourceMappingURL references; maps often leak original source."""
    maps = []
    for m in re.finditer(r"//#\s*sourceMappingURL=(\S+)", js_text):
        ref = m.group(1).strip()
        if ref.startswith(("http://", "https://", "//")):
            maps.append(ref if "://" in ref else "https:" + ref)
        else:
            # relative to the JS file
            base = js_url.rsplit("/", 1)[0]
            maps.append(base + "/" + ref.lstrip("./"))
    return maps
