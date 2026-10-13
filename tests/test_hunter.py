"""Tests for endpoint extraction and the hunter (mocked HTTP)."""
import responses

from jshunter.endpoints import extract_endpoints, extract_sourcemap_urls
from jshunter.hunter import hunt


def test_extract_endpoints():
    js = """
    fetch("/api/v1/users");
    axios.post('/graphql', {q: 1});
    var u = "https://api.example.com/internal/debug";
    """
    eps = extract_endpoints(js)
    vals = {e["value"] for e in eps}
    assert "/api/v1/users" in vals
    assert "/graphql" in vals
    assert "https://api.example.com/internal/debug" in vals


def test_cdn_urls_skipped():
    js = 'var x = "https://cdn.jsdelivr.net/npm/vue@3"; fetch("/api/me");'
    vals = {e["value"] for e in extract_endpoints(js)}
    assert not any("jsdelivr" in v for v in vals)
    assert "/api/me" in vals


def test_sourcemap_relative():
    maps = extract_sourcemap_urls("//# sourceMappingURL=app.js.map",
                                  "https://ex.com/static/app.js")
    assert maps == ["https://ex.com/static/app.js.map"]


@responses.activate
def test_hunt_end_to_end():
    page = ('<html><head>'
            '<script src="/static/app.js"></script>'
            '<script src="https://cdn.example.net/lib.js"></script>'
            '</head></html>')
    js = ('var key="AKIAIOSFODNN7EXAMPLE";\n'
          'fetch("/api/v1/admin");\n'
          '//# sourceMappingURL=app.js.map')
    responses.add(responses.GET, "https://target.example/", body=page, status=200)
    responses.add(responses.GET, "https://target.example/static/app.js", body=js, status=200)

    report = hunt("https://target.example/", session=None)
    assert report["summary"]["files_scanned"] == 1  # CDN host skipped
    assert report["summary"]["secrets_found"] == 1
    assert report["js_files"][0]["secrets"][0]["rule"] == "aws-access-key-id"
    assert any(e["value"] == "/api/v1/admin" for e in report["js_files"][0]["endpoints"])
    assert report["js_files"][0]["sourcemaps"] == [
        "https://target.example/static/app.js.map"]


@responses.activate
def test_hunt_fetch_failure_recorded():
    responses.add(responses.GET, "https://t.example/", body='<script src="/a.js"></script>', status=200)
    responses.add(responses.GET, "https://t.example/a.js", status=500)
    report = hunt("https://t.example/")
    assert report["summary"]["files_failed"] == 1
