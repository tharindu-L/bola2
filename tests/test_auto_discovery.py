from unittest.mock import MagicMock

from bola_framework.discovery.auto_discovery import AutoDiscoverer


def _fake_response(status_code=200, headers=None, text="", json_body=None, content=b""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    resp.iter_content = MagicMock(return_value=[content] if content else [])
    if json_body is not None:
        resp.json = MagicMock(return_value=json_body)
    else:
        resp.json = MagicMock(side_effect=ValueError())
    return resp


def test_external_js_bundle_is_scanned_for_api_path_literals():
    """Reproduces the Juice Shop scenario: the initial HTML page has no
    inline API references, but a same-origin external JS bundle does."""
    discoverer = AutoDiscoverer(start_url="http://target:3000/", max_pages=5, max_depth=1)

    html_page = _fake_response(
        status_code=200,
        headers={"content-type": "text/html"},
        text=(
            '<html><head><script src="/main.js"></script></head>'
            "<body>Loading...</body></html>"
        ),
    )
    js_bundle = _fake_response(
        status_code=200,
        headers={"content-type": "application/javascript"},
        content=b'fetch("/rest/user/login"); axios.get("/rest/products/search");',
    )

    def fake_get(url, timeout=None, stream=False, **kwargs):
        if url.endswith("/main.js"):
            return js_bundle
        return html_page

    discoverer.session.get = MagicMock(side_effect=fake_get)
    discoverer.session.post = MagicMock(
        return_value=_fake_response(status_code=404, headers={"content-type": "text/html"})
    )

    operations = discoverer.discover()
    paths = {op.path_template for op in operations}

    assert "/rest/user/login" in paths
    assert "/rest/products/search" in paths


def test_template_literal_and_concat_paths_are_discovered():
    """Reproduces the second live gap: real SPA bundles build per-object URLs
    with template literals (`/rest/basket/${id}`) or string concatenation
    ('/api/users/' + id), which the plain string-literal regex cannot match
    at all because of the interpolation syntax. These are exactly the
    endpoints that matter for BOLA testing, so missing them meant the
    scanner only ever saw static/public pages.
    """
    discoverer = AutoDiscoverer(start_url="http://target:3000/", max_pages=5, max_depth=1)

    html_page = _fake_response(
        status_code=200,
        headers={"content-type": "text/html"},
        text='<html><script src="/main.js"></script></html>',
    )
    js_bundle = _fake_response(
        status_code=200,
        headers={"content-type": "application/javascript"},
        content=(
            b"function getBasket(id) { return http.get(`/rest/basket/${id}`); }\n"
            b"function getUser(id) { return http.get('/api/users/' + id); }\n"
        ),
    )

    def fake_get(url, timeout=None, stream=False, **kwargs):
        if url.endswith("/main.js"):
            return js_bundle
        return html_page

    discoverer.session.get = MagicMock(side_effect=fake_get)
    discoverer.session.post = MagicMock(
        return_value=_fake_response(status_code=404, headers={"content-type": "text/html"})
    )

    operations = discoverer.discover()
    paths = {op.path_template for op in operations}

    assert "/rest/basket/{param1}" in paths
    assert "/api/users/{param1}" in paths


def test_off_origin_js_bundle_is_never_fetched():
    discoverer = AutoDiscoverer(start_url="http://target:3000/", max_pages=5, max_depth=1)

    html_page = _fake_response(
        status_code=200,
        headers={"content-type": "text/html"},
        text='<html><script src="https://cdn.example.com/lib.js"></script></html>',
    )
    discoverer.session.get = MagicMock(return_value=html_page)
    discoverer.session.post = MagicMock(
        return_value=_fake_response(status_code=404, headers={"content-type": "text/html"})
    )

    discoverer.discover()

    fetched_urls = [call.args[0] for call in discoverer.session.get.call_args_list]
    assert not any("cdn.example.com" in url for url in fetched_urls)
