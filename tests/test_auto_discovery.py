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


def test_template_literal_with_host_prefix_is_still_discovered():
    """Reproduces the second live gap: the actual Juice Shop production
    bundle discovers 55 candidates but none of the per-object endpoints
    ever get tested, because real minified bundles prefix the template
    literal with an interpolated host/base-URL expression first, e.g.
    `${e.hostServer}/rest/basket/${id}` -- which requires "/" to be located
    anywhere inside the backtick body, not only right after the backtick.
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
            b"function getBasket(e,t){return http.get(`${e.hostServer}/rest/basket/${t}`)}\n"
            b"function getUser(e,t){return http.get(`${e.hostServer}/api/users/${t}/profile`)}\n"
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
    assert "/api/users/{param1}/profile" in paths


def test_mutating_method_is_inferred_from_js_call_site():
    """Regression test for a live gap: known Juice Shop BOLA operations like
    `PUT /api/Users/{id}` were never tested because every JS-discovered
    candidate was hardcoded to GET, regardless of the actual HTTP client
    call it came from (`http.put(...)`, `axios.delete(...)`, etc). The
    method must be inferred from the call site so mutating operations get
    tested too, not just reads.
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
            b"function updateUser(id,body){return http.put(`/api/Users/${id}`,body)}\n"
            b"function deleteOrder(id){return http.delete(`/api/Orders/${id}`)}\n"
            b"function getOrder(id){return http.get(`/api/Orders/${id}`)}\n"
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
    by_method_path = {(op.http_method.value, op.path_template) for op in operations}

    assert ("PUT", "/api/Users/{param1}") in by_method_path
    assert ("DELETE", "/api/Orders/{param1}") in by_method_path
    assert ("GET", "/api/Orders/{param1}") in by_method_path


def test_relative_concat_prefix_with_base_url_variable_is_discovered():
    """Regression test for a live gap: SPA services frequently keep a base
    URL in a config/environment variable and concatenate a *relative*
    resource path onto it, e.g. `this.hostServer + 'api/Addresss/' + id`
    (no leading "/" on the literal, since the base variable already ends
    with one, or the client adds it). The existing concatenation pattern
    required a leading "/" on the literal and so missed this shape
    entirely, which is exactly how Juice Shop's `/api/Addresss/{id}`
    endpoint is referenced in its bundle.
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
            b"function getAddress(e,t){return http.get(e.hostServer + 'api/Addresss/' + t)}\n"
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

    assert "/api/Addresss/{param1}" in paths


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
