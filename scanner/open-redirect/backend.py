# backend.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
# allow requests from your frontend (adjust origins if needed)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Default payloads used for testing
DEFAULT_PAYLOADS = [
    "//evil.com",
    "/@evil.com",
    "https://evil.com",
    "http://evil.com",
    "////evil.com",
    "///evil.com",
    "http:evil.com",
    "https:evil.com",
    "//google.com",
    "/redirect?url=//evil.com",
    "/?next=//evil.com"
]


def is_external_location(base_url, location_header):
    """Return True if Location header points to a different host than base_url."""
    if not location_header:
        return False
    try:
        base_host = urlparse(base_url).hostname
        # Resolve relative Location URLs against base_url
        resolved = urljoin(base_url, location_header)
        loc_host = urlparse(resolved).hostname
        # If any of hosts is None, treat them as internal (conservative)
        if base_host and loc_host and base_host.lower() != loc_host.lower():
            return True
        return False
    except Exception:
        return False


def make_test_urls(base_url, payload):
    """
    Return two candidate test URLs:
      - parameter injection: append payload to query parameter if base_url already has '=' or endswith '?'
        otherwise append payload as query param (best-effort)
      - path injection: insert payload after domain/path root
    """
    test_urls = []

    # parameter-style: if base_url contains '=' or endswith '?' treat as param injection
    if "=" in base_url or base_url.endswith("?"):
        test_urls.append(base_url + payload)
    else:
        # If no query param, try adding as query param on first param name guess 'r'
        # but better: append payload as path if no param exists
        # We'll try both ways for broader coverage:
        test_urls.append(base_url.rstrip("/") + "?" + payload.lstrip("/"))
        test_urls.append(base_url.rstrip("/") + "/" + payload.lstrip("/"))

    # path-style (ensure single slash)
    if base_url.endswith("/"):
        path_url = base_url + payload.lstrip("/")
    else:
        path_url = base_url.rstrip("/") + "/" + payload.lstrip("/")
    test_urls.append(path_url)

    # deduplicate preserving order
    seen = set()
    final = []
    for u in test_urls:
        if u not in seen:
            final.append(u)
            seen.add(u)
    return final


@app.route("/api/open-redirect", methods=["POST"])
def open_redirect():
    """
    POST body expected: { "url": "http://example.com/logout?r=", "payloads": ["//evil.com"...] }
    If payloads omitted, backend uses DEFAULT_PAYLOADS.
    Returns JSON: { results: [ {payload, tested_url, status_code, location, status} ... ] }
    status is one of: Vulnerable (external redirect), Redirect (internal), No Redirect, Error
    """
    body = request.get_json(force=True, silent=True) or {}
    base_url = body.get("url")
    payloads = body.get("payloads") or DEFAULT_PAYLOADS

    if not base_url:
        return jsonify({"error": "Missing 'url' in JSON body"}), 400

    results = []

    # Ensure base_url has a scheme; if not, assume http (user should pass full URL)
    parsed = urlparse(base_url)
    if not parsed.scheme:
        base_url = "http://" + base_url
        parsed = urlparse(base_url)

    for p in payloads:
        # Generate candidate test URLs (param and path)
        test_urls = make_test_urls(base_url, p)
        for test_url in test_urls:
            entry = {
                "payload": p,
                "tested_url": test_url,
                "status_code": None,
                "location": None,
                "status": None,
            }
            try:
                # Do not follow redirects so we can inspect Location header
                r = requests.get(test_url, timeout=7, allow_redirects=False)
                entry["status_code"] = r.status_code
                location = r.headers.get("Location") or r.headers.get("location") or None
                entry["location"] = location

                # If server returned a 3xx AND Location header exists -> redirect
                if 300 <= r.status_code < 400 and location:
                    # If Location points to external host -> Vulnerable
                    if is_external_location(test_url, location):
                        entry["status"] = "Vulnerable"
                    else:
                        entry["status"] = "Redirect (internal)"
                else:
                    # Not a standard redirect; also check meta refresh or JS? (best-effort)
                    body_text = r.text or ""
                    # look for meta refresh with URL or window.location assignments (simple checks)
                    if "meta http-equiv" in body_text.lower() and "refresh" in body_text.lower() and "url=" in body_text.lower():
                        # treat as redirect (conservative)
                        entry["status"] = "Possible Redirect (meta refresh)"
                    elif "window.location" in body_text or "location.href" in body_text:
                        entry["status"] = "Possible Redirect (js)"
                    else:
                        entry["status"] = "No Redirect"
                results.append(entry)
            except requests.exceptions.RequestException as e:
                entry["status"] = "Error"
                entry["status_code"] = None
                entry["location"] = None
                entry["error"] = str(e)
                results.append(entry)

    # Return results
    return jsonify({"results": results})


if __name__ == "__main__":
    # production note: use a WSGI server for production
    app.run(host="0.0.0.0", port=5000, debug=True)
