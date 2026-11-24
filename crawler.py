"""
crawler.py — fetch pages, discover forms, and find injectable URL parameters.

Returns rich objects (including the HTTP response) so the passive checks in
checks.py can inspect headers and cookies, not just the HTML body.
"""

import time
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

USER_AGENT = "web-vuln-scanner/2.0 (authorized security testing)"
TIMEOUT = 8


def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def fetch(session, url):
    """GET a URL. Returns the Response, or None on failure."""
    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None


def is_internal(url, domain):
    return urlparse(url).netloc == domain


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        links.add(urljoin(base_url, tag["href"]))
    return links


def extract_forms(html, base_url):
    """Return each form's action, method, and input fields (name + type)."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        inputs = []
        for tag in form.find_all(("input", "textarea")):
            name = tag.get("name")
            if name:
                inputs.append({"name": name, "type": tag.get("type", "text")})
        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": form.get("method", "get").lower(),
            "inputs": inputs,
        })
    return forms


def extract_url_params(url):
    """
    Pull query parameters out of a URL so they can be tested as injection
    points (e.g. 'page.php?id=1' -> param 'id'). Returns (base_url, {param: value})
    or None if the URL has no query string.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return None
    params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return base, params


def crawl(session, start_url, max_pages=10, delay=0.3):
    """
    Walk internal links starting from start_url. Yields a dict per page:
        {url, response, html, forms, param_targets}
    `param_targets` is a list of (base_url, params_dict) for URLs with query strings.
    """
    domain = urlparse(start_url).netloc
    visited = set()
    queue = [start_url]

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        resp = fetch(session, url)
        if resp is None:
            continue
        html = resp.text if "text/html" in resp.headers.get("Content-Type", "") else ""

        param_targets = []
        pt = extract_url_params(url)
        if pt:
            param_targets.append(pt)

        page = {
            "url": url,
            "response": resp,
            "html": html,
            "forms": extract_forms(html, url),
            "param_targets": param_targets,
        }
        yield page

        # queue new internal links
        for link in extract_links(html, url):
            link = link.split("#")[0]
            if is_internal(link, domain) and link not in visited and link not in queue:
                queue.append(link)

        if delay:
            time.sleep(delay)
