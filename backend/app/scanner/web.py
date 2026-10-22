"""Other HTTP-level checks: redirect to HTTPS, CORS, information disclosure,
mixed content, Subresource Integrity, security.txt and TRACE."""
import re
from urllib.parse import urljoin, urlparse

import httpx

from .base import Finding

OWASP_MISCONFIG = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"


def check_http_redirect(client: httpx.Client, host: str) -> list[Finding]:
    url = f"http://{host}/"
    try:
        r = client.get(url, follow_redirects=False)
    except httpx.HTTPError:
        return [Finding("web.http_redirect", "transport", "Plain HTTP (port 80) not reachable", "high", True,
                        "The server does not answer on plain HTTP, so no unencrypted content is served.")]
    loc = r.headers.get("location", "")
    if r.status_code in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        if r.status_code in (301, 308):
            return [Finding("web.http_redirect", "transport", "HTTP redirects to HTTPS", "high", True,
                            f"Permanent redirect ({r.status_code}) to HTTPS.", evidence=f"{r.status_code} → {loc}")]
        return [Finding("web.http_redirect", "transport", "HTTP uses a temporary redirect to HTTPS", "low", False,
                        f"A {r.status_code} redirect is used. Permanent redirects are cached by browsers.",
                        "Use a 301 or 308 redirect from HTTP to HTTPS.", f"{r.status_code} → {loc}")]
    if r.status_code in (301, 302, 303, 307, 308):
        return [Finding("web.http_redirect", "transport", "HTTP redirect does not go to HTTPS", "high", False,
                        "The plain-HTTP site redirects, but not to an HTTPS URL.",
                        "Redirect every HTTP request to the HTTPS equivalent.", f"{r.status_code} → {loc}")]
    return [Finding("web.http_redirect", "transport", "HTTP is served without redirecting to HTTPS", "high", False,
                    f"http://{host}/ returned {r.status_code} without redirecting. Users can browse unencrypted.",
                    "Configure a 301 redirect from HTTP to HTTPS and enable HSTS.", f"HTTP {r.status_code}")]


def check_cors(client: httpx.Client, url: str) -> list[Finding]:
    probe = "https://secaudit-probe.invalid"
    ref = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
    try:
        r = client.get(url, headers={"Origin": probe})
    except httpx.HTTPError as exc:
        return [Finding("web.cors", "cors", "CORS check could not run", "info", True, str(exc))]
    acao = r.headers.get("access-control-allow-origin")
    creds = (r.headers.get("access-control-allow-credentials") or "").lower() == "true"
    ev = f"ACAO={acao}; ACAC={creds}"
    if not acao:
        return [Finding("web.cors", "cors", "No permissive CORS policy", "high", True,
                        "Arbitrary origins are not granted cross-origin access.", reference=ref)]
    if acao == probe and creds:
        return [Finding("web.cors", "cors", "CORS reflects any origin with credentials", "high", False,
                        "Any website can make authenticated requests and read the responses.",
                        "Validate Origin against an allow-list; never reflect it blindly with credentials.", ev, ref)]
    if acao == probe:
        return [Finding("web.cors", "cors", "CORS reflects arbitrary origins", "medium", False,
                        "Any website can read responses from this endpoint.",
                        "Only allow specific trusted origins.", ev, ref)]
    if acao == "*" and creds:
        return [Finding("web.cors", "cors", "CORS wildcard combined with credentials", "medium", False,
                        "This combination is invalid and indicates a misconfiguration.",
                        "Remove credentials or use an explicit origin allow-list.", ev, ref)]
    if acao == "*":
        return [Finding("web.cors", "cors", "CORS allows any origin (*)", "low", False,
                        "Fine for public, static resources, risky for anything user-specific.",
                        "Restrict Access-Control-Allow-Origin to trusted origins if content is not public.", ev, ref)]
    return [Finding("web.cors", "cors", "CORS restricted to specific origin", "high", True, ev, reference=ref)]


def check_disclosure(resp: httpx.Response) -> list[Finding]:
    out: list[Finding] = []
    h = resp.headers
    server = h.get("server")
    if server and re.search(r"\d", server):
        out.append(Finding("disclosure.server", "disclosure", "Server header reveals version", "low", False,
                           "Version numbers help attackers find matching exploits.",
                           "Hide version info (nginx: server_tokens off; Apache: ServerTokens Prod).",
                           f"Server: {server}", OWASP_MISCONFIG))
    else:
        out.append(Finding("disclosure.server", "disclosure", "Server header does not reveal version", "low", True,
                           evidence=f"Server: {server}" if server else "Server header absent"))
    leaks = [(k, h.get(k)) for k in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
             if h.get(k)]
    if leaks:
        out.append(Finding("disclosure.tech", "disclosure", "Technology stack disclosed in headers", "low", False,
                           "Headers reveal frameworks or versions in use.",
                           "Remove X-Powered-By / X-AspNet-Version / X-Generator headers.",
                           "; ".join(f"{k}: {v}" for k, v in leaks), OWASP_MISCONFIG))
    else:
        out.append(Finding("disclosure.tech", "disclosure", "No technology headers disclosed", "low", True))
    return out


_SRC_RE = re.compile(r"<(script|img|iframe|link|audio|video|source|form)\b[^>]*?\b(src|href|action)\s*=\s*[\"']([^\"']+)", re.I)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>", re.I)


def check_content(resp: httpx.Response, is_https: bool) -> list[Finding]:
    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype.lower():
        return []
    html = resp.text[:2_000_000]
    out: list[Finding] = []

    if is_https:
        insecure = []
        for tag, attr, val in _SRC_RE.findall(html):
            # <link href> is often canonical/alternate metadata, not a loaded resource
            if val.lower().startswith("http://") and tag.lower() != "link":
                insecure.append(f"<{tag} {attr}={val}>")
        if insecure:
            out.append(Finding("content.mixed", "content", "Mixed content: resources loaded over HTTP", "medium", False,
                               f"{len(insecure)} resource(s) load over plain HTTP on an HTTPS page.",
                               "Load all resources over HTTPS, or add CSP upgrade-insecure-requests.",
                               "\n".join(insecure[:10]),
                               "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"))
        else:
            out.append(Finding("content.mixed", "content", "No mixed content detected", "medium", True))

    host = urlparse(str(resp.url)).hostname
    no_sri = []
    for tag in _SCRIPT_RE.findall(html):
        m = re.search(r"src\s*=\s*[\"']([^\"']+)", tag, re.I)
        if not m:
            continue
        src_host = urlparse(urljoin(str(resp.url), m.group(1))).hostname
        if src_host and src_host != host and "integrity=" not in tag.lower():
            no_sri.append(m.group(1))
    if no_sri:
        out.append(Finding("content.sri", "content", "Third-party scripts without Subresource Integrity", "low", False,
                           f"{len(no_sri)} external script(s) load without an integrity hash. "
                           "A compromised CDN could inject malicious code.",
                           "Add integrity=\"sha384-…\" crossorigin=\"anonymous\" to external <script> tags.",
                           "\n".join(no_sri[:10]),
                           "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"))
    return out


def check_security_txt(client: httpx.Client, origin: str) -> list[Finding]:
    ref = "https://securitytxt.org/"
    try:
        r = client.get(origin + "/.well-known/security.txt")
        ok = r.status_code == 200 and "contact:" in r.text.lower()
    except httpx.HTTPError:
        ok = False
    if ok:
        return [Finding("web.security_txt", "policy", "security.txt published", "info", True,
                        "Researchers know how to report vulnerabilities.", reference=ref)]
    return [Finding("web.security_txt", "policy", "security.txt not found", "info", False,
                    "No /.well-known/security.txt with a Contact field was found.",
                    "Publish a security.txt (RFC 9116) so researchers can report issues responsibly.", None, ref)]


def check_trace(client: httpx.Client, url: str) -> list[Finding]:
    try:
        r = client.request("TRACE", url, headers={"X-SecAudit-Trace": "probe"})
    except httpx.HTTPError:
        return []
    if r.status_code == 200 and "x-secaudit-trace" in r.text.lower():
        return [Finding("web.trace", "transport", "HTTP TRACE method enabled", "low", False,
                        "TRACE echoes requests back and can aid cross-site tracing attacks.",
                        "Disable TRACE (Apache: TraceEnable off).", f"TRACE → {r.status_code}", OWASP_MISCONFIG)]
    return [Finding("web.trace", "transport", "HTTP TRACE method disabled", "low", True,
                    evidence=f"TRACE → {r.status_code}")]
