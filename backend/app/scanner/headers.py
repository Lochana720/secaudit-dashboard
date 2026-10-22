"""HTTP security header analysis."""
import re

import httpx

from .base import Finding

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


def _f(check_id, title, severity, passed, desc, rec="", evidence=None, ref=None):
    return Finding(check_id, "headers", title, severity, passed, desc, rec, evidence, ref)


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_headers(resp: httpx.Response, is_https: bool) -> list[Finding]:
    h = resp.headers
    out: list[Finding] = []

    # --- Strict-Transport-Security ---
    hsts = h.get("strict-transport-security")
    ref = MDN + "Strict-Transport-Security"
    if is_https:
        if not hsts:
            out.append(_f("headers.hsts", "Strict-Transport-Security (HSTS) missing", "high", False,
                          "Without HSTS, browsers may connect over plain HTTP first, enabling SSL-stripping attacks.",
                          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", None, ref))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age < 15768000:
                out.append(_f("headers.hsts", "HSTS max-age is too short", "medium", False,
                              f"max-age={max_age}s. At least 6 months (15768000) is recommended; 1 year is ideal.",
                              "Increase max-age to 31536000.", hsts, ref))
            else:
                out.append(_f("headers.hsts", "HSTS is enabled", "high", True,
                              f"max-age={max_age}s.", evidence=hsts, ref=ref))
            if "includesubdomains" not in hsts.lower():
                out.append(_f("headers.hsts_subdomains", "HSTS does not include subdomains", "low", False,
                              "Subdomains are not protected by the HSTS policy.",
                              "Add includeSubDomains once all subdomains support HTTPS.", hsts, ref))
            if "preload" not in hsts.lower():
                out.append(_f("headers.hsts_preload", "HSTS preload not set", "info", False,
                              "The domain is not opted into browser HSTS preload lists.",
                              "Optionally add 'preload' and submit at hstspreload.org.", hsts, ref))

    # --- Content-Security-Policy ---
    csp = h.get("content-security-policy")
    csp_ro = h.get("content-security-policy-report-only")
    ref = MDN + "Content-Security-Policy"
    directives = parse_csp(csp) if csp else {}
    if not csp:
        if csp_ro:
            out.append(_f("headers.csp", "CSP is in report-only mode", "low", False,
                          "A policy is defined but not enforced.",
                          "Switch to Content-Security-Policy once violations are reviewed.", csp_ro, ref))
        else:
            out.append(_f("headers.csp", "Content-Security-Policy missing", "medium", False,
                          "CSP is a strong defence against cross-site scripting (XSS) and data injection.",
                          "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                          "base-uri 'self'; frame-ancestors 'self'", None, ref))
    else:
        out.append(_f("headers.csp", "Content-Security-Policy is set", "medium", True,
                      "An enforced CSP is present.", evidence=csp[:500], ref=ref))
        script_src = directives.get("script-src") or directives.get("default-src") or []
        has_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_src)
        if "'unsafe-inline'" in script_src and not has_nonce:
            out.append(_f("headers.csp_unsafe_inline", "CSP allows 'unsafe-inline' scripts", "medium", False,
                          "Inline scripts are allowed, which largely defeats XSS protection.",
                          "Use nonces or hashes instead of 'unsafe-inline'.", " ".join(script_src), ref))
        if "'unsafe-eval'" in script_src:
            out.append(_f("headers.csp_unsafe_eval", "CSP allows 'unsafe-eval'", "low", False,
                          "eval() and similar functions are permitted.",
                          "Remove 'unsafe-eval' and refactor code that relies on eval.", " ".join(script_src), ref))
        if any(s in {"*", "http:", "https:", "data:"} for s in script_src):
            out.append(_f("headers.csp_wildcard", "CSP script sources are too broad", "medium", False,
                          "Wildcard or scheme-only sources allow scripts from almost anywhere.",
                          "List specific trusted origins instead of *, http:, https: or data:.",
                          " ".join(script_src), ref))
        if "object-src" not in directives and "'none'" not in (directives.get("default-src") or []):
            out.append(_f("headers.csp_object", "CSP does not restrict object-src", "low", False,
                          "Plugins (<object>, <embed>) are not explicitly blocked.",
                          "Add object-src 'none'.", None, ref))

    # --- Clickjacking ---
    xfo = (h.get("x-frame-options") or "").upper()
    frame_anc = directives.get("frame-ancestors")
    ref = MDN + "X-Frame-Options"
    if frame_anc is not None or xfo in {"DENY", "SAMEORIGIN"}:
        out.append(_f("headers.clickjacking", "Clickjacking protection enabled", "medium", True,
                      "Framing is restricted via " + ("CSP frame-ancestors" if frame_anc is not None else "X-Frame-Options") + ".",
                      evidence=xfo or "frame-ancestors " + " ".join(frame_anc or []), ref=ref))
    else:
        out.append(_f("headers.clickjacking", "No clickjacking protection", "medium", False,
                      "The page can be embedded in iframes by other sites (clickjacking risk).",
                      "Add X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors 'self'.", xfo or None, ref))

    # --- X-Content-Type-Options ---
    xcto = (h.get("x-content-type-options") or "").lower()
    out.append(_f("headers.xcto", "X-Content-Type-Options set to nosniff" if xcto == "nosniff" else "X-Content-Type-Options missing",
                  "low", xcto == "nosniff", "Prevents browsers from MIME-sniffing responses into executable types.",
                  "" if xcto == "nosniff" else "Add: X-Content-Type-Options: nosniff", xcto or None,
                  MDN + "X-Content-Type-Options"))

    # --- Referrer-Policy ---
    rp = (h.get("referrer-policy") or "").lower()
    ref = MDN + "Referrer-Policy"
    if not rp:
        out.append(_f("headers.referrer", "Referrer-Policy missing", "low", False,
                      "Full URLs (possibly with tokens) may leak to third parties via the Referer header.",
                      "Add: Referrer-Policy: strict-origin-when-cross-origin", None, ref))
    elif "unsafe-url" in rp or rp.strip() == "no-referrer-when-downgrade":
        out.append(_f("headers.referrer", "Referrer-Policy is permissive", "medium" if "unsafe-url" in rp else "low", False,
                      f"Policy '{rp}' sends full URLs cross-origin.",
                      "Use strict-origin-when-cross-origin or no-referrer.", rp, ref))
    else:
        out.append(_f("headers.referrer", "Referrer-Policy is set", "low", True, f"Policy: {rp}.", evidence=rp, ref=ref))

    # --- Permissions-Policy ---
    pp = h.get("permissions-policy")
    out.append(_f("headers.permissions", "Permissions-Policy is set" if pp else "Permissions-Policy missing", "low", bool(pp),
                  "Controls access to powerful browser features (camera, microphone, geolocation…).",
                  "" if pp else "Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                  (pp or "")[:300] or None, MDN + "Permissions-Policy"))

    # --- Cross-Origin isolation headers ---
    coop = h.get("cross-origin-opener-policy")
    out.append(_f("headers.coop", "Cross-Origin-Opener-Policy set" if coop else "Cross-Origin-Opener-Policy missing", "info",
                  bool(coop), "COOP isolates your browsing context from cross-origin windows (Spectre-class attacks).",
                  "" if coop else "Consider: Cross-Origin-Opener-Policy: same-origin", coop,
                  MDN + "Cross-Origin-Opener-Policy"))

    # --- Deprecated X-XSS-Protection ---
    xxp = h.get("x-xss-protection")
    if xxp and xxp.strip().startswith("1"):
        out.append(_f("headers.xxss", "Deprecated X-XSS-Protection enabled", "info", False,
                      "The legacy XSS auditor is removed from modern browsers and could introduce issues in old ones.",
                      "Remove the header or set it to 0, and rely on CSP.", xxp, MDN + "X-XSS-Protection"))

    # --- Caching of the main document ---
    cc = (h.get("cache-control") or "").lower()
    if resp.headers.get("set-cookie") and "no-store" not in cc and "private" not in cc:
        out.append(_f("headers.cache", "Responses setting cookies may be cached publicly", "low", False,
                      "The response sets cookies but has no 'private' or 'no-store' Cache-Control directive.",
                      "Add Cache-Control: no-store (or private) for personalized/authenticated pages.", cc or None,
                      MDN + "Cache-Control"))

    return out
