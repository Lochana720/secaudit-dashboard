"""Orchestrates all checks for one target URL."""
import time
from urllib.parse import urlparse, urlunparse

import httpx

from ..config import settings
from .base import Finding, assert_public_host, compute_score, summarize
from .cookies import check_cookies
from .dns_checks import check_dns
from .headers import check_headers
from .tls import check_tls
from .web import (check_content, check_cors, check_disclosure, check_http_redirect, check_security_txt,
                  check_trace)


class ScanError(Exception):
    pass


def _guard(request: httpx.Request) -> None:
    # Re-validated on every request, including redirects (SSRF protection).
    assert_public_host(request.url.host)


def make_client() -> httpx.Client:
    return httpx.Client(
        timeout=settings.REQUEST_TIMEOUT,
        verify=False,  # certificate problems are reported by the TLS module instead
        follow_redirects=True,
        max_redirects=5,
        headers={"User-Agent": settings.USER_AGENT},
        event_hooks={"request": [_guard]},
    )


def run_scan(url: str) -> dict:
    started = time.monotonic()
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    assert_public_host(host)

    findings: list[Finding] = []
    meta: dict = {"target_url": url}

    https_port = parsed.port if parsed.scheme == "https" and parsed.port else 443
    tls_findings, tls_meta = check_tls(host, https_port, settings.REQUEST_TIMEOUT)
    findings += tls_findings
    meta["tls"] = tls_meta
    https_ok = tls_meta.get("available", False)

    if https_ok:
        netloc = host if https_port == 443 else f"{host}:{https_port}"
        fetch_url = urlunparse(("https", netloc, parsed.path or "/", "", parsed.query, ""))
    else:
        fetch_url = urlunparse(parsed._replace(scheme="http"))

    with make_client() as client:
        try:
            resp = client.get(fetch_url)
        except httpx.HTTPError as exc:
            raise ScanError(f"Could not fetch {fetch_url}: {exc}") from exc

        final = urlparse(str(resp.url))
        is_https = final.scheme == "https"
        origin = f"{final.scheme}://{final.netloc}"
        meta.update(
            final_url=str(resp.url),
            status_code=resp.status_code,
            http_version=resp.http_version,
            redirect_chain=[f"{r.status_code} {r.url}" for r in resp.history],
            response_headers={k: v for k, v in resp.headers.multi_items() if k.lower() != "set-cookie"},
        )

        findings += check_headers(resp, is_https)
        findings += check_cookies(resp, is_https)
        findings += check_disclosure(resp)
        findings += check_content(resp, is_https)
        if parsed.port in (None, 80, 443):
            findings += check_http_redirect(client, host)
        findings += check_cors(client, str(resp.url))
        findings += check_security_txt(client, origin)
        findings += check_trace(client, str(resp.url))

    findings += check_dns(host)

    score, grade = compute_score(findings)
    return {
        "findings": findings,
        "meta": meta,
        "score": score,
        "grade": grade,
        "summary": summarize(findings),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
