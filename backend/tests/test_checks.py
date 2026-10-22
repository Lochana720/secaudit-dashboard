import httpx

from app.scanner.base import Finding, compute_score
from app.scanner.cookies import check_cookies
from app.scanner.headers import check_headers, parse_csp
from app.scanner.web import check_content, check_disclosure


def _resp(headers, text="", url="https://example.com/", ctype="text/html"):
    return httpx.Response(200, headers=[("content-type", ctype), *headers], text=text,
                          request=httpx.Request("GET", url))


def _by_id(findings, cid):
    return [f for f in findings if f.check_id == cid]


def test_missing_headers_fail():
    f = check_headers(_resp([]), is_https=True)
    assert not _by_id(f, "headers.hsts")[0].passed
    assert _by_id(f, "headers.hsts")[0].severity == "high"
    assert not _by_id(f, "headers.csp")[0].passed
    assert not _by_id(f, "headers.clickjacking")[0].passed


def test_good_headers_pass():
    f = check_headers(_resp([
        ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
        ("content-security-policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "camera=()"),
        ("cross-origin-opener-policy", "same-origin"),
    ]), is_https=True)
    failed = [x for x in f if not x.passed]
    assert failed == [], [x.title for x in failed]


def test_csp_unsafe_inline_detected():
    f = check_headers(_resp([("content-security-policy", "script-src 'self' 'unsafe-inline'")]), True)
    assert _by_id(f, "headers.csp_unsafe_inline")


def test_parse_csp():
    d = parse_csp("default-src 'self'; script-src https://cdn.x.com 'nonce-abc'")
    assert d["script-src"] == ["https://cdn.x.com", "'nonce-abc'"]


def test_cookie_flags():
    f = check_cookies(_resp([("set-cookie", "sessionid=abc; Path=/")]), is_https=True)
    assert not f[0].passed and f[0].severity == "medium"
    f = check_cookies(_resp([("set-cookie", "sessionid=abc; Secure; HttpOnly; SameSite=Lax")]), True)
    assert f[0].passed


def test_disclosure_and_mixed_content():
    f = check_disclosure(_resp([("server", "nginx/1.18.0"), ("x-powered-by", "PHP/8.1")]))
    assert all(not x.passed for x in f)
    f = check_content(_resp([], text='<img src="http://cdn.example.com/a.png"><script src="https://other.com/x.js"></script>'), True)
    assert not _by_id(f, "content.mixed")[0].passed
    assert _by_id(f, "content.sri")


def test_scoring_and_critical_cap():
    assert compute_score([]) == (100, "A+")
    mixed = [Finding("a", "tls", "t", "critical", False)] + [Finding(str(i), "h", "t", "high", True) for i in range(10)]
    score, grade = compute_score(mixed)
    assert score == 86 and grade == "D"  # good ratio, but a critical caps the grade
    assert compute_score([Finding("a", "h", "t", "low", False), Finding("b", "h", "t", "low", True)])[0] == 50
