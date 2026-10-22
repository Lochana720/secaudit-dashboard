"""Cookie security attribute checks."""
import httpx

from .base import Finding

REF = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"
SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "remember")


def _parse(raw: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if not p:
            continue
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def check_cookies(resp: httpx.Response, is_https: bool) -> list[Finding]:
    raw_cookies: list[str] = []
    for r in [*resp.history, resp]:
        raw_cookies += r.headers.get_list("set-cookie")
    if not raw_cookies:
        return [Finding("cookies.none", "cookies", "No cookies set on landing page", "info", True,
                        "No Set-Cookie headers were observed, so cookie flags could not be evaluated further.",
                        reference=REF)]

    out: list[Finding] = []
    seen = set()
    for raw in raw_cookies:
        name, attrs = _parse(raw)
        if name in seen:
            continue
        seen.add(name)
        sensitive = any(h in name.lower() for h in SESSION_HINTS)
        issues = []
        if is_https and "secure" not in attrs:
            issues.append(("Secure", "medium" if sensitive else "low",
                           "Cookie can be sent over unencrypted HTTP."))
        if "httponly" not in attrs:
            issues.append(("HttpOnly", "medium" if sensitive else "low",
                           "Cookie is readable by JavaScript, so XSS could steal it."))
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            issues.append(("SameSite", "low", "No SameSite attribute; CSRF protection depends on browser defaults."))
        elif samesite == "none" and "secure" not in attrs:
            issues.append(("SameSite=None without Secure", "medium",
                           "Browsers reject SameSite=None cookies that are not Secure."))

        if issues:
            worst = min(issues, key=lambda i: ["critical", "high", "medium", "low", "info"].index(i[1]))[1]
            out.append(Finding(
                "cookies.flags", "cookies", f"Cookie '{name}' is missing {', '.join(i[0] for i in issues)}",
                worst, False, " ".join(i[2] for i in issues),
                "Set cookies with: Secure; HttpOnly; SameSite=Lax (or Strict).", raw[:300], REF))
        else:
            out.append(Finding("cookies.flags", "cookies", f"Cookie '{name}' has secure attributes", "low", True,
                               "Secure, HttpOnly and SameSite are set.", evidence=raw[:300], reference=REF))
    return out
