"""Proof that the user is authorised to scan a site: DNS TXT record or a well-known file."""
import dns.exception
import dns.resolver
import httpx

from .config import settings
from .models import Target
from .scanner.base import TargetNotAllowed, assert_public_host


def token_value(target: Target) -> str:
    return f"secaudit-verification={target.verification_token}"


def instructions(target: Target) -> dict:
    origin = target.url.split("://", 1)[0] + "://" + target.url.split("://", 1)[1].split("/", 1)[0]
    return {
        "dns_record_name": f"{settings.VERIFY_DNS_PREFIX}.{target.hostname}",
        "dns_record_value": token_value(target),
        "file_url": origin + settings.VERIFY_FILE_PATH,
        "file_content": token_value(target),
    }


def verify(target: Target) -> tuple[bool, str | None, str]:
    expected = token_value(target)
    errors = []

    # 1) DNS TXT
    try:
        answers = dns.resolver.resolve(f"{settings.VERIFY_DNS_PREFIX}.{target.hostname}", "TXT", lifetime=5)
        for r in answers:
            if expected in b"".join(r.strings).decode(errors="replace"):
                return True, "dns", "DNS TXT record found."
        errors.append("DNS TXT record exists but token does not match.")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        errors.append("DNS TXT record not found.")
    except dns.exception.DNSException as exc:
        errors.append(f"DNS lookup failed: {exc}")

    # 2) HTTP file
    file_url = instructions(target)["file_url"]
    try:
        assert_public_host(target.hostname)
        with httpx.Client(timeout=settings.REQUEST_TIMEOUT, verify=False, follow_redirects=False,
                          headers={"User-Agent": settings.USER_AGENT}) as client:
            r = client.get(file_url)
        if r.status_code == 200 and expected in r.text:
            return True, "file", "Verification file found."
        errors.append(f"Verification file returned HTTP {r.status_code} or wrong content.")
    except TargetNotAllowed as exc:
        errors.append(str(exc))
    except httpx.HTTPError as exc:
        errors.append(f"Could not fetch verification file: {exc}")

    return False, None, " ".join(errors)
