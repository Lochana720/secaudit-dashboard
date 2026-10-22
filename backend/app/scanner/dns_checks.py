"""DNS-based email & certificate policy checks (SPF, DMARC, CAA)."""
import ipaddress

import dns.exception
import dns.resolver

from .base import Finding


def _txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode(errors="replace") for r in answers]


def _base_domain(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def check_dns(host: str) -> list[Finding]:
    try:
        ipaddress.ip_address(host)
        return []  # IP targets have no DNS records to check
    except ValueError:
        pass
    if "." not in host or host.endswith((".localhost", ".test", ".local")):
        return []  # local development hostnames have no public DNS
    domain = _base_domain(host)
    out: list[Finding] = []
    try:
        spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
        if not spf:
            out.append(Finding("dns.spf", "dns", "No SPF record", "low", False,
                               "Anyone can send email that appears to come from this domain.",
                               "Publish an SPF TXT record, e.g. v=spf1 include:_spf.google.com -all "
                               "(or v=spf1 -all if the domain sends no mail).", None,
                               "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"))
        elif "+all" in spf[0]:
            out.append(Finding("dns.spf", "dns", "SPF allows all senders (+all)", "high", False,
                               "+all authorises every server on the internet to send mail for this domain.",
                               "Replace +all with -all or ~all.", spf[0]))
        else:
            out.append(Finding("dns.spf", "dns", "SPF record present", "low", True, evidence=spf[0]))

        dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            out.append(Finding("dns.dmarc", "dns", "No DMARC record", "low", False,
                               "Receivers have no policy for handling spoofed mail from this domain.",
                               "Publish _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain, None,
                               "https://dmarc.org/overview/"))
        elif "p=none" in dmarc[0].replace(" ", "").lower():
            out.append(Finding("dns.dmarc", "dns", "DMARC policy is monitoring only (p=none)", "low", False,
                               "Spoofed mail is reported but still delivered.",
                               "Move to p=quarantine or p=reject after reviewing reports.", dmarc[0]))
        else:
            out.append(Finding("dns.dmarc", "dns", "DMARC policy enforced", "low", True, evidence=dmarc[0]))

        try:
            caa = [r.to_text() for r in dns.resolver.resolve(domain, "CAA", lifetime=5)]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            caa = []
        out.append(Finding("dns.caa", "dns", "CAA record present" if caa else "No CAA record", "info", bool(caa),
                           "CAA restricts which certificate authorities may issue certificates for the domain.",
                           "" if caa else 'Add e.g.: 0 issue "letsencrypt.org"', "; ".join(caa) or None,
                           "https://letsencrypt.org/docs/caa/"))
    except dns.exception.DNSException as exc:
        out.append(Finding("dns.error", "dns", "DNS checks could not be completed", "info", True,
                           f"DNS lookup failed: {exc}"))
    return out
