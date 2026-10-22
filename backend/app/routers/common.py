from ..models import Scan
from ..schemas import FindingOut, ScanDetail, ScanOut


def scan_out(s: Scan) -> ScanOut:
    out = ScanOut.model_validate(s)
    out.target_name, out.target_url = s.target.name, s.target.url
    return out


def scan_detail(s: Scan) -> ScanDetail:
    out = ScanDetail.model_validate(s)
    out.target_name, out.target_url = s.target.name, s.target.url
    out.findings = [FindingOut.model_validate(f) for f in s.findings]
    return out
