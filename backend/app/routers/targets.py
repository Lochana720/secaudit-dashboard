import re
import secrets
from urllib.parse import urlparse, urlunparse

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Scan, Target, utcnow
from ..schemas import ScanOut, TargetCreate, TargetOut, VerifyResult
from ..verification import instructions, verify
from .common import scan_out

router = APIRouter(prefix="/api/targets", tags=["targets"])


def normalize_url(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname or p.username or p.password:
        raise HTTPException(422, "Enter a valid URL such as https://example.com")
    host = p.hostname.lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.\-:\[\]]+", host):
        raise HTTPException(422, "Hostname contains invalid characters")
    netloc = host + (f":{p.port}" if p.port else "")
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", p.query, "")), host


def target_out(t: Target, with_instructions: bool = True) -> TargetOut:
    out = TargetOut.model_validate(t)
    out.scan_count = len(t.scans)
    done = next((s for s in t.scans if s.status == "completed"), None)
    if done:
        out.last_scan_id, out.last_score, out.last_grade, out.last_scan_at = done.id, done.score, done.grade, done.finished_at
    if with_instructions:
        out.verification = instructions(t)
    return out


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return [target_out(t) for t in db.scalars(select(Target).order_by(Target.created_at.desc()))]


@router.post("", response_model=TargetOut, status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db)):
    url, host = normalize_url(body.url)
    if db.scalar(select(Target).where(Target.url == url)):
        raise HTTPException(409, "This URL is already registered")
    t = Target(name=body.name.strip(), url=url, hostname=host, verification_token=secrets.token_hex(16))
    if settings.SKIP_VERIFICATION:
        t.verified, t.verification_method, t.verified_at = True, "dev-skip", utcnow()
    db.add(t)
    db.commit()
    db.refresh(t)
    return target_out(t)


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    return target_out(t)


@router.post("/{target_id}/verify", response_model=VerifyResult)
def verify_target(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    if t.verified:
        return VerifyResult(verified=True, method=t.verification_method, detail="Already verified.")
    ok, method, detail = verify(t)
    if ok:
        t.verified, t.verification_method, t.verified_at = True, method, utcnow()
        db.commit()
    return VerifyResult(verified=ok, method=method, detail=detail)


@router.get("/{target_id}/scans", response_model=list[ScanOut])
def target_scans(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    return [scan_out(s) for s in db.scalars(select(Scan).where(Scan.target_id == target_id).order_by(Scan.created_at.desc()))]


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    t = db.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    db.delete(t)
    db.commit()
    return Response(status_code=204)
