import logging
from dataclasses import asdict
from datetime import timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal, get_db
from ..models import Finding, Scan, Target, utcnow
from ..report import build_pdf
from ..scanner import run_scan
from ..schemas import DiffItem, ScanCreate, ScanDetail, ScanDiff, ScanOut, ScanPage
from .common import scan_detail, scan_out

log = logging.getLogger("secaudit.scans")
router = APIRouter(prefix="/api/scans", tags=["scans"])


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status, scan.started_at = "running", utcnow()
        db.commit()
        try:
            result = run_scan(scan.target.url)
        except Exception as exc:  # noqa: BLE001 - every failure is recorded on the scan
            log.warning("Scan %s failed: %s", scan_id, exc)
            scan.status, scan.error, scan.finished_at = "failed", str(exc)[:2000], utcnow()
            db.commit()
            return
        for f in result["findings"]:
            db.add(Finding(scan_id=scan.id, **asdict(f)))
        scan.status = "completed"
        scan.score, scan.grade = result["score"], result["grade"]
        scan.summary, scan.meta = result["summary"], result["meta"]
        scan.duration_ms, scan.finished_at = result["duration_ms"], utcnow()
        db.commit()
    finally:
        db.close()


def _get(db: Session, scan_id: int) -> Scan:
    s = db.get(Scan, scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return s


@router.post("", response_model=ScanOut, status_code=202)
def start_scan(body: ScanCreate, background: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(Target, body.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.verified and not settings.SKIP_VERIFICATION:
        raise HTTPException(403, "Verify ownership of this website before scanning it.")
    active = db.scalar(select(Scan).where(Scan.target_id == target.id, Scan.status.in_(["pending", "running"])))
    if active:
        raise HTTPException(409, f"Scan #{active.id} is already in progress for this target.")
    last = db.scalar(select(Scan).where(Scan.target_id == target.id).order_by(Scan.created_at.desc()))
    if last:
        created = last.created_at if last.created_at.tzinfo else last.created_at.replace(tzinfo=timezone.utc)
        wait = settings.SCAN_COOLDOWN_SECONDS - (utcnow() - created).total_seconds()
        if wait > 0:
            raise HTTPException(429, f"Please wait {int(wait) + 1}s before scanning this target again.")
    scan = Scan(target_id=target.id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background.add_task(execute_scan, scan.id)
    return scan_out(scan)


@router.get("", response_model=ScanPage)
def list_scans(
    target_id: Optional[int] = None,
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    q = select(Scan)
    if target_id:
        q = q.where(Scan.target_id == target_id)
    if status:
        q = q.where(Scan.status == status)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.scalars(q.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size))
    return ScanPage(items=[scan_out(s) for s in rows], total=total, page=page, page_size=page_size)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    return scan_detail(_get(db, scan_id))


@router.get("/{scan_id}/diff", response_model=ScanDiff)
def diff_scan(scan_id: int, db: Session = Depends(get_db)):
    """Compare with the previous completed scan of the same target."""
    scan = _get(db, scan_id)
    prev = db.scalar(
        select(Scan)
        .where(Scan.target_id == scan.target_id, Scan.status == "completed", Scan.created_at < scan.created_at)
        .order_by(Scan.created_at.desc())
    )
    if not prev or scan.status != "completed":
        return ScanDiff(scan_id=scan.id, previous_scan_id=prev.id if prev else None, score_delta=None)

    def issues(s: Scan) -> dict:
        return {(f.check_id, f.title): f for f in s.findings if not f.passed}

    cur, old = issues(scan), issues(prev)
    to_item = lambda f: DiffItem(check_id=f.check_id, title=f.title, severity=f.severity)  # noqa: E731
    return ScanDiff(
        scan_id=scan.id,
        previous_scan_id=prev.id,
        score_delta=(scan.score or 0) - (prev.score or 0),
        new_issues=[to_item(f) for k, f in cur.items() if k not in old],
        resolved_issues=[to_item(f) for k, f in old.items() if k not in cur],
        unchanged_count=len(cur.keys() & old.keys()),
    )


@router.get("/{scan_id}/report.pdf")
def scan_report(scan_id: int, db: Session = Depends(get_db)):
    scan = _get(db, scan_id)
    if scan.status != "completed":
        raise HTTPException(400, "Report is available once the scan has completed.")
    pdf = build_pdf(scan)
    fname = f"secaudit-{scan.target.hostname}-scan{scan.id}.pdf"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    db.delete(_get(db, scan_id))
    db.commit()
    return Response(status_code=204)


def fail_stale_scans() -> None:
    """On startup, scans left running by a crash are marked failed."""
    db = SessionLocal()
    try:
        for s in db.scalars(select(Scan).where(Scan.status.in_(["pending", "running"]))):
            s.status, s.error, s.finished_at = "failed", "Interrupted by server restart", utcnow()
        db.commit()
    finally:
        db.close()


