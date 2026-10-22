from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Scan, Target
from ..scanner.base import SEVERITIES
from .common import scan_out

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/config")
def config():
    return {"skip_verification": settings.SKIP_VERIFICATION, "cooldown_seconds": settings.SCAN_COOLDOWN_SECONDS}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    targets = list(db.scalars(select(Target)))
    latest = [s for s in (next((x for x in t.scans if x.status == "completed"), None) for t in targets) if s]

    severity = Counter()
    top_issues: Counter = Counter()
    grades = Counter()
    for s in latest:
        grades[s.grade] += 1
        for f in s.findings:
            if not f.passed:
                severity[f.severity] += 1
                top_issues[(f.title, f.severity)] += 1

    trend_rows = db.scalars(
        select(Scan).where(Scan.status == "completed").order_by(Scan.finished_at.desc()).limit(30)
    ).all()
    recent = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(8)).all()

    return {
        "totals": {
            "targets": len(targets),
            "verified_targets": sum(1 for t in targets if t.verified),
            "scans": db.scalar(select(func.count(Scan.id))) or 0,
            "completed_scans": db.scalar(select(func.count(Scan.id)).where(Scan.status == "completed")) or 0,
            "average_score": round(sum(s.score or 0 for s in latest) / len(latest)) if latest else None,
            "open_critical_high": severity["critical"] + severity["high"],
        },
        "severity_distribution": [{"severity": s, "count": severity[s]} for s in SEVERITIES],
        "grade_distribution": [{"grade": g, "count": grades[g]} for g in ["A+", "A", "B", "C", "D", "F"]],
        "top_issues": [{"title": t, "severity": sev, "targets": c}
                       for (t, sev), c in sorted(top_issues.items(),
                                                 key=lambda kv: (SEVERITIES.index(kv[0][1]), -kv[1]))[:8]],
        "score_trend": [{"scan_id": s.id, "target": s.target.name, "score": s.score,
                         "date": s.finished_at.isoformat() if s.finished_at else None}
                        for s in reversed(trend_rows)],
        "target_scores": [{"target_id": s.target_id, "target": s.target.name, "score": s.score, "grade": s.grade,
                           "scan_id": s.id} for s in sorted(latest, key=lambda s: s.score or 0)],
        "recent_scans": [scan_out(s).model_dump(mode="json") for s in recent],
    }
