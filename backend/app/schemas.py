from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=3, max_length=500)


class VerificationInstructions(BaseModel):
    dns_record_name: str
    dns_record_value: str
    file_url: str
    file_content: str


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    url: str
    hostname: str
    verified: bool
    verification_method: Optional[str]
    verified_at: Optional[datetime]
    created_at: datetime
    last_scan_id: Optional[int] = None
    last_score: Optional[int] = None
    last_grade: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    scan_count: int = 0
    verification: Optional[VerificationInstructions] = None


class VerifyResult(BaseModel):
    verified: bool
    method: Optional[str]
    detail: str


class ScanCreate(BaseModel):
    target_id: int


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    check_id: str
    category: str
    title: str
    severity: str
    passed: bool
    description: str
    recommendation: str
    evidence: Optional[str]
    reference: Optional[str]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    target_name: Optional[str] = None
    target_url: Optional[str] = None
    status: str
    score: Optional[int]
    grade: Optional[str]
    summary: Optional[dict[str, Any]]
    error: Optional[str]
    duration_ms: Optional[int]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]


class ScanDetail(ScanOut):
    meta: Optional[dict[str, Any]]
    findings: list[FindingOut] = []


class ScanPage(BaseModel):
    items: list[ScanOut]
    total: int
    page: int
    page_size: int


class DiffItem(BaseModel):
    check_id: str
    title: str
    severity: str


class ScanDiff(BaseModel):
    scan_id: int
    previous_scan_id: Optional[int]
    score_delta: Optional[int]
    new_issues: list[DiffItem] = []
    resolved_issues: list[DiffItem] = []
    unchanged_count: int = 0
