"""Pydantic request/response models for the socai REST API."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    email: str
    role: str
    permissions: list[str]


class InvestigationRequest(BaseModel):
    title: str = ""
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    urls: list[str] | None = None
    file_path: str | None = None
    zip_path: str | None = None
    zip_pass: str | None = None
    eml_paths: list[str] | None = None
    tags: list[str] | None = None
    detonate: bool = False
    close_case: bool = False
    include_private_ips: bool = False


class JobStatus(BaseModel):
    case_id: str
    status: str  # queued | running | complete | failed
    error: str | None = None


class CaseSummary(BaseModel):
    case_id: str
    title: str = ""
    severity: str = ""
    status: str = ""
    created: str = ""


class CaseDetail(CaseSummary):
    report_path: str | None = None
    ioc_totals: dict | None = None
    disposition: str | None = None


class CaseBrowseItem(CaseSummary):
    disposition: str = "undetermined"
    ioc_totals: dict = {}
    link_count: int = 0
    external_refs: dict = {}
