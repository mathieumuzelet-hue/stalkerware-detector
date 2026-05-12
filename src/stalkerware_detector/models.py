"""Pydantic models for the scan report and its components."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingKind(StrEnum):
    SIGNATURE_HIT = "signature_hit"
    PERMISSION_PROFILE = "permission_profile"
    DEVICE_ADMIN = "device_admin"
    ACCESSIBILITY_SVC = "accessibility_service"
    SIDELOADED_APP = "sideloaded_app"
    MDM_DETECTED = "mdm_detected"
    ANALYZER_ERROR = "analyzer_error"
    COLLECT_PARTIAL = "collect_partial"


class InstalledApp(BaseModel):
    package: str
    label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    apk_path: str
    installer_package: str | None = None
    first_install_time: datetime | None = None
    last_update_time: datetime | None = None
    system: bool = False
    enabled: bool = True


class GrantedPermission(BaseModel):
    name: str
    granted: bool = True
    flags: list[str] = Field(default_factory=list)


class Helpline(BaseModel):
    name: str
    phone: str | None = None
    url: str | None = None
    description: str | None = None


class RemediationAdvice(BaseModel):
    risk_summary: str
    safety_first: str = ""
    steps: list[str] = Field(default_factory=list)
    helplines: list[Helpline] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    severity: Severity
    kind: FindingKind
    target_package: str
    target_label: str | None = None
    summary: str
    details: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: RemediationAdvice
    references: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_safety_first_on_high_severity(self) -> Finding:
        if (
            self.severity in {Severity.CRITICAL, Severity.HIGH}
            and not self.remediation.safety_first.strip()
        ):
            raise ValueError(
                f"Finding {self.id} is {self.severity} but remediation.safety_first is empty"
            )
        return self


class DeviceInfo(BaseModel):
    serial_redacted: str
    manufacturer: str | None = None
    model: str | None = None
    android_release: str | None = None
    sdk_int: int | None = None
    build_id: str | None = None
    security_patch: str | None = None


class SignatureIndexMeta(BaseModel):
    commit: str
    fetched_at: float


class ScanReport(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    tool_version: str
    device: DeviceInfo
    signature_index: SignatureIndexMeta
    findings: list[Finding] = Field(default_factory=list)
    safety_warning: str = ""

    @computed_field
    @property
    def summary(self) -> dict[Severity, int]:
        return dict(Counter(f.severity for f in self.findings))
