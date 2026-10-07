"""Data models for Kubernetes Investigation Forensics."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LogLevel(str, Enum):
    FATAL = "FATAL"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARN = "WARN"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"
    TRACE = "TRACE"
    UNKNOWN = "UNKNOWN"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IssueCategory(str, Enum):
    OOM_KILLED = "OOM_KILLED"
    CPU_THROTTLING = "CPU_THROTTLING"
    CRASH_LOOP = "CRASH_LOOP"
    NETWORK_DNS = "NETWORK_DNS"
    PROBE_FAILURE = "PROBE_FAILURE"
    STORAGE_VOLUME = "STORAGE_VOLUME"
    RBAC_PERMISSION = "RBAC_PERMISSION"
    CONFIG_SECRET = "CONFIG_SECRET"
    DATABASE_BACKEND = "DATABASE_BACKEND"
    IMAGE_PULL = "IMAGE_PULL"
    NODE_MEMORY_PRESSURE = "NODE_MEMORY_PRESSURE"
    NODE_NOT_READY = "NODE_NOT_READY"
    RESOURCE_LIMITS = "RESOURCE_LIMITS"
    SERVICE_NO_ENDPOINTS = "SERVICE_NO_ENDPOINTS"
    SERVICE_ROUTING = "SERVICE_ROUTING"
    APP_EXCEPTION = "APP_EXCEPTION"
    UNKNOWN = "UNKNOWN"


class LogEntry(BaseModel):
    """Represents a single parsed log line or stitched multi-line entry."""
    line_number: int
    raw_text: str
    message: str
    timestamp: Optional[str] = None
    level: LogLevel = LogLevel.UNKNOWN
    stream: Optional[str] = None
    component: Optional[str] = None
    is_stack_trace: bool = False
    stack_trace: Optional[str] = None


class EvidenceItem(BaseModel):
    """Supporting evidence verifying a specific finding."""
    id: str = Field(description="Unique identifier for the evidence item")
    line_number: int
    timestamp: Optional[str] = None
    log_excerpt: str
    context_lines: List[str] = Field(default_factory=list)
    category: IssueCategory = IssueCategory.UNKNOWN
    signal_name: str
    explanation: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class TimelineEvent(BaseModel):
    """Milestone event in the incident timeline."""
    timestamp: Optional[str] = None
    line_number: int
    phase: str
    description: str
    log_excerpt: str


class RemediationStep(BaseModel):
    """Actionable step to resolve or mitigate the incident."""
    order: int
    action: str
    type: str = "immediate"  # "immediate", "investigative", "permanent_fix"
    command_or_yaml: Optional[str] = None
    rationale: str


class RootCause(BaseModel):
    """Root cause diagnosis with supporting analysis."""
    category: IssueCategory
    title: str
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    summary: str
    technical_details: str
    contributing_factors: List[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    """Comprehensive investigation report with findings and supporting evidence."""
    title: str
    severity: SeverityLevel
    status: str
    summary: str
    detected_issues: List[str] = Field(default_factory=list)
    root_causes: List[RootCause] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    impact_assessment: str
    remediation_steps: List[RemediationStep] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
