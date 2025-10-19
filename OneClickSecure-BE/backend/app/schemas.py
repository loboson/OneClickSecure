# app/schemas.py

from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

# === 호스트 관련 스키마 ===

class HostBase(BaseModel):
    """호스트 기본 스키마"""
    name: str
    username: str
    ip: str

class HostCreate(HostBase):
    """호스트 생성 스키마"""
    password: str

class HostRead(HostBase):
    """호스트 조회 스키마"""
    id: int
    os: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class HostUpdate(BaseModel):
    """호스트 업데이트 스키마"""
    name: Optional[str] = None
    username: Optional[str] = None
    ip: Optional[str] = None
    password: Optional[str] = None

class HostCheck(BaseModel):
    """호스트 점검 요청 스키마"""
    ip: str
    username: str
    password: str

class HostFilter(BaseModel):
    """호스트 필터링 스키마"""
    name: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None

class HostInfo(BaseModel):
    """호스트 정보 (플레이북용)"""
    id: int
    name: str
    ip: str
    username: str
    os: Optional[str] = None

class HostStats(BaseModel):
    """호스트 통계 스키마"""
    total_hosts: int
    active_hosts: int
    last_check_count: int
    failed_checks: int

# === 플레이북 관련 스키마 ===

class ScriptSection(BaseModel):
    """스크립트 섹션 정보"""
    id: str
    name: str
    description: str
    content: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None

class PlaybookResponse(BaseModel):
    """플레이북 응답 스키마"""
    id: int
    name: str
    description: str
    lastRun: str
    status: str
    tasks: int
    filename: Optional[str] = None
    sections: Optional[List[ScriptSection]] = None
    type: Optional[str] = None

class PlaybookExecuteRequest(BaseModel):
    """플레이북 호스트 실행 요청"""
    host_ids: List[int]
    section_ids: Optional[List[str]] = None
    password: str

class ExecuteRequest(BaseModel):
    """플레이북 실행 요청 스키마 (레거시)"""
    section_ids: Optional[List[str]] = None

class ExecutionResult(BaseModel):
    """실행 결과"""
    hostname: str
    ip: str
    success: bool
    output: str
    return_code: int
    completed_at: str

class ExecutionStatus(BaseModel):
    """실행 상태"""
    execution_id: str
    playbook_id: int
    playbook_name: str
    playbook_filename: str
    status: str
    hosts: List[Dict[str, Any]]
    start_time: str
    end_time: Optional[str] = None
    results: Dict[int, ExecutionResult] = {}
    section_ids: Optional[List[str]] = None
    total_hosts: int
    completed_hosts: int
    failed_hosts: int
    error: Optional[str] = None

class PlaybookExecutionResponse(BaseModel):
    """플레이북 실행 시작 응답"""
    execution_id: str
    message: str
    hosts_count: int
    playbook_name: str

class ExecutionHistoryResponse(BaseModel):
    """실행 히스토리 응답"""
    executions: List[ExecutionStatus]
    total: int

class PlaybookRunResult(BaseModel):
    """플레이북 실행 결과"""
    message: str
    status: str
    output: str

class PlaybookCreateResult(BaseModel):
    """플레이북 생성 결과"""
    id: int
    name: str
    description: str
    filename: Optional[str] = None
    tasks: int
    sections: Optional[List[ScriptSection]] = None

# === 점검 실행 관련 스키마 (레거시) ===

class CheckExecutionCreate(BaseModel):
    """점검 실행 생성 스키마"""
    host_id: int
    section_ids: Optional[List[str]] = None
    script_ids: List[int]

class CheckExecutionRead(BaseModel):
    """점검 실행 조회 스키마"""
    id: int
    host_id: int
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    exit_code: Optional[int] = None
    result_message: Optional[str] = None

    class Config:
        from_attributes = True

# === 스크립트 관련 스키마 ===

class ScriptStats(BaseModel):
    """스크립트 통계 스키마"""
    total_scripts: int
    active_scripts: int
    template_count: int

# === 다운로드 관련 스키마 ===

class DownloadRequest(BaseModel):
    """다운로드 요청 스키마"""
    host_id: int
    username: str
    file_type: str = "csv"

class FileUploadResponse(BaseModel):
    """파일 업로드 응답 스키마"""
    filename: str
    message: str
    file_size: int
    upload_time: datetime

# === 검색 및 필터링 스키마 ===

class HostSearchParams(BaseModel):
    """호스트 검색 매개변수 스키마"""
    search_term: Optional[str] = None
    os_type: Optional[str] = None
    limit: Optional[int] = 100
    offset: Optional[int] = 0

class PlaybookSearchParams(BaseModel):
    """플레이북 검색 매개변수 스키마"""
    search_term: Optional[str] = None
    target_os: Optional[str] = None
    limit: Optional[int] = 100
    offset: Optional[int] = 0

# === 통계 및 대시보드 스키마 ===

class ExecutionStats(BaseModel):
    """실행 통계 스키마"""
    total_executions: int
    successful_executions: int
    failed_executions: int
    recent_executions: List[Dict[str, Any]]

class DashboardStats(BaseModel):
    """대시보드 통계 스키마"""
    host_stats: HostStats
    script_stats: ScriptStats
    recent_checks: List[CheckExecutionRead]

# === 실시간 모니터링 스키마 ===

class ExecutionProgress(BaseModel):
    """실행 진행률"""
    execution_id: str
    total_hosts: int
    completed_hosts: int
    failed_hosts: int
    progress_percentage: float
    current_status: str
    estimated_remaining_time: Optional[int] = None  # 초 단위

class HostStatus(BaseModel):
    """호스트별 실행 상태"""
    host_id: int
    hostname: str
    ip: str
    status: str  # 대기중, 실행중, 완료, 실패
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    progress: Optional[int] = None  # 0-100
    current_task: Optional[str] = None
    result: Optional[str] = None

# === 배치 실행 관련 스키마 ===

class BatchExecutionRequest(BaseModel):
    """배치 실행 요청"""
    playbook_ids: List[int]
    host_ids: List[int]
    execution_mode: str = "sequential"  # sequential, parallel
    max_parallel: int = 5
    stop_on_failure: bool = False

class BatchExecutionStatus(BaseModel):
    """배치 실행 상태"""
    batch_id: str
    total_playbooks: int
    completed_playbooks: int
    failed_playbooks: int
    current_playbook: Optional[str] = None
    overall_status: str
    individual_executions: List[ExecutionStatus] = []

# === 스케줄링 관련 스키마 ===

class ScheduledExecution(BaseModel):
    """예약 실행 스키마"""
    id: Optional[int] = None
    name: str
    playbook_id: int
    host_ids: List[int]
    cron_expression: str
    is_active: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: Optional[datetime] = None

class ScheduleRequest(BaseModel):
    """예약 실행 요청"""
    name: str
    playbook_id: int
    host_ids: List[int]
    cron_expression: str  # "0 2 * * *" (매일 새벽 2시)
    is_active: bool = True

# === 템플릿 관련 스키마 ===

class PlaybookTemplate(BaseModel):
    """플레이북 템플릿"""
    id: Optional[int] = None
    name: str
    description: str
    category: str  # 시스템점검, 보안점검, 성능점검 등
    template_content: str
    variables: List[str] = []  # 템플릿 변수 목록
    target_os: Optional[List[str]] = None
    is_public: bool = False

class TemplateApplyRequest(BaseModel):
    """템플릿 적용 요청"""
    template_id: int
    variable_values: Dict[str, Any] = {}
    target_hosts: List[int]
    playbook_name: str

# === 섹션 실행 관련 스키마 ===

class SectionExecuteRequest(BaseModel):
    """섹션별 실행 요청"""
    playbook_id: int
    host_ids: List[int]
    section_ids: List[str]

# === 응답 메시지 스키마 ===

class MessageResponse(BaseModel):
    """일반 메시지 응답 스키마"""
    message: str
    success: bool = True

class ErrorResponse(BaseModel):
    """에러 응답 스키마"""
    detail: str
    error_code: Optional[str] = None
    timestamp: Optional[str] = None

class SuccessResponse(BaseModel):
    """성공 응답 스키마"""
    message: str
    data: Optional[Dict[str, Any]] = None

# === 헬스체크 스키마 ===

class HealthCheckResponse(BaseModel):
    """헬스체크 응답"""
    status: str
    playbooks_dir: str
    playbooks_dir_exists: bool
    metadata_file_exists: bool
    playbooks_count: int

# === 레거시 스키마 (호환성 유지) ===

class PlaybookInfo(BaseModel):
    """플레이북 정보 스키마 (레거시)"""
    id: str
    name: str
    description: Optional[str] = None
    filename: str
    tasks: int = 0
    variables: List[str] = []
    target_os: Optional[str] = None

class PlaybookExecution(BaseModel):
    """플레이북 실행 요청 스키마 (레거시)"""
    playbook_name: str
    playbook_filename: str
    host_ids: List[int]
    credentials: Dict[str, Any] = {}
    variables: Dict[str, Any] = {}

class PlaybookInventoryExecuteRequest(BaseModel):
    """플레이북 인벤터리 실행 요청 스키마 (레거시)"""
    host_ids: Optional[List[int]] = None  # None이면 전체 호스트
    section_ids: Optional[List[str]] = None  # Shell 스크립트의 특정 섹션만 실행
    variables: Optional[Dict[str, Any]] = {}  # 추가 변수들

class HostExecutionResult(BaseModel):
    """개별 호스트 실행 결과 (레거시)"""
    hostname: str
    ip: str
    success: bool
    output: str
    return_code: int
    completed_at: str

class PlaybookExecutionStatus(BaseModel):
    """플레이북 실행 상태 (레거시)"""
    execution_id: str
    playbook_id: int
    playbook_name: str
    playbook_filename: str
    status: str  # 준비중, 실행중, 완료, 실패
    hosts: List[Dict[str, Any]]
    start_time: str
    end_time: Optional[str] = None
    results: Dict[int, HostExecutionResult] = {}
    section_ids: Optional[List[str]] = None
    total_hosts: int
    completed_hosts: int
    failed_hosts: int
    error: Optional[str] = None

class AvailableHost(BaseModel):
    """실행 가능한 호스트 정보 (레거시)"""
    id: int
    name: str
    ip: str
    os: Optional[str] = None
    status: str  # 활성, 비활성, 알 수 없음

class YAMLValidationRequest(BaseModel):
    """YAML 검증 요청"""
    content: str

class YAMLValidationResponse(BaseModel):
    """YAML 검증 응답"""
    valid: bool
    syntax_valid: bool
    structure_valid: bool
    security_valid: bool
    syntax_error: str
    structure_issues: List[str]
    security_violations: List[str]

