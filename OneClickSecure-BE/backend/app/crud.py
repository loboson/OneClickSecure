# app/crud.py

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from app import models, schemas
import json

# ==================== Host CRUD ====================

def create_host(db: Session, host: schemas.HostCreate, os_info: str = None) -> models.Host:
    """호스트 생성"""
    # IP 중복 체크
    existing_host = get_host_by_ip(db, host.ip)
    if existing_host:
        raise ValueError(f"IP 주소 {host.ip}는 이미 등록되어 있습니다.")
    
    db_host = models.Host(
        name=host.name,
        username=host.username,
        ip=host.ip,
        os=os_info
    )
    db.add(db_host)
    db.commit()
    db.refresh(db_host)
    return db_host

def get_host(db: Session, host_id: int) -> Optional[models.Host]:
    """호스트 단일 조회"""
    return db.query(models.Host).filter(models.Host.id == host_id).first()

def get_host_by_ip(db: Session, ip: str) -> Optional[models.Host]:
    """IP로 호스트 조회"""
    return db.query(models.Host).filter(models.Host.ip == ip).first()

def get_hosts(db: Session, skip: int = 0, limit: int = 100, 
              filter_params: schemas.HostFilter = None) -> List[models.Host]:
    """호스트 목록 조회 (필터링 지원)"""
    query = db.query(models.Host)
    
    if filter_params:
        if filter_params.name:
            query = query.filter(models.Host.name.contains(filter_params.name))
        if filter_params.ip:
            query = query.filter(models.Host.ip.contains(filter_params.ip))
        if filter_params.os:
            query = query.filter(models.Host.os.contains(filter_params.os))
    
    return query.offset(skip).limit(limit).all()

def update_host(db: Session, host_id: int, host_update: schemas.HostCreate) -> Optional[models.Host]:
    """호스트 정보 업데이트"""
    db_host = get_host(db, host_id)
    if db_host:
        db_host.name = host_update.name
        db_host.username = host_update.username
        db_host.ip = host_update.ip
        db.commit()
        db.refresh(db_host)
    return db_host

def update_host_last_check(db: Session, host_id: int) -> Optional[models.Host]:
    """호스트 마지막 점검 시간 업데이트 - 현재 Host 모델에서는 스킵"""
    db_host = get_host(db, host_id)
    if db_host:
        # last_check_at 필드가 없으므로 단순히 조회만 수행
        db.commit()
        db.refresh(db_host)
    return db_host

def delete_host(db: Session, host_id: int) -> bool:
    """호스트 삭제"""
    db_host = get_host(db, host_id)
    if db_host:
        db.delete(db_host)
        db.commit()
        return True
    return False

def get_hosts_stats(db: Session) -> schemas.HostStats:
    """호스트 통계 정보 - 기본 Host 모델 호환"""
    total_hosts = db.query(models.Host).count()
    
    # 기본 Host 모델에는 is_active, last_check_at 필드가 없으므로 간소화
    return schemas.HostStats(
        total_hosts=total_hosts,
        active_hosts=total_hosts,  # 모든 호스트를 활성으로 간주
        last_check_count=0,  # last_check_at 필드가 없으므로 0
        failed_checks=0  # CheckExecution 테이블이 없을 수 있으므로 0
    )

# ==================== CheckExecution CRUD ====================
# 이 섹션들은 해당 테이블들이 생성된 후에 사용 가능

def create_check_execution(db: Session, execution: schemas.CheckExecutionCreate) -> models.CheckExecution:
    """점검 실행 기록 생성"""
    try:
        db_execution = models.CheckExecution(
            host_id=execution.host_id,
            status="pending",
            selected_section_ids=execution.section_ids,
            execution_config={"script_ids": execution.script_ids}
        )
        db.add(db_execution)
        db.commit()
        db.refresh(db_execution)
        return db_execution
    except Exception as e:
        # CheckExecution 테이블이 없는 경우 None 반환
        print(f"CheckExecution 테이블이 없습니다: {e}")
        return None

def get_check_execution(db: Session, execution_id: int) -> Optional[models.CheckExecution]:
    """점검 실행 단일 조회"""
    try:
        return db.query(models.CheckExecution).filter(
            models.CheckExecution.id == execution_id
        ).first()
    except Exception:
        return None

def get_check_executions(db: Session, host_id: int = None, skip: int = 0, limit: int = 100) -> List[models.CheckExecution]:
    """점검 실행 목록 조회"""
    try:
        query = db.query(models.CheckExecution)
        
        if host_id:
            query = query.filter(models.CheckExecution.host_id == host_id)
        
        return query.order_by(desc(models.CheckExecution.started_at)).offset(skip).limit(limit).all()
    except Exception:
        return []

def update_check_execution_status(db: Session, execution_id: int, status: str, 
                                result_data: Dict = None) -> Optional[models.CheckExecution]:
    """점검 실행 상태 업데이트"""
    try:
        db_execution = get_check_execution(db, execution_id)
        if db_execution:
            db_execution.status = status
            
            if status == "completed":
                db_execution.completed_at = datetime.now()
                if db_execution.started_at:
                    duration = db_execution.completed_at - db_execution.started_at
                    db_execution.duration_seconds = int(duration.total_seconds())
            
            if result_data:
                db_execution.exit_code = result_data.get("exit_code")
                db_execution.result_message = result_data.get("message")
                db_execution.output_content = result_data.get("output")
                db_execution.error_content = result_data.get("error")
                db_execution.result_file_path = result_data.get("result_file")
                db_execution.total_checks = result_data.get("total_checks", 0)
                db_execution.passed_checks = result_data.get("passed_checks", 0)
                db_execution.failed_checks = result_data.get("failed_checks", 0)
            
            db.commit()
            db.refresh(db_execution)
        return db_execution
    except Exception:
        return None

def get_recent_check_executions(db: Session, limit: int = 10) -> List[models.CheckExecution]:
    """최근 점검 실행 목록"""
    try:
        return db.query(models.CheckExecution).order_by(
            desc(models.CheckExecution.started_at)
        ).limit(limit).all()
    except Exception:
        return []

def get_check_execution_stats(db: Session, days: int = 30) -> Dict:
    """점검 실행 통계"""
    try:
        start_date = datetime.now() - timedelta(days=days)
        
        # 총 실행 수
        total_executions = db.query(models.CheckExecution).filter(
            models.CheckExecution.started_at >= start_date
        ).count()
        
        # 상태별 집계
        status_stats = db.query(
            models.CheckExecution.status,
            func.count(models.CheckExecution.id)
        ).filter(
            models.CheckExecution.started_at >= start_date
        ).group_by(models.CheckExecution.status).all()
        
        # 평균 실행 시간
        avg_duration = db.query(
            func.avg(models.CheckExecution.duration_seconds)
        ).filter(
            models.CheckExecution.started_at >= start_date,
            models.CheckExecution.status == "completed"
        ).scalar()
        
        return {
            "total_executions": total_executions,
            "status_breakdown": dict(status_stats),
            "average_duration_seconds": avg_duration or 0,
            "period_days": days
        }
    except Exception:
        return {
            "total_executions": 0,
            "status_breakdown": {},
            "average_duration_seconds": 0,
            "period_days": days
        }

# ==================== CheckScript CRUD (파일 기반 메타데이터) ====================

def create_check_script_record(db: Session, script_data: Dict) -> models.CheckScript:
    """점검 스크립트 레코드 생성 (파일 기반 메타데이터 동기화용)"""
    try:
        db_script = models.CheckScript(
            id=script_data["id"],
            name=script_data["name"],
            description=script_data["description"],
            script_type=script_data.get("type", "script"),
            file_path=f"playbooks/script_{script_data['id']}.sh",
            version=script_data.get("version", "1.0"),
            tags=script_data.get("tags", [])
        )
        db.add(db_script)
        db.commit()
        db.refresh(db_script)
        return db_script
    except Exception as e:
        print(f"CheckScript 테이블이 없습니다: {e}")
        return None

def sync_check_scripts_from_metadata(db: Session, metadata: List[Dict]):
    """파일 기반 메타데이터와 DB 동기화"""
    try:
        # 기존 레코드 삭제
        db.query(models.CheckScript).delete()
        
        # 새 레코드 생성
        for script_data in metadata:
            if script_data.get("type") == "script":
                create_check_script_record(db, script_data)
        
        db.commit()
    except Exception as e:
        print(f"CheckScript 동기화 실패: {e}")

# ==================== SystemConfig CRUD ====================

def get_config(db: Session, config_key: str) -> Optional[models.SystemConfig]:
    """설정 조회"""
    try:
        return db.query(models.SystemConfig).filter(
            models.SystemConfig.config_key == config_key
        ).first()
    except Exception:
        return None

def set_config(db: Session, config_key: str, config_value: str, 
               config_type: str = "string", description: str = None) -> models.SystemConfig:
    """설정 저장/업데이트"""
    try:
        db_config = get_config(db, config_key)
        
        if db_config:
            db_config.config_value = config_value
            db_config.config_type = config_type
            db_config.description = description
        else:
            db_config = models.SystemConfig(
                config_key=config_key,
                config_value=config_value,
                config_type=config_type,
                description=description
            )
            db.add(db_config)
        
        db.commit()
        db.refresh(db_config)
        return db_config
    except Exception as e:
        print(f"SystemConfig 설정 실패: {e}")
        return None

def get_all_configs(db: Session) -> List[models.SystemConfig]:
    """모든 설정 조회"""
    try:
        return db.query(models.SystemConfig).all()
    except Exception:
        return []

# ==================== AuditLog CRUD ====================

def create_audit_log(db: Session, action: str, resource_type: str, 
                    resource_id: str = None, details: Dict = None, 
                    user_id: str = None, ip_address: str = None) -> models.AuditLog:
    """감사 로그 생성"""
    try:
        db_log = models.AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        print(f"AuditLog 생성 실패: {e}")
        return None

def get_audit_logs(db: Session, skip: int = 0, limit: int = 100, 
                  action: str = None, resource_type: str = None) -> List[models.AuditLog]:
    """감사 로그 조회"""
    try:
        query = db.query(models.AuditLog)
        
        if action:
            query = query.filter(models.AuditLog.action == action)
        if resource_type:
            query = query.filter(models.AuditLog.resource_type == resource_type)
        
        return query.order_by(desc(models.AuditLog.created_at)).offset(skip).limit(limit).all()
    except Exception:
        return []

# ==================== 유틸리티 함수들 ====================

def cleanup_old_executions(db: Session, days: int = 30) -> int:
    """오래된 실행 기록 정리"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days)
        
        deleted_count = db.query(models.CheckExecution).filter(
            models.CheckExecution.started_at < cutoff_date
        ).delete()
        
        db.commit()
        return deleted_count
    except Exception:
        return 0

def get_dashboard_stats(db: Session) -> schemas.DashboardStats:
    """대시보드용 통합 통계"""
    try:
        host_stats = get_hosts_stats(db)
        
        # 스크립트 통계 (파일 기반이므로 간단히)
        try:
            script_count = db.query(models.CheckScript).count()
            active_script_count = db.query(models.CheckScript).filter(
                models.CheckScript.is_active == True
            ).count()
            template_count = db.query(models.CheckScript).filter(
                models.CheckScript.script_type == "template"
            ).count()
        except Exception:
            script_count = active_script_count = template_count = 0
            
        script_stats = schemas.ScriptStats(
            total_scripts=script_count,
            active_scripts=active_script_count,
            template_count=template_count
        )
        
        # 최근 점검 목록
        recent_checks = get_recent_check_executions(db, limit=5)
        
        return schemas.DashboardStats(
            host_stats=host_stats,
            script_stats=script_stats,
            recent_checks=recent_checks
        )
    except Exception as e:
        print(f"대시보드 통계 조회 실패: {e}")
        # 기본값 반환
        return schemas.DashboardStats(
            host_stats=schemas.HostStats(
                total_hosts=0,
                active_hosts=0,
                last_check_count=0,
                failed_checks=0
            ),
            script_stats=schemas.ScriptStats(
                total_scripts=0,
                active_scripts=0,
                template_count=0
            ),
            recent_checks=[]
        )