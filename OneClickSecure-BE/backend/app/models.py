# app/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .database import Base

class Host(Base):
    __tablename__ = "hosts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    username = Column(String)
    password = Column(String)
    ip = Column(String, unique=True, index=True)
    os = Column(String, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_check_at = Column(DateTime(timezone=True))

class CheckExecution(Base):
    __tablename__ = "check_executions"
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"))
    status = Column(String, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    exit_code = Column(Integer)
    result_message = Column(Text)
    output_content = Column(Text)
    error_content = Column(Text)
    result_file_path = Column(String)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    selected_section_ids = Column(JSON)  # 선택된 섹션 ID 목록
    execution_config = Column(JSON)      # 실행 설정 (script_ids 등)
    
    # 관계 설정
    host = relationship("Host")

class CheckScript(Base):
    __tablename__ = "check_scripts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    script_type = Column(String, default="script")  # script, template
    file_path = Column(String)
    version = Column(String, default="1.0")
    tags = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class SystemConfig(Base):
    __tablename__ = "system_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String, unique=True, nullable=False)
    config_value = Column(Text)
    config_type = Column(String, default="string")  # string, int, bool, json
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String)  # 사용자 식별자
    action = Column(String, nullable=False)  # create, update, delete, execute
    resource_type = Column(String, nullable=False)  # host, script, execution
    resource_id = Column(String)  # 대상 리소스 ID
    details = Column(JSON)  # 추가 세부 정보
    ip_address = Column(String)  # 요청 IP
    created_at = Column(DateTime(timezone=True), server_default=func.now())