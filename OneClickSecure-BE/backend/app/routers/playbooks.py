from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, BackgroundTasks, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path
import json
import re
import os
import uuid
import tempfile
import subprocess
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime

# 데이터베이스 import
from app.database import SessionLocal
from app import crud, models
from app.check_runner import run_custom_script
from app.schemas import (
    ScriptSection,
    PlaybookResponse, 
    HostInfo,
    PlaybookExecuteRequest,
    ExecutionResult,
    YAMLValidationRequest,
    YAMLValidationResponse
)
from app.yaml_validator import yaml_validator  

# 경로 설정
BASE_DIR = Path("/home/user/projects/OneClickSecure-BE/backend")
PLAYBOOKS_DIR = BASE_DIR / "playbooks"
METADATA_FILE = PLAYBOOKS_DIR / "metadata.json"

# 디렉토리 생성
PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)

# 실행 상태 저장소
execution_status_store: Dict[str, Dict] = {}

router = APIRouter(prefix="/api/playbooks", tags=["Playbooks"])

def get_db():
    """데이터베이스 세션"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def load_metadata():
    """메타데이터 파일 로드"""
    if not METADATA_FILE.exists():
        print(f"📄 메타데이터 파일이 없음: {METADATA_FILE}")
        return scan_existing_scripts()
    
    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"✅ 메타데이터 로드 성공: {len(data)}개 플레이북")
        return data
    except Exception as e:
        print(f"❌ 메타데이터 로드 실패: {e}")
        return scan_existing_scripts()

def scan_existing_scripts():
    """기존 스크립트 파일들을 스캔해서 메타데이터 생성"""
    scripts = []
    script_id = 1
    
    try:
        for file_path in PLAYBOOKS_DIR.iterdir():
            if file_path.is_file() and file_path.suffix in ['.sh', '.py', '.yml', '.yaml']:
                # 시스템 파일 제외
                if file_path.name in ['metadata.json', 'hosts', 'run_script.yml']:
                    continue
                
                sections = None
                tasks = 1
                file_type = "script"
                
                if file_path.suffix == '.sh':
                    sections = parse_shell_script(str(file_path))
                    tasks = len(sections) if sections else 1
                    file_type = "shell"
                elif file_path.suffix in ['.yml', '.yaml']:
                    tasks = count_yaml_tasks(str(file_path))
                    file_type = "ansible"
                elif file_path.suffix == '.py':
                    file_type = "python"
                
                script_data = {
                    "id": script_id,
                    "name": file_path.stem,
                    "description": f"{file_path.suffix[1:].upper()} 스크립트",
                    "lastRun": "실행 안됨",
                    "status": "대기중",
                    "tasks": tasks,
                    "filename": file_path.name,
                    "sections": [section.dict() for section in sections] if sections else None,
                    "type": file_type
                }
                scripts.append(script_data)
                script_id += 1
        
        # 생성된 메타데이터 저장
        if scripts:
            save_metadata(scripts)
        
        print(f"🔍 스캔 완료: {len(scripts)}개 스크립트 발견")
        return scripts
        
    except Exception as e:
        print(f"❌ 스크립트 스캔 실패: {e}")
        return []

def save_metadata(data):
    """메타데이터 파일 저장"""
    try:
        PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
        with open(METADATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"✅ 메타데이터 저장 성공: {len(data)}개 플레이북")
        return True
    except Exception as e:
        print(f"❌ 메타데이터 저장 실패: {e}")
        raise HTTPException(status_code=500, detail=f"메타데이터 저장 실패: {str(e)}")

def parse_shell_script(file_path: str) -> List[ScriptSection]:
    """셸 스크립트를 섹션별로 파싱"""
    sections = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        current_section = None
        section_content = []
        section_id_counter = 1
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # u_XX 함수 정의 패턴
            function_pattern = r'^(u_\d+)\s*\(\)\s*\{'
            func_match = re.match(function_pattern, line_stripped)
            
            if func_match:
                # 이전 섹션 저장
                if current_section and section_content:
                    content = ''.join(section_content).strip()
                    if content:
                        sections.append(ScriptSection(
                            id=f"section_{current_section['id']}",
                            name=current_section['name'],
                            description=current_section['description'],
                            content=content
                        ))
                
                # 새 섹션 시작
                func_name = func_match.group(1)
                current_section = {
                    'id': section_id_counter,
                    'name': func_name,
                    'description': f"{func_name} 함수 실행"
                }
                section_content = [line]
                section_id_counter += 1
            else:
                if current_section:
                    section_content.append(line)
        
        # 마지막 섹션 저장
        if current_section and section_content:
            content = ''.join(section_content).strip()
            if content:
                sections.append(ScriptSection(
                    id=f"section_{current_section['id']}",
                    name=current_section['name'],
                    description=current_section['description'],
                    content=content
                ))
        
        # 섹션이 없으면 전체를 하나의 섹션으로
        if not sections:
            full_content = ''.join(lines).strip()
            if full_content:
                sections.append(ScriptSection(
                    id="section_1",
                    name="전체 스크립트",
                    description="전체 스크립트 실행",
                    content=full_content
                ))
    
    except Exception as e:
        print(f"❌ 스크립트 파싱 오류: {e}")
    
    return sections

def count_yaml_tasks(file_path):
    """YAML 파일에서 tasks 개수 카운트"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            import re
            tasks = re.findall(r'^\s*-\s+name:', content, re.MULTILINE)
            return len(tasks)
    except:
        return 0

# === API 엔드포인트들 ===

@router.get("/hosts", response_model=List[HostInfo])
async def get_available_hosts(db: Session = Depends(get_db)):
    """플레이북 실행 가능한 호스트 목록 조회"""
    try:
        print("📋 호스트 목록 조회 (플레이북용)")
        
        hosts = crud.get_hosts(db)
        
        host_list = []
        for host in hosts:
            host_list.append(HostInfo(
                id=host.id,
                name=host.name,
                ip=host.ip,
                username=host.username,
                os=host.os
            ))
        
        print(f"✅ 조회된 호스트 수: {len(host_list)}")
        return host_list
        
    except Exception as e:
        print(f"❌ 호스트 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=f"호스트 목록 조회 실패: {str(e)}")

@router.get("", response_model=List[PlaybookResponse])
async def get_playbooks():
    """플레이북 목록 조회"""
    try:
        print("📋 플레이북 목록 조회 시작")
        metadata = load_metadata()
        print(f"✅ 플레이북 목록 반환: {len(metadata)}개")
        return metadata
    except Exception as e:
        print(f"❌ 플레이북 목록 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=f"플레이북 목록 조회 실패: {str(e)}")

@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(playbook_id: int):
    """특정 플레이북 상세 조회"""
    try:
        metadata = load_metadata()
        playbook = next((p for p in metadata if p["id"] == playbook_id), None)
        if not playbook:
            raise HTTPException(status_code=404, detail="Playbook not found")
        return playbook
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"플레이북 조회 실패: {str(e)}")

@router.post("", response_model=PlaybookResponse)
async def create_playbook(
    name: str = Form(...),
    description: str = Form(...),
    file: Optional[UploadFile] = File(None)
):
    """새 플레이북 생성"""
    try:
        metadata = load_metadata()
        
        # 새 ID 생성
        next_id = max([p["id"] for p in metadata], default=0) + 1
        
        filename = None
        tasks_count = 0
        sections = None
        file_type = None
        
        if file and file.filename:
            # 파일 확장자 검증
            allowed_extensions = ('.yml', '.yaml', '.sh', '.py')
            if not file.filename.endswith(allowed_extensions):
                error_msg = f"지원하지 않는 파일 형식: {file.filename}. 지원 형식: {', '.join(allowed_extensions)}"
                raise HTTPException(status_code=400, detail=error_msg)
            
            # 파일 저장
            filename = f"{next_id}_{file.filename}"
            file_path = PLAYBOOKS_DIR / filename
            
            try:
                with open(file_path, "wb") as buffer:
                    content = await file.read()
                    if file_path.suffix == '.sh':
                        content = content.replace(b'\r\n', b'\n')
                    buffer.write(content)
                
                # 파일 타입별 처리
                if filename.endswith('.sh'):
                    sections = parse_shell_script(str(file_path))
                    tasks_count = len(sections)
                    file_type = "shell"
                elif filename.endswith(('.yml', '.yaml')):
                    tasks_count = count_yaml_tasks(str(file_path))
                    file_type = "ansible"
                elif filename.endswith('.py'):
                    tasks_count = 1
                    file_type = "python"
                    
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"파일 저장 실패: {str(e)}")
        
        # 메타데이터 추가
        new_playbook = {
            "id": next_id,
            "name": name,
            "description": description,
            "lastRun": "실행 안됨",
            "status": "대기중",
            "tasks": tasks_count,
            "filename": filename,
            "sections": [section.dict() for section in sections] if sections else None,
            "type": file_type
        }
        
        metadata.append(new_playbook)
        save_metadata(metadata)
        
        return new_playbook
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"생성 실패: {str(e)}")

@router.delete("/{playbook_id}")
async def delete_playbook(playbook_id: int):
    """플레이북 삭제"""
    try:
        metadata = load_metadata()
        
        # 플레이북 찾기
        playbook = next((p for p in metadata if p["id"] == playbook_id), None)
        if not playbook:
            raise HTTPException(status_code=404, detail="Playbook not found")
        
        # 파일 삭제
        if playbook.get("filename"):
            file_path = PLAYBOOKS_DIR / playbook["filename"]
            if file_path.exists():
                try:
                    file_path.unlink()
                except Exception as e:
                    print(f"⚠️ 파일 삭제 실패: {e}")
        
        # 메타데이터에서 제거
        metadata = [p for p in metadata if p["id"] != playbook_id]
        save_metadata(metadata)
        
        return {"message": "Playbook deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"삭제 실패: {str(e)}")

@router.post("/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: int,
    request: PlaybookExecuteRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """플레이북을 선택된 호스트에서 실행"""
    try:
        print(f"🚀 플레이북 실행 요청: ID {playbook_id}")
        
        # 실행 ID 생성
        execution_id = str(uuid.uuid4())
        
        # 호스트 정보 조회
        hosts = []
        for host_id in request.host_ids:
            host = db.query(models.Host).filter(models.Host.id == host_id).first()
            if not host:
                raise HTTPException(status_code=404, detail=f"호스트 ID {host_id}를 찾을 수 없습니다")
            hosts.append(host)
        
        # 플레이북 정보 조회
        metadata = load_metadata()
        playbook = next((p for p in metadata if p["id"] == playbook_id), None)
        if not playbook:
            raise HTTPException(status_code=404, detail="플레이북을 찾을 수 없습니다")
        
        # 실행 상태 초기화
        execution_status_store[execution_id] = {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook["name"],
            "playbook_filename": playbook.get("filename", ""),
            "status": "준비중",
            "hosts": [{"id": h.id, "name": h.name, "ip": h.ip} for h in hosts],
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "results": {},
            "section_ids": request.section_ids,
            "total_hosts": len(hosts),
            "completed_hosts": 0,
            "failed_hosts": 0,
            "error": None
        }
        
        # 백그라운드에서 실행
        background_tasks.add_task(
            execute_playbook_on_hosts_task,
            execution_id,
            playbook,
            hosts,
            request.password,
            request.section_ids
        )
        
        return {
            "execution_id": execution_id,
            "message": f"플레이북 '{playbook['name']}' 실행이 시작되었습니다",
            "hosts_count": len(hosts),
            "playbook_name": playbook["name"]
        }
        
    except Exception as e:
        print(f"❌ 플레이북 실행 시작 오류: {e}")
        raise HTTPException(status_code=500, detail=f"플레이북 실행 시작 실패: {str(e)}")

async def execute_playbook_on_hosts_task(
    execution_id: str,
    playbook: dict,
    hosts: List,
    password: str,
    section_ids: Optional[List[str]] = None
):
    """실제 플레이북 실행 로직 (백그라운드 작업)"""
    try:
        print(f"🔄 플레이북 실행 시작: {execution_id}")
        
        # 상태 업데이트: 실행중
        execution_status_store[execution_id]["status"] = "실행중"
        
        # 플레이북 파일 경로
        playbook_file = playbook.get("filename")
        if not playbook_file:
            raise Exception("플레이북 파일이 지정되지 않았습니다")
        
        playbook_path = PLAYBOOKS_DIR / playbook_file
        if not playbook_path.exists():
            raise Exception(f"플레이북 파일을 찾을 수 없습니다: {playbook_path}")
        
        results = {}
        completed_count = 0
        failed_count = 0
        
        # 스크립트 내용 준비
        script_content = prepare_script_content(playbook_path, section_ids)
        
        # 각 호스트에서 실행
        for host in hosts:
            try:
                print(f"🖥️ 호스트 {host.name}({host.ip})에서 실행 중...")
                
                result = run_custom_script(
                    ip=host.ip,
                    username=host.username,
                    password=password,
                    script_content=script_content,
                    host_id=host.id,
                    hostname=host.name
                )
                
                execution_result = ExecutionResult(
                    hostname=host.name,
                    ip=host.ip,
                    success=result.get("returncode", 1) == 0,
                    output=result.get("stdout", "") + result.get("stderr", ""),
                    return_code=result.get("returncode", 1),
                    completed_at=datetime.now().isoformat()
                )
                
                results[host.id] = execution_result.dict()
                
                if execution_result.success:
                    completed_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                print(f"❌ 호스트 {host.name} 실행 오류: {e}")
                results[host.id] = ExecutionResult(
                    hostname=host.name,
                    ip=host.ip,
                    success=False,
                    output=f"실행 오류: {str(e)}",
                    return_code=1,
                    completed_at=datetime.now().isoformat()
                ).dict()
                failed_count += 1
        
        # 최종 상태 업데이트
        execution_status_store[execution_id].update({
            "status": "완료" if failed_count == 0 else "실패",
            "end_time": datetime.now().isoformat(),
            "results": results,
            "completed_hosts": completed_count,
            "failed_hosts": failed_count
        })
        
        print(f"✅ 플레이북 실행 완료: {execution_id}")
        
    except Exception as e:
        print(f"❌ 플레이북 실행 오류 ({execution_id}): {e}")
        execution_status_store[execution_id].update({
            "status": "실패",
            "end_time": datetime.now().isoformat(),
            "error": str(e),
            "failed_hosts": len(hosts)
        })

def prepare_script_content(playbook_path: Path, section_ids: Optional[List[str]]) -> str:
    """스크립트 내용 준비 (섹션 선택 지원)"""
    try:
        with open(playbook_path, 'r', encoding='utf-8') as f:
            full_content = f.read()
        
        # 섹션 선택이 있고, 셸 스크립트인 경우
        if section_ids and playbook_path.suffix == '.sh':
            return build_selected_sections_script(full_content, section_ids)
        
        return full_content
        
    except Exception as e:
        raise Exception(f"스크립트 내용 준비 실패: {str(e)}")

def build_selected_sections_script(script_content: str, section_ids: List[str]) -> str:
    """선택된 섹션들로 스크립트 재구성"""
    script_parts = ["#!/bin/bash", ""]
    
    lines = script_content.split('\n')
    
    for section_id in section_ids:
        try:
            section_num = int(section_id.replace("section_", ""))
            function_name = f"u_{section_num:02d}"
            
            # 해당 함수 찾기
            in_function = False
            brace_count = 0
            section_lines = []
            
            for line in lines:
                if f"{function_name}()" in line and "{" in line:
                    in_function = True
                    section_lines.append(line)
                    brace_count = line.count('{') - line.count('}')
                elif in_function:
                    section_lines.append(line)
                    brace_count += line.count('{') - line.count('}')
                    
                    if brace_count <= 0:
                        break
            
            if section_lines:
                script_parts.append(f"# === {function_name} 실행 ===")
                script_parts.extend(section_lines)
                script_parts.append(f"{function_name}")  # 함수 호출 추가
                script_parts.append("")
                
        except (ValueError, IndexError):
            continue
    
    return '\n'.join(script_parts) if len(script_parts) > 2 else script_content

@router.get("/execution/{execution_id}")
def get_execution_status(execution_id: str):
    """실행 상태 조회"""
    if execution_id not in execution_status_store:
        raise HTTPException(status_code=404, detail="실행 기록을 찾을 수 없습니다")
    
    return execution_status_store[execution_id]

@router.get("/{playbook_id}/script")
async def get_playbook_script(
    playbook_id: int,
    section_ids: Optional[List[str]] = Query(None)
):
    """플레이북 스크립트 내용 가져오기"""
    try:
        metadata = load_metadata()
        playbook = next((p for p in metadata if p["id"] == playbook_id), None)
        
        if not playbook:
            raise HTTPException(status_code=404, detail="플레이북을 찾을 수 없습니다")
        
        if not playbook.get("filename"):
            raise HTTPException(status_code=400, detail="플레이북에 파일이 없습니다")
        
        file_path = PLAYBOOKS_DIR / playbook["filename"]
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="스크립트 파일을 찾을 수 없습니다")
        
        # 파일 내용 읽기
        with open(file_path, 'r', encoding='utf-8') as f:
            script_content = f.read()
        
        # 섹션 필터링 (셸 스크립트인 경우)
        if section_ids and playbook["filename"].endswith('.sh'):
            script_content = build_selected_sections_script(script_content, section_ids)
        
        return {
            "playbook_id": playbook_id,
            "playbook_name": playbook["name"],
            "filename": playbook["filename"],
            "script_content": script_content,
            "selected_sections": section_ids or [],
            "file_type": playbook.get("type", "unknown"),
            "content_length": len(script_content)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"스크립트 가져오기 실패: {str(e)}")

@router.get("/{playbook_id}/script/download")
async def download_playbook_script(
    playbook_id: int,
    section_ids: Optional[List[str]] = Query(None)
):
    """플레이북 스크립트 다운로드"""
    try:
        # 스크립트 내용 가져오기
        script_data = await get_playbook_script(playbook_id, section_ids)
        
        # 임시 파일 생성
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh', encoding='utf-8') as tmp_file:
            tmp_file.write(script_data["script_content"])
            tmp_file_path = tmp_file.name
        
        # 다운로드 파일명 생성
        if section_ids and len(section_ids) > 0:
            download_filename = f"{script_data['playbook_name']}_sections.sh"
        else:
            download_filename = f"{script_data['playbook_name']}.sh"
        
        return FileResponse(
            path=tmp_file_path,
            filename=download_filename,
            media_type='application/octet-stream'
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"다운로드 실패: {str(e)}")

@router.get("/health")
async def health_check():
    """API 상태 확인"""
    try:
        dir_exists = PLAYBOOKS_DIR.exists()
        metadata_exists = METADATA_FILE.exists()
        playbooks_count = len(load_metadata())
        
        # 실제 스크립트 파일 개수 확인
        script_files = []
        if dir_exists:
            for file_path in PLAYBOOKS_DIR.iterdir():
                if file_path.is_file() and file_path.suffix in ['.sh', '.py', '.yml', '.yaml']:
                    if file_path.name not in ['metadata.json', 'hosts', 'run_script.yml']:
                        script_files.append(file_path.name)
        
        return {
            "status": "healthy",
            "playbooks_dir": str(PLAYBOOKS_DIR),
            "playbooks_dir_exists": dir_exists,
            "metadata_file_exists": metadata_exists,
            "playbooks_count": playbooks_count,
            "actual_script_files": script_files,
            "execution_count": len(execution_status_store)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"헬스체크 실패: {str(e)}")




@router.post("/validate-yaml")
async def validate_yaml_content(request: YAMLValidationRequest):
    """YAML 플레이북 내용 검증"""
    try:
        print(f"🔍 YAML 검증 요청 수신")
        
        # yaml_validator 사용하여 검증
        result = yaml_validator.validate_complete(request.content)
        
        return YAMLValidationResponse(
            valid=result["valid"],
            syntax_valid=result["syntax_valid"],
            structure_valid=result["structure_valid"],
            security_valid=result["security_valid"],
            syntax_error=result["syntax_error"],
            structure_issues=result["structure_issues"],
            security_violations=result["security_violations"]
        )
        
    except Exception as e:
        print(f"❌ YAML 검증 오류: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"YAML 검증 실패: {str(e)}"
        )