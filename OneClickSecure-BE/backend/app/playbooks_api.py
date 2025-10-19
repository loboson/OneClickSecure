from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
import os
import json
import subprocess
import re
from datetime import datetime
from typing import List, Optional, Dict

router = APIRouter()

# 플레이북 저장 폴더
PLAYBOOKS_DIR = "playbooks"
METADATA_FILE = os.path.join(PLAYBOOKS_DIR, "metadata.json")

# 데이터 모델
class ScriptSection(BaseModel):
    id: str
    name: str
    description: str
    content: str
    line_start: int
    line_end: int

class PlaybookCreate(BaseModel):
    name: str
    description: str

class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: str
    lastRun: str
    status: str
    tasks: int
    filename: Optional[str] = None
    sections: Optional[List[ScriptSection]] = None

class ExecuteRequest(BaseModel):
    section_ids: List[str]

def parse_shell_script(file_path: str) -> List[ScriptSection]:
    """셸 스크립트를 섹션별로 파싱 (u_XX 함수만 섹션으로 인식)"""
    sections = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        current_section = None
        section_content = []
        section_start = 0
        section_id_counter = 1
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # u_XX 함수 정의 패턴만 섹션으로 인식
            function_pattern = r'^(u_\d+)\s*\(\)\s*\{'
            
            func_match = re.match(function_pattern, line_stripped)
            
            # 함수 정의 발견
            if func_match:
                # 이전 섹션 저장
                if current_section and section_content:
                    content = ''.join(section_content).strip()
                    if content:
                        sections.append(ScriptSection(
                            id=f"section_{current_section['id']}",
                            name=current_section['name'],
                            description=current_section['description'],
                            content=content,
                            line_start=section_start + 1,
                            line_end=i
                        ))
                
                # 새 섹션 시작
                func_name = func_match.group(1)
                current_section = {
                    'id': section_id_counter,
                    'name': func_name,
                    'description': f"보안 점검: {func_name.upper()}"
                }
                section_content = [line]
                section_start = i
                section_id_counter += 1
            else:
                if current_section:
                    section_content.append(line)
                else:
                    # 첫 번째 섹션이 없으면 "초기화" 섹션으로 생성
                    if not sections and line_stripped and not line_stripped.startswith('#'):
                        current_section = {
                            'id': section_id_counter,
                            'name': "초기화",
                            'description': "스크립트 초기 설정"
                        }
                        section_content = [line]
                        section_start = i
                        section_id_counter += 1
                    elif current_section is None and line_stripped:
                        section_content.append(line)
        
        # 마지막 섹션 저장
        if current_section and section_content:
            content = ''.join(section_content).strip()
            if content:
                sections.append(ScriptSection(
                    id=f"section_{current_section['id']}",
                    name=current_section['name'],
                    description=current_section['description'],
                    content=content,
                    line_start=section_start + 1,
                    line_end=len(lines)
                ))
        
        # 섹션이 없으면 전체를 하나의 섹션으로
        if not sections:
            full_content = ''.join(lines).strip()
            if full_content:
                sections.append(ScriptSection(
                    id="section_1",
                    name="전체 스크립트",
                    description="전체 스크립트 실행",
                    content=full_content,
                    line_start=1,
                    line_end=len(lines)
                ))
    
    except Exception as e:
        print(f"스크립트 파싱 오류: {e}")
        # 오류 발생시 전체를 하나의 섹션으로
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            if content:
                sections.append(ScriptSection(
                    id="section_1",
                    name="전체 스크립트",
                    description="전체 스크립트 실행",
                    content=content,
                    line_start=1,
                    line_end=len(content.split('\n'))
                ))
        except:
            pass
    
    return sections

# 메타데이터 로드/저장 함수 (기존과 동일)
def load_metadata():
    """메타데이터 파일 로드"""
    if os.path.exists(METADATA_FILE):
        try:
            with open(METADATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    return []

def save_metadata(data):
    """메타데이터 파일 저장"""
    os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

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

# API 엔드포인트들
@router.get("/api/playbooks", response_model=List[PlaybookResponse])
async def get_playbooks():
    """플레이북 목록 조회"""
    metadata = load_metadata()
    return metadata

@router.get("/api/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(playbook_id: int):
    """특정 플레이북 상세 조회"""
    metadata = load_metadata()
    playbook = next((p for p in metadata if p["id"] == playbook_id), None)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook

@router.post("/api/playbooks", response_model=PlaybookResponse)
async def create_playbook(
    name: str = Form(...),
    description: str = Form(...),
    file: Optional[UploadFile] = File(None)
):
    """새 플레이북 생성"""
    metadata = load_metadata()
    
    # 새 ID 생성
    next_id = max([p["id"] for p in metadata], default=0) + 1
    
    filename = None
    tasks_count = 0
    sections = None
    
    if file:
        # 파일 확장자 검증
        if not (file.filename.endswith(('.yml', '.yaml', '.sh'))):
            raise HTTPException(
                status_code=400, 
                detail="YAML 파일(.yml, .yaml) 또는 Shell Script 파일(.sh)만 업로드 가능합니다."
            )
        
        # 파일 저장
        filename = f"{next_id}_{file.filename}"
        file_path = os.path.join(PLAYBOOKS_DIR, filename)
        
        try:
            with open(file_path, "wb") as buffer:
                content = await file.read()
                if file_path.endswith('.sh'):
                    content = content.replace(b'\r\n', b'\n')
                buffer.write(content)
            
            # 파일 타입별 처리
            if filename.endswith('.sh'):
                # 셸 스크립트 파싱
                sections = parse_shell_script(file_path)
                tasks_count = len(sections)
            elif filename.endswith(('.yml', '.yaml')):
                # YAML 파일 tasks 개수 계산
                tasks_count = count_yaml_tasks(file_path)
                
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
        "sections": [section.dict() for section in sections] if sections else None
    }
    
    metadata.append(new_playbook)
    save_metadata(metadata)
    
    return new_playbook

@router.post("/api/playbooks/{playbook_id}/run")
async def run_playbook(playbook_id: int, request: Optional[ExecuteRequest] = None):
    """플레이북 실행 (전체 또는 선택된 섹션)"""
    metadata = load_metadata()
    
    # 플레이북 찾기
    playbook_index = next((i for i, p in enumerate(metadata) if p["id"] == playbook_id), None)
    if playbook_index is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    playbook = metadata[playbook_index]
    
    try:
        status = "성공"
        output = ""
        
        if playbook.get("filename"):
            file_path = os.path.join(PLAYBOOKS_DIR, playbook["filename"])
            
            if not os.path.exists(file_path):
                raise HTTPException(status_code=404, detail="Playbook file not found")
            
            # 파일 타입에 따른 실행
            if file_path.endswith('.sh'):
                # 선택된 섹션이 있으면 해당 섹션만 실행
                if request and request.section_ids and playbook.get("sections"):
                    sections_to_run = []
                    for section_data in playbook["sections"]:
                        if section_data["id"] in request.section_ids:
                            sections_to_run.append(section_data["content"])
                    
                    if not sections_to_run:
                        raise HTTPException(status_code=400, detail="선택된 섹션이 없습니다")
                    
                    # 선택된 섹션들을 임시 스크립트로 생성
                    combined_script = "\n\n".join(sections_to_run)
                    temp_script_path = os.path.join(PLAYBOOKS_DIR, f"temp_{playbook_id}.sh")
                    
                    try:
                        with open(temp_script_path, "w", encoding='utf-8') as f:
                            f.write("#!/bin/bash\n\n")
                            f.write(combined_script)
                        
                        # 임시 스크립트 실행
                        result = subprocess.run(
                            ['bash', temp_script_path], 
                            capture_output=True, 
                            text=True,
                            timeout=300
                        )
                        output = result.stdout + result.stderr
                        status = "성공" if result.returncode == 0 else "실패"
                        
                    finally:
                        # 임시 파일 삭제
                        if os.path.exists(temp_script_path):
                            os.remove(temp_script_path)
                else:
                    # 전체 스크립트 실행
                    result = subprocess.run(
                        ['bash', file_path], 
                        capture_output=True, 
                        text=True,
                        timeout=300
                    )
                    output = result.stdout + result.stderr
                    status = "성공" if result.returncode == 0 else "실패"
                    
            elif file_path.endswith(('.yml', '.yaml')):
                # Ansible Playbook 실행 (기존 로직 유지)
                try:
                    result = subprocess.run(
                        ['ansible-playbook', file_path, '--check'], 
                        capture_output=True, 
                        text=True,
                        timeout=300
                    )
                    output = result.stdout + result.stderr
                    status = "성공" if result.returncode == 0 else "실패"
                except FileNotFoundError:
                    try:
                        import yaml
                        with open(file_path, 'r', encoding='utf-8') as f:
                            yaml.safe_load(f)
                        status = "성공"
                        output = "YAML 문법 검증 완료 (ansible-playbook 미설치)"
                    except yaml.YAMLError as e:
                        status = "실패"
                        output = f"YAML 문법 오류: {str(e)}"
                    except ImportError:
                        status = "성공"
                        output = "파일 존재 확인 완료 (YAML 라이브러리 미설치)"
            else:
                raise HTTPException(status_code=400, detail="지원하지 않는 파일 형식")
                
        else:
            # 파일이 없는 경우 더미 실행
            status = "성공"
            output = "파일 없이 실행 완료"
        
        # 메타데이터 업데이트
        metadata[playbook_index]["status"] = status
        metadata[playbook_index]["lastRun"] = "방금 전"
        save_metadata(metadata)
        
        return {
            "message": "Playbook executed", 
            "status": status,
            "output": output[:2000]  # 출력 내용 제한
        }
        
    except subprocess.TimeoutExpired:
        metadata[playbook_index]["status"] = "실패"
        metadata[playbook_index]["lastRun"] = "방금 전"
        save_metadata(metadata)
        
        return {
            "message": "Execution timeout", 
            "status": "실패",
            "output": "실행 시간 초과 (5분)"
        }
        
    except Exception as e:
        metadata[playbook_index]["status"] = "실패"
        metadata[playbook_index]["lastRun"] = "방금 전"
        save_metadata(metadata)
        
        return {
            "message": f"Execution failed: {str(e)}", 
            "status": "실패",
            "output": str(e)
        }

@router.delete("/api/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: int):
    """플레이북 삭제"""
    metadata = load_metadata()
    
    # 플레이북 찾기
    playbook = next((p for p in metadata if p["id"] == playbook_id), None)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # 파일 삭제
    if playbook.get("filename"):
        file_path = os.path.join(PLAYBOOKS_DIR, playbook["filename"])
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"파일 삭제 실패: {e}")
    
    # 메타데이터에서 제거
    metadata = [p for p in metadata if p["id"] != playbook_id]
    save_metadata(metadata)
    
    return {"message": "Playbook deleted successfully"}

# 헬스체크 엔드포인트
@router.get("/api/playbooks/health")
async def health_check():
    """API 상태 확인"""
    return {
        "status": "healthy",
        "playbooks_dir": PLAYBOOKS_DIR,
        "playbooks_dir_exists": os.path.exists(PLAYBOOKS_DIR),
        "metadata_file_exists": os.path.exists(METADATA_FILE)
    }