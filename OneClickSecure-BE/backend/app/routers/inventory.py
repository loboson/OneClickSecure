from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pathlib import Path
from app.database import SessionLocal
from app import crud, schemas, models
from app.ansible_utils import get_os_info_with_ansible
from app.check_runner import run_os_check_script

router = APIRouter(prefix="/inventory", tags=["Inventory"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def update_ansible_inventory(db: Session):
    """Ansible 인벤토리 파일 업데이트"""
    hosts = crud.get_hosts(db)
    inventory_content = "[all]\n"
    for host in hosts:
        inventory_content += f"{host.ip}\n"
    
    inventory_path = Path("/home/user/ansible-manager/backend/playbooks/hosts")
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(inventory_content)

@router.post("/register", response_model=schemas.HostRead)
def register_host(host: schemas.HostCreate, db: Session = Depends(get_db)):
    """호스트 등록"""
    try:
        # OS 정보 자동 감지
        os_info = get_os_info_with_ansible(host.ip, host.username, host.password)
        
        # 호스트 생성
        new_host = crud.create_host(db, host, os_info)
        
        # 인벤토리 파일 갱신
        update_ansible_inventory(db)
        
        return new_host
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"호스트 등록 실패: {str(e)}")

@router.get("/list", response_model=list[schemas.HostRead])
def list_hosts(db: Session = Depends(get_db)):
    """호스트 목록 조회"""
    try:
        return crud.get_hosts(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"호스트 목록 조회 실패: {str(e)}")

@router.delete("/delete/{host_id}")
def delete_host(host_id: int, db: Session = Depends(get_db)):
    """호스트 삭제"""
    try:
        host = db.query(models.Host).filter(models.Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        db.delete(host)
        db.commit()
        
        # 인벤토리 파일 갱신
        update_ansible_inventory(db)
        
        return {"message": "호스트가 성공적으로 삭제되었습니다"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"호스트 삭제 실패: {str(e)}")

@router.post("/check")
def check_host(info: schemas.HostCheck, db: Session = Depends(get_db)):
    """호스트 점검 실행"""
    try:
        # 호스트 정보 조회
        host = db.query(models.Host).filter(models.Host.ip == info.ip).first()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        
        # OS 정보 가져오기
        os_info = host.os or "Unknown"
        
        # 점검 스크립트 실행
        result = run_os_check_script(
            ip=info.ip,
            username=info.username,
            password=info.password,
            os_info=os_info,
            host_id=host.id,
            hostname=host.name
        )
        
        return {
            "message": "점검이 완료되었습니다",
            "host_id": host.id,
            "host_name": host.name,
            "result": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "return_code": result.get("returncode", 0),
            "success": result.get("returncode", 0) == 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"점검 실행 실패: {str(e)}")

@router.get("/health")
def health_check():
    """인벤토리 시스템 상태 확인"""
    try:
        return {
            "status": "healthy",
            "service": "inventory",
            "features": {
                "host_management": True,
                "os_detection": True,
                "security_check": True
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "service": "inventory",
            "error": str(e)
        }