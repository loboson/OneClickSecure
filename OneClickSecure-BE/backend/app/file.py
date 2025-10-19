from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
import os

router = APIRouter()

@router.get("/download/{host_id}/{username}")
def download_result_file(host_id: int, username: str):
    # 파일 경로 패턴 (host_id, username으로 파일 찾기)
    file_pattern = f"./collected_results/Results_{host_id}_{username}_*.txt"
    import glob
    files = glob.glob(file_pattern)
    if not files:
        raise HTTPException(status_code=404, detail="결과 파일이 없습니다")
    # 가장 최신 파일 선택
    latest_file = max(files, key=os.path.getctime)
    return FileResponse(latest_file, filename=os.path.basename(latest_file))
