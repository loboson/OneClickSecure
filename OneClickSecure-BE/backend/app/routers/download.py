from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
import glob
import re
from datetime import datetime
import os
import csv

app = FastAPI()
router = APIRouter()

@router.get("/download/{host_id}/{username}")
def download_result_file(host_id: int, username: str):
    file_pattern = f"/home/user/ansible-manager/backend/playbooks/collected_results/Results_{host_id}_{username}_*.csv"
    print(f"DEBUG: Searching for pattern: {file_pattern}") # 어떤 패턴으로 찾는지 로그!

    files = glob.glob(file_pattern)
    if not files:
        print(f"DEBUG: No files found for pattern: {file_pattern}") # 파일이 하나도 없으면 로그!
        raise HTTPException(status_code=404, detail="결과 파일이 없습니다")

    print("DEBUG: Files found:", files) # 찾은 파일 목록 전부 로그!

    # 각 파일의 최종 수정 시간도 같이 확인해보자!
    files_with_mtime = []
    for f in files:
        try:
            mtime = os.path.getmtime(f)
            files_with_mtime.append((f, mtime))
            print(f"DEBUG: File: {f}, mtime: {mtime}") # 각 파일 이름과 수정 시간 로그!
        except Exception as e:
            print(f"DEBUG: Error getting mtime for {f}: {e}") # 혹시 에러나면 로그!


    if not files_with_mtime: # 혹시 mtime 가져오다 다 실패했으면...
         print("DEBUG: Could not get mtime for any file.")
         raise HTTPException(status_code=500, detail="파일 시간 정보를 가져올 수 없습니다.")


    # 파일 이름 대신 파일의 최종 수정 시간을 기준으로 최신 파일 찾기!
    # (파일 경로, 수정 시간) 튜플 리스트에서 수정 시간을 기준으로 max 찾기
    latest_file_info = max(files_with_mtime, key=lambda item: item[1])
    latest_file = latest_file_info[0] # 파일 경로만 가져오기

    print("DEBUG: Latest file selected:", latest_file) # 최종 선택된 파일 로그!
    print("DEBUG: Latest file mtime:", latest_file_info[1]) # 최종 선택된 파일의 수정 시간 로그!


    return FileResponse(
        latest_file,
        filename=os.path.basename(latest_file),
        media_type="text/csv; charset=utf-8"
    )

@router.get("/download/{host_id}/{username}/json")
def download_result_file_json(host_id: int, username: str):
    file_pattern = f"/home/user/ansible-manager/backend/playbooks/collected_results/Results_{host_id}_{username}_*.csv"
    files = glob.glob(file_pattern)
    if not files:
        raise HTTPException(status_code=404, detail="결과 파일이 없습니다")

    # 최신 파일 찾기
    files_with_mtime = []
    for f in files:
        try:
            mtime = os.path.getmtime(f)
            files_with_mtime.append((f, mtime))
        except Exception:
            continue

    if not files_with_mtime:
        raise HTTPException(status_code=500, detail="파일 시간 정보를 가져올 수 없습니다.")

    latest_file = max(files_with_mtime, key=lambda item: item[1])[0]

    # CSV 읽어서 JSON 변환
    try:
        with open(latest_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        return JSONResponse(content={"rows": rows})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV 파일 읽기 실패: {e}")

app.include_router(router, prefix="/api")
