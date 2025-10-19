import tempfile
import subprocess
import os
import re
import codecs

def extract_check_result(ansible_stdout):
    match = re.search(r'"check_result.stdout":\s*"((?:[^"\\]|\\.)*)"', ansible_stdout)
    if match:
        return codecs.decode(match.group(1), 'unicode_escape')
    return ansible_stdout

def run_os_check_script(ip, username, password, os_info, host_id=None, hostname=None):
    BASE_PATH = "/home/user/ansible-manager/backend/playbooks"
    if "Ubuntu" in os_info:
        script_path = f"{BASE_PATH}/ubuntu_check.py"
    elif "CentOS" in os_info:
        script_path = f"{BASE_PATH}/centos_check.py"
    else:
        script_path = f"{BASE_PATH}/generic_check.py"

    inventory_content = f"""[target]
{ip} ansible_user={username} ansible_password={password} ansible_become=yes ansible_become_method=sudo ansible_become_password={password} ansible_ssh_common_args='-o StrictHostKeyChecking=no'
"""
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as inv_file:
        inv_file.write(inventory_content)
        inv_path = inv_file.name

    # 플레이북에 전달할 extra_vars 준비
    extra_vars = [
        "-e", f"script_path={script_path}",
        "-e", f"username={username}"
    ]
    if host_id is not None:
        extra_vars.extend(["-e", f"host_id={host_id}"])
    if hostname is not None:
        extra_vars.extend(["-e", f"hostname={hostname}"])

    try:
        result = subprocess.run(
            [
                "ansible-playbook",
                "-i", inv_path,
                f"{BASE_PATH}/run_script.yml",
            ] + extra_vars,
            capture_output=True,
            text=True,
            timeout=300
        )
        clean_stdout = extract_check_result(result.stdout)
        return {
            "stdout": clean_stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    finally:
        os.remove(inv_path)
def run_os_check_script_with_password(ip, username, password, os_info, host_id=None, hostname=None):
    """비밀번호를 사용한 기본 OS 점검 스크립트 실행"""
    
    BASE_PATH = "/home/user/ansible-manager/backend/playbooks"
    if "Ubuntu" in os_info:
        script_path = f"{BASE_PATH}/ubuntu_check.py"
    elif "CentOS" in os_info:
        script_path = f"{BASE_PATH}/centos_check.py"
    else:
        script_path = f"{BASE_PATH}/generic_check.py"
    
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            script_content = f.read()
        return run_custom_script(ip, username, password, script_content, host_id, hostname)
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"스크립트 파일을 찾을 수 없습니다: {script_path}. 오류: {str(e)}",
            "returncode": 1
        }



def run_custom_script(ip, username, password, script_content, host_id=None, hostname=None):
    """커스텀 스크립트 실행 - 3단계 처리"""
    
    import tempfile
    import os

    try:
        # 임시 스크립트 파일 생성
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, encoding='utf-8') as temp_script:
            temp_script.write("#!/bin/bash\n")
            temp_script.write("set -e\n")  # 오류 발생시 즉시 중단
            temp_script.write(script_content)
            temp_script_path = temp_script.name
        
        # 실행 권한 부여
        os.chmod(temp_script_path, 0o755)
        
        # Ansible 인벤토리 생성
        inventory_content = f"""[target]
{ip} ansible_user={username} ansible_password={password} ansible_become=yes ansible_become_method=sudo ansible_become_password={password} ansible_ssh_common_args='-o StrictHostKeyChecking=no'
"""
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as inv_file:
            inv_file.write(inventory_content)
            inv_path = inv_file.name
        
        # 결과 수집 디렉토리 설정
        result_dir = "/home/user/ansible-manager/backend/playbooks/collected_results"
        os.makedirs(result_dir, exist_ok=True)
        
        # 환경 변수 설정
        env_vars = {
            "HOST_ID": str(host_id) if host_id else "unknown",
            "HOSTNAME": hostname if hostname else "unknown",
            "USERNAME": username
        }
        
        try:
            # Ansible을 통해 스크립트 실행
            result = subprocess.run([
                "ansible",
                "all",
                "-i", inv_path,
                "-m", "script",
                "-a", temp_script_path,
                "-o"
            ], 
            capture_output=True, 
            text=True, 
            timeout=300,
            env={**os.environ, **env_vars}
            )
            
            # 결과 정리
            clean_stdout = extract_check_result(result.stdout) if result.stdout else ""
            
            return {
                "stdout": clean_stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        finally:
            # 임시 파일들 정리
            try:
                os.remove(inv_path)
                os.remove(temp_script_path)
            except:
                pass
                
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "스크립트 실행 시간 초과 (5분)",
            "returncode": 1
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"스크립트 실행 오류: {str(e)}",
            "returncode": 1
        }


    # 결과 파일명 생성
    import time
    timestamp = str(int(time.time()))
    result_filename = f"Results_{host_id or 'unknown'}_{username}_{timestamp}.csv"
    
    # 스크립트 헤더 + 내용 결합
    script_header = f"""#!/bin/bash

# 환경변수 설정
export HOST_ID="{host_id or 'unknown'}"
export USERNAME="{username}"
export resultfile="/tmp/{result_filename}"

# 결과 파일 초기화
echo "항목코드,결과" > "$resultfile"

echo "=== 점검 시작 ===" >&2
echo "Result file: $resultfile" >&2

"""
    
    # 기존 스크립트 정리 후 결합
    cleaned_script = clean_script_content(script_content)
    full_script = script_header + cleaned_script + f"""

echo "=== 점검 완료 ===" >&2
if [ -f "$resultfile" ]; then
    echo "결과 파일 생성 완료: $resultfile" >&2
    cat "$resultfile" >&2
else
    echo "ERROR: 결과 파일이 생성되지 않았습니다" >&2
    exit 1
fi
"""
    
    # 임시 파일들 생성
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, encoding='utf-8') as temp_script:
        temp_script.write(full_script)
        temp_script_path = temp_script.name
    
    inventory_content = f"""[target]
{ip} ansible_user={username} ansible_password={password} ansible_become=yes ansible_become_method=sudo ansible_become_password={password} ansible_ssh_common_args='-o StrictHostKeyChecking=no'
"""
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as inv_file:
        inv_file.write(inventory_content)
        inv_path = inv_file.name

    try:
        print(f"🚀 스크립트 실행: {ip} -> {result_filename}")
        
        # 1단계: 스크립트 실행
        script_result = subprocess.run([
            "ansible", "all", "-i", inv_path,
            "-m", "script", "-a", temp_script_path,
            "-v"
        ], capture_output=True, text=True, timeout=300)
        
        print(f"스크립트 실행 결과: {script_result.returncode}")
        
        # 2단계: 결과 파일 가져오기
        fetch_result = subprocess.run([
            "ansible", "all", "-i", inv_path,
            "-m", "fetch",
            "-a", f"src=/tmp/{result_filename} dest=/home/user/projects/OneClickSecure-BE/backend/playbooks/collected_results/ flat=yes",
        ], capture_output=True, text=True)
        
        print(f"파일 가져오기 결과: {fetch_result.returncode}")
        
        # 3단계: 원격 임시 파일 정리
        cleanup_result = subprocess.run([
            "ansible", "all", "-i", inv_path,
            "-m", "file",
            "-a", f"path=/tmp/{result_filename} state=absent",
        ], capture_output=True, text=True)
        
        return {
            "stdout": script_result.stdout + "\n=== FETCH ===\n" + fetch_result.stdout,
            "stderr": script_result.stderr + "\n" + fetch_result.stderr,
            "returncode": script_result.returncode
        }
        
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "스크립트 실행 시간 초과",
            "returncode": 124
        }
    finally:
        # 로컬 임시 파일 정리
        try:
            os.remove(temp_script_path)
            os.remove(inv_path)
        except:
            pass

def clean_script_content(script_content):
    """스크립트에서 기존 resultfile 정의나 shebang 제거"""
    lines = script_content.split('\n')
    cleaned_lines = []
    
    for line in lines:
        stripped = line.strip()
        # 불필요한 라인들 제거
        if (stripped.startswith('#!') or 
            'resultfile=' in line or
            'export resultfile=' in line or
            stripped == 'echo "항목코드,결과" > "$resultfile"' or
            stripped == 'echo "항목코드,결과" > $resultfile'):
            continue
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)