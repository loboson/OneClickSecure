#!/usr/bin/env python3

import subprocess
import csv
import os
import re
import stat
import glob
import platform
import datetime
import shutil
import pwd

results = []

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode == 0:
            return result.stdout.strip()
        elif result.returncode == 1:
            return ""
        else:
            return f"[Error] {command}{result.stderr.strip()}"
    except subprocess.CalledProcessError as e:
        return f"[Error] {e.stderr.strip()}"

def print_table_header():
    print(f"{'항목':<40} | {'결과':<6} | 상세")
    print("-" * 80)

def print_table_row(item, result, detail):
    result_map = {
        "GOOD": "양호",
        "BAD": "취약",
        "N/A": "해당 없음"
    }
    result_display = result_map.get(result, result)
    print(f"{item:<40} | {result_display:<6} | {detail}")
    results.append([item, result_display, detail])

def check_remote_service():
    item = "[U-01] root 계정 원격접속제한"
    state = "GOOD"
    reasons = []
    telnet_services = run_command("systemctl list-unit-files | grep -i telnet")
    if telnet_services:
        state = "BAD"
        reasons.append("Telnet 서비스가 등록되어 있음")
    telnet_packages = run_command("dpkg -l | grep -i telnet")
    if telnet_packages:
        state = "BAD"
        reasons.append("Telnet 패키지가 설치되어 있음")
    if subprocess.run("grep -Eq '^\\s*#\\s*PermitRootLogin' /etc/ssh/sshd_config", shell=True).returncode == 0:
        pass
    elif subprocess.run("grep -Eq '^\\s*PermitRootLogin\\s+yes\\b' /etc/ssh/sshd_config", shell=True).returncode == 0:
        state = "BAD"
        reasons.append("SSH PermitRootLogin yes로 설정됨")
    else:
        pass
    detail = "; ".join(reasons) if state != "GOOD" else "원격 접속 보안 설정이 적절히 구성됨"
    print_table_row(item, state, detail)

def check_password_complexity():
    item = "[U-02] 패스워드 복잡성 설정"
    state = "GOOD"
    reasons = []
    params = ["lcredit", "ucredit", "dcredit", "ocredit", "minlen", "difok"]
    filepath = "/etc/security/pwquality.conf"
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
        conf = {k: None for k in params}
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for p in params:
                if line.startswith(p):
                    parts = line.split("=")
                    if len(parts) == 2:
                        conf[p] = parts[1].strip()
        for p in params:
            v = conf[p]
            if v is None:
                state = "BAD"
                reasons.append(f"{p} 미설정")
            elif p in ["lcredit", "ucredit", "dcredit", "ocredit"]:
                try:
                    if int(v) < -1:
                        state = "BAD"
                        reasons.append(f"{p}={v} (약한 정책)")
                except:
                    state = "BAD"
                    reasons.append(f"{p} 값 오류")
            elif p == "minlen":
                try:
                    if int(v) < 9:
                        state = "BAD"
                        reasons.append(f"minlen={v} (9 미만)")
                except:
                    state = "BAD"
                    reasons.append("minlen 값 오류")
            elif p == "difok":
                if v.strip().upper() != "N":
                    state = "BAD"
                    reasons.append(f"difok={v} (비권장)")
    except FileNotFoundError:
        state = "N/A"
        reasons.append("pwquality.conf 파일 없음")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준 충족됨"
    print_table_row(item, state, detail)

def check_common_auth():
    item = "[U-03] 계정 잠금 임계값 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/pam.d/common-auth"
    found = False
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if "pam_tally2.so" in line or "pam_faillock.so" in line:
                    found = True
                    parts = line.split()
                    for part in parts:
                        if part.startswith("deny="):
                            try:
                                deny_val = int(part.split("=")[1])
                                if deny_val > 10:
                                    state = "BAD"
                                    reasons.append(f"deny={deny_val} (10회 초과)")
                                break
                            except:
                                state = "BAD"
                                reasons.append("deny 값 오류")
                    else:
                        state = "BAD"
                        reasons.append("deny 설정 없음")
                    break
        if not found:
            state = "N/A"
            reasons.append("pam_tally2/faillock 관련 설정 없음")
    except FileNotFoundError:
        state = "N/A"
        reasons.append("common-auth 파일 없음")
    detail = "; ".join(reasons) if state != "GOOD" else "계정 잠금 임계값이 적절히 설정됨"
    print_table_row(item, state, detail)

def protect_hash_pwd_file():
    item = "[U-04] 패스워드 파일 보호"
    state = "GOOD"
    reasons = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split(":")
                if len(parts) > 1 and parts[1] != "x":
                    state = "BAD"
                    reasons.append(f"{parts[0]} 계정 패스워드 필드에 암호 저장")
    except Exception as e:
        state = "N/A"
        reasons.append(f"/etc/passwd 읽기 오류: {e}")
    try:
        with open("/etc/shadow", "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split(":")
                if len(parts) > 1:
                    password_hash = parts[1]
                    if password_hash not in ["*", "!", "!!"] and not password_hash.startswith("$"):
                        state = "BAD"
                        reasons.append(f"{parts[0]} 계정 해시 이상")
    except Exception as e:
        state = "N/A"
        reasons.append(f"/etc/shadow 읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "보안 조치 완료: 패스워드가 shadow 파일에 안전하게 저장됨, 모든 계정 해시가 적절한 형식으로 저장됨"
    print_table_row(item, state, detail)

def only_root_uid():
    item = "[U-44] root 이외의 UID가 '0' 금지"
    state = "GOOD"
    reasons = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split(":")
                if len(parts) > 2 and parts[2] == "0" and parts[0] != "root":
                    state = "BAD"
                    reasons.append(f"{parts[0]} 계정이 UID 0")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "root 외 UID 0 계정이 없음"
    print_table_row(item, state, detail)

def check_su_restriction():
    item = "[U-45] root 계정 su 제한"
    state = "GOOD"
    reasons = []
    
    # 1. pam_wheel.so 설정 검사
    pam_file = "/etc/pam.d/su"
    try:
        with open(pam_file, 'r') as f:
            pam_found = False
            for line in f:
                line = line.strip()
                if "pam_wheel.so" in line and not line.startswith("#"):
                    pam_found = True
                    if "use_uid" not in line:
                        reasons.append(f"{pam_file}: use_uid 옵션 누락")
                    break
            
            if not pam_found:
                reasons.append(f"{pam_file}: pam_wheel.so 미설정")

    except Exception as e:
        state = "ERROR"
        reasons.append(f"{pam_file} 읽기 실패: {str(e)}")
    
    # 2. sudo/wheel 그룹 검사
    group_file = "/etc/group"
    try:
        sudo_group = None
        wheel_group = None
        
        with open(group_file, 'r') as f:
            for line in f:
                if line.startswith('sudo:'):
                    sudo_group = line.strip()
                elif line.startswith('wheel:'):
                    wheel_group = line.strip()
        
        # 그룹 존재 여부 확인
        if not sudo_group and not wheel_group:
            reasons.append("sudo/wheel 그룹 미존재")
        else:
            # 사용자 존재 여부 확인
            for group in [sudo_group, wheel_group]:
                if group:
                    users = group.split(':')[-1]
                    if not users:
                        reasons.append(f"{group.split(':')[0]} 그룹에 사용자 없음")

    except Exception as e:
        state = "ERROR"
        reasons.append(f"{group_file} 읽기 실패: {str(e)}")
    
    # 최종 결과 판정
    if reasons:
        state = "BAD" if state != "ERROR" else state
        detail = "; ".join(reasons)
    else:
        detail = "보안 조치 완료: pam_wheel.so 모듈 적절히 설정됨, sudo/wheel 그룹으로 권한 관리"  # GOOD 상태 시 상세 설명 생략
    
    print_table_row(item, state, detail)

def check_pwd_length():
    item = "[U-46] 패스워드 최소 길이 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/security/pwquality.conf"
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                if "minlen" in line:
                    parts = line.split("=")
                    if len(parts) == 2 and parts[0].strip() == "minlen":
                        try:
                            minlen_value = int(parts[1].strip())
                            if minlen_value < 8:
                                state = "BAD"
                                reasons.append(f"minlen={minlen_value} (8 미만)")
                        except:
                            state = "BAD"
                            reasons.append("minlen 값 오류")
                        break
        if state == "GOOD" and not reasons:
            pass
        elif not reasons:
            state = "BAD"
            reasons.append("minlen 설정 없음")
    except FileNotFoundError:
        state = "N/A"
        reasons.append("pwquality.conf 파일 없음")
    detail = "; ".join(reasons) if state != "GOOD" else "패스워드 최소 길이가 적절히 설정됨"
    print_table_row(item, state, detail)

def check_pwd_maxdays():
    item = "[U-47] 패스워드 최대 사용기간 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/login.defs"
    found = False
    try:
        with open(filepath, "r") as f:
            for line in f:
                l = line.strip()
                if l.startswith("#") or not l:
                    continue
                if "PASS_MAX_DAYS" in l:
                    found = True
                    if "=" in l:
                        parts = l.split("=")
                    else:
                        parts = l.split()
                    if len(parts) >= 2 and parts[0].strip() == "PASS_MAX_DAYS":
                        try:
                            max_value = int(parts[1].strip())
                            if max_value < 90:
                                state = "BAD"
                                reasons.append(f"PASS_MAX_DAYS={max_value} (90 미만)")
                        except:
                            state = "BAD"
                            reasons.append("PASS_MAX_DAYS 값 오류")
                        break
        if not found:
            state = "BAD"
            reasons.append("PASS_MAX_DAYS 설정 없음")
    except FileNotFoundError:
        state = "N/A"
        reasons.append("login.defs 파일 없음")
    detail = "; ".join(reasons) if state != "GOOD" else "패스워드 최대 사용기간이 적절히 설정됨"
    print_table_row(item, state, detail)

def check_pwd_mindays():
    item = "[U-48] 패스워드 최소 사용기간 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/login.defs"
    found = False
    try:
        with open(filepath, "r") as f:
            for line in f:
                l = line.strip()
                if l.startswith("#") or not l:
                    continue
                if "PASS_MIN_DAYS" in l:
                    found = True
                    if "=" in l:
                        parts = l.split("=")
                    else:
                        parts = l.split()
                    if len(parts) >= 2 and parts[0].strip() == "PASS_MIN_DAYS":
                        try:
                            min_value = int(parts[1].strip())
                            if min_value > 1:
                                state = "BAD"
                                reasons.append(f"PASS_MIN_DAYS={min_value} (1 초과)")
                        except:
                            state = "BAD"
                            reasons.append("PASS_MIN_DAYS 값 오류")
                        break
        if not found:
            state = "BAD"
            reasons.append("PASS_MIN_DAYS 설정 없음")
    except FileNotFoundError:
        state = "N/A"
        reasons.append("login.defs 파일 없음")
    detail = "; ".join(reasons) if state != "GOOD" else "패스워드 최소 사용기간이 적절히 설정됨"
    print_table_row(item, state, detail)

def useless_user():
    item = "[U-49] 불필요한 계정 제거"
    state = "GOOD"
    reasons = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split(":")
                if len(parts) >= 6:
                    try:
                        uid = int(parts[2])
                    except:
                        continue
                    home_dir = parts[5]
                    if uid >= 1000 and (not home_dir or not home_dir.startswith("/home/")):
                        state = "BAD"
                        reasons.append(f"{parts[0]}: 홈디렉토리({home_dir or '(없음)'})")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else ""
    print_table_row(item, state, detail)

def check_admin_groups():
    item = "[U-50] 관리자 그룹에 최소한의 계정포함"
    state = "GOOD"
    reasons = []
    groups_to_check = ["wheel", "sudo"]
    try:
        with open("/etc/group", "r") as f:
            for line in f:
                for group in groups_to_check:
                    if line.startswith(f"{group}:"):
                        parts = line.strip().split(":")
                        if len(parts) >= 4 and parts[3]:
                            members = [m for m in parts[3].split(",") if m]
                            if members:
                                state = "BAD"
                                reasons.append(f"{group} 그룹: {', '.join(members)}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "관리자 그룹에 허용된 사용자만 포함됨"
    print_table_row(item, state, detail)

def check_useless_groups():
    item = "[U-51] 계정이 존재하지 않는 GID 금지"
    state = "GOOD"
    reasons = []
    group_file = "/etc/group"
    gshadow_file = "/etc/gshadow"
    try:
        group_members = {}
        gshadow_members = {}
        with open(group_file, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    groupname = parts[0]
                    members = parts[3].split(",") if parts[3] else []
                    group_members[groupname] = sorted([m for m in members if m])
        with open(gshadow_file, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    groupname = parts[0]
                    members = parts[3].split(",") if parts[3] else []
                    gshadow_members[groupname] = sorted([m for m in members if m])
        for group in group_members:
            if group in gshadow_members:
                if group_members[group] != gshadow_members[group]:
                    state = "BAD"
                    reasons.append(f"{group}: /etc/group({','.join(group_members[group])}) != /etc/gshadow({','.join(gshadow_members[group])})")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 그룹이 일관되게 관리됨"
    print_table_row(item, state, detail)

def no_same_uid():
    item = "[U-52] 동일한 UID 금지"
    state = "GOOD"
    reasons = []
    try:
        uid_map = {}
        with open("/etc/passwd", "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    username = parts[0]
                    uid = parts[2]
                    if uid not in uid_map:
                        uid_map[uid] = []
                    uid_map[uid].append(username)
        for uid, users in uid_map.items():
            if len(users) > 1:
                state = "BAD"
                reasons.append(f"UID {uid}: {', '.join(users)}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 계정이 고유한 UID를 가짐"
    print_table_row(item, state, detail)

def check_user_shell():
    item = "[U-53] 사용자 Shell 점검"
    state = "GOOD"
    reasons = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                username = parts[0]
                try:
                    uid = int(parts[2])
                except:
                    continue
                shell = parts[6]
                if 0 < uid < 1000 and shell not in ["/usr/sbin/nologin", "/bin/false"]:
                    state = "BAD"
                    reasons.append(f"{username}(UID:{uid}) shell:{shell}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 시스템 계정이 안전한 쉘 사용"
    print_table_row(item, state, detail)

def session_timeout():
    item = "[U-54] Session Timeout 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/profile"
    tmout_value = None
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "TMOUT" in line:
                    parts = line.split("=")
                    if len(parts) == 2:
                        right = parts[1].strip()
                        num_str = ""
                        for ch in right:
                            if ch.isdigit():
                                num_str += ch
                            else:
                                break
                        if num_str.isdigit():
                            tmout_value = int(num_str)
                            break
        if tmout_value is None:
            state = "BAD"
            reasons.append("TMOUT 설정 없음")
        elif tmout_value < 600:
            state = "BAD"
            reasons.append(f"TMOUT={tmout_value} (600 미만)")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "세션 타임아웃이 적절히 설정됨"
    print_table_row(item, state, detail)

def check_path():
    item = "[U-05] root 홈, 패스 디렉토리 권한 및 패스 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/environment"
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "PATH" in line:
                    parts = line.split("=")
                    if len(parts) != 2:
                        continue
                    path_value = parts[1].strip().strip('"')
                    if ".:" in path_value or "::" in path_value:
                        state = "BAD"
                        reasons.append("'.:' 또는 '::' 포함")
                    break
        if state == "GOOD" and not reasons:
            pass
        elif not reasons:
            state = "BAD"
            reasons.append("PATH 설정 없음")
    except Exception as e:
        state = "N/A"
        reasons.append(f"읽기 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "안전한 PATH 설정 적용됨"
    print_table_row(item, state, detail)

def check_owner_fd():
    item = "[U-06] 파일 및 디렉토리 소유자 설정"
    state = "GOOD"
    reasons = []
    bad_files = []

    try:
        nouser_result = subprocess.run(["find", "/", "-nouser"],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL,
                                       universal_newlines=True)
        nogroup_result = subprocess.run(["find", "/", "-nogroup"],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,
                                        universal_newlines=True)

        nouser_files = nouser_result.stdout.strip().splitlines()
        nogroup_files = nogroup_result.stdout.strip().splitlines()

        bad_files.extend(nouser_files)
        bad_files.extend(nogroup_files)

        if bad_files:
            state = "BAD"
            reasons.append(f"소유자/그룹 없는 파일 {len(bad_files)}개 존재")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 중 오류: {e}")

    detail = "; ".join(reasons) if state != "GOOD" else "모든 파일이 적절한 소유자/그룹을 가짐"
    print_table_row(item, state, detail)

def check_fowner_auth():
    item = "[U-07] /etc/passwd 파일 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/passwd"

    try:            
        owner = subprocess.run(["stat", "-c", "%U", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        group = subprocess.run(["stat", "-c", "%G", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        perm = subprocess.run(["stat", "-c", "%a", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()

        if owner != "root":
            state = "BAD"
            reasons.append(f"owner: {owner}")
        if group != "root":
            state = "BAD"
            reasons.append(f"group: {group}")
        if perm != "644":
            state = "BAD"
            reasons.append(f"permission: {perm}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 중 오류: {e}")

    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)

def check_shaowner_auth():
    item = "[U-08] /etc/shadow 파일 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/shadow"

    try:
        owner = subprocess.run(["stat", "-c", "%U", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        group = subprocess.run(["stat", "-c", "%G", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        perm = subprocess.run(["stat", "-c", "%a", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()

        if owner != "root":
            state = "BAD"
            reasons.append(f"owner: {owner}")
        if group != "root":
            state = "BAD"
            reasons.append(f"group: {group}")
        if perm != "400":
            state = "BAD"
            reasons.append(f"permission: {perm}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 중 오류: {e}")

    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)

def check_hostsowner_auth():
    item = "[U-09] /etc/hosts 파일 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/hosts"

    try:            
        owner = subprocess.run(["stat", "-c", "%U", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        group = subprocess.run(["stat", "-c", "%G", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        perm = subprocess.run(["stat", "-c", "%a", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()

        if owner != "root":
            state = "BAD"
            reasons.append(f"owner: {owner}")
        if group != "root":
            state = "BAD"
            reasons.append(f"group: {group}")
        if perm != "644":
            state = "BAD"
            reasons.append(f"permission: {perm}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 중 오류: {e}")

    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)

def inetd_owner_auth():
    item = "[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/inetd.conf"
    result = subprocess.run(
        ["ls", filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    if result.returncode == 0:
        try:
            owner = subprocess.run(
                ["stat", "-c", "%U", filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            ).stdout.strip()
            perm = subprocess.run(
                ["stat", "-c", "%a", filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            ).stdout.strip()

            if owner != "root":
                state = "BAD"
                reasons.append(f"owner: {owner}")
            if not (perm.startswith('6') or perm.startswith('4')):
                state = "BAD"
                reasons.append(f"permission: {perm}")
        except Exception as e:
            state = "N/A"
            reasons.append(f"점검 중 오류: {e}")
    else:
        state = "N/A"
        reasons.append(f"{filepath} 미설치")

    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)

def check_owner_perm(paths):
    item = "[U-11] /etc/syslog.conf 파일 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    for path in paths:
        result = subprocess.run(["ls", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode != 0:
            state = "BAD"
            reasons.append(f"{path} 없음")
            continue
        try:
            owner = subprocess.run(["stat", "-c", "%U", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
            perm = subprocess.run(["stat", "-c", "%a", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
            if owner != "root":
                state = "BAD"
                reasons.append(f"{path} owner: {owner}")
            if perm != "644":
                state = "BAD"
                reasons.append(f"{path} permission: {perm}")
        except Exception as e:
            state = "N/A"
            reasons.append(f"{path} 점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)

def check_servicesowner_auth():
    item = "[U-12] /etc/services 파일 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    filepath = "/etc/services"
    try:
        owner = subprocess.run(["stat", "-c", "%U", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        group = subprocess.run(["stat", "-c", "%G", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        perm = subprocess.run(["stat", "-c", "%a", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
        if owner != "root":
            state = "BAD"
            reasons.append(f"owner: {owner}")
        if group != "root":
            state = "BAD"
            reasons.append(f"group: {group}")
        if perm != "644":
            state = "BAD"
            reasons.append(f"permission: {perm}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)

def check_suid_sgid():
    item = "[U-13] SUID, SGID, 설정 파일 점검"
    state = "GOOD"
    reasons = []
    try:
        suid_result = subprocess.run(
            ["find", "/", "-perm", "/4000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        suid_files = suid_result.stdout.strip().splitlines()
        sgid_result = subprocess.run(
            ["find", "/", "-perm", "/2000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        sgid_files = sgid_result.stdout.strip().splitlines()
        def is_unusual_path(path):
            return not (
                path.startswith("/usr") or
                path.startswith("/snap") or
                path.startswith("/bin") or
                path.startswith("/sbin") or
                path.startswith("/lib")
            )
        flagged_files = [f for f in suid_files + sgid_files if is_unusual_path(f)]
        if flagged_files:
            state = "BAD"
            reasons.append(f"비정상 경로 SUID/SGID 파일 {len(flagged_files)}개")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 SUID/SGID 파일이 정상 경로에 존재"
    print_table_row(item, state, detail)

def check_startsetting_auth():
    item = "[U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한설정"
    state = "GOOD"
    reasons = []
    files_to_check = [".bashrc", ".bash_logout", ".profile"]
    try:
        result = subprocess.run(["ls", "/home"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        users = result.stdout.strip().splitlines()
        for user in users:
            home_dir = f"/home/{user}"
            for filename in files_to_check:
                filepath = f"{home_dir}/{filename}"
                if subprocess.run(["test", "-e", filepath]).returncode != 0:
                    continue
                owner = subprocess.run(["stat", "-c", "%U", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
                perm = subprocess.run(["stat", "-c", "%a", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
                if owner not in [user, "root"]:
                    state = "BAD"
                    reasons.append(f"{filepath} owner: {owner}")
                if not perm.startswith("6") or perm[1] != "4" or perm[2] != "4":
                    state = "BAD"
                    reasons.append(f"{filepath} perm: {perm}")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 시작 파일이 적절한 소유자와 권한을 가짐"
    print_table_row(item, state, detail)

def check_world_writable():
    item = "[U-15] world writable 파일 점검"
    state = "GOOD"
    reasons = []
    try:
        result = subprocess.run(
            ["find", "/", "-type", "f", "-perm", "-0002", "!", "-path", "/proc/*", "!", "-path", "/sys/*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        files = result.stdout.strip().splitlines()
        def is_unusual_path(path):
            return not (
                path.startswith("/proc") or
                path.startswith("/sys") or
                path.startswith("/usr") or
                path.startswith("/snap") or
                path.startswith("/bin") or
                path.startswith("/lib") or
                path.startswith("/sbin")
            )
        flagged_files = [f for f in files if is_unusual_path(f)]
        if flagged_files:
            state = "BAD"
            reasons.append(f"world-writable 파일 {len(flagged_files)}개")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "비정상 World Writable 파일 없음"
    print_table_row(item, state, detail)

def check_device_dev():
    item = "[U-16] /dev에 존재하지 않는 device 파일 점검"
    state = "GOOD"
    reasons = []
    try:
        result = subprocess.run(
            ["find", "/dev", "-type", "f"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        files = result.stdout.strip().splitlines()
        bad_files = []
        for file in files:
            ls_result = subprocess.run(
                ["ls", "-l", file],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )
            output = ls_result.stdout.strip()
            if output and not (output.startswith('c') or output.startswith('b')):
                bad_files.append(file)
        if bad_files:
            state = "BAD"
            reasons.append(f"/dev 내 일반파일 {len(bad_files)}개")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "모든 파일이 device 파일 또는 심볼릭 링크입니다."
    print_table_row(item, state, detail)

def check_hosts_notuse():
    item = "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지"
    state = "GOOD"
    reasons = []
    files_to_check = ["/etc/hosts.equiv"]
    try:
        result = subprocess.run(["ls", "/home"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        users = result.stdout.strip().splitlines()
        for user in users:
            files_to_check.append(f"/home/{user}/.rhosts")
        found_any = False
        for filepath in files_to_check:
            if subprocess.run(["test", "-e", filepath]).returncode != 0:
                continue
            found_any = True
            owner = subprocess.run(["stat", "-c", "%U", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
            perm = subprocess.run(["stat", "-c", "%a", filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
            if owner != "root":
                state = "BAD"
                reasons.append(f"{filepath} owner: {owner}")
            if not perm.startswith("6") or perm[1] != "4" or perm[2] != "4":
                state = "BAD"
                reasons.append(f"{filepath} perm: {perm}")
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "+" in line.strip():
                        state = "BAD"
                        reasons.append(f"{filepath}에 '+' 포함")
                        break
        if not found_any:
            state = "N/A"
            reasons.append("점검 대상 파일 없음")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons) if state != "GOOD" else "관련 파일이 존재하지 않음"
    print_table_row(item, state, detail)

# ------------------------- TCP Wrapper Check -------------------------
def parse_tcpwrapper_file(filepath):
    """Return list of non-comment, non-empty lines."""
    rules = []
    if os.path.isfile(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    rules.append(line)
    return rules

def has_strict_allow_rule(rules):
    for rule in rules:
        parts = rule.split(':', 1)
        if len(parts) != 2:
            continue
        service, client = parts
        client = client.strip()
        if client and client not in ('ALL', 'localhost', '127.0.0.1'):
            if re.search(r'(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.|[a-zA-Z0-9_\-\.]+)', client):
                return True
    return False

def has_deny_all_rule(rules):
    for rule in rules:
        if rule.replace(' ', '') == 'ALL:ALL':
            return True
    return False

def check_tcp_wrappers():
    allow_path = "/etc/hosts.allow"
    deny_path = "/etc/hosts.deny"
    allow_rules = parse_tcpwrapper_file(allow_path)
    deny_rules = parse_tcpwrapper_file(deny_path)
    return has_strict_allow_rule(allow_rules) and has_deny_all_rule(deny_rules)

# ------------------------- iptables Check -------------------------
def check_iptables_rules():
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-L', '--line-numbers'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if result.returncode != 0:
            return False
        
        output = result.stdout
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) < 7:
                continue
            source = parts[4]
            options = parts[6:]
            # IP 제한 확인 (0.0.0.0/0이 아닌 경우)
            if source not in ('0.0.0.0/0', '::/0'):
                return True
            # 포트 제한 확인 (dpt:포트번호 포함)
            if any(re.search(r'dpt:\d+', opt) for opt in options):
                return True
        return False
    except:
        return False

def run_ip_port_restriction_check():
    item = "[U-18] 접속 IP 및 포트 제한"
    state = "GOOD"
    reasons = []

    # TCP Wrapper 점검
    tcp_secure = check_tcp_wrappers()
    if not tcp_secure:
        state = "BAD"
        reasons.append("TCP Wrapper 설정 미흡")

    # iptables 점검
    iptables_secure = check_iptables_rules()
    if not iptables_secure:
        state = "BAD"
        reasons.append("iptables 설정 미흡")

    # 상세 사유 정리
    detail = "; ".join(reasons) if reasons else "모든 접근 제어 설정이 적절히 구성되어 있음"

    print_table_row(item, state, detail)

def check_finger_service():
    item = "[U-19] Finger 서비스 비활성화"
    state = "GOOD"
    reasons = []
    inetd_conf_path = "/etc/inetd.conf"
    inetd_d_path = "/etc/inetd.d"

    # 1. /etc/inetd.conf 검사
    if os.path.isfile(inetd_conf_path):
        try:
            with open(inetd_conf_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_clean = line.strip()
                    if line_clean and not line_clean.startswith('#') and 'finger' in line_clean.lower():
                        reasons.append("inetd.conf에 finger 서비스 활성화됨")
                        state = "BAD"
        except Exception as e:
            reasons.append(f"inetd.conf 읽기 오류: {str(e)}")
            state = "ERROR"

    # 2. /etc/inetd.d/* 검사
    if os.path.isdir(inetd_d_path):
        try:
            for filename in os.listdir(inetd_d_path):
                file_path = os.path.join(inetd_d_path, filename)
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line_clean = line.strip()
                                if line_clean and not line_clean.startswith('#') and 'finger' in line_clean.lower():
                                    reasons.append(f"{filename} 파일에 finger 서비스 활성화됨")
                                    state = "BAD"
                    except:
                        reasons.append(f"{filename} 파일 읽기 실패")
                        state = "ERROR"
        except Exception as e:
            reasons.append(f"inetd.d 디렉토리 접근 오류: {str(e)}")
            state = "ERROR"

    # 결과 출력
    detail = "; ".join(reasons) if reasons else "모든 설정이 기준에 부합함"
    print_table_row(item, state, detail)
    return state == "GOOD"


def check_ftp_anonymous():
    item = "[U-20] Anonymous FTP 비활성화"
    state = "GOOD"
    reasons = []

    # 1. FTP 관련 패키지 설치 여부
    ftp_packages = subprocess.run(
        ["dpkg", "-l"], stdout=subprocess.PIPE, universal_newlines=True
    ).stdout
    installed = any(pkg in ftp_packages for pkg in ["ftp", "vsftpd", "proftpd"])
    if installed:
        reasons.append("FTP 관련 패키지 설치됨")

    # 2. FTP 서비스 실행 여부
    vsftpd_active = subprocess.run(
        ["systemctl", "is-active", "vsftpd"], stdout=subprocess.PIPE, universal_newlines=True
    ).stdout.strip() == "active"
    proftpd_active = subprocess.run(
        ["systemctl", "is-active", "proftpd"], stdout=subprocess.PIPE, universal_newlines=True
    ).stdout.strip() == "active"
    if vsftpd_active or proftpd_active:
        reasons.append("FTP 서비스 실행 중")

    # 3. 설정 파일에서 anonymous 허용 여부
    vsftpd_secure = False
    if os.path.isfile("/etc/vsftpd.conf"):
        with open("/etc/vsftpd.conf") as f:
            vsftpd_secure = "anonymous_enable=NO" in f.read()
        if not vsftpd_secure:
            reasons.append("vsftpd.conf에서 anonymous_enable=NO 아님")

    proftpd_secure = False
    if os.path.isfile("/etc/proftpd/proftpd.conf"):
        with open("/etc/proftpd/proftpd.conf") as f:
            proftpd_secure = "<Anonymous ~ftp>" not in f.read()
        if not proftpd_secure:
            reasons.append("proftpd.conf에 <Anonymous ~ftp> 블록 존재")

    # 4. ftpusers 파일에 'ftp' 또는 'anonymous' 계정 차단 여부
    ftpusers_entries = []
    ftpusers_path = "/etc/ftpd/ftpusers"
    if os.path.isfile(ftpusers_path):
        with open(ftpusers_path) as f:
            ftpusers_entries = [line.strip() for line in f if "ftp" in line or "anonymous" in line]
        if not ftpusers_entries:
            reasons.append("ftpusers 파일에 ftp/anonymous 계정 미차단")

    # 최종 판정
    if not installed and not vsftpd_active and not proftpd_active:
        state = "GOOD"
        detail = "FTP 서비스 미설치"
    elif (vsftpd_secure or proftpd_secure) and ftpusers_entries:
        state = "GOOD"
        detail = "Anonymous FTP 접근 비활성화"
    else:
        state = "BAD"
        detail = "; ".join(reasons) if reasons else "Anonymous FTP 접근 허용됨"

    print_table_row(item, state, detail)
    return state == "GOOD"


def run_r_commands_check():
    item = "[U-21] r 계열 서비스 비활성화"
    state = "GOOD"
    reasons = []
    
    inetd_conf = "/etc/inetd.conf"
    target_keywords = ["shell", "login", "exec"]
    vulnerable_lines = []

    # 1. inetd.conf 파일 존재 여부 확인
    if not os.path.exists(inetd_conf):
        print_table_row(item, "N/A", "inetd.conf 파일 없음")
        return

    # 2. 활성화된 서비스 검사
    with open(inetd_conf, "r") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for keyword in target_keywords:
                if keyword in stripped:
                    vulnerable_lines.append(stripped)
                    reasons.append(f"{keyword} 서비스 활성화됨")

    # 3. 결과 판정
    if vulnerable_lines:
        state = "BAD"
        detail = "; ".join(reasons)
        print_table_row(item, state, detail)
    else:
        detail = "활성화된 r-command 서비스 없음"
        print_table_row(item, state, detail)


def check_permission(filepath, max_mode):
    """파일 권한 검사 (상세 사유 반환)"""
    try:
        st = os.stat(filepath)
        mode = stat.S_IMODE(st.st_mode)
        if mode > max_mode:
            return False, f"{filepath} 권한 부적절 ({oct(mode)[-3:]})"
        return True, ""
    except FileNotFoundError:
        return True, ""  # 파일 없으면 문제 없음
    except Exception as e:
        return False, f"{filepath} 접근 오류: {str(e)}"

def check_crontab_binary():
    """crontab 바이너리 검사"""
    path = "/usr/bin/crontab"
    state = "GOOD"
    reasons = []

    if not os.path.exists(path):
        return state, ["crontab 바이너리 없음"]
    
    try:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        
        # others 실행 권한 확인
        if mode & 0o001:
            state = "BAD"
            reasons.append(f"others 실행 권한 있음 ({oct(mode)[-3:]})")
        
        # 권한 값 검사 (750 이하 허용)
        if mode > 0o750:
            state = "BAD"
            reasons.append(f"과도한 권한 ({oct(mode)[-3:]})")
    
    except Exception as e:
        state = "ERROR"
        reasons.append(f"파일 검사 오류: {str(e)}")
    
    return state, reasons

def check_cron_dirs():
    """cron 디렉토리 파일 검사"""
    paths = ["/etc/cron.hourly", "/etc/cron.daily", 
            "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d"]
    state = "GOOD"
    reasons = []
    
    for dir_path in paths:
        if not os.path.exists(dir_path):
            continue
            
        for f in os.listdir(dir_path):
            full_path = os.path.join(dir_path, f)
            if os.path.isfile(full_path):
                is_secure, reason = check_permission(full_path, 0o640)
                if not is_secure:
                    state = "BAD"
                    reasons.append(reason)
                    
    return state, reasons

def run_cron_permission_check():
    item = "[U-22] crond 파일 소유자 및 권한 설정"
    state = "GOOD"
    all_reasons = []
    
    # 1. crontab 바이너리 검사
    crontab_state, crontab_reasons = check_crontab_binary()
    all_reasons.extend(crontab_reasons)
    
    # 2. cron 디렉토리 파일 검사
    cron_dirs_state, cron_dirs_reasons = check_cron_dirs()
    all_reasons.extend(cron_dirs_reasons)
    
    # 최종 상태 결정
    if crontab_state == "BAD" or cron_dirs_state == "BAD":
        state = "BAD"
    elif crontab_state == "ERROR" or cron_dirs_state == "ERROR":
        state = "ERROR"
    
    # 결과 출력
    detail = "; ".join(all_reasons) if all_reasons else "모든 권한 적절"
    print_table_row(item, state, detail)


def check_dos_services():
    item = "[U-23] DoS 공격에 취약한 서비스 비활성화"
    state = "GOOD"
    reasons = []
    
    conf_path = "/etc/inetd.conf"
    keywords = ["discard", "daytime", "snmp", "smtp", "chargen", "ntp", "echo"]

    # 1. 설정 파일 존재 여부 확인
    if not os.path.exists(conf_path):
        print_table_row(item, "N/A", "inetd.conf 파일 없음")
        return

    # 2. 취약 서비스 검사
    with open(conf_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line_clean = line.strip()
            if line_clean.startswith("#") or not line_clean:
                continue
            
            for keyword in keywords:
                if keyword in line_clean:
                    reasons.append(f"{line_num}번 줄: {keyword} 서비스 활성화")

    # 3. 결과 판정
    if reasons:
        state = "BAD"
        detail = "; ".join(reasons)
    else:
        detail = "취약 서비스 미활성화 상태"
    
    print_table_row(item, state, detail)


def check_nfs_services():
    item = "[U-24] NFS 서비스 비활성화"
    state = "GOOD"
    active_services = []
    
    services = ["nfs-server", "nfs-lock", "nfs-idmapd", "rpcbind"]

    # 서비스 활성화 상태 확인
    for svc in services:
        try:
            result = subprocess.check_output(
                f"systemctl is-active {svc}",
                shell=True,
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )
            if result.strip() == "active":
                active_services.append(svc)
        except subprocess.CalledProcessError:
            continue

    # 결과 판정
    if active_services:
        state = "BAD"
        detail = "활성화된 서비스: " + ", ".join(active_services)
    else:
        detail = "모든 NFS 서비스가 비활성화됨"
    
    print_table_row(item, state, detail)


def check_nfs_access():
    item = "[U-25] NFS 접근 통제"
    state = "GOOD"
    reasons = []
    
    exports_file = "/etc/exports"
    
    # 1. NFS 설정 파일 존재 여부 확인
    if not os.path.exists(exports_file):
        print_table_row(item, "N/A", "NFS 설정 파일 없음")
        return

    # 2. 활성 공유 설정 확인
    with open(exports_file, "r") as file:
        lines = [line.strip() for line in file if line.strip() and not line.startswith("#")]

    if not lines:
        print_table_row(item, "GOOD", "")
        return

    # 3. 보안 설정 검사
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
            
        # 접근 제어 옵션 분석
        for option in parts[1:]:
            if '*' in option:
                reasons.append(f"와일드카드 사용: {line}")
            elif 'no_root_squash' in option:
                reasons.append(f"위험 옵션 사용: {line}")
            elif not any(char in option for char in ('.', ':', 'network/')):
                reasons.append(f"IP 제한 미적용: {line}")

    # 4. 결과 판정
    if reasons:
        state = "BAD"
        detail = "; ".join(reasons)
    else:
        detail = "모든 공유가 IP 제한 및 안전 옵션 적용됨"
    
    print_table_row(item, state, detail)


def run_command(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return result.stdout
    except Exception as e:
        return str(e)

def check_automountd():
    item = "[U-26] automountd 제거"
    state = "GOOD"
    reasons = []

    # 1. 서비스 상태 확인
    systemctl_output = run_command("systemctl status autofs automountd 2>&1")
    if "Active: active (running)" in systemctl_output:
        reasons.append("automountd/autofs 서비스 실행 중")

    # 2. 프로세스 확인
    ps_output = run_command("ps -ef | grep -E 'autofs|automountd' | grep -v grep")
    if ps_output.strip():
        reasons.append("automountd/autofs 프로세스 실행 중")

    # 3. 결과 판정
    if reasons:
        state = "BAD"
        detail = "; ".join(reasons)
    else:
        detail = "모든 automountd 관련 설정이 비활성화됨"
    
    print_table_row(item, state, detail)



def run_command(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def check_rpc_services():
    item = "[U-27] RPC 서비스 확인"
    state = "GOOD"
    reasons = []

    # 1. systemctl로 RPC 관련 서비스 확인
    rpc_services = run_command("systemctl list-units --type=service --no-legend | grep -E 'rpcbind|rpc-statd'")
    if rpc_services:
        reasons.append("활성화된 RPC 서비스: \n" + rpc_services)

    # 2. rpcinfo로 등록 서비스 확인
    rpcinfo_output = run_command("rpcinfo -p 2>/dev/null")
    if rpcinfo_output and "program vers proto" not in rpcinfo_output:
        reasons.append("rpcinfo 등록 서비스: \n" + rpcinfo_output)

    # 3. 결과 판정
    if reasons:
        state = "BAD"
        detail = "\n".join(reasons)
    else:
        detail = "모든 RPC 서비스가 비활성화됨"
    
    print_table_row(item, state, detail)


def run_command(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True
        )
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def check_nis_services():
    item = "[U-28] NIS, NIS+ 점검"
    state = "GOOD"
    detail = "모든 NIS/NIS+ 서비스가 비활성화됨"
    
    # NIS 관련 프로세스 확인
    processes = run_command("ps -ef | grep -E 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v grep")
    
    if processes:
        state = "BAD"
        detail = "실행 중인 NIS 서비스:\n" + processes.replace('\n', '; ')
    
    print_table_row(item, state, detail)


def is_service_active(service):
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result.returncode == 0

def check_services():
    item = "[U-29] tftp, talk 서비스 비활성화"
    state = "GOOD"
    active_services = []
    
    target_services = ["tftp", "talk", "ntalk"]

    for service in target_services:
        if is_service_active(service):
            active_services.append(service)

    if active_services:
        state = "BAD"
        detail = "활성화된 서비스: " + ", ".join(active_services)
    else:
        detail = "모든 tftp/talk 서비스가 비활성화됨"
    
    print_table_row(item, state, detail)


def check_sendmail_version():
    item = "[U-30] Sendmail 버전 점검"
    state = "GOOD"
    details = []
    latest_version = "8.17.2"  # 최신 안전 버전 (주기적 업데이트 필요)

    # 1. 서비스 활성화 상태 확인 (멀티 init 시스템 지원)
    def is_service_active():
        try:
            # systemd 체크
            result = subprocess.run(
                ["systemctl", "is-active", "sendmail"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            # SysV init 체크
            result = subprocess.run(
                ["service", "sendmail", "status"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        return False

    # 2. 패키지 관리자 감지
    def get_package_manager():
        if os.path.exists('/etc/debian_version'):
            return 'dpkg'
        elif os.path.exists('/etc/redhat-release'):
            return 'rpm'
        return None

    # 3. 버전 정보 가져오기
    def get_sendmail_version(pkg_manager):
        try:
            if pkg_manager == 'dpkg':
                result = subprocess.run(
                    ["dpkg", "-s", "sendmail"],
                    stdout=subprocess.PIPE,
                    text=True
                )
                match = re.search(r'Version: (\d+\.\d+\.\d+)', result.stdout)
            elif pkg_manager == 'rpm':
                result = subprocess.run(
                    ["rpm", "-q", "sendmail"],
                    stdout=subprocess.PIPE,
                    text=True
                )
                match = re.search(r'sendmail-(\d+\.\d+\.\d+)', result.stdout)
            return match.group(1) if match else None
        except:
            return None

    # 4. 네트워크 리스닝 확인
    def check_network_exposure():
        try:
            result = subprocess.run(
                ["ss", "-ltnp"],
                stdout=subprocess.PIPE,
                text=True
            )
            listening = []
            for line in result.stdout.splitlines():
                if ':25' in line and 'sendmail' in line:
                    listening.append(line.strip())
            return listening
        except:
            return []

    # 5. 보안 설정 확인
    def check_security_config():
        config_files = [
            '/etc/mail/sendmail.cf',
            '/etc/mail/submit.cf'
        ]
        security_flags = {
            'PortOptions=Addr=127.0.0.1': '로컬 호스트만 리스닝',
            'confPRIVACY_FLAGS=authwarnings': '인증 경고 활성화',
            'Dj$w.FULLY.QUALIFIED.DOMAIN': '정규화된 도메인 설정'
        }
        issues = []
        for conf_file in config_files:
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    content = f.read()
                    for flag, desc in security_flags.items():
                        if flag not in content:
                            issues.append(f"{conf_file} - {desc} 누락")
        return issues

    # 실행 흐름
    if not is_service_active():
        details.append("Sendmail 서비스 비활성화 상태")
    else:
        details.append("Sendmail 서비스 활성화 상태")
        state = "BAD"

        pkg_manager = get_package_manager()
        if pkg_manager:
            current_version = get_sendmail_version(pkg_manager)
            if current_version:
                details.append(f"설치 버전: {current_version}")
                # 버전 비교
                if current_version < latest_version:
                    details.append(f"취약 버전: {latest_version} 미만")
                else:
                    details.append("최신 버전 사용 중")
            else:
                details.append("Sendmail 패키지 미설치")
                state = "WARN"

        # 네트워크 노출 확인
        listening = check_network_exposure()
        if listening:
            details.append("네트워크 리스닝 중:\n" + "\n".join(listening))
            state = "BAD"

        # 보안 설정 확인
        config_issues = check_security_config()
        if config_issues:
            details.append("보안 설정 문제:\n" + "\n".join(config_issues))
            state = "BAD"

    # 결과 출력
    if state == "GOOD":
        details.insert(0, "모든 검사 항목 통과")
    elif state == "WARN":
        details.insert(0, "부분 검사 실패")

    print_table_row(item, state, "\n- ".join(details))
    return state == "GOOD"

    print_table_row(item, state, detail)

def check_mail_relay_restriction():
    item = "[U-31] 스팸 메일 릴레이 제한"
    state = "GOOD"
    detail = ""
    
    sendmail_cf = "/etc/mail/sendmail.cf"

    # 1. 설정 파일 존재 여부 확인
    if not os.path.isfile(sendmail_cf):
        print_table_row(item, "N/A", "Sendmail 설정 파일 없음 (서비스 미사용)")
        return

    # 2. 릴레이 제한 설정 검사
    try:
        with open(sendmail_cf, 'r', encoding='utf-8', errors='ignore') as f:
            relay_denied = False
            for line in f:
                line_clean = line.strip()
                if line_clean.startswith('#'):
                    continue
                if re.search(r'R\$\*', line_clean) and 'relaying denied' in line_clean.lower():
                    relay_rule_found = line_clean
                    break
            
            if relay_rule_found:
                detail = "릴레이 제한 설정 확인: {relay_rule_found}"
            else:
                state = "BAD"
                detail = "릴레이 제한 미설정 (스팸 메일 릴레이 가능)"
                
    except Exception as e:
        state = "ERROR"
        detail = f"파일 읽기 오류: {str(e)}"
    
    print_table_row(item, state, detail)


def check_sendmail_restrictqrun():
    item = "[U-32] 일반사용자의 Sendmail 실행 방지"
    state = "GOOD"
    detail = ""
    
    sendmail_cf = "/etc/mail/sendmail.cf"

    # 1. 설정 파일 존재 여부 확인
    if not os.path.isfile(sendmail_cf):
        print_table_row(item, "N/A", "Sendmail 설정 파일 없음 (서비스 미사용)")
        return

    # 2. restrictqrun 옵션 검사
    try:
        with open(sendmail_cf, 'r', encoding='utf-8', errors='ignore') as f:
            privacy_line = None
            for line in f:
                original_line = line.strip()  # 원본 라인 유지
                line_clean = original_line.lower()  # 검색용 소문자 변환
                
                # 주석 처리된 라인 스킵
                if line_clean.startswith('#'):
                    continue
                
                # PrivacyOptions 설정 라인에서 restrictqrun 검색
                if 'privacyoptions' in line_clean and 'restrictqrun' in line_clean:
                    privacy_line = original_line  # 원본 설정 라인 저장
                    break

            if privacy_line:
                detail = f"restrictqrun 옵션 설정 확인: {privacy_line}"
            else:
                state = "BAD"
                detail = "restrictqrun 옵션 미설정 (일반 사용자 Sendmail 실행 가능)"
                
    except Exception as e:
        state = "ERROR"
        detail = f"파일 읽기 오류: {str(e)}"
    
    print_table_row(item, state, detail)



def check_dns_version_and_status():
    item = "[U-33] DNS 보안 버전 패치"
    state = "GOOD"
    detail = ""

    # 1. DNS 서비스 설치 여부 확인
    if not shutil.which("named"):
        print_table_row(item, "N/A", "DNS 서비스(named) 미설치")
        return

    # 2. 버전 정보 추출
    version_result = subprocess.run(
        ["named", "-v"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    version = version_result.stdout.strip() or "버전 확인 불가"

    # 3. 서비스 실행 상태 확인
    service_status = subprocess.run(
        ["systemctl", "is-active", "bind9.service"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if service_status.returncode == 0:  # 서비스 활성화 상태
        state = "BAD"
        detail = f"DNS 서비스 실행 중 ({version}), 보안 패치 수동 확인 필요"
    else:
        detail = f"DNS 서비스 비활성화 ({version})"

    print_table_row(item, state, detail)

def check_zone_transfer():
    item = "[U-34] DNS Zone Transfer 설정"
    state = "GOOD"
    detail = ""
    
    named_conf = "/etc/bind/named.conf"

    # 1. 설정 파일 존재 여부 확인
    if not os.path.isfile(named_conf):
        print_table_row(item, "N/A", "DNS 설정 파일 없음 (서비스 미사용)")
        return

    # 2. Zone Transfer 설정 분석
    try:
        with open(named_conf, 'r', encoding='utf-8', errors='ignore') as f:
            transfers = []
            open_transfer = []
            
            for line in f:
                line_clean = line.strip()
                if line_clean.startswith(('#', '//')):
                    continue
                
                # allow-transfer 검출
                if 'allow-transfer' in line_clean.lower():
                    transfers.append(line_clean)
                    # 위험 설정 검사
                    if re.search(r'\b(any|0\.0\.0\.0|::/0)\b', line_clean, re.IGNORECASE):
                        open_transfer.append(line_clean)

            # 3. 결과 판정
            if not transfers:
                detail = ""
            elif open_transfer:
                state = "BAD"
                detail = "위험 설정 발견: " + "; ".join(open_transfer)
            else:
                detail = "안전한 IP 제한 적용: " + "; ".join(transfers)
                
    except Exception as e:
        state = "ERROR"
        detail = f"파일 읽기 오류: {str(e)}"
    
    print_table_row(item, state, detail)


def check_directory_listing():
    item = "[U-35] 웹서비스 디렉토리 리스팅 제거"
    state = "GOOD"
    detail = []
    config_files = [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-available/000-default.conf",
        "/etc/apache2/sites-available/default-ssl.conf"
    ]
    pattern = re.compile(r'^Options\s+.*Indexes', re.IGNORECASE)
    file_found = False

    for conf_file in config_files:
        if not os.path.isfile(conf_file):
            continue
        file_found = True
        
        try:
            with open(conf_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if line_clean.startswith('#'):
                        continue
                    if pattern.search(line_clean):
                        detail.append(f"{conf_file} {line_num}번 줄: {line_clean}")
                        state = "BAD"
        except Exception as e:
            detail.append(f"{conf_file} 읽기 오류: {str(e)}")
            state = "ERROR"

    if not file_found:
        state = "N/A"
        detail.append("Apache 설정 파일을 찾을 수 없음")
    elif state == "GOOD":
        detail.append("모든 설정에서 Indexes 옵션 비활성화됨")

    print_table_row(item, state, "; ".join(detail))


def check_apache_user_group():
    item = "[U-36] 웹서비스 웹 프로세스 권한 제한"
    state = "GOOD"
    detail = ""
    config_file = "/etc/apache2/apache2.conf"

    # 1. 설정 파일 존재 여부 확인
    if not os.path.isfile(config_file):
        print_table_row(item, "N/A", "Apache 설정 파일 없음")
        return

    user = group = None
    
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line_clean = line.strip()
                if line_clean.startswith('#'):
                    continue

                # User/Group 지시어 추출
                if re.match(r'^User\s+', line_clean, re.IGNORECASE):
                    user = line_clean.split()[1].split('#')[0].strip()
                elif re.match(r'^Group\s+', line_clean, re.IGNORECASE):
                    group = line_clean.split()[1].split('#')[0].strip()

                if user and group:
                    break

        # 2. 결과 판정
        if not user or not group:
            state = "BAD"
            detail = "User/Group 지시어 누락"
        elif user.lower() == "root" or group.lower() == "root":
            state = "BAD"
            detail = f"권한 문제 (User={user}, Group={group})"
        else:
            detail = f"적절한 권한 설정 확인 (User={user}, Group={group})"

    except Exception as e:
        state = "ERROR"
        detail = f"파일 읽기 오류: {str(e)}"
    
    print_table_row(item, state, detail)


def check_allowoverride():
    item = "[U-37] 웹서비스 상위 디렉토리 접근 금지"
    state = "BAD"
    detail = []
    config_files = [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-available/000-default.conf",
        "/etc/apache2/sites-available/default-ssl.conf"
    ]
    allowed_values = {"none", "limit", "fileinfo"}
    pattern = re.compile(r'^AllowOverride\s+(\S+)', re.IGNORECASE)
    file_found = False

    for conf_file in config_files:
        if not os.path.isfile(conf_file):
            continue
        file_found = True
        
        try:
            with open(conf_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if line_clean.startswith('#'):
                        continue
                    match = pattern.search(line_clean)
                    if match:
                        value = match.group(1).lower()
                        if value in allowed_values:
                            state = "GOOD"
                        else:
                            detail.append(f"{conf_file} {line_num}번 줄: 위험 설정({value})")
        except Exception as e:
            detail.append(f"{conf_file} 읽기 오류: {str(e)}")
            state = "ERROR"

    if not file_found:
        state = "N/A"
        detail.append("Apache 설정 파일을 찾을 수 없음")
    elif state == "GOOD" and not any("위험 설정" in d for d in detail):
        detail.insert(0, f"안전 설정 확인")
    elif state == "BAD":
        detail.insert(0, "위험한 AllowOverride 설정 발견")

    print_table_row(item, state, "; ".join(detail))


def check_unnecessary_apache_files():
    item = "[U-38] 웹서비스 불필요한 파일 제거"
    state = "GOOD"
    detail = []
    
    base_dir = "/etc/apache2"
    unnecessary_items = [
        "README",
        "conf-enabled/serve-cgi-bin.conf",
        "conf-available/serve-cgi-bin.conf",
        "sites-available/default.conf",
        "sites-available/example.conf",
        "sites-enabled/000-default.conf~",
        "sites-enabled/default"
    ]

    # 1. 아파치 설정 디렉토리 존재 여부 확인
    if not os.path.isdir(base_dir):
        print_table_row(item, "N/A", "Apache 설치되지 않음")
        return

    # 2. 불필요 파일 검사
    for item_path in unnecessary_items:
        full_path = os.path.join(base_dir, item_path)
        if os.path.exists(full_path):
            detail.append(full_path)
    
    # 3. 결과 판정
    if detail:
        state = "BAD"
        print_table_row(item, state, "; ".join(detail))
    else:
        print_table_row(item, state, "불필요 파일 미검출")


def check_followsymlinks():
    item = "[U-39] 웹서비스 링크 사용금지"
    state = "GOOD"
    detail = []
    config_files = [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-available/000-default.conf",
        "/etc/apache2/sites-available/default-ssl.conf"
    ]
    pattern = re.compile(r'^Options\s+.*FollowSymLinks\b', re.IGNORECASE)
    file_found = False

    for conf_file in config_files:
        if not os.path.isfile(conf_file):
            continue
        file_found = True
        
        try:
            with open(conf_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if line_clean.startswith('#'):
                        continue
                    if pattern.search(line_clean):
                        state = "BAD"
                        detail.append(f"{conf_file} {line_num}번 줄: FollowSymLinks 사용")
        except Exception as e:
            detail.append(f"{conf_file} 읽기 오류: {str(e)}")
            state = "ERROR"

    if not file_found:
        state = "N/A"
        detail.append("Apache 설정 파일을 찾을 수 없음")
    elif state == "GOOD":
        detail.append("모든 설정에서 FollowSymLinks 미사용")

    print_table_row(item, state, "; ".join(detail))


def check_limit_request_body():
    item = "[U-40] 웹서비스 파일 업로드 및 다운로드 제한"
    state = "BAD"
    detail = []
    config_files = [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-available/000-default.conf",
        "/etc/apache2/sites-available/default-ssl.conf"
    ]
    pattern = re.compile(r'^LimitRequestBody\s+(\d+)', re.IGNORECASE)
    file_exists = False

    for conf_file in config_files:
        if not os.path.isfile(conf_file):
            continue
        file_exists = True
        
        try:
            with open(conf_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if line_clean.startswith('#'):
                        continue
                    match = pattern.search(line_clean)
                    if match:
                        state = "GOOD"
                        detail.append(f"{conf_file} {line_num}번 줄: {match.group(0)}")
        except Exception as e:
            detail.append(f"{conf_file} 읽기 오류: {str(e)}")
            state = "ERROR"

    if not file_exists:
        state = "N/A"
        detail.append("Apache 설정 파일 없음")
    elif state == "BAD" and file_exists:
        detail.insert(0, "파일 크기 제한 설정 미적용")

    print_table_row(item, state, "; ".join(detail))

def check_document_root():
    item = "[U-41] 웹서비스 영역의 분리"
    state = "GOOD"
    detail = ""
    config_file = "/etc/apache2/sites-available/000-default.conf"
    default_paths = ["/var/www/html", "/var/www"]

    # 1. 설정 파일 존재 여부 확인
    if not os.path.isfile(config_file):
        print_table_row(item, "N/A", "Apache 설정 파일 없음")
        return

    # 2. DocumentRoot 설정 추출
    try:
        with open(config_file, 'r') as f:
            doc_root = None
            pattern = re.compile(r'^DocumentRoot\s+"?(.+?)"?(\s+#.*)?$', re.IGNORECASE)
            
            for line in f:
                line_clean = line.strip()
                if line_clean.startswith('#'):
                    continue
                match = pattern.match(line_clean)
                if match:
                    doc_root = match.group(1).strip()
                    break

            # 3. 결과 판정
            if not doc_root:
                state = "BAD"
                detail = "DocumentRoot 설정 누락"
            elif doc_root in default_paths:
                state = "BAD"
                detail = f"기본 디렉토리 사용 ({doc_root})"
            else:
                detail = f"사용자 정의 디렉토리 사용 ({doc_root})"
                
    except Exception as e:
        state = "ERROR"
        detail = f"파일 읽기 오류: {str(e)}"
    
    print_table_row(item, state, detail)

def check_hosts_lpd():
    item = "[U-55] hosts.lpd 파일 소유자 및 권한 설정"
    state = "GOOD"
    detail = ""
    file_path = "/etc/hosts.lpd"

    try:
        if not os.path.exists(file_path):
            detail = "hosts.lpd 파일이 존재하지 않음 (보안 권장 상태)"
            print_table_row(item, state, detail)
            return True

        st = os.stat(file_path)
        owner_uid = st.st_uid
        owner_name = pwd.getpwuid(owner_uid).pw_name
        perm = stat.S_IMODE(st.st_mode)

        if owner_name == "root" and perm == 0o600:
            detail = f"소유자: {owner_name}, 권한: {oct(perm)[-3:]} (적정)"
        else:
            state = "BAD"
            detail = f"소유자: {owner_name}(부적절), 권한: {oct(perm)[-3:]}(부적절)"

    except Exception as e:
        state = "ERROR"
        detail = f"파일 검사 오류: {str(e)}"
    
    print_table_row(item, state, detail)
    return state == "GOOD"

def get_current_umask():
    """현재 umask 값을 안전하게 가져오는 함수"""
    current_umask = os.umask(0)
    os.umask(current_umask)
    return current_umask

def check_umask():
    item = "[U-56] UMASK 설정 관리"
    state = "GOOD"
    bad_reasons = []  # 문제가 있는 설정만 저장
    good_reasons = []  # 안전한 설정 저장
    error_flag = False

    # 1. /etc/login.defs 검사
    login_defs_path = '/etc/login.defs'
    umask_pattern = re.compile(r'^\s*UMASK\s+(\d+)', re.IGNORECASE)
    if os.path.exists(login_defs_path):
        try:
            with open(login_defs_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    match = umask_pattern.match(line.strip())
                    if match:
                        umask_str = match.group(1)
                        try:
                            umask_val = int(umask_str, 8)
                            if umask_val < 0o22:
                                bad_reasons.append(f"{login_defs_path} {line_num}번 줄: UMASK {oct(umask_val)} (위험)")
                                state = "BAD"
                            else:
                                good_reasons.append(f"{login_defs_path} {line_num}번 줄: UMASK {oct(umask_val)} (안전)")
                        except ValueError:
                            error_flag = True
                            bad_reasons.append(f"{login_defs_path} {line_num}번 줄: 잘못된 UMASK 값 ({umask_str})")
        except Exception as e:
            error_flag = True
            bad_reasons.append(f"{login_defs_path} 파일 읽기 실패: {str(e)}")

    # 2. 글로벌 설정 파일 검사
    global_configs = ['/etc/profile', '/etc/bash.bashrc']
    for config in global_configs:
        if os.path.exists(config):
            try:
                with open(config, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        if re.match(r'^\s*umask\s+\d+', line):
                            umask_str = line.split()[-1]
                            try:
                                umask_val = int(umask_str, 8)
                                if umask_val < 0o22:
                                    bad_reasons.append(f"{config} {line_num}번 줄: umask {oct(umask_val)} (위험)")
                                    state = "BAD"
                                else:
                                    good_reasons.append(f"{config} {line_num}번 줄: umask {oct(umask_val)} (안전)")
                            except ValueError:
                                error_flag = True
                                bad_reasons.append(f"{config} {line_num}번 줄: 잘못된 umask 값 ({umask_str})")
            except Exception as e:
                error_flag = True
                bad_reasons.append(f"{config} 파일 읽기 실패: {str(e)}")

    # 3. 사용자 셸 설정 검사
    home_dir = os.path.expanduser('~')
    user_configs = ['.bashrc', '.profile', '.bash_profile']
    for config in user_configs:
        config_path = os.path.join(home_dir, config)
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        if re.match(r'^\s*umask\s+\d+', line):
                            umask_str = line.split()[-1]
                            try:
                                umask_val = int(umask_str, 8)
                                if umask_val < 0o22:
                                    bad_reasons.append(f"{config_path} {line_num}번 줄: umask {oct(umask_val)} (위험)")
                                    state = "BAD"
                                else:
                                    good_reasons.append(f"{config_path} {line_num}번 줄: umask {oct(umask_val)} (안전)")
                            except ValueError:
                                error_flag = True
                                bad_reasons.append(f"{config_path} {line_num}번 줄: 잘못된 umask 값 ({umask_str})")
            except Exception as e:
                error_flag = True
                bad_reasons.append(f"{config_path} 파일 읽기 실패: {str(e)}")

    # 4. 현재 umask 값 검사
    try:
        current_umask = get_current_umask()
        if current_umask < 0o22:
            bad_reasons.append(f"현재 세션 umask: {oct(current_umask)} (위험)")
            state = "BAD"
        else:
            good_reasons.append(f"현재 세션 umask: {oct(current_umask)} (안전)")
    except Exception as e:
        error_flag = True
        bad_reasons.append(f"현재 umask 확인 실패: {str(e)}")

    # 결과 판정
    if error_flag:
        state = "ERROR"

    # 결과 메시지 구성
    if bad_reasons:
        detail = "; ".join(bad_reasons)
    elif good_reasons:
        detail = "모든 UMASK 설정이 022 이상으로 안전함"
    else:
        detail = "UMASK 설정 없음 (시스템 기본값 사용)"

    print_table_row(item, state, detail)

def check_home_permissions():
    item = "[U-57] 홈디렉토리 소유자 및 권한 설정"
    state = "GOOD"
    reasons = []
    passwd_path = "/etc/passwd"
    # 시스템 계정 홈디렉토리 경로는 검사에서 제외
    system_dirs = [
        '/bin', '/sbin', '/usr', '/usr/bin', '/usr/sbin', '/lib', '/lib64', '/etc',
        '/dev', '/proc', '/sys', '/root', '/var', '/run'
    ]
    
    try:
        with open(passwd_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                fields = line.split(':')
                if len(fields) < 7:
                    continue
                username = fields[0]
                uid = int(fields[2])
                home_dir = fields[5]

                # Skip non-existent home directories
                if not os.path.isdir(home_dir):
                    continue

                # Skip system directories and root directory
                if home_dir == '/' or any(home_dir == sd or home_dir.startswith(sd + '/') for sd in system_dirs):
                    continue

                try:
                    stat_info = os.stat(home_dir)
                    owner_uid = stat_info.st_uid
                    mode = stat.S_IMODE(stat_info.st_mode)
                except Exception as e:
                    reasons.append(f"{home_dir} 접근 불가: {str(e)}")
                    state = "BAD"
                    continue

                # Check 1: 소유자 일치 여부
                if owner_uid != uid:
                    owner_name = pwd.getpwuid(owner_uid).pw_name
                    reasons.append(f"{home_dir} 소유자 불일치 ({username} != {owner_name})")
                    state = "BAD"
                
                # Check 2: Others 쓰기 권한 확인
                if mode & 0o0002:
                    reasons.append(f"{home_dir} 타인 쓰기 권한 있음 ({oct(mode)})")
                    state = "BAD"

    except Exception as e:
        state = "ERROR"
        reasons.append(f"{passwd_path} 파일 읽기 실패: {str(e)}")
    
    # 결과 출력
    detail = "; ".join(reasons) if reasons else "모든 사용자 홈디렉토리 적합"
    print_table_row(item, state, detail)

def check_home_directories():
    item = "[U-58] 홈디렉토리로 지정한 디렉토리의 존재 관리"
    state = "GOOD"
    reasons = []
    passwd_file = "/etc/passwd"
    
    try:
        with open(passwd_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                fields = line.split(':')
                if len(fields) < 6:
                    continue
                username = fields[0]
                home_dir = fields[5]

                # 1. 홈 디렉토리 유효성 검사
                if home_dir == "/":
                    reasons.append(f"{username} 계정 홈디렉토리: / (루트 디렉토리)")
                    state = "BAD"
                elif not os.path.isdir(home_dir):
                    reasons.append(f"{username} 계정 홈디렉토리: {home_dir} (존재하지 않음)")
                    state = "BAD"

    except Exception as e:
        state = "ERROR"
        reasons.append(f"{passwd_file} 파일 읽기 실패: {str(e)}")
    
    # 결과 출력
    detail = "; ".join(reasons) if reasons else "모든 계정에 유효한 홈디렉토리 존재"
    print_table_row(item, state, detail)

def find_hidden_files_and_dirs():
    item = "[U-59] 숨겨진 파일 및 디렉토리 검색 및 제거"
    state = "GOOD"
    details = []
    excluded_dirs = ['/usr', '/sys', '/snap', '/proc', '/dev', '/run', '/var/lib', '/var/run', '/var/snap']
    
    try:
        for root, dirs, files in os.walk('/', topdown=True):
            # 제외 디렉터리 필터링
            dirs[:] = [d for d in dirs if not any(
                os.path.abspath(os.path.join(root, d)).startswith(ex) 
                for ex in excluded_dirs
            )]
            
            # 숨겨진 디렉터리 검출
            for d in dirs:
                if d.startswith('.') and d not in ('.', '..'):
                    full_path = os.path.join(root, d)
                    details.append(f"디렉토리: {full_path}")
            
            # 숨겨진 파일 검출
            for f in files:
                if f.startswith('.') and f not in ('.', '..'):
                    full_path = os.path.join(root, f)
                    details.append(f"파일: {full_path}")

    except Exception as e:
        state = "ERROR"
        details.append(f"파일 시스템 검사 오류: {str(e)}")
    
    # 결과 판정
    if details:
        state = "BAD" if state != "ERROR" else state
        detail_str = "; ".join(details[:10])  # 최대 10개까지 표시
        if len(details) > 10:
            detail_str += f" ... (총 {len(details)}개 발견)"
    else:
        detail_str = "숨겨진 파일/디렉토리 미검출 (시스템 경로 제외)"
    
    print_table_row(item, state, detail_str)

def check_remote_services():
    item = "[U-60] ssh 원격접속 허용"
    state = "GOOD"
    detail = []
    problem_services = []

    # SSH 상태 및 버전 확인
    ssh_status = get_service_status('ssh')
    ssh_active = ssh_status == 'active'
    ssh_version = get_ssh_version()

    # FTP 관련 정보 확인
    ftp_service = 'vsftpd'
    ftp_status = get_service_status(ftp_service)
    ftp_active = ftp_status == 'active'
    ftp_exists = service_exists(ftp_service)

    # Telnet 관련 정보 확인
    telnet_services = ['telnet.socket', 'telnet']
    telnet_statuses = [get_service_status(svc) for svc in telnet_services]
    telnet_active = any(status == 'active' for status in telnet_statuses)
    telnet_exists = any(service_exists(svc) for svc in telnet_services)

    # 문제 식별
    if not ssh_active:
        problem_services.append(f"SSH 비활성화 (현재 상태: {ssh_status})")
    if ftp_active:
        problem_services.append(f"FTP 활성화 (서비스: {ftp_service})")
    if telnet_active:
        problem_services.append(f"Telnet 활성화 (서비스: {telnet_services})")

    # 상태 판정
    if problem_services:
        state = "BAD"
        detail = "문제 항목:\n- " + "\n- ".join(problem_services)
    else:
        # GOOD 상태 상세 정보 구성
        status_info = [
            f"SSH 서비스:",
            f"  - 상태: 활성화 (버전: {ssh_version})",
            f"  - 설정 파일: /etc/ssh/sshd_config",
            "",
            f"FTP 서비스:",
            f"  - 상태: {'미설치' if not ftp_exists else '비활성화'}",
            "",
            f"Telnet 서비스:",
            f"  - 상태: {'미설치' if not telnet_exists else '비활성화'}"
        ]
        detail = "\n".join(status_info)

    print_table_row(item, state, detail)

def get_ssh_version():
    """SSH 버전 정보 추출"""
    try:
        result = subprocess.run(
            ['ssh', '-V'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        version_output = result.stdout.strip()
        version_match = re.search(r'OpenSSH_(\d+\.\d+[^, ]*)', version_output)
        return version_match.group(1) if version_match else "버전 확인 불가"
    except Exception as e:
        return f"버전 확인 오류: {str(e)}"

def service_exists(service):
    """서비스 존재 여부 심층 확인"""
    try:
        check = subprocess.run(
            ['systemctl', 'list-unit-files', '-t', 'service', '--full', '--no-legend', f"{service}.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        return bool(check.stdout.strip())
    except:
        return False

def check_ftp_service():
    item = "[U-61] ftp 서비스 확인"
    state = "GOOD"
    reasons = []
    ftp_services = ["vsftpd", "proftpd", "pure-ftpd"]
    installed_services = []
    inactive_services = []

    try:
        for service in ftp_services:
            if not service_exists(service):
                continue
            
            installed_services.append(service)
            
            # 활성화 상태 확인
            active_result = subprocess.run(
                ['systemctl', 'is-active', service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            active_status = active_result.stdout.strip()

            # 자동시작 상태 확인
            enabled_result = subprocess.run(
                ['systemctl', 'is-enabled', service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            enabled_status = enabled_result.stdout.strip()

            # 상태 판정
            if active_status != 'inactive' or enabled_status not in ['disabled', 'static']:
                reasons.append(f"{service} 서비스 문제 (실행: {active_status}, 자동시작: {enabled_status})")
                state = "BAD"
            else:
                inactive_services.append(service)

        # GOOD 상태 시 상세 정보 구성
        if state == "GOOD":
            if installed_services:
                detail = "FTP 서비스 설치됨 (비활성화 상태):\n- " + "\n- ".join(inactive_services)
            else:
                detail = "FTP 서비스 미설치 (vsftpd/proftpd/pure-ftpd)"
        else:
            detail = "문제 발견:\n- " + "\n- ".join(reasons)

    except Exception as e:
        state = "ERROR"
        detail = f"서비스 검사 오류: {str(e)}"

    print_table_row(item, state, detail)



def check_ftp_shell():
    item = "[U-62] ftp 계정 shell 제한"
    state = "GOOD"
    detail = ""
    passwd_file = "/etc/passwd"
    ftp_shell = None
    allowed_shells = ["/bin/false", "/sbin/nologin", "/usr/sbin/nologin"]

    try:
        with open(passwd_file, 'r') as f:
            for line in f:
                if line.startswith('ftp:'):
                    fields = line.strip().split(':')
                    if len(fields) >= 7:
                        ftp_shell = fields[6]
                    break

        # 결과 판정
        if ftp_shell is None:
            detail = "ftp 계정 미존재 (권장 상태)"
        elif ftp_shell in allowed_shells:
            detail = f"""적절한 쉘 설정 확인:
- 계정명: ftp
- 사용 쉘: {ftp_shell}
- 권장 쉘: {", ".join(allowed_shells)}"""
        else:
            state = "BAD"
            detail = f"""위험한 쉘 설정 발견:
- 계정명: ftp
- 현재 설정: {ftp_shell}
- 권장 설정: {", ".join(allowed_shells)}"""

    except FileNotFoundError:
        state = "ERROR"
        detail = f"{passwd_file} 파일 없음"
    except Exception as e:
        state = "ERROR"
        detail = f"파일 읽기 오류: {str(e)}"

    print_table_row(item, state, detail)


def check_ftpusers_file():
    item = "[U-63] ftpusers 파일 소유자 및 권한 설정"
    state = "GOOD"
    detail = ""
    file_path = "/etc/ftpusers"

    try:
        if not os.path.isfile(file_path):
            state = "BAD"
            detail = "파일 미존재"
            print_table_row(item, state, detail)
            return

        st = os.stat(file_path)
        owner_uid = st.st_uid
        perm = stat.S_IMODE(st.st_mode)
        owner_name = pwd.getpwuid(owner_uid).pw_name

        # 소유자 확인
        if owner_name != "root":
            state = "BAD"
            detail += f"소유자: {owner_name}(부적절); "
        
        # 권한 확인 (640 = 0o640)
        if perm > 0o640:  # 640보다 큰 권한(예: 755, 777)인 경우
            state = "BAD"
            detail += f"권한: {oct(perm)[-3:]}(부적절)"
        else:
            detail += f"권한: {oct(perm)[-3:]}(적정)" if detail else f"소유자: root, 권한: {oct(perm)[-3:]}"

    except Exception as e:
        state = "ERROR"
        detail = f"파일 접근 오류: {str(e)}"

    print_table_row(item, state, detail)

def check_ftp_root_access():
    item = "[U-64] ftpusers 파일 설정(FTP 서비스 root 계정 접근제한)"
    state = "GOOD"
    detail = []
    ftp_service = "vsftpd"
    ftpusers_path = "/etc/ftpusers"
    service_active = False
    root_blocked = False
    config_details = []

    try:
        # 1. FTP 서비스 실행 상태 확인
        service_status = subprocess.run(
            ["systemctl", "is-active", ftp_service],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        service_active = (service_status.returncode == 0)

        if service_active:
            # 2. ftpusers 파일 존재 여부 확인
            if not os.path.isfile(ftpusers_path):
                state = "BAD"
                detail.append("ftpusers 파일 미존재")
            else:
                # 3. root 계정 차단 여부 및 상세 정보 수집
                with open(ftpusers_path, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        cleaned_line = line.strip().lower()
                        if cleaned_line == "root":
                            root_blocked = True
                            config_details.append(f"{ftpusers_path} {line_num}번 줄: '{line.strip()}'")
                            break

                if not root_blocked:
                    state = "BAD"
                    detail.append("root 계정 미차단")
                else:
                    config_details.insert(0, f"FTP 서비스 활성화 ({ftp_service})")

        # GOOD 상태 시 상세 정보 구성
        if state == "GOOD":
            if service_active:
                detail = [
                    "적절한 root 계정 차단 설정:",
                    *config_details,
                    f"설정 파일 경로: {ftpusers_path}"
                ]
            else:
                detail = [f"{ftp_service} 서비스 비활성화 (권장 상태)"]

    except Exception as e:
        state = "ERROR"
        detail = [f"검사 오류: {str(e)}"]

    # 결과 출력 포맷팅
    print_table_row(item, state, "\n- ".join(detail) if detail else "")

def check_at_permissions():
    item = "[U-65] at 서비스 권한 설정"
    state = "GOOD"
    details = []
    target_files = [
        '/usr/bin/at',
        '/etc/at.allow',
        '/etc/at.deny'
    ]
    
    try:
        # 1. at 명령어 설치 여부 확인
        at_path = shutil.which('at')
        if not at_path:
            print_table_row(item, "GOOD", "at 서비스 미설치 (권장 상태)")
            return

        # 2. 파일별 권한 검사
        for file_path in target_files:
            if not os.path.exists(file_path):
                details.append(f"{file_path} 미존재")
                continue

            try:
                st = os.stat(file_path)
                owner = pwd.getpwuid(st.st_uid).pw_name
                perm = stat.S_IMODE(st.st_mode)

                # 소유자 및 권한 검사
                owner_ok = (owner == 'root')
                perm_ok = (perm <= 0o640)  # 0o640는 8진수 표기

                if owner_ok and perm_ok:
                    details.append(f"{file_path}\n  - 소유자: {owner}\n  - 권한: {oct(perm)[-3:]}")
                else:
                    details.append(f"{file_path}\n  - 소유자: {owner}(부적절)\n  - 권한: {oct(perm)[-3:]}(부적절)")
                    state = "BAD"

            except Exception as e:
                state = "ERROR"
                details.append(f"{file_path} 검사 실패: {str(e)}")

        # 3. 결과 메시지 구성
        if state == "GOOD":
            detail_msg = "적절한 권한 설정 확인:\n- " + "\n- ".join(details)
        elif state == "BAD":
            detail_msg = "문제 발견:\n- " + "\n- ".join(details)
        else:
            detail_msg = "\n".join(details)

    except Exception as e:
        state = "ERROR"
        detail_msg = f"전체 검사 오류: {str(e)}"

    print_table_row(item, state, detail_msg)

def check_snmpd_running():
    item = "[U-66] SNMP 서비스 구동 점검"
    state = "GOOD"
    reasons = []
    detail = ""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', '--quiet', 'snmpd']
        )
        if result.returncode == 0:
            state = "BAD"
            reasons.append("SNMP 서비스(snmpd)가 실행 중임")
        else:
            state = "GOOD"
            reasons.append("SNMP 서비스(snmpd)가 비활성화 상태 (권장)")
    except Exception as e:
        state = "N/A"
        reasons.append(f"점검 오류: {e}")
    detail = "; ".join(reasons)
    print_table_row(item, state, detail)


def check_snmp_community_string():
    item = "[U-67] SNMP 서비스 Community String의 복잡성 설정"
    state = "GOOD"
    reasons = []
    config_file = "/etc/snmp/snmpd.conf"
    if not os.path.isfile(config_file):
        state = "GOOD"
        reasons.append("SNMP 미설치 또는 설정 파일 없음")
    else:
        matches = []
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    if line.strip().startswith('#'):
                        continue
                    if re.search(r'rocommunity\s+(public|private)\b', line, re.IGNORECASE):
                        matches.append(line.strip())
        except Exception as e:
            state = "N/A"
            reasons.append(f"파일 읽기 오류: {e}")
        if matches:
            state = "BAD"
            reasons.append(f"취약한 community string 발견: {', '.join(matches)}")
    detail = "; ".join(reasons) if state != "GOOD" else "SNMP 미설치 또는 설정 파일 없음"
    print_table_row(item, state, detail)

def check_logon_warning():
    item = "[U-68] 로그온 시 경고 메시지 제공"
    state = "GOOD"
    good_reasons = []
    bad_reasons = []
    checked_files = 0

    # 검사 대상 파일과 권장 설정 패턴
    configs = {
        "/etc/motd": re.compile(r"Unauthorized.access.prohibited", re.IGNORECASE),
        "/etc/issue.net": re.compile(r"Authorized.users.only", re.IGNORECASE),
        "/etc/vsftpd.conf": re.compile(r"^banner_file\s*=\s*/etc/vsftpd\.banner", re.MULTILINE),
        "/etc/mail/sendmail.cf": re.compile(r"^GreetingMessage\s*=\s*\$j.Sendmail", re.MULTILINE),
        "/etc/named.conf": re.compile(r"^directory\s+\"/var/named\"", re.MULTILINE)
    }

    for file_path, pattern in configs.items():
        if not os.path.isfile(file_path):
            continue
        checked_files += 1

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                match = pattern.search(content)

                if match:
                    # GOOD: 설정 라인 하이라이트
                    lines = content.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        if pattern.search(line):
                            good_reasons.append(
                                f"{file_path} {line_num}번 줄: "
                                f"'{line.strip()}'"
                            )
                else:
                    bad_reasons.append(f"{file_path} 경고 메시지 미설정")
                    state = "BAD"

        except Exception as e:
            state = "ERROR"
            bad_reasons.append(f"{file_path} 읽기 오류: {str(e)}")

    # 결과 메시지 구성
    if state == "GOOD":
        if checked_files > 0:
            detail = "적절한 경고 메시지 설정 확인:\n- " + "\n- ".join(good_reasons)
        else:
            state = "N/A"
            detail = "로그온 메시지 설정 파일이 없음 (추가 설정 권장)"
    elif state == "BAD":
        detail = "문제 발견:\n- " + "\n- ".join(bad_reasons)
    else:
        detail = "\n".join(bad_reasons)

    print_table_row(item, state, detail)


def check_nfs_exports():
    item = "[U-69] NFS 설정파일 접근권한"
    state = "GOOD"
    detail = ""
    config_file = "/etc/exports"
    
    if not os.path.isfile(config_file):
        state = "N/A"
        detail = "NFS 미설정 (설정 파일 없음)"
    else:
        try:
            file_stat = os.stat(config_file)
            owner_uid = file_stat.st_uid
            owner_name = pwd.getpwuid(owner_uid).pw_name
            permissions = file_stat.st_mode & 0o777  # 파일 권한 정수값 추출
            
            # 권한 검사 기준
            owner_valid = (owner_name == "root")
            perm_valid = (permissions <= 0o644)  # 0o644 = owner RW, group R, others R

            if owner_valid and perm_valid:
                detail = f"""적절한 권한 설정 확인:
- 소유자: {owner_name}
- 파일 권한: {oct(permissions)[-3:]} (최대 644 권한 권장)"""
            else:
                state = "BAD"
                issues = []
                if not owner_valid:
                    issues.append(f"소유자: {owner_name} (root 계정 필요)")
                if not perm_valid:
                    issues.append(f"권한: {oct(permissions)[-3:]} (644 이하로 설정 필요)")
                detail = "문제 발견:\n- " + "\n- ".join(issues)

        except PermissionError:
            state = "ERROR"
            detail = "파일 접근 권한 없음 (root 권한 필요)"
        except Exception as e:
            state = "ERROR"
            detail = f"파일 검사 오류: {str(e)}"
    
    print_table_row(item, state, detail)


def check_expn_vrfy():
    item = "[U-70] EXPN, VRFY 명령어 제한"
    state = "GOOD"
    config_file = "/etc/mail/sendmail.cf"
    noexpn_lines = []
    novrfy_lines = []

    if not os.path.isfile(config_file):
        state = "N/A"
        detail = "Sendmail 미설치 또는 설정 파일 없음"
    else:
        try:
            with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if re.search(r'noexpn', line_clean, re.IGNORECASE):
                        noexpn_lines.append(f"{line_num}번 줄: {line_clean}")
                    if re.search(r'novrfy', line_clean, re.IGNORECASE):
                        novrfy_lines.append(f"{line_num}번 줄: {line_clean}")

            # 결과 판정
            if noexpn_lines and novrfy_lines:
                detail = f"""EXPN/VRFY 명령어 제한 설정 확인:
- noexpn 설정:
  {'  '.join(noexpn_lines)}
- novrfy 설정:
  {'  '.join(novrfy_lines)}"""
            else:
                state = "BAD"
                issues = []
                if not noexpn_lines:
                    issues.append("noexpn 미설정")
                if not novrfy_lines:
                    issues.append("novrfy 미설정")
                detail = "문제 발견: " + ", ".join(issues)

        except Exception as e:
            state = "ERROR"
            detail = f"파일 읽기 오류: {str(e)}"

    print_table_row(item, state, detail)


def get_service_status(service):
    """서비스 상태 확인 함수"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"

def check_security_updates():
    item = "[U-42] 최신 보안패치 및 벤더 권고사항 적용"
    state = "GOOD"
    reasons = []

    # 패키지 매니저 확인
    package_manager = None
    for pm in ['apt', 'yum', 'dnf']:
        result = subprocess.run(
            ['which', pm],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            package_manager = pm
            break

    if not package_manager:
        state = "N/A"
        reasons.append("지원하지 않는 패키지 관리자")
    else:
        try:
            if package_manager == 'apt':
                result = subprocess.run(
                    ['apt', 'list', '--upgradable'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                security_updates = sum(1 for line in result.stdout.splitlines() if 'security' in line.lower())
                if security_updates > 0:
                    state = "BAD"
                    reasons.append(f"{security_updates}개의 보안 업데이트 필요")
            elif package_manager in ['yum', 'dnf']:
                result = subprocess.run(
                    [package_manager, 'check-update', '--security'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                if 'Security' in result.stdout:
                    state = "BAD"
                    reasons.append("보안 업데이트 필요")
        except Exception as e:
            state = "N/A"
            reasons.append(f"업데이트 확인 중 오류: {e}")

    detail = "; ".join(reasons) if state != "GOOD" else "모든 보안 패치 적용 완료"
    print_table_row(item, state, detail)


def check_log():
    item = "[U-43] 로그의 정기적 검토 및 보고"
    state = "GOOD"
    log_details = []
    reasons = []

    # 개별 로그 검사 함수 (상태와 출력 반환)
    def check_single_log(filepath, command=None, lines=None, sudo=False, filter_str=None):
        if not os.path.exists(filepath):
            return {"status": "N/A", "output": f"{filepath} 없음"}
        try:
            cmd = command if command else f"tail -n {lines} {filepath}" if lines else f"cat {filepath}"
            if sudo:
                cmd = f"sudo {cmd}"
            result = subprocess.run(
                cmd, shell=True, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                universal_newlines=True, timeout=10
            )
            output = result.stdout.strip()[:1000]  # 출력 길이 제한
            
            # 검사 조건 판정
            status = "GOOD"
            if filter_str and filter_str not in output:
                status = "BAD"
            elif lines and len(output.split('\n')) < lines:
                status = "BAD"
                
            return {"status": status, "output": output}
            
        except Exception as e:
            return {"status": "ERROR", "output": str(e)}

    # 검사 대상 로그 정의
    log_checks = [
        {
            "name": "시스템 로그인 기록 (wtmp)",
            "params": {
                "filepath": "/var/log/wtmp",
                "command": "last -F -n 10",  # 최근 10개 로그인 기록
                "lines": 10
            }
        },
        {
            "name": "실패한 로그인 시도 (btmp)",
            "params": {
                "filepath": "/var/log/btmp",
                "command": "lastb -F -n 10",
                "sudo": True,
                "lines": 10
            }
        },
        {
            "name": "권한 상승 시도 (auth.log)",
            "params": {
                "filepath": "/var/log/auth.log",
                "filter_str": "su:",  # su 명령어 사용 기록 필터
                "lines": 10
            }
        }
    ]

    # 각 로그별 검사 수행
    for check in log_checks:
        res = check_single_log(**check["params"])
        
        if res["status"] == "GOOD":
            log_details.append(
                f"""▼ {check['name']} ▼
{res['output']}
───────────────────────────────""")
        else:
            state = "BAD"
            reasons.append(f"{check['name']}: {res['status']} - {res['output']}")

    # 결과 메시지 구성
    if state == "GOOD":
        detail = f"""정기 로그 모니터링 활성화 확인:
        
{''.join(log_details)}"""
    else:
        detail = "문제 발견:\n- " + "\n- ".join(reasons)

    print_table_row(item, state, detail)


def check_syslog_config():
    item = "[U-72] 정책에 따른 시스템 로깅 설정"
    state = "GOOD"
    details = []
    error_flag = False
    config_found = False
    log_config_files = ["/etc/rsyslog.conf"] + glob.glob("/etc/rsyslog.d/*.conf")
    pattern = re.compile(r'^\s*([^#]\S+\s+\.*/var/log/(secure|auth\.log))', re.IGNORECASE)

    # 1. 설정 파일 존재 여부 확인
    existing_configs = [f for f in log_config_files if os.path.isfile(f)]
    if not existing_configs:
        print_table_row(item, "N/A", "rsyslog 설정 파일 없음")
        return

    # 2. 각 설정 파일 검사
    for file_path in existing_configs:
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    match = pattern.search(line_clean)
                    if match:
                        config_found = True
                        details.append(
                            f"{os.path.basename(file_path)} {line_num}번 줄: "
                            f"{match.group(1).strip()}"
                        )
        except Exception as e:
            error_flag = True
            details.append(f"{file_path} 읽기 오류: {str(e)}")

    # 3. 결과 판정
    if error_flag:
        state = "ERROR"
    elif not config_found:
        state = "BAD"
        details.append("인증 로그 설정 미확인 (auth/authpriv facility 설정 필요)")

    # 4. 결과 메시지 구성
    if state == "GOOD":
        formatted_details = "적절한 로깅 설정 확인:\n- " + "\n- ".join(details)
    else:
        formatted_details = "문제 발견:\n- " + "\n- ".join(details)

    print_table_row(item, state, formatted_details)


def check_apache_info_hiding():
    item = "[U-71] Apache 웹 서비스 정보 숨김"
    state = "GOOD"
    details = []
    config_files = [
        "/etc/apache2/conf-enabled/security.conf",
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
        "/etc/httpd/conf.d/security.conf"
    ]
    found_settings = {
        'ServerTokens': {'value': None, 'location': ''},
        'ServerSignature': {'value': None, 'location': ''}
    }

    # 1. 설정 파일 검색
    existing_configs = [f for f in config_files if os.path.isfile(f)]
    if not existing_configs:
        print_table_row(item, "N/A", "Apache 설정 파일을 찾을 수 없음")
        return

    # 2. 각 설정 파일에서 지시어 검색
    for config_file in existing_configs:
        try:
            with open(config_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line_clean = line.strip()
                    if line_clean.startswith('#'):
                        continue

                    # ServerTokens 검색
                    if re.match(r'^ServerTokens\s+', line_clean, re.I):
                        parts = line_clean.split()
                        found_settings['ServerTokens']['value'] = parts[1]
                        found_settings['ServerTokens']['location'] = f"{config_file} {line_num}번 줄"
                        
                    # ServerSignature 검색
                    if re.match(r'^ServerSignature\s+', line_clean, re.I):
                        parts = line_clean.split()
                        found_settings['ServerSignature']['value'] = parts[1]
                        found_settings['ServerSignature']['location'] = f"{config_file} {line_num}번 줄"

        except Exception as e:
            state = "ERROR"
            details.append(f"{config_file} 읽기 오류: {str(e)}")
            continue

    # 3. 설정 값 검증
    tokens_valid = (found_settings['ServerTokens']['value'] in ['Prod', 'ProductOnly'])
    signature_valid = (found_settings['ServerSignature']['value'] == 'Off')

    # 4. 결과 판정
    if not all([found_settings['ServerTokens']['value'], found_settings['ServerSignature']['value']]):
        state = "BAD"
        if not found_settings['ServerTokens']['value']:
            details.append("ServerTokens 지시어 없음")
        if not found_settings['ServerSignature']['value']:
            details.append("ServerSignature 지시어 없음")
    elif not tokens_valid or not signature_valid:
        state = "BAD"
        if not tokens_valid:
            details.append(f"ServerTokens={found_settings['ServerTokens']['value']} (Prod/ProductOnly 필요)")
        if not signature_valid:
            details.append(f"ServerSignature={found_settings['ServerSignature']['value']} (Off 필요)")
    else:
        details.append(
            f"""적절한 정보 숨김 설정 적용:
- ServerTokens ({found_settings['ServerTokens']['location']}): {found_settings['ServerTokens']['value']}
- ServerSignature ({found_settings['ServerSignature']['location']}): {found_settings['ServerSignature']['value']}
※ 실제 적용 확인: `curl -I http://localhost | grep 'Server'` 실행 확인"""
        )

    print_table_row(item, state, "\n".join(details))



def save_results_to_csv(filename="security_check_results.csv"):
    with open(filename, "w", newline='', encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["항목", "결과", "상세"])
        writer.writerows(results)
    print(f"\n[+] 결과가 '{filename}' 파일로 저장되었습니다.")

if __name__ == "__main__":
    print("\n------------------------------------<<계정관리>>-------------------------------------")
    results.append(["------------------------------------<<계정관리>>-------------------------------------", "", ""])
    print_table_header()
    check_remote_service()
    check_password_complexity()
    check_common_auth()
    protect_hash_pwd_file()
    only_root_uid()
    check_su_restriction()
    check_pwd_length()
    check_pwd_maxdays()
    check_pwd_mindays()
    useless_user()
    check_admin_groups()
    check_useless_groups()
    no_same_uid()
    check_user_shell()
    session_timeout()

    print("\n------------------------------------<<파일 및 디렉토리>>-------------------------------------")
    results.append(["------------------------------------<<파일 및 디렉토리>>-------------------------------------", "", ""])
    print_table_header()
    check_path()
    check_owner_fd()
    check_fowner_auth()
    check_shaowner_auth()
    check_hostsowner_auth()
    inetd_owner_auth()
    check_owner_perm(["/etc/rsyslog.conf", "/etc/rsyslog.d"])
    check_servicesowner_auth()
    check_suid_sgid()
    check_startsetting_auth()
    check_world_writable()
    check_device_dev()
    check_hosts_notuse()
    run_ip_port_restriction_check()
    check_hosts_lpd()
    check_umask()
    check_home_permissions()
    check_home_directories()
    find_hidden_files_and_dirs()

    print("\n------------------------------------<<서비스 관리>>-------------------------------------")
    results.append(["------------------------------------<<서비스 관리>>-------------------------------------", "", ""])
    print_table_header()
    check_finger_service()
    check_ftp_anonymous()
    run_r_commands_check()
    run_cron_permission_check()
    check_dos_services()
    check_nfs_services()
    check_nfs_access()
    check_automountd()
    check_rpc_services()
    check_nis_services()
    check_services()
    check_sendmail_version()
    check_mail_relay_restriction()
    check_sendmail_restrictqrun()
    check_dns_version_and_status()
    check_zone_transfer()
    check_directory_listing()
    check_apache_user_group()
    check_allowoverride()
    check_unnecessary_apache_files()
    check_followsymlinks()
    check_limit_request_body()
    check_document_root()
    check_remote_services()
    check_ftp_service()
    check_ftp_shell()
    check_ftpusers_file()
    check_ftp_root_access()
    check_at_permissions()
    check_snmpd_running()
    check_snmp_community_string()
    check_logon_warning()
    check_nfs_exports()
    check_expn_vrfy()
    check_apache_info_hiding()

    print("\n------------------------------------<<패치 관리>>-------------------------------------")
    results.append(["------------------------------------<<패치 관리>>-------------------------------------", "", ""])
    print_table_header()
    check_security_updates()

    print("\n------------------------------------<<로그 관리>>-------------------------------------")
    results.append(["------------------------------------<<로그 관리>>-------------------------------------", "", ""])
    print_table_header()
    check_log()
    check_syslog_config()


    save_results_to_csv()


