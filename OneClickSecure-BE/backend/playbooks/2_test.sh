#!/bin/bash

HOSTNAME=$(hostname)
HOST_IP=$(hostname -I | awk '{print $1}' | tr -d ' ')
resultfile="Results_${HOSTNAME}_${HOST_IP}.csv"

# task 계정관리 | 계정에 대한 점검
u_01() {
	echo "U_01: 원격에서 루트 계정 접근 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 1. 텔넷 서비스 점검
    if dpkg -l 2>/dev/null | grep -iq telnet; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 텔넷 패키지가 설치되어 있음\n"
    fi
    
    if systemctl list-unit-files 2>/dev/null | grep -iq telnet; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 텔넷 서비스가 등록되어 있음\n"
    fi
    
    if systemctl is-active --quiet telnet.service 2>/dev/null; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 텔넷 서비스가 활성화되어 있음\n"
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":23 " || ss -tlnp 2>/dev/null | grep -q ":23 "; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 텔넷 포트(23)가 열려있음\n"
    fi
    
    # 2. SSH 서비스 root 접속 설정 점검 
    if [ -f "/etc/ssh/sshd_config" ]; then
        if grep -Eq "^\s*PermitRootLogin\s+yes\s*$" /etc/ssh/sshd_config; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH에서 root 직접 접속이 허용되어 있음\n"
        elif ! grep -Eq "^\s*PermitRootLogin\s+(no|prohibit-password|forced-commands-only)\s*$" /etc/ssh/sshd_config; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH PermitRootLogin 설정이 명시되지 않음\n"
        fi
    fi
    
    # 3. 기타 원격 접속 서비스 확인
    if systemctl list-unit-files 2>/dev/null | grep -Eq "(rlogin|rsh)"; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- rlogin/rsh 서비스가 등록되어 있음\n"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-01 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-01 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_02(){
	echo "U_02: 비밀번호 복잡성">>$resultfile 2>&1
	   VULNERABLE=0
    VULN_REASONS=""

    # /etc/security/pwquality.conf 파일 존재 확인
    if [ ! -f "/etc/security/pwquality.conf" ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- pwquality.conf 파일이 존재하지 않음\n"
    else
        # 각 설정값 확인

        # minlen (최소 길이) - 권장: 9자 이상, 기본값: 8
        minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
        [ -z "$minlen" ] && minlen=8  # 기본값
        if [ "$minlen" -lt 9 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 최소 비밀번호 길이가 부족함 (현재: $minlen, 권장: 9 이상)\n"
        fi

        # dcredit (숫자) - 권장: -1 (최소 1개 이상), 기본값: 0
        dcredit=$(grep -E "^\s*dcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
        [ -z "$dcredit" ] && dcredit=0  # 기본값
        if [ "$dcredit" -gt -1 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 숫자 문자 요구사항이 부족함 (현재: $dcredit, 권장: -1)\n"
        fi

        # ucredit (대문자) - 권장: -1 (최소 1개 이상), 기본값: 0
        ucredit=$(grep -E "^\s*ucredit\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
        [ -z "$ucredit" ] && ucredit=0  # 기본값
        if [ "$ucredit" -gt -1 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 대문자 요구사항이 부족함 (현재: $ucredit, 권장: -1)\n"
        fi

        # lcredit (소문자) - 권장: -1 (최소 1개 이상), 기본값: 0
        lcredit=$(grep -E "^\s*lcredit\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
        [ -z "$lcredit" ] && lcredit=0  # 기본값
        if [ "$lcredit" -gt -1 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 소문자 요구사항이 부족함 (현재: $lcredit, 권장: -1)\n"
        fi

        # ocredit (특수문자) - 권장: -1 (최소 1개 이상), 기본값: 0
        ocredit=$(grep -E "^\s*ocredit\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
        [ -z "$ocredit" ] && ocredit=0  # 기본값
        if [ "$ocredit" -gt -1 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 특수문자 요구사항이 부족함 (현재: $ocredit, 권장: -1)\n"
        fi

        # difok (기존 패스워드와 차이) - 권장: 5 이상 (50%), 기본값: 1
        difok=$(grep -E "^\s*difok\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
        [ -z "$difok" ] && difok=1  # 기본값
        if [ "$difok" -lt 5 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 기존 패스워드와 차이 요구사항이 부족함 (현재: $difok, 권장: 5 이상)\n"
        fi
    fi

    # PAM 설정 확인 (pwquality 모듈 사용 여부)
    if [ -f "/etc/pam.d/common-password" ]; then
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- PAM에서 pwquality 모듈이 설정되지 않음\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- PAM password 설정 파일이 존재하지 않음\n"
    fi

    if [ $VULNERABLE -eq 1 ]; then
        echo "U-02 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-02 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_03(){
	echo "U_03: 계정 잠금 임계값 설정">>$resultfile 2>&1
	VULENRABLE=0
	VULN_REASONS=""

	 # PAM 설정 파일들 확인
    pam_files=("/etc/pam.d/common-auth" "/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
    found_config=0

    for pam_file in "${pam_files[@]}"; do
        if [ -f "$pam_file" ]; then
            # pam_faillock 또는 pam_tally2 설정 확인
            if grep -q "pam_faillock\|pam_tally2" "$pam_file"; then
                found_config=1

                # deny 설정 확인 (권장: 5번 실패)
                deny_value=$(grep -E "(pam_faillock|pam_tally2)" "$pam_file" | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
                if [ -z "$deny_value" ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- deny 설정이 없음 → 권장: deny=5 옵션 추가\n"
                elif [ "$deny_value" -gt 5 ] || [ "$deny_value" -lt 3 ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- deny 값이 부적절함 (현재: $deny_value) → 권장: deny=5로 변경\n"
                fi

                # unlock_time 설정 확인 (권장: 600초/10분)
                unlock_value=$(grep -E "(pam_faillock|pam_tally2)" "$pam_file" | grep -o "unlock_time=[0-9]*" | cut -d= -f2 | head -1)
                if [ -z "$unlock_value" ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- unlock_time 설정이 없음 → 권장: unlock_time=600 옵션 추가\n"
                elif [ "$unlock_value" -lt 300 ] || [ "$unlock_value" -gt 1800 ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- unlock_time 값이 부적절함 (현재: ${unlock_value}초) → 권장: unlock_time=600으로 변경\n"
                fi

                # even_deny_root 설정 확인 (권장: 활성화)
                if ! grep -E "(pam_faillock|pam_tally2)" "$pam_file" | grep -q "even_deny_root"; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- even_deny_root 설정이 없음 → 권장: even_deny_root 옵션 추가\n"
                fi

                # onerr 설정 확인 (권장: fail)
                onerr_value=$(grep -E "(pam_faillock|pam_tally2)" "$pam_file" | grep -o "onerr=[a-z]*" | cut -d= -f2 | head -1)
                if [ -z "$onerr_value" ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- onerr 설정이 없음 → 권장: onerr=fail 옵션 추가\n"
                elif [ "$onerr_value" != "fail" ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- onerr 값이 부적절함 (현재: $onerr_value) → 권장: onerr=fail로 변경\n"
                fi

                break
            fi
        fi
    done

    # PAM 모듈 설정이 아예 없는 경우
    if [ "$found_config" -eq 0 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 계정 잠금 정책이 설정되지 않음 → 권장: PAM 파일에 'auth required pam_faillock.so deny=5 unlock_time=600 even_deny_root onerr=fail' 추가\n"
    fi

    # /etc/login.defs에서 추가 설정 확인
    if [ -f "/etc/login.defs" ]; then
        # LOGIN_RETRIES 확인
        login_retries=$(grep -E "^\s*LOGIN_RETRIES" /etc/login.defs | awk '{print $2}')
        if [ -z "$login_retries" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- LOGIN_RETRIES 설정이 없음 → 권장: /etc/login.defs에 'LOGIN_RETRIES 5' 추가\n"
        elif [ "$login_retries" -gt 5 ] || [ "$login_retries" -lt 3 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- LOGIN_RETRIES 값이 부적절함 (현재: $login_retries) → 권장: LOGIN_RETRIES 5로 변경\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- login.defs 파일이 존재하지 않음 → 권장: /etc/login.defs 파일 생성 필요\n"
    fi

    # 최종 결과만 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-03 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-03 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_04() {
    echo "U_04:계정 비번 암호화 여부" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # shadow 패스워드를 사용하지 않는 계정 찾기 (두 번째 필드가 "x"가 아닌 경우)
    non_shadow_accounts=$(awk -F: '$2!="x" && $2!="" && $2!="*" && $2!="!" && $2!="!!" {print $1}' /etc/passwd)
    
    # 최종 결과 출력
    if [ -n "$non_shadow_accounts" ]; then
        VULNERABLE=1
        VULN_REASONS="shadow를 사용하고 있지 않습니다."
        
        echo "U-04 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo "$VULN_REASONS" >> $resultfile 2>&1
        echo "암호화되지 않은 패스워드 발견:" >> $resultfile 2>&1
        
        # 취약 계정 목록 출력
        echo "$non_shadow_accounts" | while IFS= read -r account; do
            echo "  계정: $account" >> $resultfile 2>&1
        done
    else
        echo "※ U-04 결과 : 양호(Good)" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_44() {
    echo "U-44 루트 이외의 UID가 0인지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # UID가 0인 계정 중 root가 아닌 계정 찾기
    non_root_uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

    if [ -n "$non_root_uid0" ]; then
        VULNERABLE=1
        echo "$non_root_uid0의 uid를 변경하세요" >> $resultfile 2>&1
        VULN_REASONS="$VULN_REASONS- root 이외의 UID 0 계정 발견: $non_root_uid0 → 권장: usermod -u [새UID] [계정명]\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-44 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-44 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_45() {
    echo "U-45: 루트계정 su 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 1. PAM 설정에서 pam_wheel.so 확인
    pam_wheel_check=$(grep -E "^\s*auth\s+required\s+pam_wheel.so" /etc/pam.d/su 2>/dev/null)
    if [ -z "$pam_wheel_check" ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- PAM에서 wheel 그룹 제한이 설정되지 않음 → 권장: /etc/pam.d/su에 'auth required pam_wheel.so' 추가\n"
    fi
    
    # 2. wheel 그룹 또는 sudo 그룹 존재 확인
    wheel_group=$(grep "^wheel:" /etc/group 2>/dev/null)
    sudo_group=$(grep "^sudo:" /etc/group 2>/dev/null)
    
    if [ -z "$wheel_group" ] && [ -z "$sudo_group" ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- wheel 또는 sudo 그룹이 존재하지 않음 → 권장: groupadd wheel 명령으로 그룹 생성\n"
    else
        if [ -n "$wheel_group" ]; then
            echo "wheel 그룹 존재: $wheel_group" >> $resultfile 2>&1
        fi
        if [ -n "$sudo_group" ]; then
            echo "sudo 그룹 존재: $sudo_group" >> $resultfile 2>&1
        fi
    fi
    
    # 3. su 명령어 권한 확인 (권장: 4750)
    if [ -f "/bin/su" ]; then
        su_perm=$(stat -c "%a" /bin/su 2>/dev/null)
        if [ "$su_perm" != "4750" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- su 명령어 권한이 부적절함 (현재: $su_perm) → 권장: chmod 4750 /bin/su\n"
        fi
        
        # su 명령어 그룹 소유권 확인
        su_group=$(stat -c "%G" /bin/su 2>/dev/null)
        if [ "$su_group" != "wheel" ] && [ "$su_group" != "sudo" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- su 명령어 그룹 소유권이 부적절함 (현재: $su_group) → 권장: chgrp wheel /bin/su\n"
        fi
    fi
    
    # 4. 일반 사용자 계정 존재 확인 (UID 1000 이상)
    regular_users=$(awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)
    if [ -z "$regular_users" ]; then
        echo "일반 사용자 계정이 없어 su 제한 불필요" >> $resultfile 2>&1
        VULNERABLE=0  # 일반 사용자가 없으면 제한 불필요
        VULN_REASONS=""
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-45 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-45 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_46() {
    echo "U-46: 패스워드 최소 길이 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # /etc/security/pwquality.conf에서 minlen 확인
    minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | sed 's/.*=\s*//')
    # 빈 값이거나 숫자가 아닌 경우 기본값 설정
    if [ -z "$minlen" ] || ! [[ "$minlen" =~ ^[0-9]+$ ]]; then
        minlen=8  # 기본값
    fi

    if [ "$minlen" -lt 8 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 최소 비밀번호 길이가 부족함 (현재: $minlen) → 권장: minlen = 8 이상\n"
    fi

    # /etc/login.defs에서 PASS_MIN_LEN 확인
    pass_min_len=$(grep -E "^\s*PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$pass_min_len" ] && [[ "$pass_min_len" =~ ^[0-9]+$ ]] && [ "$pass_min_len" -lt 8 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- PASS_MIN_LEN이 부족함 (현재: $pass_min_len) → 권장: PASS_MIN_LEN 8 이상\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-46 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-46 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_47() {
    echo "U-47: 패스워드 최대 사용기간" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # /etc/login.defs에서 PASS_MAX_DAYS 확인
    pass_max_days=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')

    if [ -z "$pass_max_days" ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- PASS_MAX_DAYS 설정이 없음 → 권장: PASS_MAX_DAYS 90 설정\n"
    elif [[ "$pass_max_days" =~ ^[0-9]+$ ]] && ([ "$pass_max_days" -gt 90 ] || [ "$pass_max_days" -eq 99999 ]); then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 패스워드 최대 사용기간이 과도함 (현재: $pass_max_days일) → 권장: PASS_MAX_DAYS 90 이하\n"
    fi

    # 실제 사용자 계정의 패스워드 만료 설정 확인
    user_accounts=$(awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)
    if [ -n "$user_accounts" ]; then
        for user in $user_accounts; do
            user_max_days=$(chage -l "$user" 2>/dev/null | grep "Maximum number of days" | awk -F: '{print $2}' | tr -d ' ')
            # 빈 값이거나 숫자가 아닌 경우 처리
            if [ -z "$user_max_days" ] || ! [[ "$user_max_days" =~ ^-?[0-9]+$ ]]; then
                user_max_days=99999  # 기본값
            fi

            if [ "$user_max_days" = "-1" ] || [ "$user_max_days" -gt 90 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- 계정 $user의 패스워드 만료 설정이 부적절함 (현재: $user_max_days) → 권장: chage -M 90 $user\n"
            fi
        done
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-47 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-47 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_48() {
    echo "U-48: 패스워드 최소 사용기간" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # /etc/login.defs에서 PASS_MIN_DAYS 확인
    pass_min_days=$(grep -E "^\s*PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')

    if [ -z "$pass_min_days" ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- PASS_MIN_DAYS 설정이 없음 → 권장: PASS_MIN_DAYS 1 설정\n"
    elif [[ "$pass_min_days" =~ ^[0-9]+$ ]] && [ "$pass_min_days" -lt 1 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 패스워드 최소 사용기간이 부족함 (현재: $pass_min_days일) → 권장: PASS_MIN_DAYS 1 이상\n"
    fi

    # 실제 사용자 계정의 패스워드 최소 사용기간 확인
    user_accounts=$(awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)
    if [ -n "$user_accounts" ]; then
        for user in $user_accounts; do
            user_min_days=$(chage -l "$user" 2>/dev/null | grep "Minimum number of days" | awk -F: '{print $2}' | tr -d ' ')
            # 빈 값이거나 숫자가 아닌 경우 처리
            if [ -z "$user_min_days" ] || ! [[ "$user_min_days" =~ ^-?[0-9]+$ ]]; then
                user_min_days=0  # 기본값
            fi

            if [ "$user_min_days" -lt 1 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- 계정 $user의 패스워드 최소 사용기간이 부족함 (현재: $user_min_days) → 권장: chage -m 1 $user\n"
            fi
        done
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-48 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-48 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_49() {
    echo "U-49: 불필요한 계정 제거" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 불필요한 계정 목록 정의
    truly_unnecessary="www-data|games|gopher|ftp|apache|httpd|mysql|mariadb|postgres|postfix|uucp|news"

    if [ -f "/etc/passwd" ]; then
        # 불필요한 계정 탐지
        found_accounts=$(awk -F: '{print $1}' /etc/passwd | grep -wE "$unnecessary_accounts")

        if [ -n "$found_accounts" ]; then
            VULNERABLE=1
            # 줄바꿈을 공백으로 변환하여 한 줄로 표시
            account_list=$(echo "$found_accounts" | tr '\n' ' ' | sed 's/ $//')
            VULN_REASONS="$VULN_REASONS- 불필요한 계정 발견: $account_list → 권장: userdel 명령으로 제거\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/passwd 파일이 존재하지 않음\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-49 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-49 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_50() {
    echo "U-50: 관리자 그룹에 최소한의 계정 포함" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 불필요한 계정 목록 정의
    unnecessary_accounts="daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|gopher|games|ftp|apache|httpd|www-data|mysql|mariadb|postgres|mail|postfix|news|lp|uucp|nuucp"

    if [ -f "/etc/group" ]; then
        # root 그룹의 멤버 확인
        root_members=$(awk -F: '$1=="root" {print $4}' /etc/group)

        if [ -n "$root_members" ]; then
            # 쉼표로 구분된 멤버를 줄바꿈으로 변환하여 불필요한 계정 확인
            found_accounts=$(echo "$root_members" | tr ',' '\n' | grep -wE "$unnecessary_accounts")

            if [ -n "$found_accounts" ]; then
                VULNERABLE=1
                # 줄바꿈을 공백으로 변환하여 한 줄로 표시
                account_list=$(echo "$found_accounts" | tr '\n' ' ' | sed 's/ $//')
                VULN_REASONS="$VULN_REASONS- root 그룹에 불필요한 계정 포함: $account_list → 권장: gpasswd -d [계정명] root\n"
            fi
        fi

        # sudo 그룹도 확인 (Ubuntu의 경우)
        sudo_members=$(awk -F: '$1=="sudo" {print $4}' /etc/group)
        if [ -n "$sudo_members" ]; then
            found_sudo_accounts=$(echo "$sudo_members" | tr ',' '\n' | grep -wE "$unnecessary_accounts")

            if [ -n "$found_sudo_accounts" ]; then
                VULNERABLE=1
                account_list=$(echo "$found_sudo_accounts" | tr '\n' ' ' | sed 's/ $//')
                VULN_REASONS="$VULN_REASONS- sudo 그룹에 불필요한 계정 포함: $account_list → 권장: gpasswd -d [계정명] sudo\n"
            fi
        fi

    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/group 파일이 존재하지 않음\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-50 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-50 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_51() {
    echo "U-51: 계정이 존재하지 않는 GID 금지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 시스템 기본 그룹 목록 (제외할 그룹들)
    system_groups="root|daemon|bin|sys|adm|tty|disk|lp|mail|news|uucp|man|proxy|kmem|dialout|fax|voice|cdrom|floppy|tape|sudo|audio|dip|www-data|backup|operator|list|irc|src|gnats|shadow|utmp|video|sasl|plugdev|staff|games|users|nogroup|systemd-journal|systemd-network|systemd-resolve|systemd-timesync|input|sgx|kvm|render|crontab|messagebus|systemd-coredump|syslog|_ssh|tss|ssl-cert|systemd-oom|bluetooth|netdev|avahi|tcpdump|sssd|fwupd-refresh|saned|colord|geoclue|pulse|pulse-access|gdm|lxd|nm-openvpn|rtkit|saned|whoopsie|systemd-network|systemd-resolve"

    # /etc/group에서만 확인 
    if [ -f "/etc/group" ]; then
        # GID 1000 이상이면서 멤버가 없는 그룹 찾기
        empty_user_groups=$(awk -F: '$3 >= 1000 && ($4 == "" || $4 == " ") {print $1 ":" $3}' /etc/group)

        if [ -n "$empty_user_groups" ]; then
            VULNERABLE=1
            group_list=$(echo "$empty_user_groups" | while read line; do
                group_name=$(echo "$line" | cut -d: -f1)
                group_gid=$(echo "$line" | cut -d: -f2)
                echo -n "$group_name(GID:$group_gid) "
            done)
            VULN_REASONS="$VULN_REASONS- 사용자 정의 그룹 중 멤버가 없는 그룹: $group_list→ 권장: groupdel 명령으로 제거\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/group 파일이 존재하지 않음\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-51 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-51 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_52() {
    echo "U-52: 동일한 UID 금지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/passwd" ]; then
        # UID가 중복되는 계정들 찾기
        duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
        
        if [ -n "$duplicate_uids" ]; then
            VULNERABLE=1
            
            # 각 중복 UID에 대해 해당 계정들 찾기
            for uid in $duplicate_uids; do
                # 동일한 UID를 가진 계정들 찾기
                accounts_with_uid=$(awk -F: -v target_uid="$uid" '$3 == target_uid {print $1}' /etc/passwd)
                
                if [ -n "$accounts_with_uid" ]; then
                    # 줄바꿈을 공백으로 변환하여 한 줄로 표시
                    account_list=$(echo "$accounts_with_uid" | tr '\n' ' ' | sed 's/ $//')
                    VULN_REASONS="$VULN_REASONS- UID $uid 중복 계정: $account_list → 권장: usermod -u [새UID] [계정명]\n"
                fi
            done
        fi
        
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/passwd 파일이 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-52 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-52 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_53() {
    echo "U-53: 사용자 Shell 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/passwd" ]; then
        # UID 1000 미만 시스템 계정 중 로그인 가능한 쉘을 가진 계정 확인
        system_accounts_with_shell=$(awk -F: '
            $3 < 1000 && $1 != "root" && 
            $7 !~ /(nologin|false|sync|halt|shutdown)$/ && 
            $7 != "" {
                print $1 ":" $3 ":" $7
            }' /etc/passwd)
        
        if [ -n "$system_accounts_with_shell" ]; then
            VULNERABLE=1
            echo "로그인 가능한 쉘을 가진 시스템 계정:" >> $resultfile 2>&1
            echo "$system_accounts_with_shell" | while read line; do
                account=$(echo $line | cut -d: -f1)
                uid=$(echo $line | cut -d: -f2)
                shell=$(echo $line | cut -d: -f3)
                echo "  계정: $account (UID:$uid), 쉘: $shell" >> $resultfile 2>&1
            done
            
            account_list=$(echo "$system_accounts_with_shell" | cut -d: -f1 | tr '\n' ' ' | sed 's/ $//')
            VULN_REASONS="$VULN_REASONS- 시스템 계정이 로그인 가능한 쉘 사용: $account_list → 권장: usermod -s /usr/sbin/nologin [계정명]\n"
        fi
        
        # 일반 사용자 계정(UID 1000 이상) 중 비정상적인 쉘 확인
        user_accounts_bad_shell=$(awk -F: '
            $3 >= 1000 && 
            $7 ~ /(nologin|false|sync|halt|shutdown)$/ {
                print $1 ":" $3 ":" $7
            }' /etc/passwd)
        
        if [ -n "$user_accounts_bad_shell" ]; then
            echo "로그인이 제한된 일반 사용자 계정:" >> $resultfile 2>&1
            echo "$user_accounts_bad_shell" | while read line; do
                account=$(echo $line | cut -d: -f1)
                uid=$(echo $line | cut -d: -f2)
                shell=$(echo $line | cut -d: -f3)
                echo "  계정: $account (UID:$uid), 쉘: $shell" >> $resultfile 2>&1
            done
        fi
        
        # 존재하지 않는 쉘 경로 확인
        invalid_shells=$(awk -F: '$7 != "" && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $7}' /etc/passwd | sort -u | while read shell; do
            if [ ! -x "$shell" ]; then
                echo "$shell"
            fi
        done)
        
        if [ -n "$invalid_shells" ]; then
            VULNERABLE=1
            shell_list=$(echo "$invalid_shells" | tr '\n' ' ' | sed 's/ $//')
            VULN_REASONS="$VULN_REASONS- 존재하지 않는 쉘 경로 사용: $shell_list → 권장: 유효한 쉘로 변경\n"
        fi
        
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/passwd 파일이 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-53 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-53 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_54() {
    echo "U-54: 세션 타임아웃 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 1. 전역 프로필에서 TMOUT 설정 확인
    profile_files=("/etc/profile" "/etc/bash.bashrc" "/etc/bashrc")
    tmout_found=0

    for profile in "${profile_files[@]}"; do
        if [ -f "$profile" ]; then
            # TMOUT 설정이 있고 주석이 아닌 경우
            tmout_setting=$(grep -E "^\s*export\s+TMOUT=|^\s*TMOUT=" "$profile" 2>/dev/null | grep -v "^#")
            if [ -n "$tmout_setting" ]; then
                tmout_found=1
                # TMOUT 값 추출
                tmout_value=$(echo "$tmout_setting" | sed -E 's/.*TMOUT=([0-9]+).*/\1/')

                if [ -n "$tmout_value" ] && [[ "$tmout_value" =~ ^[0-9]+$ ]]; then
                    if [ "$tmout_value" -gt 600 ] || [ "$tmout_value" -eq 0 ]; then
                        VULNERABLE=1
                        VULN_REASONS="$VULN_REASONS- $profile에서 TMOUT 값이 부적절함 (현재: ${tmout_value}초) → 권장: TMOUT=600 이하 설정\n"
                    else
                        echo "$profile에서 TMOUT=$tmout_value 설정됨 [양호]" >> $resultfile 2>&1
                    fi
                fi
            fi
        fi
    done

    if [ "$tmout_found" -eq 0 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 전역 프로필에서 TMOUT 설정이 없음 → 권장: /etc/profile에 'export TMOUT=600' 추가\n"
    fi

    # 2. SSH 설정에서 세션 타임아웃 확인
    if [ -f "/etc/ssh/sshd_config" ]; then
        # ClientAliveInterval 확인
        client_alive_interval=$(grep -E "^\s*ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}')
        if [ -z "$client_alive_interval" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH ClientAliveInterval 설정이 없음 → 권장: ClientAliveInterval 300 설정\n"
        elif [ "$client_alive_interval" -gt 600 ] || [ "$client_alive_interval" -eq 0 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH ClientAliveInterval 값이 부적절함 (현재: $client_alive_interval) → 권장: 300 이하로 설정\n"
        fi

        # ClientAliveCountMax 확인
        client_alive_count=$(grep -E "^\s*ClientAliveCountMax" /etc/ssh/sshd_config | awk '{print $2}')
        if [ -z "$client_alive_count" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH ClientAliveCountMax 설정이 없음 → 권장: ClientAliveCountMax 0 설정\n"
        elif [ "$client_alive_count" -gt 3 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH ClientAliveCountMax 값이 부적절함 (현재: $client_alive_count) → 권장: 0-3 범위로 설정\n"
        fi
    else
        echo "SSH 설정 파일이 존재하지 않음" >> $resultfile 2>&1
    fi

    # 3. 현재 TMOUT 환경변수 확인
    if [ -n "$TMOUT" ]; then
        if [ "$TMOUT" -gt 600 ] || [ "$TMOUT" -eq 0 ]; then
            echo "현재 세션 TMOUT=$TMOUT (부적절)" >> $resultfile 2>&1
        else
            echo "현재 세션 TMOUT=$TMOUT (적절)" >> $resultfile 2>&1
        fi
    else
        echo "현재 세션에 TMOUT 설정 없음" >> $resultfile 2>&1
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-54 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-54 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
#task 파일 및 디렉터리 | 파일이나 디렉터리의 접근 권한 등을 점검
u_05(){

    echo "U-05: root홈, 패스 디렉토리 권한 및 패스 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # PATH에서 현재 디렉토리(.) 또는 연속된 콜론(::) 확인
    if echo "$PATH" | grep -q '\.' || echo "$PATH" | grep -q '::'; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- PATH에 현재 디렉토리(.) 또는 빈 경로가 포함됨 → 권장: PATH 설정 수정\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-05 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-05 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
#검사하는데 다소 시간이 걸리는 항목
u_06() {
    echo "U-06: 파일 및 디렉터리 소유자 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 소유자가 존재하지 않는 파일/디렉터리 검색
    echo "전체 파일시스템 검사 중... (시간이 소요될 수 있습니다)" >> $resultfile 2>&1
    
    # 개수만 먼저 확인
    orphan_count=$(find / \( -nouser -o -nogroup \) 2>/dev/null | wc -l)
    
    if [ "$orphan_count" -gt 0 ]; then
        VULNERABLE=1
        echo "소유자가 존재하지 않는 파일/디렉터리: $orphan_count 개 발견" >> $resultfile 2>&1
        
        # 처음 5개만 예시로 표시
        echo "예시 (처음 5개):" >> $resultfile 2>&1
        find / \( -nouser -o -nogroup \) 2>/dev/null | head -5 | while read file; do
            echo "  $file" >> $resultfile 2>&1
        done
        
        if [ "$orphan_count" -gt 5 ]; then
            echo "  ... 외 $((orphan_count - 5))개 더 있음" >> $resultfile 2>&1
        fi
        
        VULN_REASONS="$VULN_REASONS- 소유자가 존재하지 않는 파일 $orphan_count개 발견 → 권장: find / -nouser -o -nogroup 으로 전체 확인 후 chown 설정\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-06 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-06 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_07() {
    echo "U-07: /etc/passwd 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/passwd" ]; then
        # 소유자 확인
        pw_owner=$(stat -c "%U" /etc/passwd 2>/dev/null)
        if [ "$pw_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/passwd 파일 소유자가 root가 아님 (현재: $pw_owner) → 권장: chown root /etc/passwd\n"
        fi
        
        # 그룹 확인
        pw_group=$(stat -c "%G" /etc/passwd 2>/dev/null)
        if [ "$pw_group" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/passwd 파일 그룹이 root가 아님 (현재: $pw_group) → 권장: chgrp root /etc/passwd\n"
        fi
        
        # 권한 확인 (644 이하)
        pw_perm=$(stat -c "%a" /etc/passwd 2>/dev/null)
        if [ -n "$pw_perm" ] && [[ "$pw_perm" =~ ^[0-9]+$ ]]; then
            if [ "$pw_perm" -gt 644 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/passwd 파일 권한이 644보다 큼 (현재: $pw_perm) → 권장: chmod 644 /etc/passwd\n"
            fi
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/passwd 파일이 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-07 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-07 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_08() {
    echo "U-08: /etc/shadow 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
 
    if [ -f "/etc/shadow" ]; then
        # 소유자 확인 - 수정: /etc/shadow 파일 확인
        shadow_owner=$(stat -c "%U" /etc/shadow 2>/dev/null)
        if [ "$shadow_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/shadow 파일 소유자가 root가 아님 (현재: $shadow_owner) → 권장: chown root /etc/shadow\n"
        fi
        
        # 그룹 확인 - 추가
        shadow_group=$(stat -c "%G" /etc/shadow 2>/dev/null)
        if [ "$shadow_group" != "root" ] && [ "$shadow_group" != "shadow" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/shadow 파일 그룹이 적절하지 않음 (현재: $shadow_group) → 권장: chgrp shadow /etc/shadow\n"
        fi
        
        # 권한 확인 (640 이하) - 수정: /etc/shadow 파일 확인 및 적절한 권한값
        shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null)
        if [ -n "$shadow_perm" ] && [[ "$shadow_perm" =~ ^[0-9]+$ ]]; then
            if [ "$shadow_perm" -gt 640 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/shadow 파일 권한이 640보다 큼 (현재: $shadow_perm) → 권장: chmod 640 /etc/shadow\n"
            fi
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/shadow 파일이 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-08 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-08 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_09() {
    echo "U-09: /etc/hosts 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/hosts" ]; then
        # 소유자 확인 - 수정: /etc/hosts 파일 확인
        hosts_owner=$(stat -c "%U" /etc/hosts 2>/dev/null)
        if [ "$hosts_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts 파일 소유자가 root가 아님 (현재: $hosts_owner) → 권장: chown root /etc/hosts\n"
        fi
        
        # 그룹 확인 - 수정: /etc/hosts 파일 확인
        hosts_group=$(stat -c "%G" /etc/hosts 2>/dev/null)
        if [ "$hosts_group" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts 파일 그룹이 root가 아님 (현재: $hosts_group) → 권장: chgrp root /etc/hosts\n"
        fi
        
        # 권한 확인 (644 이하) - 수정: 적절한 권한값
        hosts_perm=$(stat -c "%a" /etc/hosts 2>/dev/null)
        if [ -n "$hosts_perm" ] && [[ "$hosts_perm" =~ ^[0-9]+$ ]]; then
            if [ "$hosts_perm" -gt 644 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/hosts 파일 권한이 644보다 큼 (현재: $hosts_perm) → 권장: chmod 644 /etc/hosts\n"
            fi
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/hosts 파일이 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-09 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-09 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_10() {
    echo "U-10: /etc/inetd.conf 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/inetd.conf" ]; then
        # 소유자 확인
        inetd_owner=$(stat -c "%U" /etc/inetd.conf 2>/dev/null)
        if [ "$inetd_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/inetd.conf 파일 소유자가 root가 아님 (현재: $inetd_owner) → 권장: chown root /etc/inetd.conf\n"
        fi
        
        # 그룹 확인
        inetd_group=$(stat -c "%G" /etc/inetd.conf 2>/dev/null)
        if [ "$inetd_group" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/inetd.conf 파일 그룹이 root가 아님 (현재: $inetd_group) → 권장: chgrp root /etc/inetd.conf\n"
        fi
        
        # 권한 확인 (600 이하)
        inetd_perm=$(stat -c "%a" /etc/inetd.conf 2>/dev/null)
        if [ -n "$inetd_perm" ] && [[ "$inetd_perm" =~ ^[0-9]+$ ]]; then
            if [ "$inetd_perm" -gt 600 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/inetd.conf 파일 권한이 600보다 큼 (현재: $inetd_perm) → 권장: chmod 600 /etc/inetd.conf\n"
            fi
        fi
    else
        echo "/etc/inetd.conf 파일이 존재하지 않음 (최근 시스템에서는 정상)" >> $resultfile 2>&1
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-10 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-10 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_11() {
    echo "U-11: /etc/syslog.conf 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # syslog.conf 또는 rsyslog.conf 확인
    syslog_files=("/etc/syslog.conf" "/etc/rsyslog.conf")
    found_file=""
    
    for file in "${syslog_files[@]}"; do
        if [ -f "$file" ]; then
            found_file="$file"
            break
        fi
    done
    
    if [ -n "$found_file" ]; then
        echo "점검 대상 파일: $found_file" >> $resultfile 2>&1
        
        # 소유자 확인
        syslog_owner=$(stat -c "%U" "$found_file" 2>/dev/null)
        if [ "$syslog_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- $found_file 파일 소유자가 root가 아님 (현재: $syslog_owner) → 권장: chown root $found_file\n"
        fi
        
        # 그룹 확인
        syslog_group=$(stat -c "%G" "$found_file" 2>/dev/null)
        if [ "$syslog_group" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- $found_file 파일 그룹이 root가 아님 (현재: $syslog_group) → 권장: chgrp root $found_file\n"
        fi
        
        # 권한 확인 (640 이하)
        syslog_perm=$(stat -c "%a" "$found_file" 2>/dev/null)
        if [ -n "$syslog_perm" ] && [[ "$syslog_perm" =~ ^[0-9]+$ ]]; then
            if [ "$syslog_perm" -gt 640 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $found_file 파일 권한이 640보다 큼 (현재: $syslog_perm) → 권장: chmod 640 $found_file\n"
            fi
        fi
    else
        echo "syslog 설정 파일이 존재하지 않음 (systemd-journald 사용 가능)" >> $resultfile 2>&1
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-11 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-11 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_12() {
    echo "U-12: /etc/services 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/services" ]; then
        # 소유자 확인
        services_owner=$(stat -c "%U" /etc/services 2>/dev/null)
        if [ "$services_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/services 파일 소유자가 root가 아님 (현재: $services_owner) → 권장: chown root /etc/services\n"
        fi
        
        # 그룹 확인
        services_group=$(stat -c "%G" /etc/services 2>/dev/null)
        if [ "$services_group" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/services 파일 그룹이 root가 아님 (현재: $services_group) → 권장: chgrp root /etc/services\n"
        fi
        
        # 권한 확인 (644 이하)
        services_perm=$(stat -c "%a" /etc/services 2>/dev/null)
        if [ -n "$services_perm" ] && [[ "$services_perm" =~ ^[0-9]+$ ]]; then
            if [ "$services_perm" -gt 644 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/services 파일 권한이 644보다 큼 (현재: $services_perm) → 권장: chmod 644 /etc/services\n"
            fi
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/services 파일이 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-12 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-12 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_13() {
    echo "U-13: SUID/SGID 파일 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 주요 디렉터리에서 SUID/SGID 파일 검색 (시간 제한)
    echo "SUID/SGID 파일 검색 중..." >> $resultfile 2>&1
    
    # 위험할 수 있는 SUID/SGID 파일들 (일반적으로 불필요한 것들)
    dangerous_files=("/sbin/dump" "/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/at" "/usr/bin/lpq" "/usr/bin/lpq-lpd" "/usr/bin/lpr" "/usr/bin/lpr-lpd" "/usr/bin/lprm" "/usr/bin/lprm-lpd" "/usr/bin/newgrp" "/usr/sbin/lpc" "/usr/sbin/lpc-lpd" "/usr/sbin/traceroute")
    
    # 위험한 파일들 중 SUID/SGID 설정된 것 확인
    found_dangerous=0
    for file in "${dangerous_files[@]}"; do
        if [ -f "$file" ]; then
            # SUID(4000) 또는 SGID(2000) 비트 확인
            if [ -u "$file" ] || [ -g "$file" ]; then
                if [ $found_dangerous -eq 0 ]; then
                    echo "위험할 수 있는 SUID/SGID 파일 발견:" >> $resultfile 2>&1
                    found_dangerous=1
                fi
                
                file_perm=$(stat -c "%a" "$file" 2>/dev/null)
                file_owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
                echo "  $file (권한:$file_perm, 소유자:$file_owner)" >> $resultfile 2>&1
                VULNERABLE=1
            fi
        fi
    done
    
    if [ $found_dangerous -eq 1 ]; then
        VULN_REASONS="$VULN_REASONS- 위험할 수 있는 SUID/SGID 파일이 발견됨 → 권장: chmod u-s,g-s [파일명] 으로 제거\n"
    fi
    
    # 전체 시스템에서 SUID/SGID 파일 목록 확인 (주요 디렉터리만)
    echo "전체 SUID/SGID 파일 목록:" >> $resultfile 2>&1
    suid_files=$(find /bin /sbin /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    
    if [ -n "$suid_files" ]; then
        echo "$suid_files" | while read file; do
            if [ -f "$file" ]; then
                file_perm=$(stat -c "%a" "$file" 2>/dev/null)
                file_owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
                echo "  $file (권한:$file_perm, 소유자:$file_owner)" >> $resultfile 2>&1
            fi
        done
        
        suid_count=$(echo "$suid_files" | wc -l)
        echo "총 $suid_count 개의 SUID/SGID 파일 발견" >> $resultfile 2>&1
        
        if [ "$suid_count" -gt 50 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SUID/SGID 파일이 과도하게 많음 ($suid_count개) → 권장: 불필요한 파일들의 SUID/SGID 제거\n"
        fi
    else
        echo "  SUID/SGID 파일이 발견되지 않음" >> $resultfile 2>&1
    fi
    
    # 추가 보안 점검: 일반 사용자 소유의 SUID 파일
    user_suid=$(find /home -type f -perm -4000 2>/dev/null)
    if [ -n "$user_suid" ]; then
        VULNERABLE=1
        echo "일반 사용자 디렉터리의 SUID 파일:" >> $resultfile 2>&1
        echo "$user_suid" | while read file; do
            echo "  $file" >> $resultfile 2>&1
        done
        VULN_REASONS="$VULN_REASONS- 일반 사용자 디렉터리에 SUID 파일 발견 → 권장: 제거 또는 권한 조정\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-13 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
        echo "참고: find / -type f \\( -perm -4000 -o -perm -2000 \\) 명령으로 전체 확인 가능" >> $resultfile 2>&1
    else
        echo "U-13 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_14() {
    echo "U-14: 사용자, 시스템 시작 파일 및 환경 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 점검할 환경 파일들
    start_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
    
    # 로그인 가능한 사용자의 홈 디렉터리 확인
    while IFS=: read -r username _ uid _ _ homedir shell; do
        # 로그인 가능한 사용자만 (nologin, false 제외)
        if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" && "$homedir" != "" && -d "$homedir" ]]; then
            
            for start_file in "${start_files[@]}"; do
                file_path="$homedir/$start_file"
                
                if [ -f "$file_path" ]; then
                    # 파일 소유자 확인
                    file_owner=$(stat -c "%U" "$file_path" 2>/dev/null)
                    file_perm=$(stat -c "%a" "$file_path" 2>/dev/null)
                    
                    # 소유자가 root 또는 해당 사용자가 아닌 경우
                    if [ "$file_owner" != "root" ] && [ "$file_owner" != "$username" ]; then
                        VULNERABLE=1
                        VULN_REASONS="$VULN_REASONS- $file_path 파일 소유자가 부적절함 (소유자: $file_owner, 해당사용자: $username) → 권장: chown $username $file_path\n"
                    fi
                    
                    # other 권한에 쓰기 권한이 있는지 확인 (마지막 자리가 2,3,6,7인 경우)
                    if [ -n "$file_perm" ]; then
                        other_perm=$((file_perm % 10))
                        if [ $((other_perm & 2)) -ne 0 ]; then
                            VULNERABLE=1
                            VULN_REASONS="$VULN_REASONS- $file_path 파일에 other 쓰기 권한 있음 (권한: $file_perm) → 권장: chmod o-w $file_path\n"
                        fi
                    fi
                fi
            done
        fi
    done < /etc/passwd
    
    # /home 디렉터리의 추가 사용자 디렉터리 확인
    if [ -d "/home" ]; then
        for user_dir in /home/*; do
            if [ -d "$user_dir" ]; then
                username=$(basename "$user_dir")
                
                for start_file in "${start_files[@]}"; do
                    file_path="$user_dir/$start_file"
                    
                    if [ -f "$file_path" ]; then
                        file_owner=$(stat -c "%U" "$file_path" 2>/dev/null)
                        file_perm=$(stat -c "%a" "$file_path" 2>/dev/null)
                        
                        # 소유자 확인
                        if [ "$file_owner" != "root" ] && [ "$file_owner" != "$username" ]; then
                            VULNERABLE=1
                            VULN_REASONS="$VULN_REASONS- $file_path 파일 소유자가 부적절함 (소유자: $file_owner) → 권장: chown $username $file_path\n"
                        fi
                        
                        # other 쓰기 권한 확인
                        if [ -n "$file_perm" ]; then
                            other_perm=$((file_perm % 10))
                            if [ $((other_perm & 2)) -ne 0 ]; then
                                VULNERABLE=1
                                VULN_REASONS="$VULN_REASONS- $file_path 파일에 other 쓰기 권한 있음 (권한: $file_perm) → 권장: chmod o-w $file_path\n"
                            fi
                        fi
                    fi
                done
            fi
        done
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-14 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-14 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_15() {
    echo "U-15: world writable 파일 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # /proc, /sys, /dev 등 시스템 디렉터리 제외하고 전체 검색
    world_writable=$(find / -type f -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" 2>/dev/null)
    
    if [ -n "$world_writable" ]; then
        VULNERABLE=1
        echo "world writable 파일 발견:" >> $resultfile 2>&1
        echo "$world_writable" | while read file; do
            if [ -f "$file" ]; then
                file_perm=$(stat -c "%a" "$file" 2>/dev/null)
                file_owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
                echo "  $file (권한:$file_perm, 소유자:$file_owner)" >> $resultfile 2>&1
            fi
        done
        
        file_count=$(echo "$world_writable" | wc -l)
        VULN_REASONS="$VULN_REASONS- world writable 파일 $file_count개 발견 → 권장: chmod o-w [파일명] 으로 쓰기 권한 제거\n"
    fi
    
    # /tmp 디렉터리 별도 확인 (sticky bit 있는지)
    if [ -d "/tmp" ]; then
        tmp_perm=$(stat -c "%a" /tmp 2>/dev/null)
        if [ -n "$tmp_perm" ]; then
            # sticky bit (1000번대) 확인
            if [ "$tmp_perm" -lt 1000 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /tmp 디렉터리에 sticky bit가 설정되지 않음 (현재: $tmp_perm) → 권장: chmod 1777 /tmp\n"
            fi
        fi
    fi
    
    # 홈 디렉터리 내 world writable 파일 확인
    if [ -d "/home" ]; then
        home_writable=$(find /home -type f -perm -002 2>/dev/null)
        if [ -n "$home_writable" ]; then
            VULNERABLE=1
            echo "홈 디렉터리 내 world writable 파일:" >> $resultfile 2>&1
            echo "$home_writable" | while read file; do
                echo "  $file" >> $resultfile 2>&1
            done
            VULN_REASONS="$VULN_REASONS- 홈 디렉터리에 world writable 파일 발견 → 권장: 권한 조정 필요\n"
        fi
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-15 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
        echo "참고: find / -type f -perm -002 명령으로 전체 확인 가능" >> $resultfile 2>&1
    else
        echo "U-15 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_16() {
    echo "U-16: /dev에 존재하지 않는 device 파일 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -d "/dev" ]; then
        # /dev 디렉터리에서 일반 파일(regular file) 검색
        regular_files=$(find /dev -type f 2>/dev/null)
        
        if [ -n "$regular_files" ]; then
            VULNERABLE=1
            echo "/dev 디렉터리에서 일반 파일 발견:" >> $resultfile 2>&1
            
            echo "$regular_files" | while read file; do
                if [ -f "$file" ]; then
                    file_perm=$(stat -c "%a" "$file" 2>/dev/null)
                    file_owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
                    file_size=$(stat -c "%s" "$file" 2>/dev/null)
                    echo "  $file (권한:$file_perm, 소유자:$file_owner, 크기:${file_size}bytes)" >> $resultfile 2>&1
                fi
            done
            
            file_count=$(echo "$regular_files" | wc -l)
            VULN_REASONS="$VULN_REASONS- /dev 디렉터리에 일반 파일 $file_count개 발견 → 권장: 파일 확인 후 제거 또는 적절한 위치로 이동\n"
        fi
        
        # 추가로 의심스러운 실행 파일 확인
        executable_files=$(find /dev -type f -executable 2>/dev/null)
        if [ -n "$executable_files" ]; then
            VULNERABLE=1
            echo "/dev 디렉터리에서 실행 가능한 파일 발견:" >> $resultfile 2>&1
            echo "$executable_files" | while read file; do
                echo "  $file" >> $resultfile 2>&1
            done
            VULN_REASONS="$VULN_REASONS- /dev 디렉터리에 실행 파일 발견 → 권장: 즉시 제거 (보안 위험)\n"
        fi
        
        # 숨겨진 파일 확인
        hidden_files=$(find /dev -name ".*" -type f 2>/dev/null)
        if [ -n "$hidden_files" ]; then
            VULNERABLE=1
            echo "/dev 디렉터리에서 숨겨진 파일 발견:" >> $resultfile 2>&1
            echo "$hidden_files" | while read file; do
                echo "  $file" >> $resultfile 2>&1
            done
            VULN_REASONS="$VULN_REASONS- /dev 디렉터리에 숨겨진 파일 발견 → 권장: 파일 확인 후 제거\n"
        fi
        
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /dev 디렉터리가 존재하지 않음\n"
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-16 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
        echo "참고: /dev 디렉터리에는 디바이스 파일만 존재해야 합니다" >> $resultfile 2>&1
    else
        echo "U-16 최종 결과: 양호" >> $resultfile 2>&1
        echo "/dev 디렉터리에 일반 파일이 존재하지 않습니다" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_17() {
    echo "U-17: \$HOME/.rhosts, hosts.equiv 사용 금지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # r-command 서비스 사용 여부 확인
    rlogin_running=$(ps aux | grep -E "(rlogind|rshd)" | grep -v grep 2>/dev/null)
    if [ -n "$rlogin_running" ]; then
        echo "r-command 서비스 실행 중:" >> $resultfile 2>&1
        echo "$rlogin_running" >> $resultfile 2>&1
    else
        echo "r-command 서비스가 실행되지 않음" >> $resultfile 2>&1
    fi

    # 1. /etc/hosts.equiv 파일 점검
    if [ -f "/etc/hosts.equiv" ]; then
        echo "/etc/hosts.equiv 파일이 존재합니다" >> $resultfile 2>&1

        # 소유자 확인
        file_owner=$(stat -c "%U" /etc/hosts.equiv 2>/dev/null)
        if [ "$file_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.equiv 파일 소유자가 root가 아님 (현재: $file_owner) → 권장: chown root /etc/hosts.equiv\n"
        fi

        # 권한 확인 (600 이하)
        file_perm=$(stat -c "%a" /etc/hosts.equiv 2>/dev/null)
        if [ -n "$file_perm" ] && [ "$file_perm" -gt 600 ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.equiv 파일 권한이 600을 초과함 (현재: $file_perm) → 권장: chmod 600 /etc/hosts.equiv\n"
        fi

        # '+' 설정 확인
        plus_setting=$(grep -E "^\s*\+\s*$|^\s*\+\s+\+\s*$" /etc/hosts.equiv 2>/dev/null)
        if [ -n "$plus_setting" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.equiv 파일에 '+' 설정이 있음 (모든 호스트 허용) → 권장: '+' 설정 제거\n"
            echo "  위험한 '+' 설정 발견:" >> $resultfile 2>&1
            echo "$plus_setting" | while read line; do
                echo "    $line" >> $resultfile 2>&1
            done
        fi

        # 파일 내용 요약
        echo "  /etc/hosts.equiv 파일 정보: 소유자=$file_owner, 권한=$file_perm" >> $resultfile 2>&1
    fi

    # 2. 사용자 홈 디렉터리의 .rhosts 파일 점검
    while IFS=: read -r username _ uid _ _ homedir shell; do
        if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" && "$homedir" != "" && -d "$homedir" ]]; then
            rhosts_file="$homedir/.rhosts"

            if [ -f "$rhosts_file" ]; then
                echo "$username 사용자의 .rhosts 파일이 존재합니다" >> $resultfile 2>&1

                # 소유자 확인
                file_owner=$(stat -c "%U" "$rhosts_file" 2>/dev/null)
                if [ "$file_owner" != "root" ] && [ "$file_owner" != "$username" ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- $rhosts_file 파일 소유자가 부적절함 (소유자: $file_owner) → 권장: chown $username $rhosts_file\n"
                fi

                # 권한 확인 (600 이하)
                file_perm=$(stat -c "%a" "$rhosts_file" 2>/dev/null)
                if [ -n "$file_perm" ] && [ "$file_perm" -gt 600 ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- $rhosts_file 파일 권한이 600을 초과함 (현재: $file_perm) → 권장: chmod 600 $rhosts_file\n"
                fi

                # '+' 설정 확인
                plus_setting=$(grep -E "^\s*\+\s*$|^\s*\+\s+\+\s*$" "$rhosts_file" 2>/dev/null)
                if [ -n "$plus_setting" ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- $rhosts_file 파일에 '+' 설정이 있음 (모든 호스트 허용) → 권장: '+' 설정 제거\n"
                    echo "  $rhosts_file에서 위험한 '+' 설정 발견:" >> $resultfile 2>&1
                    echo "$plus_setting" | while read line; do
                        echo "    $line" >> $resultfile 2>&1
                    done
                fi

                echo "  $rhosts_file 파일 정보: 소유자=$file_owner, 권한=$file_perm" >> $resultfile 2>&1
            fi
        fi
    done < /etc/passwd

    # 3. xinetd 또는 inetd에서 r-command 서비스 확인
    rcommand_services=""
    if [ -d "/etc/xinetd.d" ]; then
        rcommand_services=$(grep -l "rlogin\|rsh\|rexec" /etc/xinetd.d/* 2>/dev/null)
        if [ -n "$rcommand_services" ]; then
            echo "xinetd에서 r-command 서비스 설정 발견:" >> $resultfile 2>&1
            echo "$rcommand_services" >> $resultfile 2>&1
        fi
    fi

    if [ -f "/etc/inetd.conf" ]; then
        inetd_rcommand=$(grep -E "^[^#]*rlogin|^[^#]*rsh|^[^#]*rexec" /etc/inetd.conf 2>/dev/null)
        if [ -n "$inetd_rcommand" ]; then
            echo "inetd.conf에서 r-command 서비스 설정 발견:" >> $resultfile 2>&1
            echo "$inetd_rcommand" >> $resultfile 2>&1
            VULN_REASONS="$VULN_REASONS- inetd.conf에서 r-command 서비스가 활성화됨 → 권장: 서비스 비활성화\n"
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-17 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
        echo "권장사항: r-command 서비스를 SSH로 대체하는 것을 권장합니다" >> $resultfile 2>&1
    else
        if [ ! -f "/etc/hosts.equiv" ] && [ -z "$(find /home -name ".rhosts" -type f 2>/dev/null)" ]; then
            echo "U-17 최종 결과: 양호" >> $resultfile 2>&1
            echo "hosts.equiv 및 .rhosts 파일이 존재하지 않습니다" >> $resultfile 2>&1
        else
            echo "U-17 최종 결과: 양호" >> $resultfile 2>&1
            echo "r-command 관련 파일들이 안전하게 설정되어 있습니다" >> $resultfile 2>&1
        fi
    fi

    return $VULNERABLE
}
u_18() {
    echo "U-18: 접속 IP 및 포트 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 1. /etc/hosts.deny 파일 점검
    if [ -f "/etc/hosts.deny" ]; then
        # 소유자 확인
        hosts_deny_owner=$(stat -c "%U" /etc/hosts.deny 2>/dev/null)
        if [ "$hosts_deny_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.deny 파일의 소유자가 root가 아님 (현재: $hosts_deny_owner) → 권장: chown root /etc/hosts.deny\n"
        fi
        
        # ALL:ALL 설정 확인
        if ! grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.deny 2>/dev/null | grep -qiE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL[[:space:]]*'; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.deny에 ALL:ALL 설정이 없음 → 권장: 'ALL:ALL' 설정 추가\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/hosts.deny 파일이 존재하지 않음 → 권장: 파일 생성 후 'ALL:ALL' 설정\n"
    fi
    
    # 2. /etc/hosts.allow 파일 점검
    if [ -f "/etc/hosts.allow" ]; then
        # 소유자 확인
        hosts_allow_owner=$(stat -c "%U" /etc/hosts.allow 2>/dev/null)
        if [ "$hosts_allow_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.allow 파일의 소유자가 root가 아님 (현재: $hosts_allow_owner) → 권장: chown root /etc/hosts.allow\n"
        fi
        
        # 위험한 ALL:ALL 설정 확인
        if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.allow 2>/dev/null | grep -qiE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL[[:space:]]*'; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.allow에 ALL:ALL 설정이 있음 (모든 접근 허용) → 권장: 특정 IP/서비스만 허용하도록 수정\n"
        fi
    fi
    
    # 3. iptables 방화벽 점검
    if command -v iptables >/dev/null 2>&1; then
        # INPUT 체인 기본 정책 확인
        input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1)
        if [ -n "$input_policy" ]; then
            if echo "$input_policy" | grep -q "policy ACCEPT"; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- iptables INPUT 체인 기본 정책이 ACCEPT로 설정됨 → 권장: iptables -P INPUT DROP\n"
            fi
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- iptables 방화벽이 설치되지 않음 → 권장: 방화벽 설치 및 설정\n"
    fi
    
    # 4. UFW 방화벽 점검
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(ufw status 2>/dev/null)
        if [ -n "$ufw_status" ]; then
            if echo "$ufw_status" | grep -q "Status: inactive"; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- UFW 방화벽이 비활성화되어 있음 → 권장: ufw enable\n"
            fi
        fi
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-18 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-18 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_55() {
    echo "U-55: hosts.lpd 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # /etc/hosts.lpd 파일 점검
    if [ -f "/etc/hosts.lpd" ]; then
        # 소유자 확인
        hosts_lpd_owner=$(stat -c "%U" /etc/hosts.lpd 2>/dev/null)
        if [ "$hosts_lpd_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.lpd 파일 소유자가 root가 아님 (현재: $hosts_lpd_owner) → 권장: chown root /etc/hosts.lpd\n"
        fi
        
        # 그룹 확인
        hosts_lpd_group=$(stat -c "%G" /etc/hosts.lpd 2>/dev/null)
        if [ "$hosts_lpd_group" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/hosts.lpd 파일 그룹이 root가 아님 (현재: $hosts_lpd_group) → 권장: chgrp root /etc/hosts.lpd\n"
        fi
        
        # 권한 확인 (600 이하)
        hosts_lpd_perm=$(stat -c "%a" /etc/hosts.lpd 2>/dev/null)
        if [ -n "$hosts_lpd_perm" ] && [[ "$hosts_lpd_perm" =~ ^[0-9]+$ ]]; then
            if [ "$hosts_lpd_perm" -gt 600 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/hosts.lpd 파일 권한이 600을 초과함 (현재: $hosts_lpd_perm) → 권장: chmod 600 /etc/hosts.lpd\n"
            fi
        fi
        
        echo "/etc/hosts.lpd 파일이 존재합니다 - 권한 점검 완료" >> $resultfile 2>&1
    else
        echo "/etc/hosts.lpd 파일이 존재하지 않습니다 (양호)" >> $resultfile 2>&1
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-55 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-55 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_56() {
    echo "U-56: UMASK 설정 관리" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 1. 현재 umask 값 확인
    if command -v umask >/dev/null 2>&1; then
        current_umask=$(umask 2>/dev/null)
        if [ -n "$current_umask" ]; then
            # 4자리로 맞춤 (예: 22 -> 0022)
            while [ ${#current_umask} -lt 4 ]; do
                current_umask="0${current_umask}"
            done
            
            # group 권한 확인 (3번째 자리)
            group_digit="${current_umask:2:1}"
            if [ "$group_digit" -lt 2 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- 현재 UMASK의 그룹 사용자 권한이 취약함 (현재: $current_umask) → 권장: umask 022 설정\n"
            fi
            
            # other 권한 확인 (4번째 자리)
            other_digit="${current_umask:3:1}"
            if [ "$other_digit" -lt 2 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- 현재 UMASK의 다른 사용자 권한이 취약함 (현재: $current_umask) → 권장: umask 022 설정\n"
            fi
            
            echo "현재 UMASK: $current_umask" >> $resultfile 2>&1
        else
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 현재 UMASK 값을 확인할 수 없음 → 권장: umask 022 설정\n"
        fi
    fi
    
    # 2. /etc/login.defs 파일에서 UMASK 설정 확인
    if [ -f "/etc/login.defs" ]; then
        login_defs_umask=$(grep -v "^#" /etc/login.defs 2>/dev/null | grep -i "^UMASK" | awk '{print $2}' | tail -1)
        if [ -n "$login_defs_umask" ]; then
            # 4자리로 맞춤
            while [ ${#login_defs_umask} -lt 4 ]; do
                login_defs_umask="0${login_defs_umask}"
            done
            
            # group 권한 확인
            group_digit="${login_defs_umask:2:1}"
            if [ "$group_digit" -lt 2 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/login.defs의 UMASK 그룹 권한이 취약함 (현재: $login_defs_umask) → 권장: UMASK 022로 변경\n"
            fi
            
            # other 권한 확인
            other_digit="${login_defs_umask:3:1}"
            if [ "$other_digit" -lt 2 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/login.defs의 UMASK 다른 사용자 권한이 취약함 (현재: $login_defs_umask) → 권장: UMASK 022로 변경\n"
            fi
            
            echo "/etc/login.defs UMASK: $login_defs_umask" >> $resultfile 2>&1
        else
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/login.defs에 UMASK 설정이 없음 → 권장: UMASK 022 추가\n"
        fi
    fi
    
    # 3. /etc/profile에서 umask 설정 확인
    if [ -f "/etc/profile" ]; then
        profile_umask=$(grep -v "^#" /etc/profile 2>/dev/null | grep -i "umask" | grep -o "[0-9][0-9][0-9]" | tail -1)
        if [ -n "$profile_umask" ]; then
            # 4자리로 맞춤
            while [ ${#profile_umask} -lt 4 ]; do
                profile_umask="0${profile_umask}"
            done
            
            # group 권한 확인
            group_digit="${profile_umask:2:1}"
            if [ "$group_digit" -lt 2 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/profile의 umask 그룹 권한이 취약함 (현재: $profile_umask) → 권장: umask 022로 변경\n"
            fi
            
            # other 권한 확인
            other_digit="${profile_umask:3:1}"
            if [ "$other_digit" -lt 2 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /etc/profile의 umask 다른 사용자 권한이 취약함 (현재: $profile_umask) → 권장: umask 022로 변경\n"
            fi
            
            echo "/etc/profile umask: $profile_umask" >> $resultfile 2>&1
        fi
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-56 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-56 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_57() {
    echo "U-57: 홈디렉토리 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # /etc/passwd 파일에서 /home 하위 홈 디렉터리만 필터링 (시스템 디렉터리 제외)
    user_homedirectory_path=($(awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6~/^\/home\// {print $6}' /etc/passwd 2>/dev/null))
    
    # /home 디렉터리 내 위치한 홈 디렉터리 배열 생성
    if [ -d "/home" ]; then
        user_homedirectory_path2=($(ls -d /home/* 2>/dev/null | grep -v "lost+found"))
    else
        user_homedirectory_path2=()
    fi
    
    # 두 개의 배열 합침
    for ((i=0; i<${#user_homedirectory_path2[@]}; i++)); do
        if [ -d "${user_homedirectory_path2[$i]}" ] && [ "${user_homedirectory_path2[$i]}" != "/home" ]; then
            user_homedirectory_path[${#user_homedirectory_path[@]}]="${user_homedirectory_path2[$i]}"
        fi
    done
    
    # /etc/passwd 파일에서 /home 하위 사용자명만 필터링
    user_homedirectory_owner_name=($(awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6~/^\/home\// {print $1}' /etc/passwd 2>/dev/null))
    
    # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장
    for ((i=0; i<${#user_homedirectory_path2[@]}; i++)); do
        if [ -d "${user_homedirectory_path2[$i]}" ] && [ "${user_homedirectory_path2[$i]}" != "/home" ]; then
            dirname=$(echo "${user_homedirectory_path2[$i]}" | awk -F / '{print $3}')
            if [ -n "$dirname" ]; then
                user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]="$dirname"
            fi
        fi
    done
    
    # 각 홈 디렉터리 점검
    if [ ${#user_homedirectory_path[@]} -eq 0 ]; then
        echo "점검할 홈 디렉터리가 없음" >> $resultfile 2>&1
        echo "U-57 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi
    
    for ((i=0; i<${#user_homedirectory_path[@]}; i++)); do
        if [ -d "${user_homedirectory_path[$i]}" ]; then
            # 실제 소유자 확인
            homedirectory_owner_name=$(ls -ld "${user_homedirectory_path[$i]}" 2>/dev/null | awk '{print $3}')
            
            # 소유자 일치 여부 확인
            if [[ ! "$homedirectory_owner_name" =~ ${user_homedirectory_owner_name[$i]} ]]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- ${user_homedirectory_path[$i]} 홈 디렉터리의 소유자가 ${user_homedirectory_owner_name[$i]}이(가) 아닙니다 (현재: $homedirectory_owner_name) → 권장: chown ${user_homedirectory_owner_name[$i]} ${user_homedirectory_path[$i]}\n"
            fi
            
            # stat 명령어로 other 권한 확인
            homedirectory_other_permission=$(stat "${user_homedirectory_path[$i]}" 2>/dev/null | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}')
            
            # other 쓰기 권한이 있는 경우 (7,6,3,2) - 숫자인지 확인 후 비교
            if [ -n "$homedirectory_other_permission" ] && [[ "$homedirectory_other_permission" =~ ^[0-9]+$ ]]; then
                if [ "$homedirectory_other_permission" -eq 7 ] || [ "$homedirectory_other_permission" -eq 6 ] || [ "$homedirectory_other_permission" -eq 3 ] || [ "$homedirectory_other_permission" -eq 2 ]; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- ${user_homedirectory_path[$i]} 홈 디렉터리에 다른 사용자(other)의 쓰기 권한이 부여되어 있습니다 → 권장: chmod o-w ${user_homedirectory_path[$i]}\n"
                fi
            fi
        fi
    done
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-57 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-57 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_58() {
    echo "U-58: 홈디렉토리로 지정한 디렉토리의 존재 관리" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_COUNT=0
    
    # 카테고리별 카운터
    not_set_count=0      # 홈디렉토리 미설정
    root_set_count=0     # 루트(/) 설정
    not_exist_count=0    # 디렉토리 존재하지 않음
    orphan_count=0       # /home에 있지만 미등록
    
    # /etc/passwd에서 홈 디렉토리 정보 수집
    while IFS=: read -r username _ uid _ _ homedir shell; do
        # 로그인 가능한 사용자만 확인 (nologin, false 제외)
        if [[ "$shell" != "/bin/false" && "$shell" != "/sbin/nologin" ]]; then
            
            # 홈 디렉토리가 설정되지 않은 경우 (빈 값)
            if [ -z "$homedir" ]; then
                VULNERABLE=1
                VULN_COUNT=$((VULN_COUNT + 1))
                not_set_count=$((not_set_count + 1))
            # 홈 디렉토리가 루트(/)로 설정된 경우
            elif [ "$homedir" = "/" ]; then
                VULNERABLE=1
                VULN_COUNT=$((VULN_COUNT + 1))
                root_set_count=$((root_set_count + 1))
            else
                # 홈 디렉토리가 존재하지 않는 경우
                if [ ! -d "$homedir" ]; then
                    VULNERABLE=1
                    VULN_COUNT=$((VULN_COUNT + 1))
                    not_exist_count=$((not_exist_count + 1))
                fi
            fi
        fi
    done < /etc/passwd
    
    # 추가로 /home 디렉토리에 있지만 /etc/passwd에 등록되지 않은 디렉토리 확인
    if [ -d "/home" ]; then
        for user_dir in /home/*; do
            if [ -d "$user_dir" ]; then
                dirname=$(basename "$user_dir")
                
                # /etc/passwd에서 해당 사용자 확인
                if ! grep -q "^$dirname:" /etc/passwd 2>/dev/null; then
                    VULNERABLE=1
                    VULN_COUNT=$((VULN_COUNT + 1))
                    orphan_count=$((orphan_count + 1))
                fi
            fi
        done
    fi
    
    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-58 최종 결과: 취약 (취약 항목 $VULN_COUNT개)" >> $resultfile 2>&1
        if [ $not_set_count -gt 0 ]; then
            echo "- 홈디렉토리 미설정: ${not_set_count}개" >> $resultfile 2>&1
        fi
        if [ $root_set_count -gt 0 ]; then
            echo "- 홈디렉토리 /로 설정: ${root_set_count}개" >> $resultfile 2>&1
        fi
        if [ $not_exist_count -gt 0 ]; then
            echo "- 홈디렉토리 존재하지 않음: ${not_exist_count}개" >> $resultfile 2>&1
        fi
        if [ $orphan_count -gt 0 ]; then
            echo "- /home에 미등록 디렉토리: ${orphan_count}개" >> $resultfile 2>&1
        fi
    else
        echo "U-58 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_59() {
    echo "U-59: 숨겨진 파일 및 디렉토리 검색 및 제거" >> $resultfile 2>&1
    
    # 1단계: 사용자 영역 우선 검사 (우선순위 높음)
    user_hidden_files=$(find /home /tmp /var/tmp -name '.*' -type f 2>/dev/null | wc -l)
    user_hidden_dirs=$(find /home /tmp /var/tmp -name '.*' -type d 2>/dev/null | wc -l)
    
    # 2단계: 전체 시스템 영역 검사 (참고용)
    total_hidden_files=$(find / -name '.*' -type f 2>/dev/null | wc -l)
    total_hidden_dirs=$(find / -name '.*' -type d 2>/dev/null | wc -l)
    
    # 결과 판단
    if [ "$user_hidden_files" -gt 0 ] || [ "$user_hidden_dirs" -gt 0 ]; then
        echo "U-59 최종 결과: 취약" >> $resultfile 2>&1
        echo "※ 우선 조치 권장 영역:" >> $resultfile 2>&1
        echo "- 사용자 영역 숨겨진 파일: ${user_hidden_files}개" >> $resultfile 2>&1
        echo "- 사용자 영역 숨겨진 디렉토리: ${user_hidden_dirs}개" >> $resultfile 2>&1
        echo "전체 시스템 현황:" >> $resultfile 2>&1
        echo "- 전체 숨겨진 파일: ${total_hidden_files}개" >> $resultfile 2>&1
        echo "- 전체 숨겨진 디렉토리: ${total_hidden_dirs}개" >> $resultfile 2>&1
        return 1
    else
        echo "U-59 최종 결과: 양호 (사용자 영역 깨끗함)" >> $resultfile 2>&1
        echo "전체 시스템 현황:" >> $resultfile 2>&1
        echo "- 전체 숨겨진 파일: ${total_hidden_files}개" >> $resultfile 2>&1
        echo "- 전체 숨겨진 디렉토리: ${total_hidden_dirs}개" >> $resultfile 2>&1
        return 0
    fi
}
#task 서비스관리 | 취약한 서비스들에 대한 점검 
u_19(){

    echo "U-19: finger 서비스 비활성화" >> $resultfile 2>&1
    VULNERABLE=0
    
    # systemd 서비스 상태 확인
    active_finger=$(systemctl list-unit-files | grep -i finger | grep enabled 2>/dev/null)
    if [ -n "$active_finger" ]; then
        VULNERABLE=1
    fi
    
    # finger 프로세스 실행 확인
    finger_processes=$(ps aux | grep -i finger | grep -v grep 2>/dev/null)
    if [ -n "$finger_processes" ]; then
        VULNERABLE=1
    fi
    
    # finger 패키지 설치 여부 확인 (Ubuntu)
    finger_packages=$(dpkg -l | grep -i finger 2>/dev/null)
    if [ -n "$finger_packages" ]; then
        VULNERABLE=1
    fi
    
    # 최종 결과
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-19 최종 결과: 취약" >> $resultfile 2>&1
        return 1
    else
        echo "U-19 최종 결과: 양호 서비스 비활성화" >> $resultfile 2>&1
        return 0
    fi
}
u_20() {
    echo "U-20: Anonymous FTP 비활성화" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 1. FTP 서비스 실행 확인
    ftp_process=$(ps aux | grep -E "(vsftpd|proftpd|pureftpd|ftpd)" | grep -v grep)
    
    # 2. systemd FTP 서비스 상태 확인
    ftp_services=$(systemctl list-unit-files 2>/dev/null | grep -E "(vsftpd|proftpd|pureftpd|ftpd)" | grep enabled)
    
    # 3. FTP 패키지 설치 확인 (Ubuntu)
    ftp_packages=$(dpkg -l 2>/dev/null | grep -E "(vsftpd|proftpd|pureftpd)")

    # FTP 서비스가 활성화되어 있다면 Anonymous 설정 확인
    if [ -n "$ftp_process" ] || [ -n "$ftp_services" ] || [ -n "$ftp_packages" ]; then
        
        # vsftpd 설정 확인
        if [ -f "/etc/vsftpd.conf" ]; then
            anonymous_enabled=$(grep -E "^anonymous_enable\s*=\s*YES" /etc/vsftpd.conf 2>/dev/null)
            if [ -n "$anonymous_enabled" ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- vsftpd에서 anonymous_enable=YES로 설정됨\n"
            fi
        fi
        
        # proftpd 설정 확인
        if [ -f "/etc/proftpd/proftpd.conf" ] || [ -f "/etc/proftpd.conf" ]; then
            anonymous_user=$(grep -E "^User\s+ftp" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null)
            if [ -n "$anonymous_user" ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- proftpd에서 User ftp 설정으로 Anonymous 접근 허용\n"
            fi
        fi
        
        # pureftpd 설정 확인
        if [ -d "/etc/pure-ftpd" ]; then
            if [ -f "/etc/pure-ftpd/conf/NoAnonymous" ]; then
                no_anonymous=$(cat /etc/pure-ftpd/conf/NoAnonymous 2>/dev/null)
                if [ "$no_anonymous" != "yes" ] && [ "$no_anonymous" != "1" ]; then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- pure-ftpd에서 NoAnonymous 설정이 비활성화됨\n"
                fi
            else
                # NoAnonymous 파일이 없으면 기본적으로 anonymous 허용
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- pure-ftpd에서 NoAnonymous 설정 파일이 없어 Anonymous 접근 허용\n"
            fi
        fi
        
        # 최종 결과 출력
        if [ $VULNERABLE -eq 1 ]; then
            echo "U-20 최종 결과: 취약" >> $resultfile 2>&1
            printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
        else
            echo "U-20 최종 결과: 양호 (FTP 서비스 존재하나 Anonymous 비활성화)" >> $resultfile 2>&1
        fi
    else
        # FTP 서비스 자체가 없는 경우
        echo "U-20 최종 결과: 양호 (FTP 서비스 비활성화)" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_21() {
    echo "U-21: r계열 서비스 비활성화" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 1. systemd 서비스 상태 확인 (rsh, rlogin, rexec)
    r_services=$(systemctl list-unit-files 2>/dev/null | grep -E "(rsh|rlogin|rexec)" | grep enabled)
    if [ -n "$r_services" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- systemd에서 r계열 서비스가 활성화됨\n"
    fi

    # 2. r계열 프로세스 실행 확인
    r_process=$(ps aux | grep -E "(rshd|rlogind|rexecd)" | grep -v grep)
    if [ -n "$r_process" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- r계열 서비스 프로세스가 실행 중\n"
    fi

    # 3. r계열 패키지 설치 확인 (Ubuntu)
    r_packages=$(dpkg -l 2>/dev/null | grep -E "(rsh-server|rsh-client|rlogin)")
    if [ -n "$r_packages" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- r계열 서비스 패키지가 설치됨\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-21 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-21 최종 결과: 양호 서비스 비활성화" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_22() {
    echo "U-22: crond 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # /etc/crontab 파일 확인
    if [ -f "/etc/crontab" ]; then
        # 소유자 확인
        crontab_owner=$(stat -c "%U" /etc/crontab 2>/dev/null)
        if [ "$crontab_owner" != "root" ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- /etc/crontab 파일의 소유자가 root가 아님 ($crontab_owner)\n"
        fi
        
        # 권한 확인 (other 사용자 쓰기 권한 확인)
        crontab_perm=$(stat -c "%a" /etc/crontab 2>/dev/null)
        if [ -n "$crontab_perm" ]; then
            # 마지막 자리수(other 권한) 추출
            other_perm=${crontab_perm: -1}
            # other 사용자에게 쓰기 권한이 있는지 확인 (2, 3, 6, 7)
            if [ "$other_perm" -eq 2 ] || [ "$other_perm" -eq 3 ] || [ "$other_perm" -eq 6 ] || [ "$other_perm" -eq 7 ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- /etc/crontab 파일에 other 사용자 쓰기 권한이 부여됨 ($crontab_perm)\n"
            fi
        fi
    else
        # /etc/crontab 파일이 없는 경우는 양호로 처리
        echo "U-22 최종 결과: 양호 (/etc/crontab 파일 없음)" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-22 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-22 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_23() {
    echo "U-23: DoS 공격 취약 서비스 비활성화" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # DoS 취약 서비스 목록
    vulnerable_services=("echo" "discard" "daytime" "chargen" "ntp" "snmp" "dns" "smtp")

    # 1. systemd 서비스 상태 확인
    for service in "${vulnerable_services[@]}"; do
        # systemd 서비스 활성화 확인
        if systemctl list-unit-files 2>/dev/null | grep -E "^${service}.*enabled" >/dev/null; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- systemd에서 ${service} 서비스가 활성화됨\n"
        fi
        
        # ntp의 경우 ntp.service와 ntpd.service 모두 확인
        if [ "$service" = "ntp" ]; then
            if systemctl list-unit-files 2>/dev/null | grep -E "^ntpd.*enabled" >/dev/null; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- systemd에서 ntpd 서비스가 활성화됨\n"
            fi
        fi
        
        # snmp의 경우 snmpd.service 확인
        if [ "$service" = "snmp" ]; then
            if systemctl list-unit-files 2>/dev/null | grep -E "^snmpd.*enabled" >/dev/null; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- systemd에서 snmpd 서비스가 활성화됨\n"
            fi
        fi
        
        # dns의 경우 bind9, named 확인
        if [ "$service" = "dns" ]; then
            if systemctl list-unit-files 2>/dev/null | grep -E "^(bind9|named).*enabled" >/dev/null; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- systemd에서 DNS 서비스가 활성화됨\n"
            fi
        fi
        
        # smtp의 경우 postfix, sendmail, exim 확인
        if [ "$service" = "smtp" ]; then
            if systemctl list-unit-files 2>/dev/null | grep -E "^(postfix|sendmail|exim4?).*enabled" >/dev/null; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- systemd에서 SMTP 서비스가 활성화됨\n"
            fi
        fi
    done

    # 2. 실행 중인 프로세스 확인
    ntpd_process=$(ps aux | grep "ntpd" | grep -v grep)
    if [ -n "$ntpd_process" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- ntpd 프로세스가 실행 중\n"
    fi

    snmpd_process=$(ps aux | grep "snmpd" | grep -v grep)
    if [ -n "$snmpd_process" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- snmpd 프로세스가 실행 중\n"
    fi

    # DNS 프로세스 확인
    dns_process=$(ps aux | grep -E "(named|bind)" | grep -v grep)
    if [ -n "$dns_process" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- DNS 프로세스가 실행 중\n"
    fi

    # SMTP 프로세스 확인
    smtp_process=$(ps aux | grep -E "(postfix|sendmail|exim)" | grep -v grep)
    if [ -n "$smtp_process" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- SMTP 프로세스가 실행 중\n"
    fi

    # 3. 패키지 설치 확인 (Ubuntu)
    ntp_package=$(dpkg -l 2>/dev/null | grep -E "^ii.*ntp[[:space:]]")
    if [ -n "$ntp_package" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- ntp 패키지가 설치됨\n"
    fi

    snmp_package=$(dpkg -l 2>/dev/null | grep -E "^ii.*(snmp|snmpd)")
    if [ -n "$snmp_package" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- snmp 패키지가 설치됨\n"
    fi

    # DNS 패키지 확인
    dns_package=$(dpkg -l 2>/dev/null | grep -E "^ii.*(bind9|named)")
    if [ -n "$dns_package" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- DNS 패키지가 설치됨\n"
    fi

    # SMTP 패키지 확인
    smtp_package=$(dpkg -l 2>/dev/null | grep -E "^ii.*(postfix|sendmail|exim4?)")
    if [ -n "$smtp_package" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- SMTP 패키지가 설치됨\n"
    fi

    # 4. xinetd 설정 확인 (echo, discard, daytime, chargen)
    if [ -d "/etc/xinetd.d" ]; then
        for service in echo discard daytime chargen; do
            if [ -f "/etc/xinetd.d/$service" ]; then
                service_disabled=$(grep -E "disable\s*=\s*yes" "/etc/xinetd.d/$service" 2>/dev/null)
                if [ -z "$service_disabled" ]; then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- /etc/xinetd.d/$service 서비스가 비활성화되지 않음\n"
                fi
            fi
        done
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-23 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-23 최종 결과: 양호 " >> $resultfile 2>&1
	echo "echo,discard,daytime,chargen,ntp,snmp,dns,smtp 서비스 외에 dos 취약 서비스가 있으수도 있습니다. 한번더 체크 하기를 바랍니다." >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_24() {
    echo "U-24: NFS 서비스 비활성화" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # NFS 관련 서비스 활성화 상태 확인
    nfs_services=("nfs-server" "nfs-lock" "nfs-idmapd" "rpcbind")
    
    for service in "${nfs_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- ${service} 서비스가 활성화됨\n"
        fi
    done

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-24 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-24 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_25() {
    echo "U-25: NFS 서비스 접근 통제" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 1. /etc/exports 파일 존재 여부 확인
    if [ ! -f "/etc/exports" ]; then
        echo "U-25 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 2. /etc/exports 파일에서 활성 설정 라인 추출 (주석 제외)
    active_exports=$(grep -E "^[^#]" /etc/exports 2>/dev/null | grep -v "^$")
    
    if [ -z "$active_exports" ]; then
        echo "U-25 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 3. 각 공유 설정 라인 검사
    # 모든 호스트 접근 허용 (*) 확인
    if echo "$active_exports" | grep -E "\*|everyone" >/dev/null; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- 모든 호스트(*)에 대한 접근이 허용됨\n"
    fi

    # no_root_squash 옵션 확인 (보안 취약)
    if echo "$active_exports" | grep "no_root_squash" >/dev/null; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- no_root_squash 옵션으로 root 권한 유지됨\n"
    fi

    # 읽기/쓰기 권한과 적절한 호스트 제한 확인
    if echo "$active_exports" | grep -E "rw" >/dev/null; then
        if ! echo "$active_exports" | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" >/dev/null; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- 특정 IP 제한 없이 읽기/쓰기 권한 허용\n"
        fi
    fi

    # 4. /etc/exports 파일 권한 확인
    exports_perm=$(stat -c "%a" /etc/exports 2>/dev/null)
    if [ "$exports_perm" != "644" ] && [ "$exports_perm" != "640" ]; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- /etc/exports 파일 권한이 부적절함 (현재: $exports_perm)\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-25 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-25 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_26() {
    echo "U-26: automountd 제거" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # autofs 서비스 활성화 상태 확인
    if systemctl is-active autofs >/dev/null 2>&1; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- autofs 서비스가 활성화됨\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-26 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-26 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_27() {
    echo "U-27: RPC 서비스 확인" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # RPC 관련 서비스 활성화 상태 확인
    rpc_services=("rpcbind" "rpc-statd" "nfs-lock" "nfs-idmapd")
    
    for service in "${rpc_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- ${service} 서비스가 활성화됨\n"
        fi
    done

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-27 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-27 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_28() {
    echo "U-28: NIS/NIS+ 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # NIS 관련 서비스 활성화 상태 확인
    nis_services=("ypserv" "ypbind" "yppasswdd" "ypxfrd" "ypupdated")
    
    for service in "${nis_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- ${service} 서비스가 활성화됨\n"
        fi
    done

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-28 최종 결과: 취약 (NIS 서비스 활성화)" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-28 최종 결과: 양호 (NIS 서비스 비활성화, 필요시 NIS+ 사용)" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_29() {
    echo "U-29: tftp,talk 서비스 비활성화" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    if systemctl status talk ntalk tftp > /dev/null 2>&1;then
	    VULNERABLE=1
	    VULN_REASONS="${VULN_REASONS}- tftp, talk 서비스가 활성화됨\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-29 최종 결과: 취약 " >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-29 최종 결과: 양호 " >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_30() {
    echo "U-30: sendmail 버전 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # sendmail 설치 여부 확인
    if ! command -v sendmail >/dev/null 2>&1 && ! dpkg -l sendmail >/dev/null 2>&1; then
        echo "U-30 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # sendmail 버전 확인
    if command -v sendmail >/dev/null 2>&1; then
        sendmail_version=$(sendmail -d0.1 -bt < /dev/null 2>&1 | grep "Version" | head -1)
        if [ -n "$sendmail_version" ]; then
            # 버전 번호 추출 (8.x.x 형태)
            version_num=$(echo "$sendmail_version" | grep -o "8\.[0-9]\+\.[0-9]\+" | head -1)
            if [ -n "$version_num" ]; then
                major=$(echo "$version_num" | cut -d. -f1)
                minor=$(echo "$version_num" | cut -d. -f2)
                patch=$(echo "$version_num" | cut -d. -f3)
                
                # 8.15.0 미만을 취약한 버전으로 판단 (최신 버전 기준)
                if [ "$major" -lt 8 ] || ([ "$major" -eq 8 ] && [ "$minor" -lt 15 ]); then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- sendmail 취약한 버전 사용 (최신 버전 아님): $version_num\n"
                fi
            else
                # 버전을 파싱할 수 없는 경우
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- sendmail 버전 확인 불가\n"
            fi
        else
            # 버전 정보를 얻을 수 없는 경우
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- sendmail 버전 정보 확인 불가\n"
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-30 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-30 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_31() {
    echo "U-31: 스팸 메일 릴레이 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # sendmail 설치 여부 확인
    if ! command -v sendmail >/dev/null 2>&1 && ! dpkg -l sendmail >/dev/null 2>&1; then
        echo "U-31 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # sendmail.cf 파일 존재 확인
    sendmail_cf="/etc/mail/sendmail.cf"
    if [ ! -f "$sendmail_cf" ]; then
        sendmail_cf="/etc/sendmail.cf"
    fi

    if [ -f "$sendmail_cf" ]; then
        # 릴레이 관련 설정 확인
        # R$* 릴레이 허용 설정 확인
        if grep -E "^R.*\$\*.*relay" "$sendmail_cf" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- 무제한 릴레이 허용 설정 발견\n"
        fi

        # FEATURE(promiscuous_relay) 확인
        if grep -i "promiscuous_relay" "$sendmail_cf" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- promiscuous_relay 기능 활성화됨\n"
        fi
    fi

    # access 파일 확인
    access_file="/etc/mail/access"
    if [ -f "$access_file" ]; then
        # RELAY 허용 설정 확인
        if grep -E "^.*RELAY$" "$access_file" >/dev/null 2>&1; then
            relay_entries=$(grep -E "^.*RELAY$" "$access_file" | wc -l)
            if [ "$relay_entries" -gt 5 ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- 과도한 릴레이 허용 설정 ($relay_entries 개)\n"
            fi
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-31 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-31 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_32() {
    echo "U-32: 일반 사용자 sendmail 실행 방지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # sendmail 실행 파일 경로 확인
    sendmail_paths=("/usr/sbin/sendmail" "/usr/lib/sendmail" "/usr/bin/sendmail")
    
    for sendmail_path in "${sendmail_paths[@]}"; do
        if [ -f "$sendmail_path" ]; then
            # 파일 권한 확인
            perm=$(stat -c "%a" "$sendmail_path" 2>/dev/null)
            owner=$(stat -c "%U" "$sendmail_path" 2>/dev/null)
            
            # setuid 비트 확인 (4755 등)
            if [ "${perm:0:1}" = "4" ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- $sendmail_path setuid 권한 설정됨 ($perm)\n"
            fi
            
            # 일반 사용자 실행 권한 확인 (others 실행 권한)
            if [ "${perm:2:1}" -ge "1" ] && [ "${perm:2:1}" -le "7" ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- $sendmail_path 일반 사용자 실행 권한 있음 ($perm)\n"
            fi
            
            # 소유자가 root가 아닌 경우
            if [ "$owner" != "root" ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- $sendmail_path 소유자가 root가 아님 ($owner)\n"
            fi
        fi
    done

    # sendmail이 없는 경우
    if [ ! -f "/usr/sbin/sendmail" ] && [ ! -f "/usr/lib/sendmail" ] && [ ! -f "/usr/bin/sendmail" ]; then
        echo "U-32 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-32 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-32 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_33() {
    echo "U-33: DNS 보안 버전 패치" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # BIND(named) 설치 여부 확인
    if ! command -v named >/dev/null 2>&1 && ! dpkg -l bind9 >/dev/null 2>&1; then
        echo "U-33 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # BIND 버전 확인
    if command -v named >/dev/null 2>&1; then
        bind_version=$(named -v 2>/dev/null | head -1)
        if [ -n "$bind_version" ]; then
            # 취약한 버전 패턴 확인 (BIND 9.11.0 미만은 취약)
            version_num=$(echo "$bind_version" | grep -o "9\.[0-9]\+\.[0-9]\+" | head -1)
            if [ -n "$version_num" ]; then
                major=$(echo "$version_num" | cut -d. -f1)
                minor=$(echo "$version_num" | cut -d. -f2)
                patch=$(echo "$version_num" | cut -d. -f3)

                if [ "$major" -lt 9 ] || ([ "$major" -eq 9 ] && [ "$minor" -lt 11 ]); then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- BIND 취약한 버전 사용: $version_num\n"
                fi
            fi
        fi
    fi

    # named.conf에서 버전 정보 노출 확인
    named_conf="/etc/bind/named.conf"
    if [ ! -f "$named_conf" ]; then
        named_conf="/etc/named.conf"
    fi

    if [ -f "$named_conf" ]; then
        # version 옵션 확인
        if ! grep -i "version.*\".*\"" "$named_conf" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- BIND 버전 정보 숨김 설정 없음\n"
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-33 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-33 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_34() {
    echo "U-34: DNS zone transfer 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # BIND(named) 설치 여부 확인
    if ! command -v named >/dev/null 2>&1 && ! dpkg -l bind9 >/dev/null 2>&1; then
        echo "U-34 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # named.conf 파일 찾기
    named_conf="/etc/bind/named.conf"
    if [ ! -f "$named_conf" ]; then
        named_conf="/etc/named.conf"
    fi

    if [ -f "$named_conf" ]; then
        # allow-transfer 설정 확인
        if grep -i "allow-transfer" "$named_conf" >/dev/null 2>&1; then
            # any 또는 전체 허용 설정 확인
            if grep -i "allow-transfer.*any" "$named_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- zone transfer가 모든 호스트에 허용됨 (any)\n"
            fi
        else
            # allow-transfer 설정이 없는 경우 (기본적으로 허용)
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- zone transfer 제한 설정이 없음\n"
        fi

        # 개별 zone 설정 확인
        zone_files=$(grep -i "zone.*{" "$named_conf" | wc -l)
        if [ "$zone_files" -gt 0 ]; then
            # zone 블록에서 allow-transfer 확인
            if ! grep -A 10 -i "zone.*{" "$named_conf" | grep -i "allow-transfer" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- zone별 transfer 제한 설정이 없음\n"
            fi
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-34 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-34 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_35() {
    echo "U-35: 웹 서비스 디렉토리 리스팅 제거" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # Apache 설정 확인
    apache_configs=("/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf" "/etc/apache2/sites-enabled/000-default.conf")
    apache_found=0

    for apache_conf in "${apache_configs[@]}"; do
        if [ -f "$apache_conf" ]; then
            apache_found=1
            # Indexes 옵션 확인
            if grep -i "Options.*Indexes" "$apache_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache에서 디렉토리 리스팅 허용됨 ($apache_conf)\n"
            fi
        fi
    done

    # Apache sites-enabled 전체 확인
    if [ -d "/etc/apache2/sites-enabled" ]; then
        apache_found=1
        if grep -r -i "Options.*Indexes" /etc/apache2/sites-enabled/ >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- Apache sites-enabled에서 디렉토리 리스팅 허용됨\n"
        fi
    fi

    # Nginx 설정 확인
    nginx_configs=("/etc/nginx/nginx.conf" "/etc/nginx/sites-enabled/default")
    nginx_found=0

    for nginx_conf in "${nginx_configs[@]}"; do
        if [ -f "$nginx_conf" ]; then
            nginx_found=1
            # autoindex 옵션 확인
            if grep -i "autoindex.*on" "$nginx_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Nginx에서 디렉토리 리스팅 허용됨 ($nginx_conf)\n"
            fi
        fi
    done

    # Nginx sites-enabled 전체 확인
    if [ -d "/etc/nginx/sites-enabled" ]; then
        nginx_found=1
        if grep -r -i "autoindex.*on" /etc/nginx/sites-enabled/ >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- Nginx sites-enabled에서 디렉토리 리스팅 허용됨\n"
        fi
    fi

    # 웹 서버가 없는 경우
    if [ $apache_found -eq 0 ] && [ $nginx_found -eq 0 ]; then
        echo "U-35 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-35 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-35 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_36() {
    echo "U-36: 웹서비스 웹 프로세스 권한 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # Apache 프로세스 확인
    if ps aux | grep -E "(apache2|httpd)" | grep -v grep >/dev/null; then
        # Apache 프로세스가 root로 실행되는지 확인
        if ps aux | grep -E "(apache2|httpd)" | grep -v grep | grep "^root" >/dev/null; then
            root_processes=$(ps aux | grep -E "(apache2|httpd)" | grep -v grep | grep "^root" | wc -l)
            worker_processes=$(ps aux | grep -E "(apache2|httpd)" | grep -v grep | grep -v "^root" | wc -l)
            
            # 모든 프로세스가 root인 경우 취약
            if [ "$worker_processes" -eq 0 ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache 모든 프로세스가 root 권한으로 실행됨\n"
            fi
        fi
    fi

    # Nginx 프로세스 확인
    if ps aux | grep nginx | grep -v grep >/dev/null; then
        # Nginx worker 프로세스가 root로 실행되는지 확인
        if ps aux | grep "nginx: worker" | grep -v grep | grep "^root" >/dev/null; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- Nginx worker 프로세스가 root 권한으로 실행됨\n"
        fi
    fi

    # 웹 서버가 없는 경우
    if ! ps aux | grep -E "(apache2|httpd|nginx)" | grep -v grep >/dev/null; then
        echo "U-36 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-36 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-36 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_37() {
    echo "U-37: 웹서비스 상위 디렉토리 접근 금지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # Apache 설정 확인
    apache_configs=("/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf")
    apache_found=0
    
    for apache_conf in "${apache_configs[@]}"; do
        if [ -f "$apache_conf" ]; then
            apache_found=1
            # AllowOverride 설정 확인
            if grep -i "AllowOverride.*All" "$apache_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache AllowOverride All 설정으로 상위 디렉토리 접근 가능\n"
            fi
            
            # FollowSymLinks 설정 확인
            if grep -i "Options.*FollowSymLinks" "$apache_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache FollowSymLinks 허용으로 심볼릭 링크 접근 가능\n"
            fi
            
            # DocumentRoot 외부 Directory 접근 설정 확인
            if grep -E "<Directory.*\/>" "$apache_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache 루트 디렉토리 접근 허용 설정 발견\n"
            fi
        fi
    done

    # Apache sites-enabled 설정 확인
    if [ -d "/etc/apache2/sites-enabled" ]; then
        apache_found=1
        if grep -r -i "AllowOverride.*All" /etc/apache2/sites-enabled/ >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- Apache sites에서 AllowOverride All 설정 발견\n"
        fi
    fi

    # Nginx 설정 확인
    nginx_configs=("/etc/nginx/nginx.conf")
    nginx_found=0
    
    for nginx_conf in "${nginx_configs[@]}"; do
        if [ -f "$nginx_conf" ]; then
            nginx_found=1
            # alias 설정에서 상위 디렉토리 참조 확인
            if grep -i "alias.*\.\." "$nginx_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Nginx alias에서 상위 디렉토리 참조 발견\n"
            fi
        fi
    done

    # Nginx sites-enabled 확인
    if [ -d "/etc/nginx/sites-enabled" ]; then
        nginx_found=1
        if grep -r -i "alias.*\.\." /etc/nginx/sites-enabled/ >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- Nginx sites에서 상위 디렉토리 alias 설정 발견\n"
        fi
    fi

    # 웹 서버 설정이 없는 경우
    if [ $apache_found -eq 0 ] && [ $nginx_found -eq 0 ]; then
        echo "U-37 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-37 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-37 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_38() {
    echo "U-38: 웹서비스 불필요한 파일 제거" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # Apache2 설치 여부 확인
    if [ ! -d "/etc/apache2" ]; then
        echo "U-38 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # Apache2 기본 생성 불필요 파일/디렉토리 확인
    echo "Apache2 설정 디렉토리 내용:" >> $resultfile 2>&1
    ls -al /etc/apache2/* >> $resultfile 2>&1

    # 기본 사이트 설정 파일 (샘플/데모 파일들)
    if [ -f "/etc/apache2/sites-available/000-default.conf" ]; then
        # 기본 설정이 수정되지 않았는지 확인
        if grep -i "It works!" /var/www/html/index.html >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- Apache2 기본 index.html 파일이 존재함\n"
        fi
    fi

    # 불필요한 모듈 설정 파일들 확인
    unnecessary_mods=("autoindex" "userdir" "status" "info")
    for mod in "${unnecessary_mods[@]}"; do
        if [ -f "/etc/apache2/mods-enabled/${mod}.conf" ] || [ -f "/etc/apache2/mods-enabled/${mod}.load" ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- 불필요한 Apache2 모듈 활성화됨: ${mod}\n"
        fi
    done

    # 기본 웹 루트의 불필요한 파일들 확인
    if [ -d "/var/www/html" ]; then
        # 기본 Apache2 인덱스 파일
        if [ -f "/var/www/html/index.html" ]; then
            if grep -i "Apache2 Default Page" "/var/www/html/index.html" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache2 기본 페이지가 존재함\n"
            fi
        fi

        # README, 매뉴얼 등 불필요한 파일들
        unnecessary_files=$(find /var/www/html -type f \( -name "README*" -o -name "INSTALL*" -o -name "CHANGELOG*" -o -name "COPYING*" \) 2>/dev/null | wc -l)
        if [ "$unnecessary_files" -gt 0 ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- 웹 루트에 설치 관련 문서 파일 존재 (${unnecessary_files}개)\n"
        fi

        # 테스트/샘플 디렉토리들
        test_dirs=$(find /var/www/html -type d \( -name "manual" -o -name "doc" -o -name "test" -o -name "sample" -o -name "example" \) 2>/dev/null | wc -l)
        if [ "$test_dirs" -gt 0 ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- 웹 루트에 테스트/샘플 디렉토리 존재 (${test_dirs}개)\n"
        fi
    fi

    # Apache2 conf-enabled에서 불필요한 설정들
    if [ -d "/etc/apache2/conf-enabled" ]; then
        # 서버 정보 노출 관련 설정들
        if [ -f "/etc/apache2/conf-enabled/security.conf" ]; then
            if ! grep -E "^ServerTokens.*Prod" /etc/apache2/conf-enabled/security.conf >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache2 서버 정보 노출 설정이 안전하지 않음\n"
            fi
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-38 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-38 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}

u_39() {
    echo "U-39: 웹서비스 링크 사용 금지" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # Apache 설정에서 FollowSymLinks 확인
    apache_configs=("/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf")
    apache_found=0
    
    for apache_conf in "${apache_configs[@]}"; do
        if [ -f "$apache_conf" ]; then
            apache_found=1
            # FollowSymLinks 옵션 확인
            if grep -i "Options.*FollowSymLinks" "$apache_conf" >/dev/null 2>&1; then
                # SymLinksIfOwnerMatch가 함께 있지 않은 경우만 취약
                if ! grep -i "Options.*SymLinksIfOwnerMatch" "$apache_conf" >/dev/null 2>&1; then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- Apache에서 FollowSymLinks 허용됨\n"
                fi
            fi
        fi
    done

    # Apache sites-enabled 설정 확인
    if [ -d "/etc/apache2/sites-enabled" ]; then
        apache_found=1
        if grep -r -i "Options.*FollowSymLinks" /etc/apache2/sites-enabled/ >/dev/null 2>&1; then
            if ! grep -r -i "Options.*SymLinksIfOwnerMatch" /etc/apache2/sites-enabled/ >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache sites에서 FollowSymLinks 허용됨\n"
            fi
        fi
    fi

    # 웹 루트에서 실제 심볼릭 링크 확인
    web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/srv/www")
    web_found=0

    for web_root in "${web_roots[@]}"; do
        if [ -d "$web_root" ]; then
            web_found=1
            
            # 심볼릭 링크 파일 확인
            symlink_count=$(find "$web_root" -type l 2>/dev/null | wc -l)
            if [ "$symlink_count" -gt 0 ]; then
                # 위험한 심볼릭 링크 확인 (상위 디렉토리 참조)
                dangerous_symlinks=$(find "$web_root" -type l -exec readlink {} \; 2>/dev/null | grep -E "\.\./|^/" | wc -l)
                if [ "$dangerous_symlinks" -gt 0 ]; then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- 웹 루트에 위험한 심볼릭 링크 존재 (${dangerous_symlinks}개)\n"
                fi
            fi
        fi
    done

    # 웹 서버 설정이 없는 경우
    if [ $apache_found -eq 0 ] && [ $web_found -eq 0 ]; then
        echo "U-39 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-39 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-39 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_40() {
    echo "U-40: 웹서비스 파일 업로드 및 다운로드 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # Apache 설치 여부 확인
    if [ ! -d "/etc/apache2" ]; then
        echo "U-40 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # Apache 메인 설정 파일에서 LimitRequestBody 확인
    echo "Apache 메인 설정 파일 점검:" >> $resultfile 2>&1
    if [ -f "/etc/apache2/apache2.conf" ]; then
        limit_result=$(cat /etc/apache2/apache2.conf | grep "LimitRequestBody")
        if [ -n "$limit_result" ]; then
            echo "LimitRequestBody 설정 발견: $limit_result" >> $resultfile 2>&1
        else
            echo "LimitRequestBody 설정 없음" >> $resultfile 2>&1
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- apache2.conf에 LimitRequestBody 설정 없음\n"
        fi
    fi

    # sites-available 설정 파일들 확인
    echo "" >> $resultfile 2>&1
    echo "Sites-available 설정 파일 점검:" >> $resultfile 2>&1
    
    if [ -d "/etc/apache2/sites-available" ]; then
        sites_with_limit=0
        total_sites=0
        
        for site_file in /etc/apache2/sites-available/*.conf; do
            if [ -f "$site_file" ]; then
                total_sites=$((total_sites + 1))
                site_name=$(basename "$site_file")
                echo "점검 파일: $site_name" >> $resultfile 2>&1
                
                limit_result=$(cat "$site_file" | grep "LimitRequestBody")
                if [ -n "$limit_result" ]; then
                    echo "  LimitRequestBody 설정: $limit_result" >> $resultfile 2>&1
                    sites_with_limit=$((sites_with_limit + 1))
                else
                    echo "  LimitRequestBody 설정 없음" >> $resultfile 2>&1
                fi
            fi
        done
        
        # 모든 사이트에 LimitRequestBody 설정이 없는 경우
        if [ $sites_with_limit -eq 0 ] && [ $total_sites -gt 0 ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- sites-available의 모든 설정 파일에 LimitRequestBody 설정 없음\n"
        fi
    fi

    # sites-enabled 설정 파일들도 확인
    echo "" >> $resultfile 2>&1
    echo "Sites-enabled 설정 파일 점검:" >> $resultfile 2>&1
    
    if [ -d "/etc/apache2/sites-enabled" ]; then
        enabled_sites_with_limit=0
        total_enabled_sites=0
        
        for site_file in /etc/apache2/sites-enabled/*.conf; do
            if [ -f "$site_file" ]; then
                total_enabled_sites=$((total_enabled_sites + 1))
                site_name=$(basename "$site_file")
                echo "활성화된 파일: $site_name" >> $resultfile 2>&1
                
                limit_result=$(cat "$site_file" | grep "LimitRequestBody")
                if [ -n "$limit_result" ]; then
                    echo "  LimitRequestBody 설정: $limit_result" >> $resultfile 2>&1
                    enabled_sites_with_limit=$((enabled_sites_with_limit + 1))
                else
                    echo "  LimitRequestBody 설정 없음" >> $resultfile 2>&1
                fi
            fi
        done
        
        # 활성화된 사이트에 LimitRequestBody 설정이 없는 경우
        if [ $enabled_sites_with_limit -eq 0 ] && [ $total_enabled_sites -gt 0 ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- 활성화된 사이트에 LimitRequestBody 설정 없음\n"
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-40 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-40 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_41() {
    echo "U-41: 웹서비스 영역의 분리" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # 웹 서버 프로세스 사용자 확인
    web_processes=$(ps aux | grep -E "(apache2|httpd|nginx)" | grep -v grep | grep -v "^root")
    
    if [ -n "$web_processes" ]; then
        # 웹 서버 전용 사용자 확인
        web_users=$(echo "$web_processes" | awk '{print $1}' | sort -u)
        
        for web_user in $web_users; do
            # 시스템 사용자인지 확인 (UID < 1000)
            user_uid=$(id -u "$web_user" 2>/dev/null)
            if [ -n "$user_uid" ] && [ "$user_uid" -lt 1000 ]; then
                # 홈 디렉토리 확인
                user_home=$(eval echo "~$web_user" 2>/dev/null)
                if [ "$user_home" = "/" ] || [ "$user_home" = "/root" ]; then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- 웹 서버 사용자($web_user)가 시스템 루트 홈 디렉토리 사용\n"
                fi
                
                # 쉘 확인
                user_shell=$(getent passwd "$web_user" | cut -d: -f7)
                if [ "$user_shell" != "/usr/sbin/nologin" ] && [ "$user_shell" != "/bin/false" ] && [ "$user_shell" != "/sbin/nologin" ]; then
                    VULNERABLE=1
                    VULN_REASONS="${VULN_REASONS}- 웹 서버 사용자($web_user)에 로그인 쉘 허용: $user_shell\n"
                fi
            fi
        done
    fi

    # 웹 루트 디렉토리 권한 확인
    web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/srv/www")
    
    for web_root in "${web_roots[@]}"; do
        if [ -d "$web_root" ]; then
            # 웹 루트 소유자 확인
            root_owner=$(stat -c "%U" "$web_root" 2>/dev/null)
            if [ "$root_owner" = "root" ]; then
                # 웹 서버 프로세스 사용자와 다른 경우 확인
                web_user=$(echo "$web_processes" | head -1 | awk '{print $1}')
                if [ -n "$web_user" ] && [ "$web_user" != "$root_owner" ]; then
                    # 그룹 권한 확인
                    root_perm=$(stat -c "%a" "$web_root" 2>/dev/null)
                    if [ "${root_perm:1:1}" -ge "7" ]; then
                        VULNERABLE=1
                        VULN_REASONS="${VULN_REASONS}- 웹 루트 디렉토리에 과도한 그룹 권한: $root_perm\n"
                    fi
                fi
            fi
        fi
    done

    # chroot 환경 확인
    apache_configs=("/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf")
    
    for apache_conf in "${apache_configs[@]}"; do
        if [ -f "$apache_conf" ]; then
            # ChrootDir 설정 확인
            if ! grep -i "ChrootDir" "$apache_conf" >/dev/null 2>&1; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- Apache chroot 환경 설정 없음\n"
            fi
        fi
    done

    # 웹 서버가 없는 경우
    if [ -z "$web_processes" ]; then
        echo "U-41 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-41 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-41 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_60() {
    echo "U-60: SSH 원격접속 허용" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # SSH 서비스 활성화 확인
    if ! systemctl is-active ssh >/dev/null 2>&1 && ! systemctl is-active sshd >/dev/null 2>&1; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- SSH 서비스가 비활성화됨\n"
    fi

    # SSH 설정 파일 확인
    sshd_config="/etc/ssh/sshd_config"
    if [ -f "$sshd_config" ]; then
        # PermitRootLogin 확인
        if grep -E "^PermitRootLogin.*yes" "$sshd_config" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- SSH root 로그인이 허용됨\n"
        fi

        # PasswordAuthentication 확인
        if grep -E "^PasswordAuthentication.*no" "$sshd_config" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- SSH 패스워드 인증이 비활성화됨\n"
        fi

        # Port 확인 (기본 포트 22 사용시 취약)
        if ! grep -E "^Port" "$sshd_config" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- SSH 기본 포트(22) 사용 중\n"
        fi

        # Protocol 확인
        if grep -E "^Protocol.*1" "$sshd_config" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- SSH Protocol 1 사용 (취약)\n"
        fi
    fi

    # telnet 설치 여부 확인 (SSH와 동시 설치시 취약)
    if command -v telnet >/dev/null 2>&1 || dpkg -l telnet >/dev/null 2>&1 || rpm -q telnet >/dev/null 2>&1; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- telnet이 설치되어 있음 (암호화되지 않은 프로토콜)\n"
    fi

    # telnet 서비스 활성화 확인
    if systemctl is-active telnet >/dev/null 2>&1 || systemctl is-active telnet.socket >/dev/null 2>&1; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- telnet 서비스가 활성화됨\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-60 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-60 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_61() {
    echo "U-61: FTP 서비스 확인" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # FTP 서비스 활성화 확인
    ftp_services=("vsftpd" "proftpd" "pure-ftpd" "wu-ftpd")

    for service in "${ftp_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- ${service} 서비스가 활성화됨\n"
        fi
    done

    # FTP 포트 리스닝 확인
    if netstat -tlnp 2>/dev/null | grep ":21 " >/dev/null; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- FTP 포트(21)가 리스닝 상태임\n"
    fi

    # FTP 프로세스 확인
    if ps aux | grep -E "(vsftpd|proftpd|pure-ftpd|wu-ftpd)" | grep -v grep >/dev/null; then
        VULNERABLE=1
        VULN_REASONS="${VULN_REASONS}- FTP 데몬 프로세스가 실행 중\n"
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-61 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-61 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_62() {
    echo "U-62: FTP 계정 shell 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # FTP 서비스가 실행 중인지 확인
    ftp_running=0
    ftp_services=("vsftpd" "proftpd" "pure-ftpd" "wu-ftpd")
    
    for service in "${ftp_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            ftp_running=1
            break
        fi
    done

    # FTP 서비스가 없으면 양호
    if [ $ftp_running -eq 0 ]; then
        echo "U-62 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # FTP 전용 사용자 확인
    # /etc/passwd에서 FTP 관련 사용자 찾기
    ftp_users=$(grep -E "ftp|ftpuser" /etc/passwd | cut -d: -f1)
    
    for ftp_user in $ftp_users; do
        user_shell=$(getent passwd "$ftp_user" | cut -d: -f7)
        
        # 유효한 쉘이 할당된 경우 취약
        if [ "$user_shell" != "/usr/sbin/nologin" ] && [ "$user_shell" != "/bin/false" ] && [ "$user_shell" != "/sbin/nologin" ]; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- FTP 사용자($ftp_user)에 쉘 접근 허용: $user_shell\n"
        fi
    done

    # vsftpd 설정 확인
    if [ -f "/etc/vsftpd.conf" ]; then
        # chroot 설정 확인
        if ! grep -E "^chroot_local_user=YES" /etc/vsftpd.conf >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- vsftpd에서 chroot 설정이 활성화되지 않음\n"
        fi
        
        # 로컬 사용자 로그인 확인
        if grep -E "^local_enable=YES" /etc/vsftpd.conf >/dev/null 2>&1; then
            # 쉘 사용자 리스트 확인
            if [ -f "/etc/ftpusers" ]; then
                shell_users=$(grep -E "(bash|sh|zsh|csh)" /etc/passwd | cut -d: -f1)
                for shell_user in $shell_users; do
                    if ! grep "^$shell_user$" /etc/ftpusers >/dev/null 2>&1; then
                        VULNERABLE=1
                        VULN_REASONS="${VULN_REASONS}- 쉘 사용자($shell_user)가 FTP 접근 차단 목록에 없음\n"
                        break
                    fi
                done
            fi
        fi
    fi

    # proftpd 설정 확인
    if [ -f "/etc/proftpd/proftpd.conf" ]; then
        if ! grep -i "RequireValidShell.*off" /etc/proftpd/proftpd.conf >/dev/null 2>&1; then
            VULNERABLE=1
            VULN_REASONS="${VULN_REASONS}- proftpd에서 유효한 쉘 요구사항이 비활성화되지 않음\n"
        fi
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-62 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-62 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
u_63() {
    echo "U-63: Ftpusers 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""

    # ftpusers 파일 경로들
    ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/vsftpd.ftpusers")
    ftpusers_found=0

    for ftpusers_file in "${ftpusers_files[@]}"; do
        if [ -f "$ftpusers_file" ]; then
            ftpusers_found=1
            echo "점검 대상: $ftpusers_file" >> $resultfile 2>&1
            
            # 파일 소유자 확인
            owner=$(stat -c "%U" "$ftpusers_file" 2>/dev/null)
            if [ "$owner" != "root" ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- $ftpusers_file 소유자가 root가 아님: $owner\n"
            else
                echo "  소유자: $owner (양호)" >> $resultfile 2>&1
            fi
            
            # 파일 권한 확인 (640 이하)
            permission=$(stat -c "%a" "$ftpusers_file" 2>/dev/null)
            echo "  권한: $permission" >> $resultfile 2>&1
            
            if [ "$permission" -gt 640 ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- $ftpusers_file 권한이 과도함: $permission (640 이하 권장)\n"
            fi
            
            # 다른 사용자 쓰기 권한 확인
            other_write=${permission:2:1}
            if [ "$other_write" -ge 2 ]; then
                VULNERABLE=1
                VULN_REASONS="${VULN_REASONS}- $ftpusers_file에 다른 사용자 쓰기 권한 있음\n"
            fi
        fi
    done

    # ftpusers 파일이 없는 경우
    if [ $ftpusers_found -eq 0 ]; then
        echo "ftpusers 파일을 찾을 수 없음" >> $resultfile 2>&1
        echo "U-63 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi

    # 최종 결과 출력
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-63 최종 결과: 취약" >> $resultfile 2>&1
        printf "%b" "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-63 최종 결과: 양호" >> $resultfile 2>&1
    fi

    return $VULNERABLE
}
# Ubuntu 보안 점검 스크립트 - 서비스 관리, 패치 관리, 로그 관리

u_63() {
    echo "U-63: Ftpusers 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # ftpusers 파일 경로들
    ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/vsftpd.ftpusers")
    
    for ftpusers_file in "${ftpusers_files[@]}"; do
        if [ -f "$ftpusers_file" ]; then
            # 소유자 확인 (root여야 함)
            owner=$(stat -c "%U" "$ftpusers_file" 2>/dev/null)
            if [ "$owner" != "root" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $ftpusers_file 소유자가 root가 아님 (현재: $owner)\n"
            fi
            
            # 권한 확인 (600, 640, 644 권장)
            perms=$(stat -c "%a" "$ftpusers_file" 2>/dev/null)
            if [ "$perms" != "600" ] && [ "$perms" != "640" ] && [ "$perms" != "644" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $ftpusers_file 권한이 부적절함 (현재: $perms, 권장: 600, 640, 644)\n"
            fi
        fi
    done
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-63 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-63 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_64() {
    echo "U-64: Ftpusers 파일 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # ftpusers 파일 경로들
    ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/vsftpd.ftpusers")
    
    for ftpusers_file in "${ftpusers_files[@]}"; do
        if [ -f "$ftpusers_file" ]; then
            # root 계정이 차단되어 있는지 확인
            if ! grep -q "^root$" "$ftpusers_file"; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $ftpusers_file에 root 계정이 차단되지 않음\n"
            fi
            
            # 파일이 비어있는지 확인
            if [ ! -s "$ftpusers_file" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $ftpusers_file 파일이 비어있음\n"
            fi
        fi
    done
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-64 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-64 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_65() {
    echo "U-65: at 파일 소유자 및 권한 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # at 관련 파일들
    at_files=("/etc/at.allow" "/etc/at.deny")
    
    for at_file in "${at_files[@]}"; do
        if [ -f "$at_file" ]; then
            # 소유자 확인 (root여야 함)
            owner=$(stat -c "%U" "$at_file" 2>/dev/null)
            if [ "$owner" != "root" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $at_file 소유자가 root가 아님 (현재: $owner)\n"
            fi
            
            # 권한 확인 (600, 640 권장)
            perms=$(stat -c "%a" "$at_file" 2>/dev/null)
            if [ "$perms" != "640" ] && [ "$perms" != "600" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $at_file 권한이 부적절함 (현재: $perms, 권장: 600, 640)\n"
            fi
        fi
    done
    
    # at.allow와 at.deny 모두 없는 경우
    if [ ! -f "/etc/at.allow" ] && [ ! -f "/etc/at.deny" ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- at.allow 또는 at.deny 파일이 존재하지 않음\n"
    fi
    
    # at 서비스 상태 확인
    if systemctl is-active --quiet atd.service 2>/dev/null; then
        # at.allow가 있으면 더 안전함
        if [ -f "/etc/at.allow" ]; then
            # at.allow 존재 (권장 설정)
            :
        elif [ -f "/etc/at.deny" ]; then
            # at.deny에 root가 포함되어 있으면 문제
            if ! grep -q "^root$" "/etc/at.deny"; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- at.deny에 root 계정이 차단되지 않음\n"
            fi
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-65 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-65 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_66() {
    echo "U-66: SNMP 서비스 구동 점검" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # SNMP 패키지 설치 확인
    if dpkg -l 2>/dev/null | grep -iq snmp; then
        # SNMP 서비스 실행 상태 확인
        if systemctl is-active --quiet snmpd.service 2>/dev/null; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SNMP 서비스가 실행 중임\n"
        fi
        
        # SNMP 설정 파일 확인
        if [ -f "/etc/snmp/snmpd.conf" ]; then
            # 기본 커뮤니티 스트링 확인
            if grep -E "^\s*(community|com2sec)" /etc/snmp/snmpd.conf | grep -iq "public\|private"; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- 기본 커뮤니티 스트링(public/private) 사용\n"
            fi
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-66 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-66 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_67() {
    echo "U-67: SNMP 서비스 커뮤니티스트링의 복잡성 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    if [ -f "/etc/snmp/snmpd.conf" ]; then
        # 기본 커뮤니티 스트링(public, private) 사용 확인
        if grep -E "^\s*(community|com2sec)" /etc/snmp/snmpd.conf | grep -v "^#" | grep -iq "public\|private"; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 기본 커뮤니티 스트링(public/private) 사용\n"
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-67 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-67 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_68() {
    echo "U-68: 로그온 시 경고 메시지 제공" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # /etc/issue 파일 확인 (콘솔 로그인)
    if [ -f "/etc/issue" ]; then
        if [ ! -s "/etc/issue" ] || grep -q "Ubuntu\|Kernel\|Welcome" /etc/issue; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/issue에 보안 경고 메시지가 없음\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/issue 파일이 존재하지 않음\n"
    fi
    
    # /etc/issue.net 파일 확인 (네트워크 로그인)
    if [ -f "/etc/issue.net" ]; then
        if [ ! -s "/etc/issue.net" ] || grep -q "Ubuntu\|Kernel\|Welcome" /etc/issue.net; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /etc/issue.net에 보안 경고 메시지가 없음\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- /etc/issue.net 파일이 존재하지 않음\n"
    fi
    
    # SSH 배너 설정 확인
    if [ -f "/etc/ssh/sshd_config" ]; then
        if ! grep -q "^Banner" /etc/ssh/sshd_config; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- SSH 배너 설정이 없음\n"
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-68 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
        echo "권장 조치: 로그인 시 보안 경고 메시지 설정" >> $resultfile 2>&1
    else
        echo "U-68 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_69() {
    echo "U-69: NFS 설정파일 접근 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # NFS 설정 파일들 확인
    nfs_files=("/etc/exports" "/etc/nfs.conf" "/etc/nfsmount.conf")
    
    for nfs_file in "${nfs_files[@]}"; do
        if [ -f "$nfs_file" ]; then
            # 소유자 확인 (root여야 함)
            owner=$(stat -c "%U" "$nfs_file" 2>/dev/null)
            if [ "$owner" != "root" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $nfs_file 소유자가 root가 아님 (현재: $owner)\n"
            fi
            
            # 권한 확인 (644 이하 권장)
            perms=$(stat -c "%a" "$nfs_file" 2>/dev/null)
            if [ "$perms" -gt 644 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $nfs_file 권한이 과도함 (현재: $perms, 권장: 644 이하)\n"
            fi
            
            # /etc/exports 보안 설정 확인
            if [ "$nfs_file" = "/etc/exports" ]; then
                # no_root_squash 확인 (보안상 위험)
                if grep -v "^#" "$nfs_file" | grep -q "no_root_squash"; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- /etc/exports에 no_root_squash 설정 발견 (보안 위험)\n"
                fi
                
                # 모든 호스트 허용 확인 (*)
                if grep -v "^#" "$nfs_file" | grep -E "\s+\*\s*\("; then
                    VULNERABLE=1
                    VULN_REASONS="$VULN_REASONS- /etc/exports에서 모든 호스트(*) 허용 설정 발견\n"
                fi
            fi
        fi
    done
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-69 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-69 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_70() {
    echo "U-70: expn, vrfy 명령어 제한" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # SMTP 서비스 실행 상태 확인
    smtp_running=0
    mail_services=("sendmail" "postfix" "exim4")
    
    for service in "${mail_services[@]}"; do
        if systemctl is-active --quiet "${service}.service" 2>/dev/null; then
            smtp_running=1
            break
        fi
    done
    
    # SMTP 서비스가 실행되지 않으면 양호
    if [ $smtp_running -eq 0 ]; then
        echo "U-70 최종 결과: 양호" >> $resultfile 2>&1
        return 0
    fi
    
    # SMTP 서비스가 실행 중이면 보안 설정 확인
    # Sendmail 설정 확인
    if [ -f "/etc/mail/sendmail.cf" ]; then
        if ! grep -q "O PrivacyOptions.*noexpn" /etc/mail/sendmail.cf; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- Sendmail에서 expn 명령어가 제한되지 않음\n"
        fi
        
        if ! grep -q "O PrivacyOptions.*novrfy" /etc/mail/sendmail.cf; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- Sendmail에서 vrfy 명령어가 제한되지 않음\n"
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-70 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-70 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_71() {
    echo "U-71: Apache 웹 서비스 정보 숨김" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # Apache 설정 파일들
    apache_configs=("/etc/apache2/apache2.conf" "/etc/apache2/conf-available/security.conf" "/etc/httpd/conf/httpd.conf")
    
    apache_installed=0
    for config in "${apache_configs[@]}"; do
        if [ -f "$config" ]; then
            apache_installed=1
            
            # ServerTokens 설정 확인
            servertokens=$(grep -E "^\s*ServerTokens" "$config" | tail -1 | awk '{print $2}')
            if [ -z "$servertokens" ] || [ "$servertokens" != "Prod" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- ServerTokens가 Prod로 설정되지 않음 (현재: $servertokens)\n"
            fi
            
            # ServerSignature 설정 확인
            serversignature=$(grep -E "^\s*ServerSignature" "$config" | tail -1 | awk '{print $2}')
            if [ -z "$serversignature" ] || [ "$serversignature" != "Off" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- ServerSignature가 Off로 설정되지 않음 (현재: $serversignature)\n"
            fi
        fi
    done
    
    # Apache 서비스 상태 확인
    if systemctl is-active --quiet apache2.service 2>/dev/null || systemctl is-active --quiet httpd.service 2>/dev/null; then
        # HTTP 응답 헤더 확인 (curl이 설치된 경우)
        if command -v curl >/dev/null 2>&1; then
            server_header=$(curl -Is http://localhost 2>/dev/null | grep -i "^server:" | head -1)
            if echo "$server_header" | grep -iq "apache.*ubuntu\|apache.*[0-9]\|apache.*mod_"; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- HTTP 응답 헤더에 상세한 Apache 정보 노출\n"
            fi
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-71 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-71 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
# task 패치관리 | 최신화가 되어 있는지
u_42() {

    echo "U-42: 최신 보안패치 및 벤더 권고사항 적용" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # apt 업데이트 목록 갱신 (에러 무시)
    apt update >/dev/null 2>&1
    
    # 업그레이드 가능한 패키지 수 확인
    upgradable=$(apt list --upgradable 2>/dev/null | grep -c "upgradable from")
    if [ "$upgradable" -gt 0 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 업그레이드 가능한 패키지가 $upgradable 개 있음\n"
    fi
    
    # 보안 업데이트 확인
    security_updates=$(apt list --upgradable 2>/dev/null | grep -c "security")
    if [ "$security_updates" -gt 0 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 보안 업데이트가 $security_updates 개 있음\n"
    fi
    
    # 마지막 업데이트 시기 확인
    if [ -f "/var/log/apt/history.log" ]; then
        last_update=$(grep "Start-Date:" /var/log/apt/history.log | tail -1 | cut -d' ' -f2)
        if [ -n "$last_update" ]; then
            # 30일 이상 업데이트하지 않은 경우
            if [ $(date -d "$last_update" +%s) -lt $(date -d "30 days ago" +%s) ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- 30일 이상 시스템 업데이트를 하지 않음\n"
            fi
        fi
    fi
    
    # unattended-upgrades 설정 확인 (자동 보안 업데이트)
    if [ -f "/etc/apt/apt.conf.d/50unattended-upgrades" ]; then
        if ! grep -q "security" /etc/apt/apt.conf.d/50unattended-upgrades || \
           grep -q "^//.*security" /etc/apt/apt.conf.d/50unattended-upgrades; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- 자동 보안 업데이트가 비활성화됨\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- unattended-upgrades가 설정되지 않음\n"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-42 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-42 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
# task 로그 관리 | 로그에 대한 보고서등 
u_43() {

    echo "U-43: 로그의 정기적 검토 및 보고" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # 시스템 로그 파일들 확인
    log_files=("/var/log/syslog" "/var/log/auth.log" "/var/log/kern.log" "/var/log/daemon.log")
    
    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            # 로그 파일 크기 확인
            size=$(stat -c%s "$log_file" 2>/dev/null)
            if [ "$size" -eq 0 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $log_file 파일이 비어있음\n"
            fi
            
            # 최근 로그 기록 확인 (24시간 이내)
            if [ -z "$(find "$log_file" -mtime -1 2>/dev/null)" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $log_file: 24시간 내 기록이 없음\n"
            fi
        else
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- $log_file 파일이 존재하지 않음\n"
        fi
    done
    
    # rsyslog 서비스 확인
    if ! systemctl is-active --quiet rsyslog.service 2>/dev/null; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- rsyslog 서비스가 실행되지 않음\n"
    fi
    
    # logrotate 설정 확인
    if [ -f "/etc/logrotate.conf" ]; then
        # 로그 순환 주기 확인
        if ! grep -q "daily\|weekly\|monthly" /etc/logrotate.conf; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- logrotate 순환 주기가 설정되지 않음\n"
        fi
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- logrotate 설정 파일이 존재하지 않음\n"
    fi
    
    # 로그 모니터링 도구 확인
    monitoring_tools=("logwatch" "fail2ban" "logcheck")
    tools_installed=0
    for tool in "${monitoring_tools[@]}"; do
        if dpkg -l 2>/dev/null | grep -q "^ii.*$tool"; then
            tools_installed=1
        fi
    done
    
    if [ $tools_installed -eq 0 ]; then
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- 로그 모니터링 도구가 설치되지 않음\n"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-43 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-43 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}

u_72() {
    echo "U-72: 정책에 따른 시스템 로그 설정" >> $resultfile 2>&1
    VULNERABLE=0
    VULN_REASONS=""
    
    # rsyslog 설정 파일 확인
    if [ -f "/etc/rsyslog.conf" ]; then
        # 주요 로그 유형별 설정 확인
        log_types=("auth" "authpriv" "cron" "daemon" "kern" "mail" "user" "syslog")
        
        for log_type in "${log_types[@]}"; do
            if ! grep -q "^[^#]*$log_type\." /etc/rsyslog.conf; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $log_type 로그 설정이 없음\n"
            fi
        done
        
        # 로그 파일별 설정 확인
        required_logs=("auth.log" "syslog" "kern.log" "daemon.log")
        for log in "${required_logs[@]}"; do
            if ! grep -q "/var/log/$log" /etc/rsyslog.conf; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- /var/log/$log 설정이 없음\n"
            fi
        done
        
    else
        VULNERABLE=1
        VULN_REASONS="$VULN_REASONS- rsyslog 설정 파일이 존재하지 않음\n"
    fi
    
    # 로그 디렉토리 권한 확인
    if [ -d "/var/log" ]; then
        log_perms=$(stat -c "%a" "/var/log" 2>/dev/null)
        if [ "$log_perms" != "755" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- /var/log 디렉토리 권한이 부적절함 (현재: $log_perms, 권장: 755)\n"
        fi
    fi
    
    # 주요 로그 파일 권한 확인
    log_files=("/var/log/auth.log" "/var/log/syslog" "/var/log/kern.log")
    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            perms=$(stat -c "%a" "$log_file" 2>/dev/null)
            if [ "$perms" -gt 640 ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $log_file 권한이 과도함 (현재: $perms, 권장: 640 이하)\n"
            fi
            
            owner=$(stat -c "%U" "$log_file" 2>/dev/null)
            if [ "$owner" != "root" ] && [ "$owner" != "syslog" ]; then
                VULNERABLE=1
                VULN_REASONS="$VULN_REASONS- $log_file 소유자가 부적절함 (현재: $owner)\n"
            fi
        fi
    done
    
    # systemd journal 설정 확인
    if [ -f "/etc/systemd/journald.conf" ]; then
        # Storage 설정 확인
        storage=$(grep "^Storage=" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2)
        if [ "$storage" = "none" ]; then
            VULNERABLE=1
            VULN_REASONS="$VULN_REASONS- systemd journal Storage가 none으로 설정됨\n"
        fi
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo "U-72 최종 결과: 취약" >> $resultfile 2>&1
        echo "취약 이유:" >> $resultfile 2>&1
        echo -e "$VULN_REASONS" >> $resultfile 2>&1
    else
        echo "U-72 최종 결과: 양호" >> $resultfile 2>&1
    fi
    
    return $VULNERABLE
}
u_01
u_02
u_03
u_04
u_44
u_45
u_46
u_47
u_48
u_49
u_50
u_51
u_52
u_53
u_54
u_05
u_06 
u_07
u_08
u_09
u_10
u_11
u_12
u_13
u_14
u_15
u_16
u_17
u_18
u_55
u_56
u_57
u_58
u_59
u_19
u_20
u_21
u_22
u_23
u_24
u_25
u_26
u_27
u_28
u_29
u_30
u_31
u_32
u_33
u_34
u_35
u_36
u_37
u_38
u_39
u_60
u_61
u_62
u_63
u_64
u_65
u_66
u_67
u_68
u_69
u_70
u_71
u_42
u_43
u_72


echo "결과 파일 생성: $resultfile"
ls -la *.csv



