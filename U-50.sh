#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"         # 점검 실행 날짜(KST) EX: 2025-08-29T00:00:00+0900
DIR="$(cd "$(dirname "$0")" && pwd)"        # 점검 스크립트가 위치한 경로
LOGFILE="$DIR/KISA_LOG/U-50.log"            # 로그 파일 저장 경로 및 파일명
JSON="$DIR/KISA_RESULT/U-50.json"           # 결과 파일 저장 경로 및 파일명(json형식)

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$JSON")"       # 로그, 결과 파일의 상위 디렉터리가 없으면 생성

## 점검 할 파일명
FILE_ACCOUNT="/etc/group"

## 서비스 활성화 여부 및 원격 root 로그인 허용 여부 플래그
# TELNET_ACTIVE="no"
# SSH_ACTIVE="no"
# TELNET_ROOT_ALLOWED="no"
# SSH_ROOT_ALLOWED="no"

GROUP_ACTIVE="FAIL"

## 보안 점검 시 탐색 후, 수정 후 PASS/FAIL 기록
DETECT_STATUS="FAIL"
REMEDIATE_STATUS="FAIL"

## ANSI 코드
RED=$'\e[1;31m'         # BOLD + RED 
GREEN=$'\e[1;32m'       # BOLD + GREEN
BOLD=$'\e[1m'           # BOLD
RESET=$'\e[0m'          # 원래 글씨로 전환

## 화면에 출력한 내용 그대로 log 파일로 저장
log () {
    printf '%s\n' "$*" | tee -a "$LOGFILE"
}

## 표준 에러로 출력 후 log 파일에 저장
err() {
    printf "${RED}[ERROR] %s${RESET}\n" "$*" | tee -a "$LOGFILE" >&2
}

## 백업 파일 생성 EX: /etc/securetty -> /etc/securetty.bak.20250829-000000
backup() {
    local src="$1"
    local ts
    ts=$(date '+%Y%m%d-%H%M%S')
    local name="${src}.bak.${ts}"

    if [ -f "$src" ]; then
        cp -p "$src" "$name"
        log "$BOLD[BACKUP]$RESET $src -> $name"
    else
        log "$BOLD[BACKUP]$RESET $src no backup"        # 파일이 아니면 백업 없음
    fi
}

log "$BOLD============= [U-50] Linux Security Assessment =============$RESET"
log "$BOLD[INFO]$RESET Check file: $FILE_ACCOUNT"

# /etc/group 파일에서 root 그룹에 등록된 불필요한 계정을 확인
UNNECESSARY_ACCOUNTS=$(grep "^root:" "$FILE_ACCOUNT" | cut -d: -f4 | tr ',' '\n' | grep -v "^root$")

if [ -n "$UNNECESSARY_ACCOUNTS" ]; then
    DETECT_STATUS="FAIL"
else
    DETECT_STATUS="PASS"
fi

log "------------- Detect Result -------------"
if [ "$DETECT_STATUS" == "FAIL" ]; then
    log "$BOLD[RESULT]$RESET Account Group assesment : ${RED}$DETECT_STATUS$RESET"
else
    log "$BOLD[RESULT]$RESET Account Group assesment : ${GREEN}$DETECT_STATUS$RESET"
fi

log "------------------------------------"

# 불필요한 계정이 있을 경우, 해당 계정을 root 그룹에서 삭제
if [ "$DETECT_STATUS" == "FAIL" ]; then
    backup "$FILE_ACCOUNT"
    for ACCOUNT in $UNNECESSARY_ACCOUNTS; do
    log "$BOLD[INFO]$RESET Removing account '$ACCOUNT' from root group..."

    sed -i -E "s/(^root:[^:]*:0:[^,]*)\b,$ACCOUNT\b/\1/g" "$FILE_ACCOUNT"
    sed -i -E "s/(^root:[^:]*:0:[^,]*)\b$ACCOUNT,/\1/g" "$FILE_ACCOUNT"
    sed -i -E "s/(^root:[^:]*:0:[^,]*)\b$ACCOUNT\b/\1/g" "$FILE_ACCOUNT"
    done
    
    sed -i -E 's/,+/,/g; s/,$//' "$FILE_ACCOUNT"


    # 수정 후 점검
    if grep -q '^root:x:0:root$' "$FILE_ACCOUNT"; then
        log "$BOLD[INFO]$RESET ${GREEN}Unnecessary accounts removed successfully.$RESET"
        REMEDIATE_STATUS="PASS"
    else
        log "$BOLD${RED}[ERROR]$RESET ${RED}Failed to remove unnecessary accounts.$RESET"
        REMEDIATE_STATUS="FAIL"
    fi
else
    REMEDIATE_STATUS="PASS"
fi

cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-50",
  "check_target": "Only minimal accounts should be included in the administrator group.",
  "discussion": "Good: If no unnecessary accounts are registered in the administrator group. \\nVulnerable: If unnecessary accounts are registered in the administrator group.",
  "check_content": "[/etc/group] do only include root account. Do not include other accounts.",
  "fix_text": "Step 1) Use vi editor and open [/etc/group]. Step 2) Delete other accounts exclude root.",
  "payload": {
    "severity": "medium",
    "port": "",
    "service": "",
    "protocol": "",
    "threat": ["Account information leakage", "Configuration file and directory tampering", "etc."],
    "TTP": "T1078",
    "files_checked": ["$FILE_ACCOUNT"]
  },
  "results": [
    {
      "phase": "detect",
      "status": "$DETECT_STATUS"
      "UNNECESSARY_ACCOUNTS": "$UNNECESSARY_ACCOUNTS"
    },
    {
      "phase": "remediate",
      "status": "$REMEDIATE_STATUS"
    }
  ]
}
EOF