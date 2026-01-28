#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"         # 점검 실행 날짜(KST) EX: 2025-08-29T00:00:00+0900
DIR="$(cd "$(dirname "$0")" && pwd)"        # 점검 스크립트가 위치한 경로
LOGFILE="$DIR/KISA_LOG/U-47.log"            # 로그 파일 저장 경로 및 파일명
JSON="$DIR/KISA_RESULT/U-47.json"           # 결과 파일 저장 경로 및 파일명(json형식)

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$JSON")"       # 로그, 결과 파일의 상위 디렉터리가 없으면 생성

## 점검 할 파일명
FILE_PW="/etc/login.defs"

## 서비스 활성화 여부 및 원격 root 로그인 허용 여부 플래그
# TELNET_ACTIVE="no"
# SSH_ACTIVE="no"
# TELNET_ROOT_ALLOWED="no"
# SSH_ROOT_ALLOWED="no"

DUEDATE_ACTIVE="FAIL"

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

log "$BOLD============= [U-47] Linux Security Assessment =============$RESET"
log "$BOLD[INFO]$RESET Check file: $FILE_PW"

PASS_MAX_DAYS=$(grep -E '^PASS_MAX_DAYS' "$FILE_PW" | awk '{print $2}')
if [ -z "$PASS_MAX_DAYS" ]; then
    DUEDATE_ACTIVE="FAIL"
    DETECT_STATUS="FAIL"
else
    log "$BOLD[INFO]$RESET PASS_MAX_DAYS = $PASS_MAX_DAYS"
    if [[ "$PASS_MAX_DAYS" =~ ^[0-9]+$ ]] && [ "$PASS_MAX_DAYS" -le 90 ]; then
        DUEDATE_ACTIVE="PASS"
        DETECT_STATUS="PASS"
    else
        DUEDATE_ACTIVE="FAIL"
        DETECT_STATUS="FAIL"
    fi
fi

log "------------- Detect Result -------------"
log "$BOLD[RESULT]$RESET PASS_MAX_DAYS activation: $DUEDATE_ACTIVE"
log "------------------------------------"

if [ "$DETECT_STATUS" = "FAIL" ]; then
    backup "$FILE_PW"
    if grep -Eq '^PASS_MAX_DAYS' "$FILE_PW"; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$FILE_PW"
    else
        echo "PASS_MAX_DAYS 90" >> "$FILE_PW"
    fi
    log "${GREEN}[FIX] PASS_MAX_DAYS to 90.${RESET}"
    REMEDIATE_STATUS="PASS"
else
    REMEDIATE_STATUS="PASS"
fi

cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-47",
  "check_target": "Maximum password age setting",
  "discussion": "Good: The maximum password age is set to 90 days (12 weeks) or less.\nVulnerable: The maximum password age is not set to 90 days (12 weeks) or less."

  "check_content": "[/etc/login.defs] includes like PASS_MAX_DAYS 90",
  "fix_text": "Step 1) Use vi editor and open [/etc/login.defs] . Step 2) Edit or input like PASS_MAX_DAYS {day (max 90)}",
  "payload": {
    "severity": "medium",
    "port": "",
    "service": "",
    "protocol": "",
    "threat": ["brute-force attack", "dictionary attack, etc."],
    "TTP": "T1110, T1078",
    "files_checked": ["$FILE_PW"]
  },
  "results": [
    {
      "phase": "detect",
      "status": "$DETECT_STATUS",
      "PASSWORD_MAX_DATE": "$PASS_MAX_DAYS"
    },
    {
      "phase": "remediate",
      "status": "$REMEDIATE_STATUS",
      "PASSWORD_MAX_DATE": "$PASS_MAX_DAYS"
    }
  ]
}
EOF