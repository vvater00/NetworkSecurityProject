#!/bin/bash

TS="$(date '+%Y-%m-%dT%H:%M:%S%z')"         # 점검 실행 날짜(KST) EX: 2025-08-29T00:00:00+0900
DIR="$(cd "$(dirname "$0")" && pwd)"        # 점검 스크립트가 위치한 경로
LOGFILE="$DIR/KISA_LOG/U-66.log"            # 로그 파일 저장 경로 및 파일명
JSON="$DIR/KISA_RESULT/U-66.json"           # 결과 파일 저장 경로 및 파일명(json형식)

mkdir -p "$(dirname "$LOGFILE")" "$(dirname "$JSON")"       # 로그, 결과 파일의 상위 디렉터리가 없으면 생성

## 점검 할 파일명
FILE_PW=""


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

log "$BOLD============= [U-66] SNMP Service Running Status Check =============$RESET"
# log "$BOLD[INFO]$RESET Check file: $FILE_PW"

SNMP_PROCESS=$(ps -ef | grep snmp | grep -v grep)

if [ -n "$SNMP_PROCESS" ]; then
    DETECT_STATUS="FAIL"
    log "$BOLD[INFO]$RESET SNMP is running !"
    log "$SNMP_PROCESS"
else
    DETECT_STATUS="PASS"
    log "$BOLD[INFO]$RESET SNMP is not running."
fi

log "------------- Detect Result -------------"
if [ "$DETECT_STATUS" == "FAIL" ] ; then
    log "${BOLD}[RESULT]$RESET SNMP active status : ${RED}$DETECT_STATUS${RESET}"
else
    log "${BOLD}[RESULT]$RESET SNMP active status : ${GREEN}$DETECT_STATUS${RESET}"
fi
log "------------------------------------"

if [ "$DETECT_STATUS" = "FAIL" ]; then
    service snmpd stop 2>/dev/null
    chkconfig snmpd off 2>/dev/null
    log "${GREEN}[FIX] SNMP stopped and disabled succesfully.${RESET}"
    REMEDIATE_STATUS="PASS"
elif [ "$DETECT_STATUS" = "PASS" ]; then
    log "${GREEN}[INFO] No required to remidate.${RESET}"
    REMEDIATE_STATUS="PASS"
else
    REMEDIATE_STATUS="FAIL"
    log "${RED}[ERROR] REMEDIATE FAILED ...${RESET}"
fi

cat > "$JSON" <<EOF
{
  "date": "$TS",
  "control_family": "U-66",
  "check_target": "SNMP Service Running Status Check",
  "discussion": "Good: SNMP Service is not running. \n Vulnerable: SNMP Service is running.",
  "check_content": "Use 'ps -ef | grep snmp' at CMD to check",
  "fix_text": "Step 1) Use 'ps -ef | grep snmp' at CMD to check. Step 2) Use '#service snmpd stop' at CMD to stop SNMP service",
  "payload": {
    "severity": "medium",
    "port": "",
    "service": "",
    "protocol": "",
    "threat": ["Leakage of critical information", " Unauthorized modification of data"],
    "TTP": "T1046, T1082, T1498",
    "files_checked": [""]
  },
  "results": [
    {
      "phase": "detect",
      "status": "$DETECT_STATUS",
      "process": "$(echo "$SNMP_PROCESS" | tr '\n' ' ')"
    },
    {
      "phase": "remediate",
      "status": "$REMEDIATE_STATUS",
      
    }
  ]
}
EOF