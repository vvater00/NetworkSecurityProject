
$dir = $PSScriptRoot                                   # 점검 스크립트가 위치한 경로(자동 변수)
$log_dir = Join-Path $dir "KISA_LOG"                   # 로그 파일 저장 경로
$result_dir = Join-Path $dir "KISA_RESULT"             # 결과 파일 저장 경로
New-Item -ItemType Directory -Force -Path $log_dir,$result_dir | Out-Null   # 로그, 결과를 저장할 디렉터리가 없으면 생성

## 절대 경로
$log_file = Join-Path $log_dir "W-63.log"              # 로그 파일명
$json_file = Join-Path $result_dir "W-63.json"         # 결과 파일명

## 보안 점검 시 탐색 후, 수정 후 PASS/FAIL 기록
$detect_status = "FAIL"
$remediate_status = "FAIL"
$dnsService
$runningStatus = "FALSE"
$updateStatus = "FALSE"

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"           # 점검 실행 날짜(KST) EX: 2025-09-03 17:43:42+09:00

try {
    Start-Transcript -Path $log_file -Append            # 로그 작성 시작
    Write-Host "========= [W-63] DNS Server running Assessment =========" -ForegroundColor Cyan
    Write-Host "[$ts]"

    ## DNS 존재하는지 조회
    $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    
    ## 존재하지 않으면 PASS
    if (-not $dnsService) {
        Write-Host "[INFO] DNS Service not exists." -ForegroundColor Green
        $detect_status = "PASS"
    }

    else{
        ## 존재한다면 동적업데이트 설정 확인
        Write-Host "[INFO] DNS Service exists."  -ForegroundColor Blue
        $runningStatus = "TRUE"

        $zones = Get-DnsServerZone -ErrorAction SilentlyContinue
        foreach ($zone in $zones) {
        if ($zone.DynamicUpdate -ne 0) {
            $updateStatus = "TRUE"
            $detect_status = "FAIL"
            break 
        }
    }
}
    Write-Host "--------- Detect Result ---------"
    Write-Host "[RESULT] DNS Server running status : $($runningStatus)"  -ForegroundColor Cyan
    Write-Host "[RESULT] DNS Server Dynamic Update setting status : $($updateStatus)"  -ForegroundColor Cyan
    Write-Host "[RESULT] Policy Compliance Status: $detect_status" -ForegroundColor Cyan
    Write-Host "----------------------------"

    if ($detect_status -eq "FAIL") {
        Write-Host "--------- Remediate Result ---------"
        Write-Host "[INFO] DNS Server Dynamic Update set to DISABLED" -ForegroundColor Yellow
        try {
            # 서비스 시작 유형 Disabled로 변경
            Set-Service -Name "DNS" -StartupType Disabled -ErrorAction Stop
            Write-Host "[RESULT] DNS Server Dynamic Update set to DISABLED Successfully" -ForegroundColor Green
            $remediate_status = "PASS"
            $updateStatus = "FALSE"
        }
        catch {
            Write-Host "[ERROR] Failed to set DISABLED" -ForegroundColor Red
            $remediate_status = "FAIL"
        }

        # 사용자에게 확인 요청
        $userInput = Read-Host -Prompt "Do you want to stop DNS Service ? (y/n)"

        if ($userInput -eq 'y' -or $userInput -eq 'Y') {
            # 서비스 시작 유형 Disabled로 변경
            Write-Host "[RESULT] Change DNS Service Start type to disabled." -ForegroundColor Cyan
            Set-Service -Name "DNS" -StartupType Disabled

            # 서비스 중지
            Write-Host "[RESULT] DNS Service stopped." -ForegroundColor Green
            Stop-Service -Name "DNS" -Force
            $runningStatus = "TRUE"
        }
        else {
            Write-Host "[RESULT] Cancel to stop DNS Service." -ForegroundColor Yellow
        } 
        Write-Host "----------------------------"
    }

    

    $discussion = @"
Good: DNS service is not used or dynamic updates are set to None
Vulnerable: The service is in use and dynamic updates are enabled.
"@

    $check_content = @"
Step 1) Start > Run > DNSMGMT.MSC > each lookup zone > The corresponding zone > Properties > General
Step 2) Set Dynamic Updates to ‘None (or No).
Step 3) Remove the service if it is not needed.
Go to Start > Run > SERVICES.MSC > DNS Server > Properties [General] tab, set ‘Startup type’ to ‘Disabled,’ and then stop the DNS service.
"@

    $result = [PSCustomObject]@{
        date = $ts
        control_family = "AC-1"
        check_target = "Check the operation of the DNS service"
        discussion = $discussion
        check_content = $check_content
        fix_text = "Dynamic updates are typically not required. However, they should be verified."
        payload = [PSCustomObject]@{
            severity = "mid"
            port = ""
            service = "DNS"
            protocol = ""
            threat = @("Data from malicious users may be accepted and treated as trusted")
            TTP = @("T1071.004", "T1565.001”) 
            file_checked = ""
        }
        results = @(
            [PSCustomObject]@{
                phase = "detect"
                status = $detect_status
                running = $runningStatus
                update = $updateStatus
            },
            [PSCustomObject]@{
                phase = "remediate"
                status = $remediate_status
                running = $runningStatus
                update = $updateStatus
            }
        )
    }

    ## 결과 파일은 UTF-8로 인코딩하여 json 형식으로 저장
    $result | ConvertTo-Json -Depth 3 | Set-Content -Path $json_file  -Encoding UTF8
}
finally {
    Stop-Transcript | Out-Null
}
