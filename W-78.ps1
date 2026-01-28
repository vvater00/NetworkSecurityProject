# W-78.ps1
# 5. 보안 관리 > 5.17 보안 채널 데이터 디지털 암호화 또는 서명
# 점검 대상 정책(도메인 구성원):
# - Domain member: Digitally encrypt or sign secure channel data (always)
# - Domain member: Digitally encrypt secure channel data (when possible)
# - Domain member: Digitally sign secure channel data (when possible)
# => 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
#    RequireSignOrSeal, SealSecureChannel, SignSecureChannel (모두 1이어야 양호)

$dir        = $PSScriptRoot
$log_dir    = Join-Path $dir "KISA_LOG"
$result_dir = Join-Path $dir "KISA_RESULT"
New-Item -ItemType Directory -Force -Path $log_dir,$result_dir | Out-Null

# 로그 / 결과 파일
$log_file   = Join-Path $log_dir    "W-78.log"
$json_file  = Join-Path $result_dir "W-78.json"

# 기본 상태
$detect_status    = "FAIL"
$remediate_status = "FAIL"

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"

# Netlogon 보안 채널 관련 레지스트리 경로
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

try {
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-78] Secure Channel Data Encryption/Signing Assessment =========" -ForegroundColor Cyan
    Write-Host "[$ts]"
    Write-Host

    # 현재 설정값 읽기 (없으면 0으로 취급)
    $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    [int]$RequireSignOrSeal = 0
    [int]$SealSecureChannel = 0
    [int]$SignSecureChannel = 0

    if ($null -ne $props) {
        if ($props.PSObject.Properties.Name -contains "RequireSignOrSeal") {
            [int]$RequireSignOrSeal = $props.RequireSignOrSeal
        }
        if ($props.PSObject.Properties.Name -contains "SealSecureChannel") {
            [int]$SealSecureChannel = $props.SealSecureChannel
        }
        if ($props.PSObject.Properties.Name -contains "SignSecureChannel") {
            [int]$SignSecureChannel = $props.SignSecureChannel
        }
    }

    Write-Host "--------- Current Settings (Netlogon Secure Channel) ---------"
    Write-Host "RequireSignOrSeal (encrypt or sign always): $RequireSignOrSeal"
    Write-Host "SealSecureChannel (encrypt when possible) : $SealSecureChannel"
    Write-Host "SignSecureChannel (sign when possible)    : $SignSecureChannel"
    Write-Host "--------------------------------------------------------------"

    # 세 값이 모두 1이면 정책 준수
    if ($RequireSignOrSeal -eq 1 -and $SealSecureChannel -eq 1 -and $SignSecureChannel -eq 1) {
        $detect_status = "PASS"
        Write-Host "[RESULT] All secure channel policies are enabled. (Compliant)" -ForegroundColor Green
    } else {
        $detect_status = "FAIL"
        Write-Host "[RESULT] One or more secure channel policies are NOT enabled. (Non-compliant)" -ForegroundColor Yellow
    }

    Write-Host
    Write-Host "--------- Detect Result ---------"
    Write-Host "[RESULT] Policy Compliance Status: $detect_status" -ForegroundColor Cyan
    Write-Host "---------------------------------"
    Write-Host

    # Remediation: 필요 시 사용자에게 확인 후 값들을 1로 설정
    if ($detect_status -eq "FAIL") {
        Write-Host "[ACTION] Secure channel policies are not fully enabled." -ForegroundColor Cyan
        $userInput = Read-Host -Prompt "Do you want to enable secure channel encryption/signing policies now? (y/n)"

        if ($userInput -eq 'y' -or $userInput -eq 'Y') {

            # ===================== 여기서 '수정 전 백업' 수행 =====================
            Write-Host "[INFO] Backing up current Netlogon registry settings..." -ForegroundColor Yellow
            # 백업 파일 이름: W-78_Netlogon_backup_YYYYMMDDHHMMSS.reg
            $backupFile = Join-Path $result_dir ("W-78_Netlogon_backup_{0}.reg" -f (Get-Date -Format "yyyyMMddHHmmss"))

            try {
                & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" $backupFile /y | Out-Null
                Write-Host "[RESULT] Registry backup created: $backupFile" -ForegroundColor Green
            }
            catch {
                Write-Host "[WARN] Failed to backup Netlogon registry settings: $($_.Exception.Message)" -ForegroundColor Yellow
                # 백업 실패해도 수정은 계속 진행 (필요하면 여기서 return으로 중단도 가능)
            }
            # =====================================================================

            Write-Host "[ACTION] Enabling secure channel encryption/signing policies..." -ForegroundColor Cyan
            try {
                # 키 없으면 생성
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                New-ItemProperty -Path $regPath -Name "RequireSignOrSeal" -PropertyType DWord -Value 1 -Force | Out-Null
                New-ItemProperty -Path $regPath -Name "SealSecureChannel" -PropertyType DWord -Value 1 -Force | Out-Null
                New-ItemProperty -Path $regPath -Name "SignSecureChannel" -PropertyType DWord -Value 1 -Force | Out-Null

                # 변수 값도 1로 업데이트
                $RequireSignOrSeal = 1
                $SealSecureChannel = 1
                $SignSecureChannel = 1

                $remediate_status = "PASS"
                Write-Host "[RESULT] Secure channel policies have been set to 'Enabled(1)'." -ForegroundColor Green
                Write-Host "[INFO] A reboot or 'netlogon' service restart may be required for all changes to take effect." -ForegroundColor DarkCyan
            }
            catch {
                $remediate_status = "FAIL"
                Write-Host "[ERROR] Failed to update secure channel registry settings: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "[RESULT] Remediation cancelled by user." -ForegroundColor Yellow
            $remediate_status = "FAIL"
        }
    }
    else {
        Write-Host "[RESULT] No remediation required." -ForegroundColor Cyan
        $remediate_status = "PASS"
    }

    # 가이드 텍스트 (PDF 내용 기반)
    $discussion = @"
Good: All domain member secure channel policies are set to 'Enabled':
  - Digitally encrypt or sign secure channel data (always)
  - Digitally encrypt secure channel data (when possible)
  - Digitally sign secure channel data (when possible)

Vulnerable: One or more of the above policies are not enabled, which allows attackers
to sniff or tamper with secure channel traffic between domain members and domain controllers.
"@

    $check_content = @"
Step 1) 실행 > 'SECPOL.MSC' 실행 > [로컬 보안 정책] 창에서
       보안 설정 > 로컬 정책 > 보안 옵션으로 이동
Step 2) 다음 3가지 정책을 모두 '사용'으로 설정
    - 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상)
    - 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우)
    - 도메인 구성원: 보안 채널 데이터를 디지털 서명(가능한 경우)
"@

    $result = [PSCustomObject]@{
        date           = $ts
        control_family = "SC-8"  # 예시: 보안 채널 보호 관련 통제
        check_target   = "Enable secure channel data encryption/signing for domain members"
        discussion     = $discussion
        check_content  = $check_content
        fix_text       = "Set the three 'Domain member: secure channel' policies to 'Enabled' and apply a strong domain security policy."
        payload        = [PSCustomObject]@{
            severity     = "medium"   # W-78 (중) 기준
            port         = ""
            service      = "Netlogon"
            protocol     = "RPC/SMB"
            threat       = @(
                "Network Sniffing of secure channel traffic",
                "Man-in-the-Middle on domain member to DC communication",
                "Credential replay or tampering"
            )
            TTP          = @("T1040","T1557","T1552")
            file_checked = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"
        }
        results = @(
            [PSCustomObject]@{
                phase  = "detect"
                status = $detect_status
                RequireSignOrSeal = $RequireSignOrSeal
                SealSecureChannel = $SealSecureChannel
                SignSecureChannel = $SignSecureChannel
            },
            [PSCustomObject]@{
                phase  = "remediate"
                status = $remediate_status
                RequireSignOrSeal = $RequireSignOrSeal
                SealSecureChannel = $SealSecureChannel
                SignSecureChannel = $SignSecureChannel
            }
        )
    }

    # JSON 저장 (UTF-8)
    $result | ConvertTo-Json -Depth 4 | Set-Content -Path $json_file -Encoding UTF8
}
finally {
    Stop-Transcript | Out-Null
}
