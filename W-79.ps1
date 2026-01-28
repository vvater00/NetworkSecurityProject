# W-79.ps1
# 5. 보안 관리 > 5.18 파일 및 디렉터리 보호
# 점검내용: NTFS 파일 시스템 사용 여부 점검
# 양호: NTFS 파일 시스템을 사용하는 경우
# 취약: FAT/FAT32 등 NTFS가 아닌 파일 시스템을 사용하는 경우

$dir        = $PSScriptRoot
$log_dir    = Join-Path $dir "KISA_LOG"
$result_dir = Join-Path $dir "KISA_RESULT"
New-Item -ItemType Directory -Force -Path $log_dir,$result_dir | Out-Null

# 로그 / 결과 파일
$log_file   = Join-Path $log_dir    "W-79.log"
$json_file  = Join-Path $result_dir "W-79.json"

# 기본 상태
$detect_status    = "FAIL"
$remediate_status = "FAIL"

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"

try {
    Start-Transcript -Path $log_file -Append
    Write-Host "========= [W-79] NTFS File System Usage Assessment =========" -ForegroundColor Cyan
    Write-Host "[$ts]"
    Write-Host

    # 1) 로컬 고정 디스크(DriveType=3) 조회
    # Win32_LogicalDisk: DeviceID(C:), FileSystem(NTFS/FAT32 등), VolumeName
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue

    if (-not $drives) {
        Write-Host "[WARN] No fixed disks found." -ForegroundColor Yellow
        $detect_status = "FAIL"
    }

    # 드라이브 정보 정리
    $driveInfo = @()
    foreach ($d in $drives) {
        $obj = [PSCustomObject]@{
            Drive      = $d.DeviceID
            FileSystem = $d.FileSystem
            VolumeName = $d.VolumeName
        }
        $driveInfo += $obj
    }

    Write-Host "--------- Fixed Drives and File Systems ---------"
    foreach ($d in $driveInfo) {

        # PS 5.1 호환용: null 또는 빈 값 처리
        $fs  = if ($null -ne $d.FileSystem -and $d.FileSystem -ne "") { $d.FileSystem } else { "N/A" }
        $vol = if ($null -ne $d.VolumeName) { $d.VolumeName } else { "" }

        Write-Host ("{0,-5}  FileSystem={1,-8}  Volume='{2}'" -f $d.Drive, $fs, $vol)
    }
    Write-Host "-------------------------------------------------"
    Write-Host

    # 2) NTFS 여부 판정
    $nonNtfs = $driveInfo | Where-Object { $_.FileSystem -and $_.FileSystem -ne "NTFS" }

    if (-not $nonNtfs -and $drives) {
        $detect_status = "PASS"
        Write-Host "[RESULT] All fixed disks are using NTFS file system. (Compliant)" -ForegroundColor Green
    } else {
        $detect_status = "FAIL"
        Write-Host "[RESULT] One or more fixed disks are NOT using NTFS. (Non-compliant)" -ForegroundColor Yellow
        Write-Host
        Write-Host "Non-NTFS fixed disks:" -ForegroundColor Yellow
        foreach ($n in $nonNtfs) {
            Write-Host ("  - {0} (FileSystem={1}, Volume='{2}')" -f $n.Drive, $n.FileSystem, $n.VolumeName)
        }
        Write-Host
        Write-Host "[GUIDE] To convert a volume to NTFS (after backup), run the following commands in CMD:" -ForegroundColor Cyan
        foreach ($n in $nonNtfs) {
            $driveLetter = $n.Drive.TrimEnd('\')
            Write-Host ("    convert {0} /fs:ntfs" -f $driveLetter)
        }
        Write-Host
        Write-Host "[NOTE] File system conversion can affect existing data. Make sure to backup and plan downtime." -ForegroundColor DarkYellow
    }

    Write-Host
    Write-Host "--------- Detect Result ---------"
    Write-Host "[RESULT] Policy Compliance Status: $detect_status" -ForegroundColor Cyan
    Write-Host "---------------------------------"
    Write-Host

    # 3) Remediation 상태
    # 이 스크립트는 디스크 자동 변환은 수행하지 않고, 필요 시 백업만 도와주고 변환 명령을 안내함.
    if ($detect_status -eq "PASS") {
        $remediate_status = "PASS"
        Write-Host "[RESULT] No remediation required." -ForegroundColor Cyan
    } else {
        # 탐지 결과 FAIL이고, non-NTFS 디스크가 있을 때만 백업 여부를 물어봄
        if ($nonNtfs -and $nonNtfs.Count -gt 0) {
            $userInput = Read-Host -Prompt "Do you want to create a backup file list for non-NTFS drives before manual conversion? (y/n)"

            if ($userInput -eq 'y' -or $userInput -eq 'Y') {
                foreach ($n in $nonNtfs) {
                    $driveLetter = $n.Drive.TrimEnd('\')   # 예: 'E:'
                    $driveLabel  = $driveLetter.TrimEnd(':') # 예: 'E'
                    $backupFile  = Join-Path $result_dir ("W-79_{0}_filelist_{1}.txt" -f $driveLabel, (Get-Date -Format "yyyyMMddHHmmss"))

                    Write-Host "[INFO] Creating file list backup for drive $driveLetter ..." -ForegroundColor Yellow
                    try {
                        # 해당 드라이브의 파일 목록을 백업 (메타데이터 백업)
                        Get-ChildItem -Path ("{0}\" -f $driveLetter) -Recurse -File -ErrorAction SilentlyContinue |
                            Select-Object FullName, Length, LastWriteTime |
                            Out-File -FilePath $backupFile -Encoding UTF8

                        Write-Host "[RESULT] File list backup created: $backupFile" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[WARN] Failed to create file list backup for $driveLetter : $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "[RESULT] Backup skipped by user." -ForegroundColor Yellow
            }
        }

        # 실제 파일시스템 변환은 수행하지 않음 (관리자 수동 조치 필요)
        $remediate_status = "FAIL"
        Write-Host "[RESULT] Manual remediation required (convert FAT/FAT32 to NTFS)." -ForegroundColor Yellow
    }

    # 4) 리포트용 설명 텍스트 (PDF 기준)
    $discussion = @"
Good: All fixed disks are using NTFS, which supports ACLs and detailed access control.
Vulnerable: FAT/FAT32 or other non-NTFS file systems are used on fixed disks, so fine-grained
access control and logging cannot be applied properly, increasing the risk of data exposure.
"@

    $check_content = @"
Step 1) Check the file system type of each fixed drive:
        - Windows 탐색기에서 드라이브 속성 확인
        - 또는 CMD에서 'fsutil fsinfo volumeinfo 드라이브명:' 실행
Step 2) If any fixed drive is using FAT/FAT32, convert it to NTFS:
        - 명령 프롬프트(CMD) 실행
        - 예) convert E: /fs:ntfs
        - 필요 시 서비스 중단 및 데이터 백업 후 진행
"@

    # 5) JSON 결과 객체 구성
    $result = [PSCustomObject]@{
        date           = $ts
        control_family = "SC-28"  # 예시: 파일 시스템 보호 관련 통제
        check_target   = "Use NTFS file systems for fixed disks"
        discussion     = $discussion
        check_content  = $check_content
        fix_text       = "Convert FAT/FAT32 file systems on fixed disks to NTFS after backing up data."
        payload        = [PSCustomObject]@{
            severity    = "medium"  # W-79 (중)
            port        = ""
            service     = "FileSystem"
            protocol    = ""
            threat      = @(
                "Unauthorized access due to lack of ACL",
                "Inability to apply detailed file and directory permissions",
                "Increased risk of data exposure when disks are lost or stolen"
            )
            TTP         = @("T1005","T1070.004")
            file_checked = "Win32_LogicalDisk (DriveType=3, FileSystem != NTFS)"
        }
        results = @(
            [PSCustomObject]@{
                phase           = "detect"
                status          = $detect_status
                drives          = $driveInfo
                non_ntfs_drives = $nonNtfs
            },
            [PSCustomObject]@{
                phase   = "remediate"
                status  = $remediate_status
                note    = "Script does not auto-convert; administrator must run 'convert X: /fs:ntfs' for non-NTFS volumes."
            }
        )
    }

    # 6) JSON 저장 (UTF-8)
    $result | ConvertTo-Json -Depth 5 | Set-Content -Path $json_file -Encoding UTF8
}
finally {
    Stop-Transcript | Out-Null
}
