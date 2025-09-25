#requires -version 5.1
<#!
.SYNOPSIS
    OmniCleaner - Windows Security & Shortcut Malware Cleaner

.DESCRIPTION
    A legitimate security tool designed to remove shortcut viruses and malware from removable drives.
    This tool helps users recover their files from USB drives infected with shortcut viruses.
    
    Features:
    - Makes hidden real files visible (attrib -h -s -r)
    - Removes malicious shortcuts (.lnk) and autorun.inf files
    - Stops and disables suspicious services with random names starting with 'x'
    - Cleans suspicious .dat/.vbs/.js payload files
    - İsteğe bağlı olarak Run/Services gibi kayıt defteri başlangıç girdilerini tarar ve temizler
    
    Author: SoulzHem

.PARAMETER Targets
    Temizlenecek yollar veya sürücü kökleri (örn. D:\, E:\). Boş ise -AllRemovable kullanın.

.PARAMETER AllRemovable
    Takılı tüm çıkarılabilir sürücüleri hedefler.

.PARAMETER IncludeFixed
    Çıkarılabilir sürücülere ek olarak sabit sürücüleri de tarar (C: hariç varsayılan; -IncludeSystem ile C: eklenir).

.PARAMETER IncludeSystem
    Sistem sürücüsünü (genellikle C:) de taramaya dahil eder. Dikkatli kullanın.

.PARAMETER Aggressive
    Kayıt defteri Run/Svchost/Services alanlarında şüpheli girdileri temizler. Varsayılan: kapalı.

.PARAMETER LogPath
    Günlük dosyası yolu. Varsayılan: .\omnicleaner.log

.PARAMETER WhatIf
    Değişiklik yapmadan ne olacağını gösterir.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\OmniCleaner.ps1 -AllRemovable -Aggressive

.NOTES
    Yönetici olarak çalıştırmanız önerilir.
!#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string[]] $Targets,
    [switch] $AllRemovable,
    [switch] $IncludeFixed,
    [switch] $IncludeSystem,
    [switch] $Aggressive,
    [string] $LogPath = "$PSScriptRoot/omnicleaner.log",
    [switch] $DoServices,
    [switch] $SkipServices,
    [switch] $DoShortcuts,
    [switch] $SkipShortcuts,
    [switch] $DoPayloads,
    [switch] $SkipPayloads,
    [switch] $DoRegistry,
    [switch] $SkipRegistry,
    [switch] $Quarantine,
    [switch] $UsbHeuristics,
    [switch] $ScanOnly,
    # Advanced scans
    [switch] $DoScheduledTasks,
    [switch] $SkipScheduledTasks,
    [switch] $DoWmiSubscriptions,
    [switch] $SkipWmiSubscriptions,
    [switch] $DoLnkAnalysis,
    [switch] $SkipLnkAnalysis,
    [switch] $RestoreQuarantine,
    [string[]] $RestoreItems,
    [string[]] $DeleteItems,
    # Advanced+ (log-only for now)
    [switch] $DoKeyloggerHeuristics,
    [switch] $DoStartup,
    [switch] $DoHosts,
    [switch] $DoBrowserExt,
    [switch] $DoPSProfiles,
    [switch] $DoOpenPorts,
    [switch] $DoProcessAnomalies,
    # Actions (dangerous; use with care)
    [switch] $KillProcesses,
    [string[]] $KillProcessPatterns,
    [switch] $CloseOpenPorts,
    [int[]] $PortTargets
)
# ========== Ağ ve süreç taramaları (log-only) ==========
function Get-OpenPortsLogOnly {
    try {
        Write-Log 'Açık portlar taranıyor (netstat) ...'
        $conns = netstat -ano | Select-String -Pattern 'TCP|UDP'
        foreach ($ln in $conns) { Write-Log ("[PORT] " + $ln.ToString()) }
        Write-Log 'Açık port taraması tamamlandı.'
    } catch { Write-Log ("Open ports taraması hata: " + $_.Exception.Message) 'WARN' }
}

function Get-ProcessAnomaliesLogOnly {
    try {
        Write-Log 'Şüpheli süreçler taranıyor...'
        $badNames = @('x(?=.*\d)[0-9a-z]{3,7}\.exe','mshta','wscript','cscript','powershell','cmd')
        $procs = Get-Process | Sort-Object -Property ProcessName -Unique
        foreach ($p in $procs) {
            $name = [string]$p.ProcessName
            foreach ($pat in $badNames) { if ($name -match $pat) { Write-Log ("[PROC?] " + $name + " (Id=" + $p.Id + ")") ; break } }
        }
        # Komut satırı bilgisi (varsa)
        try {
            Get-CimInstance Win32_Process | ForEach-Object {
                $cmd = [string]$_.CommandLine
                if ($cmd -match '(?i)mshta|wscript|cscript|powershell|iex|downloadstring|http') {
                    Write-Log ("[CMD?] PID=" + $_.ProcessId + " Cmd=" + $cmd)
                }
            }
        } catch {}
        Write-Log 'Şüpheli süreç taraması tamamlandı.'
    } catch { Write-Log ("Process anomaly taraması hata: " + $_.Exception.Message) 'WARN' }
}

function Stop-SuspiciousProcesses {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]] $Patterns)
    try {
        if (-not $Patterns -or $Patterns.Count -eq 0) { $Patterns = @('^x(?=.*\d)[0-9a-z]{3,7}\.exe$','(?i)mshta','(?i)wscript','(?i)cscript') }
        Write-Log 'Şüpheli süreçler sonlandırılıyor...'
        $procs = Get-CimInstance Win32_Process
        foreach ($pr in $procs) {
            $name = [string]$pr.Name
            $cmd = [string]$pr.CommandLine
            $hit = $false
            foreach ($pat in $Patterns) { if ($name -match $pat -or $cmd -match $pat) { $hit = $true; break } }
            if ($hit) {
                Write-Log ("[KILL] PID=" + $pr.ProcessId + " Name=" + $name)
                if ($PSCmdlet.ShouldProcess($name, 'Stop-Process')) {
                    try { Stop-Process -Id $pr.ProcessId -Force -ErrorAction Stop } catch { Write-Log ("Stop-Process hata PID=" + $pr.ProcessId + ' - ' + $_.Exception.Message) 'WARN' }
                }
            }
        }
        Write-Log 'Süreç sonlandırma tamamlandı.'
    } catch { Write-Log ("Süreç sonlandırma hata: " + $_.Exception.Message) 'WARN' }
}

function Close-PortsByTargets {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int[]] $Ports)
    if (-not $Ports -or $Ports.Count -eq 0) { return }
    try {
        Write-Log ('Belirtilen portlar kapatılıyor: ' + ($Ports -join ','))
        $conns = netstat -ano | Select-String -Pattern 'TCP|UDP'
        foreach ($ln in $conns) {
            $t = $ln.ToString()
            # Örnek satır:  TCP    0.0.0.0:4444   0.0.0.0:0   LISTENING   1234
            $m = [regex]::Match($t, ':(\d+)\s+.+?(\d+)$')
            if ($m.Success) {
                $portNum = [int]$m.Groups[1].Value
                $procId = [int]$m.Groups[2].Value
                if ($Ports -contains $portNum) {
                    Write-Log ("[PORT-KILL] Port=" + $portNum + " PID=" + $procId + " -> Stop-Process")
                    if ($PSCmdlet.ShouldProcess("PID="+$procId, 'Stop-Process')) {
                        try { Stop-Process -Id $procId -Force -ErrorAction Stop } catch { Write-Log ("Port kapatma hata PID=" + $procId + ' - ' + $_.Exception.Message) 'WARN' }
                    }
                }
            }
        }
    } catch { Write-Log ("Port kapatma hata: " + $_.Exception.Message) 'WARN' }
}

# Çıkış ve konsol encodingleme (Türkçe karakterler için)
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $global:OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {}
# Karantinadan geri yükleme
function Restore-Quarantine {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $qdir = Join-Path $PSScriptRoot 'quarantine'
    $idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
    if (-not (Test-Path $qdir)) { Write-Log 'Quarantine klasörü bulunamadı.' 'WARN'; return }
    if (-not (Test-Path $idx)) { Write-Log 'quarantine_index.csv bulunamadı.' 'WARN'; return }
    try {
        $lines = Get-Content -LiteralPath $idx -ErrorAction Stop | Select-Object -Skip 1
    } catch { $lines = @() }
    $restored = 0; $failed = 0
    foreach ($ln in $lines) {
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        $parts = $ln.Split(',')
        if ($parts.Count -lt 3) { continue }
        $orig = $parts[1]
        $file = $parts[2]
        $src = Join-Path $qdir $file
        try {
            if (Test-Path -LiteralPath $src) {
                $destDir = Split-Path -Parent $orig
                try { if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null } } catch {}
                if ($PSCmdlet.ShouldProcess($orig, 'Restore from quarantine')) {
                    Move-Item -LiteralPath $src -Destination $orig -Force -ErrorAction Stop
                    Write-Log ('Restore: ' + $file + ' -> ' + $orig)
                    $restored++
                }
            }
        } catch { Write-Log ("Restore failed: " + $file + ' -> ' + $orig + ' - ' + $_.Exception.Message) 'WARN'; $failed++ }
    }
    Write-Log ('[SUMMARY] Restore Restored=' + $restored + ', Failed=' + $failed)
}

# Karantinadan seçili öğeleri geri yükle
function Restore-QuarantineItems {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]] $Items)
    if (-not $Items -or $Items.Count -eq 0) { return }
    $qdir = Join-Path $PSScriptRoot 'quarantine'
    $idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
    if (-not (Test-Path $qdir)) { Write-Log 'Quarantine klasörü bulunamadı.' 'WARN'; return }
    if (-not (Test-Path $idx)) { Write-Log 'quarantine_index.csv bulunamadı.' 'WARN'; return }
    $lines = @()
    try { $lines = Get-Content -LiteralPath $idx -ErrorAction Stop } catch {}
    if ($lines.Count -lt 2) { return }
    $header = $lines[0]
    $body = $lines | Select-Object -Skip 1
    $restored = 0; $failed = 0
    foreach ($it in $Items) {
        $match = $body | Where-Object { $_ -like "*,$it" }
        foreach ($ln in $match) {
            $parts = $ln.Split(',')
            if ($parts.Count -lt 3) { continue }
            $orig = $parts[1]
            $file = $parts[2]
            $src = Join-Path $qdir $file
            try {
                if (Test-Path -LiteralPath $src) {
                    $destDir = Split-Path -Parent $orig
                    try { if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null } } catch {}
                    if ($PSCmdlet.ShouldProcess($orig, 'Restore from quarantine')) {
                        Move-Item -LiteralPath $src -Destination $orig -Force -ErrorAction Stop
                        Write-Log ('Restore: ' + $file + ' -> ' + $orig)
                        $restored++
                        # index'ten ilgili satırı çıkar
                        $body = $body | Where-Object { $_ -ne $ln }
                    }
                }
            } catch { Write-Log ("Restore failed: " + $file + ' -> ' + $orig + ' - ' + $_.Exception.Message) 'WARN'; $failed++ }
        }
    }
    try { ($header, $body) | Set-Content -LiteralPath $idx -Encoding utf8 } catch {}
    Write-Log ('[SUMMARY] Restore Selected Restored=' + $restored + ', Failed=' + $failed)
}

# Karantinadan seçili öğeleri kalıcı sil
function Remove-QuarantineItems {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]] $Items)
    if (-not $Items -or $Items.Count -eq 0) { return }
    $qdir = Join-Path $PSScriptRoot 'quarantine'
    $idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
    if (-not (Test-Path $qdir)) { Write-Log 'Quarantine klasörü bulunamadı.' 'WARN'; return }
    if (-not (Test-Path $idx)) { Write-Log 'quarantine_index.csv bulunamadı.' 'WARN'; return }
    $lines = @()
    try { $lines = Get-Content -LiteralPath $idx -ErrorAction Stop } catch {}
    if ($lines.Count -lt 2) { return }
    $header = $lines[0]
    $body = $lines | Select-Object -Skip 1
    $deleted = 0; $failed = 0
    foreach ($it in $Items) {
        $match = $body | Where-Object { $_ -like "*,$it" }
        foreach ($ln in $match) {
            $parts = $ln.Split(',')
            if ($parts.Count -lt 3) { continue }
            $file = $parts[2]
            $src = Join-Path $qdir $file
            try {
                if (Test-Path -LiteralPath $src) {
                    if ($PSCmdlet.ShouldProcess($src, 'Delete from quarantine')) {
                        Remove-Item -LiteralPath $src -Force -ErrorAction Stop
                        Write-Log ('Deleted from quarantine: ' + $file)
                        $deleted++
                        # index'ten ilgili satırı çıkar
                        $body = $body | Where-Object { $_ -ne $ln }
                    }
                } else {
                    # Dosya yoksa index'ten yine de çıkar
                    $body = $body | Where-Object { $_ -ne $ln }
                }
            } catch { Write-Log ("Delete failed: " + $file + ' - ' + $_.Exception.Message) 'WARN'; $failed++ }
        }
    }
    try { ($header, $body) | Set-Content -LiteralPath $idx -Encoding utf8 } catch {}
    Write-Log ('[SUMMARY] Delete Selected Deleted=' + $deleted + ', Failed=' + $failed)
}


function Write-Log {
    param(
        [string] $Message,
        [string] $Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp] [$Level] $Message"
    # Hem stdout'a hem dosyaya yaz
    Write-Output $line
    try { Add-Content -Path $LogPath -Value $line -Encoding utf8 -ErrorAction Stop } catch {}
}

# ========== Advanced (log-only stubs) ==========
function Get-KeyloggerHeuristics {
    try {
        Write-Log 'Keylogger heuristics taraması başlıyor...'
        # Basit sezgiler: klavye hook DLL/EXE adları, temp/roaming içinde şüpheli dosyalar
        $patterns = @('keylog','klavye','hook','input','logger')
        foreach ($root in @($env:APPDATA,$env:LOCALAPPDATA,$env:TEMP)) {
            if (-not $root) { continue }
            try {
                Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Where-Object { $n=$_.Name.ToLower(); $patterns | Where-Object { $n -like "*$_*" } } |
                    ForEach-Object { Write-Log ("[KEYLOGGER?] " + $_.FullName) }
            } catch {}
        }
        Write-Log 'Keylogger heuristics tamamlandı.'
    } catch { Write-Log ("Keylogger heuristics hata: " + $_.Exception.Message) 'WARN' }
}

function Get-StartupItems {
    try {
        Write-Log 'Startup klasörleri taranıyor...'
        $startupPaths = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        )
        foreach ($sp in $startupPaths) {
            try {
                if ($sp -and (Test-Path $sp)) {
                    Get-ChildItem -LiteralPath $sp -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Write-Log ("[STARTUP] " + $_.FullName)
                    }
                }
            } catch {}
        }
        Write-Log 'Startup taraması tamamlandı.'
    } catch { Write-Log ("Startup taraması hata: " + $_.Exception.Message) 'WARN' }
}

function Get-HostsSuspicious {
    try {
        Write-Log 'Hosts dosyası kontrol ediliyor...'
        $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-Path $hosts) {
            $lines = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue
            foreach ($ln in $lines) {
                $t = $ln.Trim()
                if ($t -match '(^127\.0\.0\.1\s+)|(^0\.0\.0\.0\s+)' -and $t -match '(microsoft|windows|defender|update)') {
                    Write-Log ("[HOSTS?] " + $t)
                }
            }
        } else { Write-Log 'Hosts dosyası bulunamadı.' 'WARN' }
        Write-Log 'Hosts kontrolü tamamlandı.'
    } catch { Write-Log ("Hosts kontrolü hata: " + $_.Exception.Message) 'WARN' }
}

function Get-BrowserExtensions {
    try {
        Write-Log 'Tarayıcı eklentileri listeleniyor...'
        $chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Extensions'
        $edge = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Extensions'
        foreach ($p in @($chrome,$edge)) {
            if ($p -and (Test-Path $p)) {
                Get-ChildItem -LiteralPath $p -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Log ("[EXT] " + $_.FullName)
                }
            }
        }
        Write-Log 'Eklentiler listelendi.'
    } catch { Write-Log ("Eklenti listesi hata: " + $_.Exception.Message) 'WARN' }
}

function Get-PSProfilesSuspicious {
    try {
        Write-Log 'PowerShell profil dosyaları inceleniyor...'
        $profiles = @($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.CurrentUserCurrentHost) | Where-Object { $_ }
        foreach ($pf in ($profiles | Select-Object -Unique)) {
            try {
                if (Test-Path $pf) {
                    $c = Get-Content -LiteralPath $pf -ErrorAction SilentlyContinue -Raw
                    if ($c -match 'Invoke-Expression|DownloadString|IEX|WebClient') { Write-Log ("[PSPROFILE?] " + $pf) }
                }
            } catch {}
        }
        Write-Log 'PowerShell profil incelemesi tamamlandı.'
    } catch { Write-Log ("PS profile inceleme hata: " + $_.Exception.Message) 'WARN' }
}

function Get-TargetDrives {
    $drives = @()

    if ($AllRemovable) {
        try {
            $drives += Get-Volume |
                Where-Object { $_.DriveType -eq 'Removable' -and $_.OperationalStatus -eq 'OK' -and $_.DriveLetter } |
                Select-Object -ExpandProperty DriveLetter -Unique
        } catch {}
    }

    if ($IncludeFixed) {
        try {
            $fixed = Get-Volume |
                Where-Object { $_.DriveType -eq 'Fixed' -and $_.OperationalStatus -eq 'OK' -and $_.DriveLetter } |
                Select-Object -ExpandProperty DriveLetter -Unique
            if (-not $IncludeSystem) {
                $system = (Get-Location).Path.Substring(0,1)
                $fixed = $fixed | Where-Object { $_ -ne $system }
            }
            $drives += $fixed
        } catch {}
    }

    if ($Targets) {
        foreach ($t in $Targets) {
            # Parametre/switch gibi görünen öğeleri yok say
            if ($t -match '^\-') { continue }
            if (Test-Path $t) {
                if ($t.Length -ge 2 -and $t[1] -eq ':') {
                    $drives += $t[0]
                } else {
                    $drives += (Split-Path -Qualifier (Resolve-Path $t)).TrimEnd(':')
                }
            } else {
                Write-Log "Hedef bulunamadı: $t" 'WARN'
            }
        }
    }

    $drives = $drives | Where-Object { $_ } | Select-Object -Unique
    # Sadece erişilebilir ve CD-ROM olmayanları dön
    $ready = @()
    foreach ($dl in $drives) {
        try {
            $vol = Get-Volume -DriveLetter $dl -ErrorAction SilentlyContinue
            if ($vol -and $vol.DriveType -ne 'CD-ROM' -and $vol.OperationalStatus -eq 'OK') { $ready += $dl }
        } catch {}
    }
    return $ready
}

function Set-RealFilesVisible {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string] $DriveLetter)
    $root = "$( $DriveLetter ):\"
    $isSystem = ($DriveLetter.ToUpperInvariant() -eq ($env:SystemDrive.Substring(0,1).ToUpperInvariant()))
    $targets = @($root)
    if ($isSystem) {
        $targets = @()
        foreach ($p in @($env:USERPROFILE, $env:PUBLIC)) { if ($p -and (Test-Path $p)) { $targets += ($p + '\\') } }
    }
    foreach ($tp in ($targets | Select-Object -Unique)) {
        Write-Log "Gizli öznitelikler kaldırılıyor: $tp"
        try {
            if ($PSCmdlet.ShouldProcess($tp, 'attrib -h -s -r /s /d')) {
                attrib -h -s -r /s /d "${tp}*.*" 2>$null
        }
    } catch {
        Write-Log "Attrib hatası: $($_.Exception.Message)" 'ERROR'
        }
    }
}

function Remove-MaliciousShortcutsAndAutoruns {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string] $DriveLetter)
    $root = "$( $DriveLetter ):\"
    $isSystem = ($DriveLetter.ToUpperInvariant() -eq ($env:SystemDrive.Substring(0,1).ToUpperInvariant()))

    Write-Log "Kötü amaçlı .lnk ve autorun.inf temizleniyor: $root"

    $scanRoots = @($root)
    if ($isSystem) {
        $scanRoots = @()
        foreach ($p in @($env:USERPROFILE, $env:PUBLIC)) { if ($p -and (Test-Path $p)) { $scanRoots += ($p + '\\') } }
    }

    foreach ($scan in ($scanRoots | Select-Object -Unique)) {
        # Autorun.inf
        try {
            Get-ChildItem -LiteralPath $scan -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ieq 'autorun.inf' } |
        ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove autorun.inf')) {
                try { $_.Attributes = 'Normal' } catch {}
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {
                    Write-Log "Silinemedi: $($_.FullName) - $($_.Exception.Message)" 'WARN'
                }
            }
        }
        } catch { Write-Log "Autorun tarama hatası: $($_.Exception.Message)" 'WARN' }

        # .lnk
        try {
            Get-ChildItem -LiteralPath $scan -Recurse -Force -File -Filter '*.lnk' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove shortcut')) {
                        try { $_.Attributes = 'Normal' } catch {}
                        try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {
                            Write-Log "Silinemedi: $($_.FullName) - $($_.Exception.Message)" 'WARN'
                        }
                    }
                }
        } catch { Write-Log "LNK tarama hatası: $($_.Exception.Message)" 'WARN' }
    }
}

function Stop-AndDisable-SuspiciousServices {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    # Sadece x + 3-7 altkarakter (rakam zorunlu) gibi kısa adları hedefle
    $pattern = '^x(?=.*\d)[0-9a-z]{3,7}$'
    try {
        $services = Get-Service | Where-Object { $_.Name -match $pattern }
    } catch { $services = @() }

    foreach ($svc in $services) {
        Write-Log "Şüpheli hizmet bulundu: $( $svc.Name ) - Durum: $( $svc.Status )"
        try {
            if ($svc.Status -ne 'Stopped') {
                if ($PSCmdlet.ShouldProcess($svc.Name, 'Stop-Service')) { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue }
            }
        } catch { Write-Log "Durdurma hatası $( $svc.Name ): $($_.Exception.Message)" 'WARN' }
        try {
            if ($PSCmdlet.ShouldProcess($svc.Name, 'Set-Service Disabled')) { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue }
        } catch { Write-Log "Devre dışı bırakma hatası $( $svc.Name ): $($_.Exception.Message)" 'WARN' }

        try {
            $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$( $svc.Name )"
            $imagePath = (Get-ItemProperty -LiteralPath $svcKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
            if ($imagePath) {
                $expanded = [Environment]::ExpandEnvironmentVariables($imagePath) -replace '"',''
                $candidate = $expanded
                if ($candidate -match '([a-zA-Z]:\\[^\s\"]+\.(dat|vbs|js|cmd|bat))') {
                    $fileToRemove = $Matches[1]
                    if (Test-Path -LiteralPath $fileToRemove) {
                        Write-Log "Hizmet dosyası kaldırılıyor: $fileToRemove"
                        if ($PSCmdlet.ShouldProcess($fileToRemove, 'Remove service payload')) {
                            try { Remove-Item -LiteralPath $fileToRemove -Force -ErrorAction Stop } catch {
                                Write-Log "Silinemedi: $fileToRemove - $($_.Exception.Message)" 'WARN'
                            }
                        }
                    }
                }
            }
        } catch { Write-Log "Hizmet ImagePath inceleme hatası: $($_.Exception.Message)" 'WARN' }
    }
}

function Remove-SuspiciousPayloadFiles {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]] $DriveLetters
    )
    # Whitelist: meşru geliştirme/önbellek yollarını atla
    function Test-WhitelistedPath([string] $fullPath) {
        try {
            $p = $fullPath.ToLowerInvariant()
            $patterns = @(
                '\\code\\user\\history\\',
                '\\cursor\\user\\history\\',
                '\\node_modules\\',
                '\\yarn\\cache\\',
                '\\npm-cache\\',
                '\\npm\\node_modules\\',
                '\\scripts\\quarantine\\'
            )
            # Dinamik exclusions
            try {
                $exFile = Join-Path $PSScriptRoot 'exclusions.txt'
                if (Test-Path $exFile) {
                    $extra = Get-Content -LiteralPath $exFile -ErrorAction SilentlyContinue | Where-Object { $_ -and -not $_.StartsWith('#') }
                    foreach ($e in $extra) { $patterns += $e.Trim().ToLowerInvariant() }
                }
            } catch {}
            foreach ($pat in $patterns) { if ($p -like ('*' + $pat + '*')) { return $true } }
        } catch {}
        return $false
    }

    # Kullanıcı/ProgramData alanları yalnız IncludeFixed/IncludeSystem etkinse eklensin
    $searchPaths = @()
    if ($IncludeFixed -or $IncludeSystem) {
        $searchPaths += @(
        "$env:ProgramData",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:PUBLIC"
    ) | Where-Object { Test-Path $_ }
    }

    # Taşınabilir/sürücü köklerini ekle
    if ($DriveLetters) {
        foreach ($dl in $DriveLetters) {
            $rootPath = ("{0}:\" -f $dl)
            if (Test-Path -LiteralPath $rootPath) { $searchPaths += $rootPath }
        }
    }

    # Sıkı desen: x + 3-7 altkarakter, en az bir rakam ve uzantı dat/js/vbs/tmp
    $nameRegex = '^x(?=.*\d)[0-9a-z]{3,7}\.(dat|vbs|js|tmp)$'

    # USB worm heuristics: kök dizindeki script/batch/hidden exe gibi kalıplar
    $usbHeuristicExts = @('*.vbs','*.js','*.cmd','*.bat')

    $stats = [ordered]@{ Found=0; Removed=0; Quarantined=0; Errors=0 }

    foreach ($p in $searchPaths | Select-Object -Unique) {
        try {
            Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $nameRegex } |
                    ForEach-Object {
                    if (Test-WhitelistedPath $_.FullName) { Write-Log ("Whitelist skip: " + $_.FullName); return }
                        Write-Log "Şüpheli dosya bulundu: $( $_.FullName )"
                    $stats.Found++
                        if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove payload')) {
                            try { $_.Attributes = 'Normal' } catch {}
                        if ($Quarantine) {
                            try {
                                $qdir = Join-Path $PSScriptRoot 'quarantine'
                                if (-not (Test-Path $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
                                $dest = Join-Path $qdir ([IO.Path]::GetFileName($_.FullName))
                                Move-Item -LiteralPath $_.FullName -Destination $dest -Force -ErrorAction Stop
                                try {
                                    $idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
                                    $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ',' + ($_.FullName.Replace(',',';')) + ',' + ([IO.Path]::GetFileName($_.FullName).Replace(',',';'))
                                    Add-Content -LiteralPath $idx -Value $line -Encoding utf8 -ErrorAction SilentlyContinue
                                } catch {}
                                Write-Log "Karantinaya alındı: $dest"
                                $stats.Quarantined++
                            } catch { Write-Log "Karantinaya alınamadı: $($_.FullName) - $($_.Exception.Message)" 'WARN'; $stats.Errors++ }
                        } else {
                            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch {
                                Write-Log "Silinemedi: $($_.FullName) - $($_.Exception.Message)" 'WARN'; $stats.Errors++
                            }
                            $stats.Removed++
                            }
                        }
                    }
            } catch { Write-Log "Arama hatası: $($_.Exception.Message)" 'WARN' }
        }

    if ($UsbHeuristics -and $DriveLetters) {
        # Yalnız çıkarılabilir sürücülerde uygula
        $removable = @()
        foreach ($dl in $DriveLetters) {
            try {
                $vol = Get-Volume -DriveLetter $dl -ErrorAction SilentlyContinue
                if ($vol -and $vol.DriveType -eq 'Removable') { $removable += $dl }
            } catch {}
        }
        foreach ($dl in $removable | Select-Object -Unique) {
            $root = ("{0}:\" -f $dl)
            try {
                foreach ($ext in $usbHeuristicExts) {
                    Get-ChildItem -LiteralPath $root -Force -File -Filter $ext -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            if (Test-WhitelistedPath $_.FullName) { Write-Log ("Whitelist skip: " + $_.FullName); return }
                            Write-Log "USB heuristic eşleşme: $( $_.FullName )"
                            if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove USB heuristic payload')) {
                                try { $_.Attributes = 'Normal' } catch {}
                                if ($Quarantine) {
                                    try {
                                        $qdir = Join-Path $PSScriptRoot 'quarantine'
                                        if (-not (Test-Path $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
                                        $dest = Join-Path $qdir ([IO.Path]::GetFileName($_.FullName))
                                        Move-Item -LiteralPath $_.FullName -Destination $dest -Force -ErrorAction Stop
                                        try {
                                            $idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
                                            $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ',' + ($_.FullName.Replace(',',';')) + ',' + ([IO.Path]::GetFileName($_.FullName).Replace(',',';'))
                                            Add-Content -LiteralPath $idx -Value $line -Encoding utf8 -ErrorAction SilentlyContinue
                                        } catch {}
                                        Write-Log "Karantinaya alındı: $dest"
                                        $stats.Quarantined++
                                    } catch { Write-Log "Karantinaya alınamadı: $($_.FullName) - $($_.Exception.Message)" 'WARN'; $stats.Errors++ }
                                } else {
                                    try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { Write-Log "Silinemedi: $($_.FullName) - $($_.Exception.Message)" 'WARN'; $stats.Errors++ }
                                    $stats.Removed++
                                }
                            }
                        }
                }
            } catch { Write-Log "USB heuristics hatası: $($_.Exception.Message)" 'WARN' }
        }
    }

    # Karantina indexine yaz
    try {
        if ($stats.Quarantined -gt 0) {
            $idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
            if (-not (Test-Path $idx)) { 'timestamp,original_path,filename' | Out-File -FilePath $idx -Encoding utf8 }
            # Not: Bu döngüde tek tek yazılamadı; üstte yazıldıktan sonra işlendiği için
        }
    } catch {}
    Write-Log ("[SUMMARY] Payloads Found=" + $stats.Found + ", Removed=" + $stats.Removed + ", Quarantined=" + $stats.Quarantined + ", Errors=" + $stats.Errors)
}

function Get-ScheduledTasks {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log 'Scheduled Tasks taranıyor...'
    $susPatterns = @('(?i)powershell','(?i)wscript','(?i)cscript','(?i)mshta','x(?=.*\d)[0-9a-z]{3,7}\.(vbs|js|dat|tmp|exe)')
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    } catch { $tasks = @() }
    foreach ($t in $tasks) {
        try {
            $actions = $t.Actions
        } catch { $actions = @() }
        foreach ($a in $actions) {
            $cmd = (($a.Execute + ' ' + $a.Arguments).Trim())
            foreach ($pat in $susPatterns) {
                if ($cmd -match $pat) {
                    Write-Log ("[TASK] Şüpheli: Name=" + $t.TaskName + ", User=" + $t.Principal.UserId + ", Cmd=" + $cmd)
                    break
                }
            }
        }
    }
}

function Get-WmiSubscriptions {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-Log 'WMI Event Subscription taranıyor...'
    try {
        $consumers = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    } catch { $consumers = @() }
    foreach ($c in $consumers) {
        $cmd = [string]$c.CommandLineTemplate
        if ($cmd -match '(?i)powershell|wscript|cscript|mshta|x(?=.*\d)[0-9a-z]{3,7}\.(vbs|js|dat|tmp|exe)') {
            Write-Log ("[WMI] Şüpheli CommandLineConsumer: Name=" + $c.Name + ", Cmd=" + $cmd)
        }
    }
    try {
        $scripts = Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    } catch { $scripts = @() }
    foreach ($s in $scripts) {
        $prog = [string]$s.ScriptingEngine
        $scriptText = ([string]$s.ScriptText)
        if ($prog -match '(?i)VBScript|JScript' -and $scriptText.Length -gt 0) {
            Write-Log ("[WMI] ScriptConsumer: Name=" + $s.Name + ", Engine=" + $prog)
        }
    }
}

function Get-LnkTargets {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string[]] $Roots)
    if (-not $Roots) { return }
    Write-Log 'LNK hedef analizi başlıyor...'
    $shell = New-Object -ComObject WScript.Shell
    foreach ($r in ($Roots | Select-Object -Unique)) {
        try {
            Get-ChildItem -LiteralPath $r -Recurse -Force -File -Filter '*.lnk' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    try {
                        $sc = $shell.CreateShortcut($_.FullName)
                        $tp = [string]$sc.TargetPath
                        $lnkArgs = [string]$sc.Arguments
                        $cmdline = ($tp + ' ' + $lnkArgs).Trim()
                        if ($cmdline -match '(?i)powershell\s|wscript|cscript|mshta|x(?=.*\d)[0-9a-z]{3,7}\.(vbs|js|dat|tmp|exe)') {
                            Write-Log ("[LNK] Şüpheli: " + $_.FullName + " -> " + $cmdline)
                        }
                    } catch {}
                }
        } catch { Write-Log "LNK analiz hatası: $($_.Exception.Message)" 'WARN' }
    }
}

function Clear-RegistryEntries {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch] $Enable)
    if (-not $Enable) { return }

    Write-Log 'Kayıt defteri başlangıç girdileri taranıyor (-Aggressive)...'

    $runRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($root in $runRoots) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ItemProperty -LiteralPath $root -ErrorAction Stop |
                ForEach-Object {
                    foreach ($prop in $_.PSObject.Properties) {
                        if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                        $val = [string]$prop.Value
                        $malFile = $false
                        if ($val -match 'x(?=.*\d)[0-9a-z]{3,7}\.(dat|vbs|js|tmp)') { $malFile = $true }
                        if (-not $malFile) {
                            # wscript/cscript varsa ama x-random dosyaya gidiyorsa yine şüpheli
                            if (($val -match '(?i)(wscript|cscript)') -and ($val -match 'x(?=.*\d)[0-9a-z]{3,7}\.(vbs|js)')) { $malFile = $true }
                        }
                        if ($malFile) {
                            Write-Log "Run sil: $root\\$( $prop.Name ) -> $val"
                            if ($PSCmdlet.ShouldProcess("$root\\$( $prop.Name )", 'Remove Run value')) {
                                try { Remove-ItemProperty -LiteralPath $root -Name $prop.Name -Force -ErrorAction Stop } catch {
                                    Write-Log "Kaldırılamadı: $( $root ):$( $prop.Name ) - $($_.Exception.Message)" 'WARN'
                                }
                            }
                        }
                    }
                }
        } catch { Write-Log "Run tarama hatası $( $root ): $($_.Exception.Message)" 'WARN' }
    }

    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    try {
        Get-ChildItem -LiteralPath $svcRoot -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^x(?=.*\d)[0-9a-z]{3,7}$' } |
            ForEach-Object {
                $keyPath = $_.PSPath
                Write-Log "Şüpheli hizmet anahtarı: $( $._.PSChildName )"
                if ($PSCmdlet.ShouldProcess($keyPath, 'Remove service registry key')) {
                    try { Remove-Item -LiteralPath $keyPath -Recurse -Force -ErrorAction Stop } catch {
                        Write-Log "Silinemedi: $keyPath - $($_.Exception.Message)" 'WARN'
                    }
                }
            }
    } catch { Write-Log "Services tarama hatası: $($_.Exception.Message)" 'WARN' }
}

function Test-IsElevated {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Hazırlık (log dosyasını sıfırlamak yerine oturum başlığı ekle)
try { if (-not (Test-Path $LogPath)) { New-Item -ItemType File -Path $LogPath -Force | Out-Null } } catch {}
try { Add-Content -Path $LogPath -Encoding utf8 -Value ('----- SESSION ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' -----') } catch {}
Write-Log "OmniCleaner başlatıldı (WhatIf=$( $PSCmdlet.WhatIfPreference -eq $true ), Aggressive=$Aggressive, ScanOnly=$ScanOnly)"
if ($PSCmdlet.WhatIfPreference -eq $true -or $ScanOnly) { Write-Log '[MODE] Dry run (scan only) - No changes will be made.' }
Write-Log ("Scope: Services=" + ($DoServices -and -not $SkipServices) + ", Shortcuts=" + ($DoShortcuts -and -not $SkipShortcuts) + ", Payloads=" + ($DoPayloads -and -not $SkipPayloads) + ", Registry=" + ($DoRegistry -and -not $SkipRegistry))
Write-Log ("Advanced: Tasks=" + ($DoScheduledTasks -and -not $SkipScheduledTasks) + ", WMI=" + ($DoWmiSubscriptions -and -not $SkipWmiSubscriptions) + ", LNKAnalyze=" + ($DoLnkAnalysis -and -not $SkipLnkAnalysis))

$elevated = Test-IsElevated
if (-not $elevated) {
    Write-Log 'UYARI: Yönetici olarak çalıştırmıyorsunuz. Bazı işlemler başarısız olabilir.' 'WARN'
}

if (-not ($PSCmdlet.WhatIfPreference -eq $true -or $ScanOnly)) {
    if ($DoServices -and -not $SkipServices -or (-not $DoServices -and -not $SkipServices)) { Stop-AndDisable-SuspiciousServices }
} else {
    Write-Log '[SCAN] Services would be scanned.'
}

$driveLetters = Get-TargetDrives
if (-not $driveLetters -or $driveLetters.Count -eq 0) {
    Write-Log 'Hedef sürücü bulunamadı. -AllRemovable ve/veya -Targets kullanın.' 'WARN'
} else {
    foreach ($dl in $driveLetters | Sort-Object -Unique) {
        try {
            if (-not ($PSCmdlet.WhatIfPreference -eq $true -or $ScanOnly)) {
                if ($DoShortcuts -and -not $SkipShortcuts -or (-not $DoShortcuts -and -not $SkipShortcuts)) { Remove-MaliciousShortcutsAndAutoruns -DriveLetter $dl }
            Set-RealFilesVisible -DriveLetter $dl
            } else {
                Write-Log ("[SCAN] Shortcuts/autorun would be cleaned on " + $dl + ":\")
                Write-Log ("[SCAN] Attributes would be fixed on " + $dl + ":\")
            }
        } catch { Write-Log "Sürücü temizliği hatası $( $dl ): $($_.Exception.Message)" 'WARN' }
    }
}

# Kullanıcı ve taşınabilir alanlarda şüpheli taşıyıcıları temizle
if ($DoPayloads -and -not $SkipPayloads -or (-not $DoPayloads -and -not $SkipPayloads)) {
    if (-not ($PSCmdlet.WhatIfPreference -eq $true -or $ScanOnly)) {
        Remove-SuspiciousPayloadFiles -DriveLetters $driveLetters
    } else {
        Write-Log '[SCAN] Payloads would be scanned.'
    }
}

if ($DoRegistry -and -not $SkipRegistry) {
    if (-not ($PSCmdlet.WhatIfPreference -eq $true -or $ScanOnly)) { Clear-RegistryEntries -Enable:$Aggressive } else { Write-Log '[SCAN] Registry would be scanned.' }
}

# Advanced scans (read-only unless explicit clean routines added later)
if ($DoScheduledTasks -and -not $SkipScheduledTasks) { Get-ScheduledTasks }
if ($DoWmiSubscriptions -and -not $SkipWmiSubscriptions) { Get-WmiSubscriptions }
if ($DoLnkAnalysis -and -not $SkipLnkAnalysis) {
    $roots = @()
    if ($driveLetters) { foreach ($dl in $driveLetters) { $roots += ("{0}:\" -f $dl) } }
    $roots += @($env:USERPROFILE, $env:PUBLIC) | Where-Object { $_ }
    Get-LnkTargets -Roots $roots
}

# Advanced+ (log-only)
if ($DoKeyloggerHeuristics) { Get-KeyloggerHeuristics }
if ($DoStartup) { Get-StartupItems }
if ($DoHosts) { Get-HostsSuspicious }
if ($DoBrowserExt) { Get-BrowserExtensions }
if ($DoPSProfiles) { Get-PSProfilesSuspicious }
if ($DoOpenPorts) { Get-OpenPortsLogOnly }
if ($DoProcessAnomalies) { Get-ProcessAnomaliesLogOnly }
if ($KillProcesses) { Stop-SuspiciousProcesses -Patterns $KillProcessPatterns }
if ($CloseOpenPorts) { Close-PortsByTargets -Ports $PortTargets }

Write-Log 'Temizlik tamamlandı.'
if ($RestoreQuarantine) { Restore-Quarantine }
if ($RestoreItems) { Restore-QuarantineItems -Items $RestoreItems }
if ($DeleteItems) { Remove-QuarantineItems -Items $DeleteItems }
exit 0
