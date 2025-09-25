#requires -version 5.1
<#!
.SYNOPSIS
    OmniCleaner - Online Bootstrap Launcher

.DESCRIPTION
    Tek satırlık komutla (irm ... | iex) OmniCleaner'ı geçici klasöre indirir,
    dosyaları unblocks eder ve GUI'yi başlatır. Release varsa onu, yoksa main ZIP'ini kullanır.

.PARAMETER Cleanup
    Çıkışta indirilen geçici klasörü siler.

.EXAMPLE
    irm 'https://raw.githubusercontent.com/SoulzHem/OmniCleaner/main/bootstrap.ps1' | iex

.EXAMPLE
    iwr -useb 'https://raw.githubusercontent.com/SoulzHem/OmniCleaner/main/bootstrap.ps1' | iex
#>

param(
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red }

try {
    Write-Info "OmniCleaner bootstrap başlıyor..."

    $owner = 'SoulzHem'
    $repo  = 'OmniCleaner'

    $tempRoot = Join-Path $env:TEMP ("omnicleaner_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    Write-Info ("Geçici klasör: " + $tempRoot)

    $zipPath = Join-Path $tempRoot 'OmniCleaner.zip'

    $releaseApi = "https://api.github.com/repos/$owner/$repo/releases/latest"
    $headers = @{ 'User-Agent' = 'PowerShell' }

    $downloaded = $false
    try {
        Write-Info "Son release bilgisi alınıyor..."
        $rel = Invoke-RestMethod -Uri $releaseApi -Headers $headers -UseBasicParsing
        if ($rel -and $rel.assets) {
            $asset = $rel.assets | Where-Object { $_.name -ieq 'OmniCleaner.zip' } | Select-Object -First 1
            if ($asset -and $asset.browser_download_url) {
                Write-Info "Release bulundu, indiriliyor: $($asset.name)"
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing
                $downloaded = $true
            }
        }
    } catch {
        Write-Warn "Release alınamadı, main ZIP'e düşülecek. ($_ )"
    }

    if (-not $downloaded) {
        $mainZip = "https://github.com/$owner/$repo/archive/refs/heads/main.zip"
        Write-Info "Main zip indiriliyor..."
        Invoke-WebRequest -Uri $mainZip -OutFile $zipPath -UseBasicParsing
    }

    Write-Info "Arşiv açılıyor..."
    Expand-Archive -LiteralPath $zipPath -DestinationPath $tempRoot -Force

    # Release zip ise kökte dosyalar olacaktır; main zip ise tek bir üst klasör açılır
    $candidateRoots = @(
        $tempRoot,
        (Get-ChildItem -LiteralPath $tempRoot -Directory | Select-Object -Expand FullName -First 1)
    ) | Where-Object { $_ -ne $null }

    $workDir = $null
    foreach ($c in $candidateRoots) {
        if (Test-Path (Join-Path $c 'RunCleanerGUI.bat') -PathType Leaf) { $workDir = $c; break }
        if (Test-Path (Join-Path $c 'scripts\OmniCleaner.GUI.ps1') -PathType Leaf) { $workDir = $c; break }
    }

    if (-not $workDir) { throw "Beklenen dosya yapısı bulunamadı." }

    Write-Info ("Çalışma klasörü: " + $workDir)

    # Unblock all scripts
    Get-ChildItem -LiteralPath $workDir -Recurse -Include *.ps1,*.bat | ForEach-Object {
        try { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue } catch {}
    }

    # GUI başlat
    $launcher = Join-Path $workDir 'RunCleanerGUI.bat'
    if (Test-Path $launcher) {
        Write-Info "GUI başlatılıyor..."
        Start-Process -FilePath $launcher -WorkingDirectory $workDir
    } else {
        # Doğrudan PS GUI betiği
        $psGui = Join-Path $workDir 'scripts\OmniCleaner.GUI.ps1'
        Write-Info "PowerShell GUI başlatılıyor..."
        Start-Process powershell.exe -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-Sta","-File","$psGui" -WorkingDirectory $workDir
    }

    if ($Cleanup) {
        Write-Info "Geçici dosyalar temizleniyor..."
        Start-Sleep -Milliseconds 300
        try { Remove-Item -LiteralPath $tempRoot -Recurse -Force } catch { Write-Warn "Klasör silinemedi: $($_.Exception.Message)" }
    } else {
        Write-Info ("İndirilen klasör korunmuştur: " + $tempRoot)
    }

    Write-Info "Bootstrap tamamlandı."
} catch {
    Write-Err ("Bootstrap hata: " + $_.Exception.Message)
    exit 1
}
