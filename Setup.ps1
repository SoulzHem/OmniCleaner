param()

Write-Host "== OmniCleaner - Setup ==" -ForegroundColor Cyan

try {
	$root = $PSScriptRoot
	if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
	$scripts = Join-Path $root 'scripts'
	$logsDir = Join-Path $scripts 'logs'
	$quarantineDir = Join-Path $scripts 'quarantine'

	# Klasörler
	foreach ($d in @($scripts,$logsDir,$quarantineDir)) {
		if (-not (Test-Path $d)) {
			New-Item -ItemType Directory -Path $d -Force | Out-Null
			Write-Host ("Created: " + $d)
		}
	}

	# Unblock ps1 ve bat dosyaları
	$toUnblock = @()
	$toUnblock += Get-ChildItem -LiteralPath $root -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
	$toUnblock += Get-ChildItem -LiteralPath $root -Filter '*.bat' -Recurse -ErrorAction SilentlyContinue
	foreach ($f in $toUnblock) {
		try { Unblock-File -LiteralPath $f.FullName -ErrorAction SilentlyContinue } catch {}
	}
	Write-Host ("Unblocked files: " + ($toUnblock.Count))

	# ExecutionPolicy bilgisi
	$policy = Get-ExecutionPolicy -Scope Process
	Write-Host ("Process ExecutionPolicy: " + $policy)
	if ($policy -eq 'Undefined' -or $policy -eq 'Restricted' -or $policy -eq 'AllSigned') {
		Write-Host "Uyarı: Betikleri çalıştırmak için bu oturumda Bypass kullanmanız gerekebilir:" -ForegroundColor Yellow
		Write-Host "PowerShell'i şu şekilde başlatın: powershell -ExecutionPolicy Bypass -NoProfile" -ForegroundColor Yellow
	}


	Write-Host "Setup completed successfully." -ForegroundColor Green
} catch {
	Write-Host ("Setup failed: " + $_.Exception.Message) -ForegroundColor Red
}


