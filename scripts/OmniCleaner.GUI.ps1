#requires -version 5.1
<#!
.SYNOPSIS
    OmniCleaner GUI - Security Tool Interface

.DESCRIPTION
    A legitimate security tool GUI for removing shortcut viruses and malware.
    This is a graphical interface that calls OmniCleaner.ps1 for cleaning operations.
    
    This tool helps users:
    - Remove shortcut viruses from USB drives
    - Recover hidden files
    - Clean malicious autorun files
    - Quarantine threats safely
    
    Version: 1.0
    Author: SoulzHem
    License: MIT
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Dot-source modular components
try {
	. "$PSScriptRoot\gui\Logging.ps1"
	. "$PSScriptRoot\gui\Theme.ps1"
	. "$PSScriptRoot\gui\Settings.ps1"
    . "$PSScriptRoot\gui\CleanTab.ps1"
    . "$PSScriptRoot\gui\AdvancedTab.ps1"
    . "$PSScriptRoot\gui\Quarantine.ps1"
} catch {}

# STA requirement
try {
	if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
		$psi = New-Object System.Diagnostics.ProcessStartInfo
		$psi.FileName = 'powershell.exe'
		$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Sta -File `"$PSCommandPath`""
		$psi.UseShellExecute = $true
		[System.Diagnostics.Process]::Start($psi) | Out-Null
		exit
	}
} catch {}

try {
	[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
	$global:OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {}

function Test-IsAdmin {
	$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
	$wp = New-Object Security.Principal.WindowsPrincipal($wi)
	return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Elevate if needed (STA)
if (-not (Test-IsAdmin)) {
	$psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.FileName = 'powershell.exe'
	$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Sta -File `"$PSCommandPath`""
	$psi.Verb = 'runas'
	try { [System.Diagnostics.Process]::Start($psi) | Out-Null } catch { [System.Windows.Forms.MessageBox]::Show('Administrator required.','Warning','OK','Warning') }
	exit
}

function Enable-TextRenderingIfAvailable {
	param([System.Windows.Forms.Control]$ctrl)
	try {
		$prop = $ctrl.GetType().GetProperty('UseCompatibleTextRendering')
		if ($prop -and $prop.CanWrite) { $prop.SetValue($ctrl, $true, $null) }
	} catch {}
}

# Settings (modüler) – Settings.ps1 içinde tanımlıdır

# Form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'OmniCleaner'
$form.Size = New-Object System.Drawing.Size(960,700)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI',11)
$form.AutoScaleMode = 'Font'
try { $form.Icon = [System.Drawing.SystemIcons]::Shield } catch {}

# Tabs
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(10,10)
$tabs.Size = New-Object System.Drawing.Size(900,700)
$tabs.Anchor = 'Top,Left,Right,Bottom'
Enable-TextRenderingIfAvailable $tabs

$tabClean = New-Object System.Windows.Forms.TabPage
$tabClean.Text = 'Clean'
Enable-TextRenderingIfAvailable $tabClean

$tabLog = New-Object System.Windows.Forms.TabPage
$tabLog.Text = 'Log'
Enable-TextRenderingIfAvailable $tabLog

# Advanced tab
$tabAdvanced = New-Object System.Windows.Forms.TabPage
$tabAdvanced.Text = 'Advanced'
Enable-TextRenderingIfAvailable $tabAdvanced

$tabs.TabPages.AddRange(@($tabClean,$tabAdvanced,$tabLog))

# Build Clean tab via module
Initialize-CleanTab

Initialize-AdvancedTab

# Advanced scan click (log-only)
$btnAdvScan.Add_Click({
	try {
		# Advanced sekmesini öne getir ve log alanını üstte tut
		try { if ($tabs -and $tabAdvanced) { $tabs.SelectedTab = $tabAdvanced } } catch {}
		try { if ($txtAdvInlineLog) { $txtAdvInlineLog.BringToFront() } } catch {}
		$flags = @()
		if ($chkAdvKeylog.Checked) { $flags += '-DoKeyloggerHeuristics' }
		if ($chkAdvStartup.Checked) { $flags += '-DoStartup' }
		if ($chkAdvHosts.Checked) { $flags += '-DoHosts' }
		if ($chkAdvBrowser.Checked) { $flags += '-DoBrowserExt' }
		if ($chkAdvPSProf.Checked) { $flags += '-DoPSProfiles' }
		if ($chkAdvOpenPorts.Checked) { $flags += '-DoOpenPorts' }
		if ($chkAdvProcAnom.Checked) { $flags += '-DoProcessAnomalies' }
		# Actions (guarded)
		if ($chkAdvEnableActions.Checked) {
			if ($chkAdvClosePorts.Checked) {
				$ports = @()
				try {
					$ports = ($txtRiskPorts.Text -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
				} catch { $ports = @() }
				if ($ports.Count -gt 0) {
					$flags += '-CloseOpenPorts'
					$flags += ('-PortTargets ' + (($ports | ForEach-Object { [int]$_ }) -join ','))
				}
			}
		}
		if ($flags.Count -eq 0) {
			# Mesajı sadece Advanced alanına yaz
			try {
				if ($txtAdvInlineLog) {
					$action = [Action]{ Write-AdvLogLineWithColor -line 'Select at least one advanced scan option or enable an action (e.g., Close risky ports) with valid ports.' }
					if ($txtAdvInlineLog.InvokeRequired) { $null = $txtAdvInlineLog.BeginInvoke($action) } else { & $action }
				}
			} catch {}
			return
		}

		$scriptPath = Join-Path $PSScriptRoot 'OmniCleaner.ps1'
		if (-not (Test-Path $scriptPath)) { Write-Log 'Cleaner script not found.'; return }

		$logPath = Join-Path $PSScriptRoot 'omnicleaner.log'
		$script:AdvLogPath = $logPath
		$cmd = '"' + $scriptPath + '" ' + ($flags -join ' ') + ' -LogPath ' + ('"' + $logPath + '"')
		Write-Log ('Starting advanced scan with: ' + $cmd)
		Set-UiBusy $true
		$ajob = Start-Job -ScriptBlock { param($c) powershell -NoProfile -ExecutionPolicy Bypass -Command $c 2>&1 } -ArgumentList $cmd
		$script:AdvJob = $ajob

		# Inline takip – log timer zaten aynı dosyayı izliyor, ayrıca Advanced alanına da yaz
		try {
			if ($txtAdvInlineLog) { $txtAdvInlineLog.Clear() }
		} catch {}
# 
		# Advanced için FileSystemWatcher yerine UI Timer ile log tail et
		try { if ($script:AdvLogTimer) { $script:AdvLogTimer.Stop(); $script:AdvLogTimer.Dispose() } } catch {}
		$script:AdvLastCount = 0
		try {
			if (Test-Path $script:AdvLogPath) {
				$contentInit = Get-Content -LiteralPath $script:AdvLogPath -Encoding UTF8 -ErrorAction SilentlyContinue
				if ($contentInit) {
					$script:AdvLastCount = $contentInit.Count
					# Advanced alanını hızlıca doldur (renkli), sadece Advanced'e yaz
					try {
						if ($txtAdvInlineLog) {
							$startIdx = [Math]::Max(0, $contentInit.Count - 200)
							for ($j=$startIdx; $j -lt $contentInit.Count; $j++) {
								$linePrefill = $contentInit[$j]
								Write-AdvOnly $linePrefill
							}
						}
					} catch {}
				}
			}
		} catch {}
		$script:AdvLogTimer = New-Object System.Windows.Forms.Timer
		$script:AdvLogTimer.Interval = 700
		$script:AdvLogTimer.Add_Tick({
			try {
				if (Test-Path $script:AdvLogPath) {
					$content = Get-Content -LiteralPath $script:AdvLogPath -Encoding UTF8 -ErrorAction SilentlyContinue
					if ($content) {
						$len = $content.Count
						if ($len -lt $script:AdvLastCount) { $script:AdvLastCount = 0; try { if ($txtAdvInlineLog) { $txtAdvInlineLog.Clear() } } catch {} }
						if ($len -gt $script:AdvLastCount) {
							for ($i=$script:AdvLastCount; $i -lt $len; $i++) {
								$ln = $content[$i]
								try { Write-Log $ln } catch {}
							}
							$script:AdvLastCount = $len
						}
					}
				}
			} catch {}
		})
		$script:AdvLogTimer.Start()

		# Advanced job tamamlandığında UI'yı eski haline getir
		try {
			if ($script:AdvStateEvent) { Unregister-Event -SourceIdentifier $script:AdvStateEvent.Name -ErrorAction SilentlyContinue }
		} catch {}
		$script:AdvStateEvent = Register-ObjectEvent -InputObject $ajob -EventName StateChanged -Action {
			try {
				if ($event.Sender.State -in 'Completed','Failed','Stopped') {
					try { if ($script:AdvLogTimer) { $script:AdvLogTimer.Stop(); $script:AdvLogTimer.Dispose() } } catch {}
					try { Receive-Job -Job $event.Sender -Keep -ErrorAction SilentlyContinue | ForEach-Object { Write-Log (($_ | Out-String).TrimEnd()) } } catch {}
					Set-UiBusy $false
				}
			} catch {}
		}
	} catch { Write-Log ("ERROR: Advanced scan failed - " + $_.Exception.Message) }
})

# Log tab
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$txtLog.WordWrap = $true
$txtLog.Location = New-Object System.Drawing.Point(10,10)
$txtLog.Size = New-Object System.Drawing.Size(800,120)
$txtLog.Anchor = 'Top,Left,Right,Bottom'

$tabLog.Controls.Add($txtLog)

$form.Controls.Add($tabs)

# Global hata yakalama: beklenmeyen hataları logla ve göster
try {
	[AppDomain]::CurrentDomain.UnhandledException += {
		param($evtSender,$ueArgs)
		try { if ($ueArgs -and $ueArgs.ExceptionObject) { Write-Log ("FATAL: " + $ueArgs.ExceptionObject.ToString()) } } catch {}
		try { [System.Windows.Forms.MessageBox]::Show('Beklenmeyen bir hata oluştu. Log sekmesini kontrol edin.','Error','OK','Error') | Out-Null } catch {}
	}
} catch {}

function Invoke-LogRotation {
	param([string]$path)
	try {
		if (-not $path) { return }
		if (Test-Path $path) {
			$dir = Split-Path -Parent $path
			$base = [System.IO.Path]::GetFileNameWithoutExtension($path)
			$ext = [System.IO.Path]::GetExtension($path)
			$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
			$logsDir = Join-Path $dir 'logs'
			if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
			$dest = Join-Path $logsDir ("{0}_{1}{2}" -f $base,$ts,$ext)
			Move-Item -LiteralPath $path -Destination $dest -Force
		}
	} catch {}
}

## Logging functions moved to scripts\gui\Logging.ps1

function Update-DriveBadges { }

function Set-UiBusy {
	param([bool]$busy)
	$controls = @($btnClean,$chkAllRemovable,$chkAggressive,$chkIncludeFixed,$chkIncludeSystem,$chkWhatIf,$chkDarkTheme,$txtDrives,$btnListDrives,$btnOpenLog,$btnClearLog,$btnOpenExcl,$btnOpenQ,$btnRestoreQ,$btnScan,$btnCancel)
	foreach ($c in $controls) { $c.Enabled = -not $busy }
	if ($busy) {
		$lblStatus.Text = 'Cleaning...'
		$progress.Style = 'Marquee'
		$progress.MarqueeAnimationSpeed = 30
		$progress.Visible = $true
		$btnCancel.Enabled = $true
	} else {
		$lblStatus.Text = 'Ready'
		$progress.Visible = $false
		$progress.MarqueeAnimationSpeed = 0
		$progress.Style = 'Continuous'
		$btnCancel.Enabled = $false
	}
}

## Theme functions moved to scripts\gui\Theme.ps1

function Invoke-Clean {
	Set-UiBusy $true
	Write-Log "Cleaning started..."
	$scriptPath = Join-Path $PSScriptRoot 'OmniCleaner.ps1'
	if (-not (Test-Path $scriptPath)) {
		Write-Log "ERROR: Cleaner script not found: $scriptPath"
		Set-UiBusy $false
		return
	}

	# Log dosyasını hazırla
	$logPath = Join-Path $PSScriptRoot 'omnicleaner.log'
	Invoke-LogRotation -path $logPath
	try { Add-Content -Path $logPath -Value ("[" + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + "] [GUI] Invoke-Clean başlatılıyor") -Encoding utf8 -ErrorAction SilentlyContinue } catch {}


	$drivesRaw = $txtDrives.Text.Trim()
	# Process yerine arka plan işi ile çalıştır
	try {
		$script:CleanerJob | Out-Null
	} catch { $script:CleanerJob = $null }

	$cleanerParams = @()
	if ($drivesRaw) {
		$tokens = $drivesRaw -split '\s+'
		$validDrives = @()
		foreach ($t in $tokens) {
			if ([string]::IsNullOrWhiteSpace($t)) { continue }
			if ($t -match '^[A-Za-z](:\\\\)?$' -or $t -match '^[A-Za-z]:$' -or $t -match '^[A-Za-z]$') {
				$letter = ([char]$t[0]).ToString().ToUpper()
				$validDrives += ("{0}:\\" -f $letter)
			} else {
				Write-Log ("Ignoring invalid drive token: '" + $t + "'")
			}
		}
		if ($validDrives.Count -gt 0) { $cleanerParams += @('-Targets'); $cleanerParams += $validDrives }
		else { Write-Log 'No valid drive tokens provided; falling back to checkbox options.' }
	} else {
		if ($chkAllRemovable.Checked) { $cleanerParams += '-AllRemovable' }
		if ($chkIncludeFixed.Checked) { $cleanerParams += '-IncludeFixed' }
		if ($chkIncludeSystem.Checked) { $cleanerParams += '-IncludeSystem' }
	}
	# Sabit sıralama: mod bayrakları sonra LogPath
	if ($chkAggressive.Checked) { $cleanerParams += '-Aggressive' }
	if ($chkWhatIf.Checked) { $cleanerParams += '-WhatIf' }
	if ($script:ForceScanOnly) { $cleanerParams += '-ScanOnly' }
	$cleanerParams += @('-LogPath', $logPath)

	# Scope flags
	if ($chkScanServices.Checked) { $cleanerParams += '-DoServices' } else { $cleanerParams += '-SkipServices' }
	if ($chkScanShortcuts.Checked) { $cleanerParams += '-DoShortcuts' } else { $cleanerParams += '-SkipShortcuts' }
	if ($chkScanPayloads.Checked) { $cleanerParams += '-DoPayloads' } else { $cleanerParams += '-SkipPayloads' }
	if ($chkScanRegistry.Checked) { $cleanerParams += '-DoRegistry' } else { $cleanerParams += '-SkipRegistry' }
	if ($chkQuarantine.Checked) { $cleanerParams += '-Quarantine' }
	if ($chkUsbHeuristics.Checked) { $cleanerParams += '-UsbHeuristics' }
	if ($chkDoTasks.Checked) { $cleanerParams += '-DoScheduledTasks' } else { $cleanerParams += '-SkipScheduledTasks' }
	if ($chkDoWmi.Checked) { $cleanerParams += '-DoWmiSubscriptions' } else { $cleanerParams += '-SkipWmiSubscriptions' }
	if ($chkDoLnk.Checked) { $cleanerParams += '-DoLnkAnalysis' } else { $cleanerParams += '-SkipLnkAnalysis' }

	# Encode full command to avoid parameter binding issues
	$psFile = '"' + $scriptPath + '"'
	$psArgs = ($cleanerParams | ForEach-Object { if ($_ -match '\\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
	$commandString = $psFile + ' ' + $psArgs

	Write-Log ("Starting background job with: " + $commandString)

	$job = Start-Job -ScriptBlock {
		param($cmd)
		try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
		powershell -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1
	} -ArgumentList $commandString
	$script:CleanerJob = $job

	# Çıktı ve hata akışlarını GUI log'una bağla
	$child = $job.ChildJobs[0]
	$script:OutputEvent = Register-ObjectEvent -InputObject $child.Output -EventName DataAdded -Action {
		try {
			$idx = $eventArgs.Index
			$item = $event.Sender[$idx]
			if ($item) { Write-Log ($item | Out-String).TrimEnd() }
		} catch {}
	}
	$script:ErrorEvent = Register-ObjectEvent -InputObject $child.Error -EventName DataAdded -Action {
		try {
			$idx = $eventArgs.Index
			$item = $event.Sender[$idx]
			if ($item) { Write-Log ("ERR: " + (($item | Out-String).TrimEnd())) }
		} catch {}
	}
	$script:StateEvent = Register-ObjectEvent -InputObject $job -EventName StateChanged -Action {
		try {
			if ($event.Sender.State -eq 'Completed' -or $event.Sender.State -eq 'Failed' -or $event.Sender.State -eq 'Stopped') {
				Write-Log ("Job finished: " + $event.Sender.State)
				try { Unregister-Event -SourceIdentifier $script:OutputEvent.Name -ErrorAction SilentlyContinue } catch {}
				try { Unregister-Event -SourceIdentifier $script:ErrorEvent.Name -ErrorAction SilentlyContinue } catch {}
				try { Unregister-Event -SourceIdentifier $script:StateEvent.Name -ErrorAction SilentlyContinue } catch {}
				try { Receive-Job -Job $event.Sender -Keep -ErrorAction SilentlyContinue | ForEach-Object { Write-Log ($_ | Out-String).TrimEnd() } } catch {}
				try { if ($script:LogTimer) { $script:LogTimer.Stop(); $script:LogTimer.Dispose() } } catch {}
				try { if ($script:AdvLogTimer) { $script:AdvLogTimer.Stop(); $script:AdvLogTimer.Dispose() } } catch {}
		Set-UiBusy $false
		Set-Settings
	}
		} catch {}
	}

	# Log dosyasını periyodik olarak içeri al (1sn)
	try { if ($script:LogTimer) { $script:LogTimer.Stop(); $script:LogTimer.Dispose() } } catch {}
	$script:LogTimer = New-Object System.Windows.Forms.Timer
	$script:LastLogLength = 0
	$script:LogTimer.Interval = 1000
	$script:LogTimer.Add_Tick({
		try {
			if (Test-Path $logPath) {
				$content = Get-Content -LiteralPath $logPath -Encoding UTF8 -ErrorAction SilentlyContinue
				if ($content) {
					$len = $content.Length
					if ($len -gt $script:LastLogLength) {
						for ($i = $script:LastLogLength; $i -lt $len; $i++) { Write-Log $content[$i] }
						$script:LastLogLength = $len
					}
				}
			}
			if ($script:CleanerJob -and ($script:CleanerJob.State -in 'Completed','Failed','Stopped')) {
				$script:LogTimer.Stop(); $script:LogTimer.Dispose()
			}
		} catch {}
	})
	$script:LogTimer.Start()
}

# Button behaviors
$btnListDrives.Add_Click({
	try {
		$lstDrives.Items.Clear()
		$vols = Get-Volume -ErrorAction Stop | Select-Object DriveLetter, DriveType, SizeRemaining, FileSystemLabel | Sort-Object DriveLetter
		foreach ($v in $vols) {
			$lstDrives.Items.Add(("{0}:\  {1}  Label='{2}'  Free={3:N1} GB" -f $v.DriveLetter, $v.DriveType, $v.FileSystemLabel, ($v.SizeRemaining/1GB))) | Out-Null
		}
	} catch { Write-Log ("ERROR: Could not list drives - " + $_.Exception.Message) }
})

$btnOpenLog.Add_Click({
	$log = Join-Path $PSScriptRoot 'omnicleaner.log'
	if (Test-Path $log) { Start-Process -FilePath $log } else { Write-Log "Log file not found: $log" }
})

$btnClearLog.Add_Click({
	$txtLog.Clear()
	try { if ($txtInlineLog) { $txtInlineLog.Clear() } } catch {}
	try { if ($txtAdvInlineLog) { $txtAdvInlineLog.Clear() } } catch {}
	$log = Join-Path $PSScriptRoot 'omnicleaner.log'
	try { if (Test-Path $log) { Clear-Content -LiteralPath $log -Force } } catch {}
	Write-Log 'Log cleared.'
})

# Open exclusions
$btnOpenExcl.Add_Click({
	try {
		$ex = Join-Path $PSScriptRoot 'exclusions.txt'
		if (-not (Test-Path $ex)) { New-Item -ItemType File -Path $ex -Force | Out-Null }
		Start-Process -FilePath $ex
	} catch { Write-Log ("ERROR: Cannot open exclusions - " + $_.Exception.Message) }
})

# Open quarantine
$btnOpenQ.Add_Click({
	try {
		$q = Join-Path $PSScriptRoot 'quarantine'
		if (-not (Test-Path $q)) { New-Item -ItemType Directory -Path $q -Force | Out-Null }
		Start-Process -FilePath $q
	} catch { Write-Log ("ERROR: Cannot open quarantine - " + $_.Exception.Message) }
})

# Restore quarantine
$btnRestoreQ.Add_Click({
	try {
		# Restore by re-invoking backend with -RestoreQuarantine
		$scriptPath = Join-Path $PSScriptRoot 'OmniCleaner.ps1'
		$cmd = '"' + $scriptPath + '" -RestoreQuarantine -LogPath ' + (Join-Path $PSScriptRoot 'omnicleaner.log')
		Write-Log ('Launching restore: ' + $cmd)
		Start-Job -ScriptBlock { param($c) powershell -NoProfile -ExecutionPolicy Bypass -Command $c 2>&1 } -ArgumentList $cmd | Out-Null
	} catch { Write-Log ("ERROR: Restore failed to launch - " + $_.Exception.Message) }
})

# Export CSV
$btnExportCsv.Add_Click({
	try {
		$reportsDir = Join-Path $PSScriptRoot 'reports'
		if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null }
		$log = Join-Path $PSScriptRoot 'omnicleaner.log'
		$out = Join-Path $reportsDir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.csv')
		if (Test-Path $log) {
			(Get-Content -LiteralPath $log -Encoding UTF8) | Set-Content -LiteralPath $out -Encoding UTF8
			Write-Log ('CSV exported: ' + $out)
		} else { Write-Log 'No log to export.' }
	} catch { Write-Log ("ERROR: Export CSV failed - " + $_.Exception.Message) }
})

# Export HTML (simple preformatted)
$btnExportHtml.Add_Click({
	try {
		$reportsDir = Join-Path $PSScriptRoot 'reports'
		if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null }
		$log = Join-Path $PSScriptRoot 'omnicleaner.log'
		$out = Join-Path $reportsDir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.html')
		if (Test-Path $log) {
			$lines = Get-Content -LiteralPath $log -Encoding UTF8 | ForEach-Object { $_ -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' }
			$html = @(
				'<!DOCTYPE html>','<meta charset="utf-8"/>','<title>OmniCleaner Report</title>',
				'<pre style="font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;">'
			) + $lines + '</pre>'
			Set-Content -LiteralPath $out -Value $html -Encoding UTF8
			Write-Log ('HTML exported: ' + $out)
		} else { Write-Log 'No log to export.' }
	} catch { Write-Log ("ERROR: Export HTML failed - " + $_.Exception.Message) }
})

# Refresh butonu kaldırıldı; rozetler form load'da güncelleniyor

# Manage quarantine click
$btnManageQ.Add_Click({ Open-QuarantineManager })

# Scan click (dry run)
$btnScan.Add_Click({
	try {
		$prev = $chkWhatIf.Checked
		$chkWhatIf.Checked = $false
		$script:ForceScanOnly = $true
		Invoke-Clean
		$script:ForceScanOnly = $false
		$chkWhatIf.Checked = $prev
	} catch {}
})

# Cancel click
$btnCancel.Add_Click({
	try {
		if ($script:CleanerJob) {
			Write-Log 'Cancelling job...'
			try { Stop-Job -Job $script:CleanerJob -Force -ErrorAction SilentlyContinue } catch {}
			try { Receive-Job -Job $script:CleanerJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Log ($_ | Out-String).TrimEnd() } } catch {}
			try { if ($script:OutputEvent) { Unregister-Event -SourceIdentifier $script:OutputEvent.Name -ErrorAction SilentlyContinue } } catch {}
			try { if ($script:ErrorEvent) { Unregister-Event -SourceIdentifier $script:ErrorEvent.Name -ErrorAction SilentlyContinue } } catch {}
			try { if ($script:StateEvent) { Unregister-Event -SourceIdentifier $script:StateEvent.Name -ErrorAction SilentlyContinue } } catch {}
			try { if ($script:LogTimer) { $script:LogTimer.Stop(); $script:LogTimer.Dispose() } } catch {}
			try { Remove-Job -Job $script:CleanerJob -Force -ErrorAction SilentlyContinue } catch {}
			$script:CleanerJob = $null
			Set-UiBusy $false
			Write-Log 'Job cancelled.'
		}
		# Advanced job iptali
		if ($script:AdvJob) {
			Write-Log 'Cancelling advanced job...'
			try { Stop-Job -Job $script:AdvJob -Force -ErrorAction SilentlyContinue } catch {}
			try { Receive-Job -Job $script:AdvJob -ErrorAction SilentlyContinue | ForEach-Object { Write-Log ($_ | Out-String).TrimEnd() } } catch {}
			try { if ($script:AdvStateEvent) { Unregister-Event -SourceIdentifier $script:AdvStateEvent.Name -ErrorAction SilentlyContinue } } catch {}
			try { if ($script:AdvLogTimer) { $script:AdvLogTimer.Stop(); $script:AdvLogTimer.Dispose() } } catch {}
			try { Remove-Job -Job $script:AdvJob -Force -ErrorAction SilentlyContinue } catch {}
			$script:AdvJob = $null
			Set-UiBusy $false
			Write-Log 'Advanced job cancelled.'
		}
	} catch {}
})

# Theme toggle
$chkDarkTheme.Add_CheckedChanged({ Set-Theme $chkDarkTheme.Checked; Set-UiStyle $chkDarkTheme.Checked; Set-Settings })

# Select all toggle
$chkSelectAll.Add_CheckedChanged({
	try {
		$val = $chkSelectAll.Checked
		# Tarama kutucukları (Quarantine'i değiştirme)
		$chkScanServices.Checked = $val
		$chkScanShortcuts.Checked = $val
		$chkScanPayloads.Checked = $val
		$chkScanRegistry.Checked = $val
		$chkUsbHeuristics.Checked = $val
		$chkDoTasks.Checked = $val
		$chkDoWmi.Checked = $val
		$chkDoLnk.Checked = $val
		Set-Settings
	} catch {}
})

# Select all toggle
$chkSelectAll.Add_CheckedChanged({
	try {
		$val = $chkSelectAll.Checked
		$chkScanServices.Checked = $val
		$chkScanShortcuts.Checked = $val
		$chkScanPayloads.Checked = $val
		$chkScanRegistry.Checked = $val
		$chkQuarantine.Checked = $val
		$chkUsbHeuristics.Checked = $val
		$chkDoTasks.Checked = $val
		$chkDoWmi.Checked = $val
		$chkDoLnk.Checked = $val
		Set-Settings
	} catch {}
})

# Load settings on form load
$form.add_Load({
	$loaded = Get-Settings
	if ($loaded -ne $null) {
		try {
			$chkAllRemovable.Checked = [bool]$loaded.AllRemovable
			$chkAggressive.Checked = [bool]$loaded.Aggressive
			$chkIncludeFixed.Checked = [bool]$loaded.IncludeFixed
			$chkIncludeSystem.Checked = [bool]$loaded.IncludeSystem
			$chkWhatIf.Checked = [bool]$loaded.WhatIf
			if ($loaded.Drives) { $txtDrives.Text = [string]$loaded.Drives }
			if ($loaded.DarkTheme -ne $null) { $chkDarkTheme.Checked = [bool]$loaded.DarkTheme }
			if ($loaded.ScanServices -ne $null) { $chkScanServices.Checked = [bool]$loaded.ScanServices }
			if ($loaded.ScanShortcuts -ne $null) { $chkScanShortcuts.Checked = [bool]$loaded.ScanShortcuts }
			if ($loaded.ScanPayloads -ne $null) { $chkScanPayloads.Checked = [bool]$loaded.ScanPayloads }
			if ($loaded.ScanRegistry -ne $null) { $chkScanRegistry.Checked = [bool]$loaded.ScanRegistry }
			if ($loaded.Quarantine -ne $null) { $chkQuarantine.Checked = [bool]$loaded.Quarantine }
			if ($loaded.UsbHeuristics -ne $null) { $chkUsbHeuristics.Checked = [bool]$loaded.UsbHeuristics }
			if ($loaded.DoTasks -ne $null) { $chkDoTasks.Checked = [bool]$loaded.DoTasks }
			if ($loaded.DoWmi -ne $null) { $chkDoWmi.Checked = [bool]$loaded.DoWmi }
			if ($loaded.DoLnk -ne $null) { $chkDoLnk.Checked = [bool]$loaded.DoLnk }
			if ($loaded.AdvEnableActions -ne $null) { $chkAdvEnableActions.Checked = [bool]$loaded.AdvEnableActions }
			if ($loaded.AdvClosePorts -ne $null) { $chkAdvClosePorts.Checked = [bool]$loaded.AdvClosePorts }
			if ($loaded.AdvRiskPorts) { $txtRiskPorts.Text = [string]$loaded.AdvRiskPorts }
			if ($loaded.AdvWarnPorts) { $txtWarnPorts.Text = [string]$loaded.AdvWarnPorts }
		} catch {}
	}
	Set-Theme $chkDarkTheme.Checked
	Set-UiStyle $chkDarkTheme.Checked
})

# Persist on close
$form.add_FormClosing({ Set-Settings })

# Initialize drive badges on form load
# Rozet güncelleme kaldırıldı

$btnClean.Add_Click({ Invoke-Clean })

[void][System.Windows.Forms.Application]::Run($form)
