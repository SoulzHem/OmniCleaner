# Settings
$SettingsPath = Join-Path $PSScriptRoot 'gui_settings.json'

function Get-Settings {
	if (Test-Path $SettingsPath) {
		try {
			$raw = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 -ErrorAction Stop
			return $raw | ConvertFrom-Json -ErrorAction Stop
		} catch { return $null }
	}
	return $null
}

function Set-Settings {
	$settings = [ordered]@{
		AllRemovable = $chkAllRemovable.Checked
		Aggressive = $chkAggressive.Checked
		IncludeFixed = $chkIncludeFixed.Checked
		IncludeSystem = $chkIncludeSystem.Checked
		WhatIf = $chkWhatIf.Checked
		Drives = $txtDrives.Text
		DarkTheme = $chkDarkTheme.Checked
		ScanServices = $chkScanServices.Checked
		ScanShortcuts = $chkScanShortcuts.Checked
		ScanPayloads = $chkScanPayloads.Checked
		ScanRegistry = $chkScanRegistry.Checked
		Quarantine = $chkQuarantine.Checked
		UsbHeuristics = $chkUsbHeuristics.Checked
		DoTasks = $chkDoTasks.Checked
		DoWmi = $chkDoWmi.Checked
		DoLnk = $chkDoLnk.Checked
		AdvEnableActions = $chkAdvEnableActions.Checked
		AdvClosePorts = $chkAdvClosePorts.Checked
		AdvRiskPorts = $txtRiskPorts.Text
		AdvWarnPorts = $txtWarnPorts.Text
	}
	try { ($settings | ConvertTo-Json -Depth 3) | Out-File -FilePath $SettingsPath -Encoding UTF8 -Force } catch {}
}
