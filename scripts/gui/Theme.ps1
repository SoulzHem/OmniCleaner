function Set-UiStyle {
	param([bool]$dark)
	try {
		$mono = New-Object System.Drawing.Font('Consolas',9)
		$txtLog.Font = $mono
		$txtInlineLog.Font = $mono
	} catch {}

	# Renkler (tek tip teal palet)
	$accent = [System.Drawing.Color]::FromArgb(0,150,136)
	$accentText = [System.Drawing.Color]::White
	$neutral = [System.Drawing.Color]::FromArgb(224,242,241)

	# Yardımcı: Buton stilleri
	function Set-ButtonStyle([System.Windows.Forms.Button]$b,[bool]$isPrimary) {
		try {
			$b.FlatStyle = 'Flat'
			$b.FlatAppearance.BorderSize = 0
			$b.Cursor = [System.Windows.Forms.Cursors]::Hand
			if ($isPrimary) {
				$b.BackColor = $accent
				$b.ForeColor = $accentText
			} else {
				$b.BackColor = $neutral
				$b.ForeColor = [System.Drawing.SystemColors]::ControlText
			}
		} catch {}
	}

	# Tüm butonları aynı görselde uygula (primary)
	Set-ButtonStyle $btnClean $true
	Set-ButtonStyle $btnCancel $true
	Set-ButtonStyle $btnListDrives $true
	Set-ButtonStyle $btnOpenLog $true
	Set-ButtonStyle $btnClearLog $true
	Set-ButtonStyle $btnScan $true
	try { Set-ButtonStyle $btnManageQ $true } catch {}
	try { Set-ButtonStyle $btnOpenExcl $true } catch {}
	try { Set-ButtonStyle $btnOpenQ $true } catch {}
	try { Set-ButtonStyle $btnRestoreQ $true } catch {}
	try { Set-ButtonStyle $btnExportCsv $true } catch {}
	try { Set-ButtonStyle $btnExportHtml $true } catch {}
	# Refresh kaldırıldı
}

function Set-Theme {
	param([bool]$dark)
	if ($dark) {
		$bg = [System.Drawing.Color]::FromArgb(28,32,34)      # koyu arka plan
		$fg = [System.Drawing.Color]::White
		$grp = [System.Drawing.Color]::FromArgb(40,44,46)      # grup arka plan
		$form.BackColor = $bg
		foreach ($ctrl in @(
			$tabs,$tabClean,$tabLog,$tabAdvanced,
			$grpOptions,$grpActions,$grpAdv,$bottomPanel,
			$lblStatus,$lblDrives,$txtDrives,$lblDriveStatus,
			$btnClean,$btnCancel,$btnListDrives,$btnOpenLog,$btnClearLog,$btnScan,$btnManageQ,$btnOpenExcl,$btnOpenQ,$btnRestoreQ,$btnExportCsv,$btnExportHtml,$btnAdvScan,
			$chkAllRemovable,$chkAggressive,$chkIncludeFixed,$chkIncludeSystem,$chkWhatIf,$chkDarkTheme,
			$chkScanServices,$chkScanShortcuts,$chkScanPayloads,$chkScanRegistry,$chkQuarantine,$chkUsbHeuristics,$chkDoTasks,$chkDoWmi,$chkDoLnk,$chkSelectAll,
			$chkAdvKeylog,$chkAdvStartup,$chkAdvHosts,$chkAdvBrowser,$chkAdvPSProf,$chkAdvOpenPorts,$chkAdvProcAnom,$chkAdvEnableActions,$chkAdvClosePorts,$lblRiskPorts,$txtRiskPorts,$lblWarnPorts,$txtWarnPorts,
			$txtLog,$lstDrives,$txtInlineLog,$txtAdvInlineLog
		)) {
			try { $ctrl.ForeColor = $fg } catch {}
			try { if ($ctrl -is [System.Windows.Forms.GroupBox] -or $ctrl -is [System.Windows.Forms.TabPage] -or $ctrl -is [System.Windows.Forms.Panel]) { $ctrl.BackColor = $grp } else { $ctrl.BackColor = $bg } } catch {}
		}
	} else {
		$bg = [System.Drawing.Color]::FromArgb(245,245,247)   # açık arka plan
		$fg = [System.Drawing.SystemColors]::ControlText
		$grp = [System.Drawing.Color]::FromArgb(236,239,241)   # açık grup arka plan
		$form.BackColor = $bg
		foreach ($ctrl in @(
			$tabs,$tabClean,$tabLog,$tabAdvanced,
			$grpOptions,$grpActions,$grpAdv,$bottomPanel,
			$lblStatus,$lblDrives,$txtDrives,$lblDriveStatus,
			$btnClean,$btnCancel,$btnListDrives,$btnOpenLog,$btnClearLog,$btnScan,$btnManageQ,$btnOpenExcl,$btnOpenQ,$btnRestoreQ,$btnExportCsv,$btnExportHtml,$btnAdvScan,
			$chkAllRemovable,$chkAggressive,$chkIncludeFixed,$chkIncludeSystem,$chkWhatIf,$chkDarkTheme,
			$chkScanServices,$chkScanShortcuts,$chkScanPayloads,$chkScanRegistry,$chkQuarantine,$chkUsbHeuristics,$chkDoTasks,$chkDoWmi,$chkDoLnk,$chkSelectAll,
			$chkAdvKeylog,$chkAdvStartup,$chkAdvHosts,$chkAdvBrowser,$chkAdvPSProf,$chkAdvOpenPorts,$chkAdvProcAnom,$chkAdvEnableActions,$chkAdvClosePorts,$lblRiskPorts,$txtRiskPorts,$lblWarnPorts,$txtWarnPorts,
			$txtLog,$lstDrives,$txtInlineLog,$txtAdvInlineLog
		)) {
			try { $ctrl.ForeColor = $fg } catch {}
			try { if ($ctrl -is [System.Windows.Forms.GroupBox] -or $ctrl -is [System.Windows.Forms.TabPage] -or $ctrl -is [System.Windows.Forms.Panel]) { $ctrl.BackColor = $grp } else { $ctrl.BackColor = $bg } } catch {}
		}
	}
}
