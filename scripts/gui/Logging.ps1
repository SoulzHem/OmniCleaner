function Write-Log {
	param([string]$line)
	if ([string]::IsNullOrWhiteSpace($line)) { return }
	try {
		if ($txtLog -and $txtLog.InvokeRequired) {
		$null = $txtLog.BeginInvoke([Action]{ $txtLog.AppendText($line + [Environment]::NewLine) })
		} elseif ($txtLog) {
		$txtLog.AppendText($line + [Environment]::NewLine)
		}
	} catch {}
	# Inline loglara da aynen yaz (Clean ve Advanced)
	try {
		if ($txtInlineLog) {
			if ($txtInlineLog.InvokeRequired) { $null = $txtInlineLog.BeginInvoke([Action]{ $txtInlineLog.AppendText($line + [Environment]::NewLine) }) }
			else { $txtInlineLog.AppendText($line + [Environment]::NewLine) }
		}
	} catch {}
	try {
		if ($txtAdvInlineLog) {
			if ($txtAdvInlineLog.InvokeRequired) { $null = $txtAdvInlineLog.BeginInvoke([Action]{ $txtAdvInlineLog.AppendText($line + [Environment]::NewLine) }) }
			else { $txtAdvInlineLog.AppendText($line + [Environment]::NewLine) }
		}
	} catch {}
	# OmniFix inline log
	try {
		if ($script:txtFixLog) {
			if ($script:txtFixLog.InvokeRequired) { $null = $script:txtFixLog.BeginInvoke([Action]{ $script:txtFixLog.AppendText($line + [Environment]::NewLine) }) }
			else { $script:txtFixLog.AppendText($line + [Environment]::NewLine) }
		}
	} catch {}
}

function Write-AdvOnly {
	param([string]$line)
	if ([string]::IsNullOrWhiteSpace($line)) { return }
	try {
		if ($txtAdvInlineLog) {
			$action = [Action]{ Write-AdvLogLineWithColor -line $line }
			if ($txtAdvInlineLog.InvokeRequired) { $null = $txtAdvInlineLog.BeginInvoke($action) } else { & $action }
		}
	} catch {}
}

function Write-AdvLogLineWithColor {
	param([string]$line)
	if (-not $txtAdvInlineLog) { return }
	# Varsayılan renk
	$color = $txtAdvInlineLog.ForeColor
	try {
		# Riskli port listesinden regex üret
		$ports = @()
		try { $ports = ($txtRiskPorts.Text -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } } catch { $ports = @() }
		if ($ports.Count -gt 0) {
			# Netstat satırlarında :PORT veya ->PORT eşleşmeleri için kaba kontrol
			$pattern = ':' + '(' + ([string]::Join('|', $ports)) + ')\b'
			if ($line -match $pattern) { $color = [System.Drawing.Color]::Red }
		}
		# Warning ports
		$warnPorts = @()
		try { $warnPorts = ($txtWarnPorts.Text -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } } catch { $warnPorts = @() }
		if ($warnPorts.Count -gt 0 -and $color -ne [System.Drawing.Color]::Red) {
			$pattern2 = ':' + '(' + ([string]::Join('|', $warnPorts)) + ')\b'
			if ($line -match $pattern2) { $color = [System.Drawing.Color]::Orange }
		}
		$start = $txtAdvInlineLog.TextLength
		$txtAdvInlineLog.SelectionStart = $start
		$txtAdvInlineLog.SelectionLength = 0
		$txtAdvInlineLog.SelectionColor = $color
		$txtAdvInlineLog.AppendText($line + [Environment]::NewLine)
		# Rengi geri al
		$txtAdvInlineLog.SelectionColor = $txtAdvInlineLog.ForeColor
	} catch {
		# Sorun olursa düz yaz
		try { $txtAdvInlineLog.AppendText($line + [Environment]::NewLine) } catch {}
	}
}
