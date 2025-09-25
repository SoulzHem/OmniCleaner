function Initialize-AdvancedTab {
	# Advanced tab content
	$script:grpAdv = New-Object System.Windows.Forms.GroupBox
	$script:grpAdv.Text = 'Advanced scans (log-only)'
	$script:grpAdv.Location = New-Object System.Drawing.Point(10,10)
	$script:grpAdv.Size = New-Object System.Drawing.Size(800,800)
	$script:grpAdv.Anchor = 'Top,Left,Right'
	Enable-TextRenderingIfAvailable $script:grpAdv

	$script:chkAdvKeylog = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvKeylog.Text = 'Keylogger heuristics'
	$script:chkAdvKeylog.AutoSize = $true
	$script:chkAdvKeylog.Location = New-Object System.Drawing.Point(20,30)

	$script:chkAdvStartup = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvStartup.Text = 'Scan Startup folders'
	$script:chkAdvStartup.AutoSize = $true
	$script:chkAdvStartup.Location = New-Object System.Drawing.Point(20,56)

	$script:chkAdvHosts = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvHosts.Text = 'Inspect hosts file redirects'
	$script:chkAdvHosts.AutoSize = $true
	$script:chkAdvHosts.Location = New-Object System.Drawing.Point(20,82)

	$script:chkAdvBrowser = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvBrowser.Text = 'List suspicious browser extensions'
	$script:chkAdvBrowser.AutoSize = $true
	$script:chkAdvBrowser.Location = New-Object System.Drawing.Point(320,30)

	$script:chkAdvPSProf = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvPSProf.Text = 'Inspect PowerShell profiles'
	$script:chkAdvPSProf.AutoSize = $true
	$script:chkAdvPSProf.Location = New-Object System.Drawing.Point(320,56)

	# New Advanced options
	$script:chkAdvOpenPorts = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvOpenPorts.Text = 'Scan open ports (log-only)'
	$script:chkAdvOpenPorts.AutoSize = $true
	$script:chkAdvOpenPorts.Location = New-Object System.Drawing.Point(20,108)

	$script:chkAdvProcAnom = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvProcAnom.Text = 'Scan suspicious processes (log-only)'
	$script:chkAdvProcAnom.AutoSize = $true
	$script:chkAdvProcAnom.Location = New-Object System.Drawing.Point(320,82)

	$script:chkAdvEnableActions = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvEnableActions.Text = 'Enable advanced actions (dangerous)'
	$script:chkAdvEnableActions.AutoSize = $true
	$script:chkAdvEnableActions.Location = New-Object System.Drawing.Point(20,134)

	$script:chkAdvClosePorts = New-Object System.Windows.Forms.CheckBox
	$script:chkAdvClosePorts.Text = 'Close risky ports'
	$script:chkAdvClosePorts.AutoSize = $true
	$script:chkAdvClosePorts.Location = New-Object System.Drawing.Point(20,160)

	$script:lblRiskPorts = New-Object System.Windows.Forms.Label
	$script:lblRiskPorts.Text = 'Risky ports (comma separated)'
	$script:lblRiskPorts.AutoSize = $true
	$script:lblRiskPorts.Location = New-Object System.Drawing.Point(200,162)
	Enable-TextRenderingIfAvailable $script:lblRiskPorts

	$script:txtRiskPorts = New-Object System.Windows.Forms.TextBox
	$script:txtRiskPorts.Location = New-Object System.Drawing.Point(440,158)
	$script:txtRiskPorts.Size = New-Object System.Drawing.Size(160,26)
	$script:txtRiskPorts.Text = '135,139,445,3389,5900,23'

	# Warning ports (orange)
	$script:lblWarnPorts = New-Object System.Windows.Forms.Label
	$script:lblWarnPorts.Text = 'Warning ports (comma separated)'
	$script:lblWarnPorts.AutoSize = $true
	$script:lblWarnPorts.Location = New-Object System.Drawing.Point(200,188)
	Enable-TextRenderingIfAvailable $script:lblWarnPorts

	$script:txtWarnPorts = New-Object System.Windows.Forms.TextBox
	$script:txtWarnPorts.Location = New-Object System.Drawing.Point(440,184)
	$script:txtWarnPorts.Size = New-Object System.Drawing.Size(160,26)
	$script:txtWarnPorts.Text = '21,22,25,1433,3306'

	$script:btnAdvScan = New-Object System.Windows.Forms.Button
	$script:btnAdvScan.Text = 'Scan (advanced)'
	$script:btnAdvScan.Size = New-Object System.Drawing.Size(160,30)
	$script:btnAdvScan.Location = New-Object System.Drawing.Point(20,222)

	$script:txtAdvInlineLog = New-Object System.Windows.Forms.RichTextBox
	$script:txtAdvInlineLog.Multiline = $true
	$script:txtAdvInlineLog.ScrollBars = 'Vertical'
	$script:txtAdvInlineLog.ReadOnly = $true
	$script:txtAdvInlineLog.DetectUrls = $false
	$script:txtAdvInlineLog.WordWrap = $true
	$script:txtAdvInlineLog.Location = New-Object System.Drawing.Point(20,266)
	$script:txtAdvInlineLog.Size = New-Object System.Drawing.Size(760,400)
	$script:txtAdvInlineLog.Anchor = 'Top,Left,Right'

	$script:grpAdv.Controls.AddRange(@($script:chkAdvKeylog,$script:chkAdvStartup,$script:chkAdvHosts,$script:chkAdvBrowser,$script:chkAdvPSProf,$script:chkAdvOpenPorts,$script:chkAdvProcAnom,$script:chkAdvEnableActions,$script:chkAdvClosePorts,$script:lblRiskPorts,$script:txtRiskPorts,$script:lblWarnPorts,$script:txtWarnPorts,$script:btnAdvScan,$script:txtAdvInlineLog))
	$tabAdvanced.Controls.Add($script:grpAdv)

	# Advanced scan click (log-only)
	$script:btnAdvScan.Add_Click({
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
			try { Invoke-LogRotation -path $logPath } catch {}
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
}
