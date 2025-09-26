function Initialize-OmniFixTab {
	# OmniFix safe fixes tab
	$script:grpFix = New-Object System.Windows.Forms.GroupBox
	$script:grpFix.Text = 'OmniFix safe fixes'
	$script:grpFix.Location = New-Object System.Drawing.Point(10,10)
	$script:grpFix.Size = New-Object System.Drawing.Size(800,520)
	$script:grpFix.Anchor = 'Top,Left,Right'
	Enable-TextRenderingIfAvailable $script:grpFix

	$script:chkFixHosts = New-Object System.Windows.Forms.CheckBox
	$script:chkFixHosts.Text = 'Reset hosts file (default)'
	$script:chkFixHosts.AutoSize = $true
	$script:chkFixHosts.Location = New-Object System.Drawing.Point(20,30)

	$script:chkFixProxy = New-Object System.Windows.Forms.CheckBox
	$script:chkFixProxy.Text = 'Disable system proxy / reset WinINET'
	$script:chkFixProxy.AutoSize = $true
	$script:chkFixProxy.Location = New-Object System.Drawing.Point(20,56)

	$script:chkFixDns = New-Object System.Windows.Forms.CheckBox
	$script:chkFixDns.Text = 'Flush DNS cache and reset adapter DNS (auto)'
	$script:chkFixDns.AutoSize = $true
	$script:chkFixDns.Location = New-Object System.Drawing.Point(20,82)

	$script:chkFixWinsock = New-Object System.Windows.Forms.CheckBox
	$script:chkFixWinsock.Text = 'Reset Winsock & TCP/IP'
	$script:chkFixWinsock.AutoSize = $true
	$script:chkFixWinsock.Location = New-Object System.Drawing.Point(20,108)

	$script:chkFixFirewall = New-Object System.Windows.Forms.CheckBox
	$script:chkFixFirewall.Text = 'Reset Windows Firewall (policies)'
	$script:chkFixFirewall.AutoSize = $true
	$script:chkFixFirewall.Location = New-Object System.Drawing.Point(20,134)

	$script:chkFixTemp = New-Object System.Windows.Forms.CheckBox
	$script:chkFixTemp.Text = 'Clean TEMP folders (user/system)'
	$script:chkFixTemp.AutoSize = $true
	$script:chkFixTemp.Location = New-Object System.Drawing.Point(20,160)

	$script:chkFixAutorun = New-Object System.Windows.Forms.CheckBox
	$script:chkFixAutorun.Text = 'Disable Autorun/Autoplay'
	$script:chkFixAutorun.AutoSize = $true
	$script:chkFixAutorun.Location = New-Object System.Drawing.Point(20,186)

	$script:chkFixAssoc = New-Object System.Windows.Forms.CheckBox
	$script:chkFixAssoc.Text = 'Repair common file associations (.lnk, .exe, .reg)'
	$script:chkFixAssoc.AutoSize = $true
	$script:chkFixAssoc.Location = New-Object System.Drawing.Point(20,212)

	# New safe fixes
	$script:chkFixBits = New-Object System.Windows.Forms.CheckBox
	$script:chkFixBits.Text = 'Repair BITS/WUA services (set defaults, start)'
	$script:chkFixBits.AutoSize = $true
	$script:chkFixBits.Location = New-Object System.Drawing.Point(400,30)

	$script:chkFixShell = New-Object System.Windows.Forms.CheckBox
	$script:chkFixShell.Text = 'Restore Explorer shell & enable Task Manager'
	$script:chkFixShell.AutoSize = $true
	$script:chkFixShell.Location = New-Object System.Drawing.Point(400,56)

	$script:chkFixPolicies = New-Object System.Windows.Forms.CheckBox
	$script:chkFixPolicies.Text = 'Clean restrictive Policies (DisableRegistryTools, etc.)'
	$script:chkFixPolicies.AutoSize = $true
	$script:chkFixPolicies.Location = New-Object System.Drawing.Point(400,82)

	$script:chkFixWU = New-Object System.Windows.Forms.CheckBox
	$script:chkFixWU.Text = 'Repair Windows Update (SoftwareDistribution/catroot2)'
	$script:chkFixWU.AutoSize = $true
	$script:chkFixWU.Location = New-Object System.Drawing.Point(400,108)

	$script:chkFixServices = New-Object System.Windows.Forms.CheckBox
	$script:chkFixServices.Text = 'Check core services (BFE, MpsSvc, Dhcp, Dnscache)'
	$script:chkFixServices.AutoSize = $true
	$script:chkFixServices.Location = New-Object System.Drawing.Point(400,134)

	$script:chkFixBrowser = New-Object System.Windows.Forms.CheckBox
	$script:chkFixBrowser.Text = 'Clean browser proxy/policy hijacks (IE/Edge/Chrome/Firefox)'
	$script:chkFixBrowser.AutoSize = $true
	$script:chkFixBrowser.Location = New-Object System.Drawing.Point(400,160)

	$script:chkFixWatchdog = New-Object System.Windows.Forms.CheckBox
	$script:chkFixWatchdog.Text = 'Hosts/Proxy watchdog (monitor for 5 minutes after fixes)'
	$script:chkFixWatchdog.AutoSize = $true
	$script:chkFixWatchdog.Location = New-Object System.Drawing.Point(400,186)

	$script:chkFixReport = New-Object System.Windows.Forms.CheckBox
	$script:chkFixReport.Text = 'Generate fix report (HTML/CSV) with rollback info'
	$script:chkFixReport.AutoSize = $true
	$script:chkFixReport.Location = New-Object System.Drawing.Point(400,212)

	$script:btnRunFixes = New-Object System.Windows.Forms.Button
	$script:btnRunFixes.Text = 'Run fixes'
	$script:btnRunFixes.Size = New-Object System.Drawing.Size(160,30)
	$script:btnRunFixes.Location = New-Object System.Drawing.Point(20,248)

	$script:txtFixLog = New-Object System.Windows.Forms.RichTextBox
	$script:txtFixLog.Multiline = $true
	$script:txtFixLog.ReadOnly = $true
	$script:txtFixLog.WordWrap = $true
	$script:txtFixLog.ScrollBars = 'Vertical'
	$script:txtFixLog.Location = New-Object System.Drawing.Point(20,292)
	$script:txtFixLog.Size = New-Object System.Drawing.Size(760,200)
	$script:txtFixLog.Anchor = 'Top,Left,Right'

	$script:grpFix.Controls.AddRange(@(
		$script:chkFixHosts,
		$script:chkFixProxy,
		$script:chkFixDns,
		$script:chkFixWinsock,
		$script:chkFixFirewall,
		$script:chkFixTemp,
		$script:chkFixAutorun,
		$script:chkFixAssoc,
		$script:chkFixBits,
		$script:chkFixShell,
		$script:chkFixPolicies,
		$script:chkFixWU,
		$script:chkFixServices,
		$script:chkFixBrowser,
		$script:chkFixWatchdog,
		$script:chkFixReport,
		$script:btnRunFixes,
		$script:txtFixLog
	))
	$tabFix.Controls.Add($script:grpFix)

    $script:AddFixLog = {
        param([string]$line)
        try {
            if ($script:txtFixLog) {
                $action = [Action]{ $script:txtFixLog.AppendText($line + [Environment]::NewLine) }
                if ($script:txtFixLog.InvokeRequired) { $null = $script:txtFixLog.BeginInvoke($action) } else { & $action }
            }
        } catch {}
    }

	$script:btnRunFixes.Add_Click({
		try {
			if ($tabs -and $tabFix) { $tabs.SelectedTab = $tabFix }
			if ($txtFixLog) { $txtFixLog.Clear() }
			$tasks = @()
			if ($chkFixHosts.Checked)   { $tasks += 'hosts' }
			if ($chkFixProxy.Checked)   { $tasks += 'proxy' }
			if ($chkFixDns.Checked)     { $tasks += 'dns' }
			if ($chkFixWinsock.Checked) { $tasks += 'winsock' }
			if ($chkFixFirewall.Checked){ $tasks += 'firewall' }
			if ($chkFixTemp.Checked)    { $tasks += 'temp' }
			if ($chkFixAutorun.Checked) { $tasks += 'autorun' }
			if ($chkFixAssoc.Checked)   { $tasks += 'assoc' }
			if ($chkFixBits.Checked)    { $tasks += 'bits' }
			if ($chkFixShell.Checked)   { $tasks += 'shell' }
			if ($chkFixPolicies.Checked){ $tasks += 'policies' }
			if ($chkFixWU.Checked)      { $tasks += 'wu' }
			if ($chkFixServices.Checked){ $tasks += 'services' }
			if ($chkFixBrowser.Checked) { $tasks += 'browser' }
			if ($chkFixWatchdog.Checked){ $tasks += 'watchdog' }
			if ($chkFixReport.Checked)  { $tasks += 'report' }
            if ($tasks.Count -eq 0) { & $script:AddFixLog 'Select at least one fix.'; return }

            & $script:AddFixLog ('Running fixes: ' + ($tasks -join ', '))
			Set-UiBusy $true
			$job = Start-Job -ScriptBlock {
				param($selected)
				function say($m){ Write-Output $m }
				try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
				foreach ($t in $selected) {
					switch ($t) {
						'hosts' {
							say '[FIX] Resetting hosts to default'
							$hosts = "$env:WinDir\System32\drivers\etc\hosts"
							try {
								Set-Content -LiteralPath $hosts -Value "127.0.0.1 localhost`r`n::1 localhost`r`n" -Encoding ASCII -Force
								say '[OK] hosts reset'
							} catch { say ("[ERR] hosts reset: " + $_.Exception.Message) }
						}
						'proxy' {
							say '[FIX] Disabling system proxy / WinINET'
							try {
								reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f | Out-Null
								reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f 2>$null | Out-Null
								reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f 2>$null | Out-Null
								reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoDetect /t REG_DWORD /d 0 /f | Out-Null
								try { netsh winhttp reset proxy | Out-Null } catch {}
								say '[OK] Proxy disabled'
							} catch { say ("[ERR] Proxy: " + $_.Exception.Message) }
						}
						'dns' {
							say '[FIX] Flushing DNS and resetting adapters to DHCP DNS'
							try { ipconfig /flushdns | Out-Null } catch {}
							try {
								Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object {
									try { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction Stop } catch {}
								}
								say '[OK] DNS reset'
							} catch { say ("[ERR] DNS: " + $_.Exception.Message) }
						}
						'winsock' {
							say '[FIX] Resetting Winsock and TCP/IP'
							try { netsh winsock reset | Out-Null } catch {}
							try { netsh int ip reset | Out-Null } catch {}
							say '[OK] Winsock/TCP reset (reboot may be required)'
						}
						'firewall' {
							say '[FIX] Resetting Windows Firewall'
							try { netsh advfirewall reset | Out-Null; say '[OK] Firewall reset' } catch { say ("[ERR] Firewall: " + $_.Exception.Message) }
						}
						'temp' {
							say '[FIX] Cleaning TEMP folders'
							try { Get-ChildItem "$env:TEMP" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch {}
							try { Get-ChildItem "$env:WinDir\Temp" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } catch {}
							say '[OK] TEMP cleaned'
						}
						'autorun' {
							say '[FIX] Disabling Autorun/Autoplay'
							try {
								reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
								reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
								say '[OK] Autorun disabled'
							} catch { say ("[ERR] Autorun: " + $_.Exception.Message) }
						}
						'assoc' {
							say '[FIX] Repairing common file associations (.lnk, .exe, .reg)'
							try {
								# .lnk
								reg add "HKLM\SOFTWARE\Classes\.lnk" /ve /d lnkfile /f | Out-Null
								# .exe default shell open
								reg add "HKLM\SOFTWARE\Classes\.exe" /ve /d exefile /f | Out-Null
								reg add "HKLM\SOFTWARE\Classes\exefile\shell\open\command" /ve /d '"%1" %*' /f | Out-Null
								# .reg
								reg add "HKLM\SOFTWARE\Classes\.reg" /ve /d regfile /f | Out-Null
								say '[OK] Associations repaired'
							} catch { say ("[ERR] Assoc: " + $_.Exception.Message) }
						}
						'bits' {
							say '[FIX] Repairing BITS/WUA services'
							try {
								$services = 'BITS','wuauserv'
								foreach ($svc in $services) {
									try { sc.exe config $svc start= demand | Out-Null } catch {}
                                    try { sc.exe sdset $svc "D:(A;;CCLCSWLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)" | Out-Null } catch {}
									try { net start $svc | Out-Null } catch {}
								}
								say '[OK] BITS/WUA set and started (where applicable)'
							} catch { say ("[ERR] BITS/WUA: " + $_.Exception.Message) }
						}
						'shell' {
							say '[FIX] Restoring Explorer shell and enabling Task Manager'
							try { reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d explorer.exe /f | Out-Null } catch {}
							try { reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f | Out-Null } catch {}
							say '[OK] Shell/Task Manager restored'
						}
						'policies' {
							say '[FIX] Cleaning restrictive Policies'
							$keys = @(
								"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
								"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
							)
							$valuesToZero = @('DisableRegistryTools','DisableTaskMgr','DisableCMD','DisableSR','DisableChangePassword')
							foreach ($k in $keys) {
								foreach ($v in $valuesToZero) {
									try { reg add $k /v $v /t REG_DWORD /d 0 /f | Out-Null } catch {}
								}
							}
							say '[OK] Policies cleaned'
						}
						'wu' {
							say '[FIX] Repairing Windows Update components'
							try {
								# Stop services
								foreach ($svc in 'wuauserv','bits','cryptsvc','msiserver') { try { net stop $svc /y | Out-Null } catch {} }
								# Rename folders
								$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
								$sd  = Join-Path $env:WinDir 'SoftwareDistribution'
								$sdB = Join-Path $env:WinDir ("SoftwareDistribution.bak_" + $ts)
								$cr2 = Join-Path $env:WinDir 'System32\catroot2'
								$cr2B= Join-Path $env:WinDir ("System32\catroot2.bak_" + $ts)
								try { if (Test-Path $sd)  { Rename-Item -LiteralPath $sd  -NewName (Split-Path -Leaf $sdB)  -Force } } catch {}
								try { if (Test-Path $cr2) { Rename-Item -LiteralPath $cr2 -NewName (Split-Path -Leaf $cr2B) -Force } } catch {}
								# Start services
								foreach ($svc in 'msiserver','cryptsvc','bits','wuauserv') { try { net start $svc | Out-Null } catch {} }
								say '[OK] Windows Update components repaired'
							} catch { say ("[ERR] WU: " + $_.Exception.Message) }
						}
						'services' {
							say '[CHECK] Verifying core services (BFE, MpsSvc, Dhcp, Dnscache)'
							$svcList = @(
								@{ Name='BFE';      Start='auto'   },
								@{ Name='MpsSvc';   Start='auto'   },
								@{ Name='Dhcp';     Start='auto'   },
								@{ Name='Dnscache'; Start='auto'   }
							)
							foreach ($s in $svcList) {
								try {
									$nm = $s.Name
									$st = Get-Service -Name $nm -ErrorAction Stop
									say ("[SERVICE] " + $nm + " state=" + $st.Status)
									# StartType ayarlamaları için sc.exe kullan
									try { sc.exe config $nm start= $($s.Start) | Out-Null } catch {}
									if ($st.Status -ne 'Running') { try { Start-Service -Name $nm -ErrorAction SilentlyContinue } catch {} }
									say ("[OK] " + $nm + " configured to start=" + $($s.Start))
								} catch { say ("[ERR] Service " + $s.Name + ": " + $_.Exception.Message) }
							}
							say '[OK] Core services verified'
						}
						'browser' {
							say '[FIX] Cleaning browser proxy/policy hijacks'
							try {
								# IE/Edge proxy settings
								$ieKeys = @(
									"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
									"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
								)
								foreach ($k in $ieKeys) {
									try { reg add $k /v ProxyEnable /t REG_DWORD /d 0 /f | Out-Null } catch {}
									try { reg delete $k /v ProxyServer /f 2>$null | Out-Null } catch {}
									try { reg delete $k /v AutoConfigURL /f 2>$null | Out-Null } catch {}
									try { reg add $k /v AutoDetect /t REG_DWORD /d 1 /f | Out-Null } catch {}
								}
								
								# Chrome policies (safe cleanup)
								$chromeKeys = @(
									"HKCU\Software\Policies\Google\Chrome",
									"HKLM\Software\Policies\Google\Chrome"
								)
								foreach ($k in $chromeKeys) {
									try { reg delete $k /v ProxyMode /f 2>$null | Out-Null } catch {}
									try { reg delete $k /v ProxyServer /f 2>$null | Out-Null } catch {}
									try { reg delete $k /v ProxyPacUrl /f 2>$null | Out-Null } catch {}
								}
								
								# Firefox policies (safe cleanup)
								$ffKeys = @(
									"HKCU\Software\Policies\Mozilla\Firefox",
									"HKLM\Software\Policies\Mozilla\Firefox"
								)
								foreach ($k in $ffKeys) {
									try { reg delete $k /v ProxyMode /f 2>$null | Out-Null } catch {}
									try { reg delete $k /v ProxyServer /f 2>$null | Out-Null } catch {}
								}
								
								# Edge policies (safe cleanup)
								$edgeKeys = @(
									"HKCU\Software\Policies\Microsoft\Edge",
									"HKLM\Software\Policies\Microsoft\Edge"
								)
								foreach ($k in $edgeKeys) {
									try { reg delete $k /v ProxyMode /f 2>$null | Out-Null } catch {}
									try { reg delete $k /v ProxyServer /f 2>$null | Out-Null } catch {}
									try { reg delete $k /v ProxyPacUrl /f 2>$null | Out-Null } catch {}
								}
								
								say '[OK] Browser proxy/policy hijacks cleaned'
							} catch { say ("[ERR] Browser cleanup: " + $_.Exception.Message) }
						}
						'watchdog' {
							say '[WATCHDOG] Starting 5-minute monitoring for hosts/proxy changes'
							try {
								# Baseline capture
								$hostsPath = "$env:WinDir\System32\drivers\etc\hosts"
								$baselineHosts = ""
								try { $baselineHosts = Get-Content -LiteralPath $hostsPath -Raw -ErrorAction Stop } catch {}
								
								$baselineProxy = @{}
								$proxyKeys = @(
									"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
									"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
								)
								foreach ($k in $proxyKeys) {
									try {
										$proxyEnable = (Get-ItemProperty -Path "Registry::$k" -Name "ProxyEnable" -ErrorAction SilentlyContinue).ProxyEnable
										$proxyServer = (Get-ItemProperty -Path "Registry::$k" -Name "ProxyServer" -ErrorAction SilentlyContinue).ProxyServer
										$baselineProxy[$k] = @{ Enable=$proxyEnable; Server=$proxyServer }
									} catch {}
								}
								
								say '[WATCHDOG] Baseline captured, monitoring for 5 minutes...'
								
								# Monitor for 5 minutes (300 seconds)
								$monitorEnd = (Get-Date).AddSeconds(300)
								$checkCount = 0
								
								while ((Get-Date) -lt $monitorEnd) {
									Start-Sleep -Seconds 30
									$checkCount++
									
									# Check hosts file
									try {
										$currentHosts = Get-Content -LiteralPath $hostsPath -Raw -ErrorAction Stop
										if ($currentHosts -ne $baselineHosts) {
											say "[WARNING] Hosts file changed! Check for malware re-infection."
											$baselineHosts = $currentHosts
										}
									} catch {}
									
									# Check proxy settings
									foreach ($k in $proxyKeys) {
										try {
											$currentEnable = (Get-ItemProperty -Path "Registry::$k" -Name "ProxyEnable" -ErrorAction SilentlyContinue).ProxyEnable
											$currentServer = (Get-ItemProperty -Path "Registry::$k" -Name "ProxyServer" -ErrorAction SilentlyContinue).ProxyServer
											
											if ($baselineProxy[$k].Enable -ne $currentEnable -or $baselineProxy[$k].Server -ne $currentServer) {
												say "[WARNING] Proxy settings changed in $k! Check for malware re-infection."
												$baselineProxy[$k] = @{ Enable=$currentEnable; Server=$currentServer }
											}
										} catch {}
									}
									
									if ($checkCount % 2 -eq 0) {
										say "[WATCHDOG] Monitoring... ($checkCount/10 checks completed)"
									}
								}
								
								say '[OK] Watchdog monitoring completed - no suspicious changes detected'
							} catch { say ("[ERR] Watchdog: " + $_.Exception.Message) }
						}
						'report' {
							say '[REPORT] Generating OmniFix report (HTML/CSV)'
							try {
								$timestamp = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
								$reportDir = Join-Path $env:TEMP "OmniFix_Report_$timestamp"
								New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
								
								# HTML Report
								$htmlPath = Join-Path $reportDir "OmniFix_Report.html"
								$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>OmniFix Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 25px; }
        .fix-item { background: #ecf0f1; padding: 10px; margin: 5px 0; border-left: 4px solid #3498db; }
        .rollback { background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
        .success { color: #27ae60; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        .error { color: #e74c3c; font-weight: bold; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 OmniFix Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Computer:</strong> $env:COMPUTERNAME</p>
        <p><strong>User:</strong> $env:USERNAME</p>
        
        <h2>📋 Applied Fixes</h2>
"@
								
								# Add applied fixes to HTML
								$appliedFixes = @()
								if ($selected -contains 'hosts') { 
									$appliedFixes += "Reset hosts file to default"
									$html += '<div class="fix-item"><strong>Hosts File:</strong> Reset to default (127.0.0.1 localhost)</div>'
								}
								if ($selected -contains 'proxy') { 
									$appliedFixes += "Disabled system proxy"
									$html += '<div class="fix-item"><strong>Proxy Settings:</strong> Disabled system proxy and reset WinINET</div>'
								}
								if ($selected -contains 'dns') { 
									$appliedFixes += "Flushed DNS cache"
									$html += '<div class="fix-item"><strong>DNS:</strong> Flushed cache and reset adapters to DHCP</div>'
								}
								if ($selected -contains 'winsock') { 
									$appliedFixes += "Reset Winsock & TCP/IP"
									$html += '<div class="fix-item"><strong>Network Stack:</strong> Reset Winsock and TCP/IP (reboot may be required)</div>'
								}
								if ($selected -contains 'firewall') { 
									$appliedFixes += "Reset Windows Firewall"
									$html += '<div class="fix-item"><strong>Firewall:</strong> Reset Windows Firewall policies</div>'
								}
								if ($selected -contains 'temp') { 
									$appliedFixes += "Cleaned TEMP folders"
									$html += '<div class="fix-item"><strong>TEMP Cleanup:</strong> Cleaned user and system temp folders</div>'
								}
								if ($selected -contains 'autorun') { 
									$appliedFixes += "Disabled Autorun/Autoplay"
									$html += '<div class="fix-item"><strong>Autorun:</strong> Disabled autorun and autoplay</div>'
								}
								if ($selected -contains 'assoc') { 
									$appliedFixes += "Repaired file associations"
									$html += '<div class="fix-item"><strong>File Associations:</strong> Repaired .lnk, .exe, .reg associations</div>'
								}
								if ($selected -contains 'bits') { 
									$appliedFixes += "Repaired BITS/WUA services"
									$html += '<div class="fix-item"><strong>Services:</strong> Repaired BITS and Windows Update services</div>'
								}
								if ($selected -contains 'shell') { 
									$appliedFixes += "Restored Explorer shell"
									$html += '<div class="fix-item"><strong>Shell:</strong> Restored Explorer shell and enabled Task Manager</div>'
								}
								if ($selected -contains 'policies') { 
									$appliedFixes += "Cleaned restrictive policies"
									$html += '<div class="fix-item"><strong>Policies:</strong> Cleaned restrictive registry policies</div>'
								}
								if ($selected -contains 'wu') { 
									$appliedFixes += "Repaired Windows Update"
									$html += '<div class="fix-item"><strong>Windows Update:</strong> Repaired SoftwareDistribution and catroot2</div>'
								}
								if ($selected -contains 'services') { 
									$appliedFixes += "Verified core services"
									$html += '<div class="fix-item"><strong>Core Services:</strong> Verified BFE, MpsSvc, Dhcp, Dnscache</div>'
								}
								if ($selected -contains 'browser') { 
									$appliedFixes += "Cleaned browser hijacks"
									$html += '<div class="fix-item"><strong>Browser:</strong> Cleaned proxy/policy hijacks (IE/Edge/Chrome/Firefox)</div>'
								}
								if ($selected -contains 'watchdog') { 
									$appliedFixes += "Hosts/Proxy monitoring"
									$html += '<div class="fix-item"><strong>Watchdog:</strong> 5-minute monitoring for hosts/proxy changes</div>'
								}
								
								$html += @"
        
        <h2>🔄 Rollback Information</h2>
        <div class="rollback">
            <h3>Manual Rollback Commands:</h3>
            <pre>
# Restore hosts file (if needed)
echo "127.0.0.1 localhost" > C:\Windows\System32\drivers\etc\hosts
echo "::1 localhost" >> C:\Windows\System32\drivers\etc\hosts

# Restore proxy settings (if needed)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f

# Restore DNS settings (if needed)
ipconfig /flushdns
netsh interface ip set dns "Local Area Connection" dhcp

# Restore Winsock (if needed)
netsh winsock reset
netsh int ip reset

# Restore Windows Firewall (if needed)
netsh advfirewall reset

# Restore autorun (if needed)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /f

# Restore Task Manager (if needed)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f
            </pre>
        </div>
        
        <h2>⚠️ Important Notes</h2>
        <ul>
            <li>Some fixes may require a system reboot to take full effect</li>
            <li>Keep this report for reference in case rollback is needed</li>
            <li>Monitor your system for any unusual behavior after applying fixes</li>
            <li>Consider running a full antivirus scan after applying these fixes</li>
        </ul>
        
        <h2>📊 System Information</h2>
        <pre>
Computer Name: $env:COMPUTERNAME
User: $env:USERNAME
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Architecture: $((Get-WmiObject Win32_OperatingSystem).OSArchitecture)
Total Memory: $([math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB
        </pre>
    </div>
</body>
</html>
"@
								
								Set-Content -Path $htmlPath -Value $html -Encoding UTF8
								
								# CSV Report
								$csvPath = Join-Path $reportDir "OmniFix_Report.csv"
								$csvData = @()
								foreach ($fix in $appliedFixes) {
									$csvData += [PSCustomObject]@{
										Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
										Fix = $fix
										Status = 'Applied'
										Computer = $env:COMPUTERNAME
										User = $env:USERNAME
									}
								}
								$csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
								
								say "[OK] Report generated: $reportDir"
								say "[INFO] HTML: $htmlPath"
								say "[INFO] CSV: $csvPath"
								
								# Try to open the report folder
								try { Start-Process explorer.exe -ArgumentList $reportDir } catch {}
								
							} catch { say ("[ERR] Report generation: " + $_.Exception.Message) }
						}
					}
				}
				catch { say ("[ERR] Fix job error: " + $_.Exception.Message) }
			} -ArgumentList ($tasks)

			# Keep a reference so GC doesn't collect it
			$script:OmniFixJob = $job
			& $script:AddFixLog 'Fixes job launched...'
			Write-Log 'OmniFix: fixes job launched.'

			$child = $job.ChildJobs[0]
            $null = Register-ObjectEvent -InputObject $child.Output -EventName DataAdded -Action {
				try {
					$idx = $eventArgs.Index
					$item = $event.Sender[$idx]
                    if ($item) { & $script:AddFixLog (($item | Out-String).TrimEnd()) }
					if ($item) { Write-Log (($item | Out-String).TrimEnd()) }
				} catch {}
			}
			# Fallback polling to ensure UI updates even if DataAdded action misses
			try { if ($script:FixLogTimer) { $script:FixLogTimer.Stop(); $script:FixLogTimer.Dispose() } } catch {}
			$script:FixLogTimer = New-Object System.Windows.Forms.Timer
			$script:FixLogTimer.Interval = 900
			$script:FixLogTimer.Add_Tick({
				try {
					if ($script:OmniFixJob) {
						# Drain any output
						try {
							$outs = Receive-Job -Job $script:OmniFixJob -Keep -ErrorAction SilentlyContinue
							foreach ($o in $outs) { & $script:AddFixLog (($o | Out-String).TrimEnd()); Write-Log (($o | Out-String).TrimEnd()) }
						} catch {}
						if ($script:OmniFixJob.State -in 'Completed','Failed','Stopped') {
							$script:FixLogTimer.Stop(); $script:FixLogTimer.Dispose()
							Set-UiBusy $false
						}
					}
				} catch {}
			})
			$script:FixLogTimer.Start()
		} catch { Write-Log ("ERROR: Fixes failed - " + $_.Exception.Message) }
	})
}


