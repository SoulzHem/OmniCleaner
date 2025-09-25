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


