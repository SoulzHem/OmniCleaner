function Open-QuarantineManager {
	try {
		$idx = Join-Path $PSScriptRoot 'quarantine_index.csv'
		$formQ = New-Object System.Windows.Forms.Form
		$formQ.Text = 'Quarantine Manager'
		$formQ.Size = New-Object System.Drawing.Size(780,460)
		$formQ.StartPosition = 'CenterParent'
		
		$txtSearch = New-Object System.Windows.Forms.TextBox
		try { $txtSearch.PlaceholderText = 'Search (filename or path)' } catch {}
		$txtSearch.Location = New-Object System.Drawing.Point(10,10)
		$txtSearch.Size = New-Object System.Drawing.Size(520,26)

		$btnSelectAll = New-Object System.Windows.Forms.Button
		$btnSelectAll.Text = 'Select all'
		$btnSelectAll.Location = New-Object System.Drawing.Point(540,10)
		$btnSelectAll.Size = New-Object System.Drawing.Size(90,26)

		$btnInvert = New-Object System.Windows.Forms.Button
		$btnInvert.Text = 'Invert'
		$btnInvert.Location = New-Object System.Drawing.Point(640,10)
		$btnInvert.Size = New-Object System.Drawing.Size(90,26)

		$lv = New-Object System.Windows.Forms.ListView
		$lv.View = 'Details'
		$lv.FullRowSelect = $true
		$lv.CheckBoxes = $true
		$lv.Location = New-Object System.Drawing.Point(10,44)
		$lv.Size = New-Object System.Drawing.Size(740,320)
		$lv.Anchor = 'Top,Left,Right,Bottom'
		[void]$lv.Columns.Add('Time',150)
		[void]$lv.Columns.Add('Original Path',460)
		[void]$lv.Columns.Add('Filename',120)

		$btnRefresh = New-Object System.Windows.Forms.Button
		$btnRefresh.Text = 'Refresh'
		$btnRefresh.Location = New-Object System.Drawing.Point(10,372)
		$btnRefresh.Size = New-Object System.Drawing.Size(90,30)

		$btnRestoreSel = New-Object System.Windows.Forms.Button
		$btnRestoreSel.Text = 'Restore selected'
		$btnRestoreSel.Location = New-Object System.Drawing.Point(110,372)
		$btnRestoreSel.Size = New-Object System.Drawing.Size(130,30)

		$btnDeleteSel = New-Object System.Windows.Forms.Button
		$btnDeleteSel.Text = 'Delete selected'
		$btnDeleteSel.Location = New-Object System.Drawing.Point(250,372)
		$btnDeleteSel.Size = New-Object System.Drawing.Size(130,30)

		$btnClose = New-Object System.Windows.Forms.Button
		$btnClose.Text = 'Close'
		$btnClose.Location = New-Object System.Drawing.Point(660,372)
		$btnClose.Size = New-Object System.Drawing.Size(90,30)

		$script:QAllRows = @()
		function Get-QuarantineIndex {
			try {
				$lv.Items.Clear()
				if (-not (Test-Path $idx)) { return }
				$lines = Get-Content -LiteralPath $idx -ErrorAction SilentlyContinue
				if ($lines.Count -lt 2) { return }
				# Satır doğrulama
				$expectedMinColumns = 3
				$skipped = 0
				$validRows = @()
				$lines | Select-Object -Skip 1 | ForEach-Object {
					if ([string]::IsNullOrWhiteSpace($_)) { return }
					$parts = $_.Split(',')
					if ($parts.Count -lt $expectedMinColumns) { $skipped++; return }
					$validRows += $_
				}
				$script:QAllRows = $validRows
				foreach ($row in $validRows) {
					$parts = $row.Split(',')
					$item = New-Object System.Windows.Forms.ListViewItem($parts[0])
					[void]$item.SubItems.Add($parts[1])
					[void]$item.SubItems.Add($parts[2])
					$lv.Items.Add($item) | Out-Null
				}
				if ($skipped -gt 0) { Write-Log ("[Quarantine] Geçersiz satır atlandı: " + $skipped) }
			} catch {}
		}

		function Set-QuarantineFilter {
			try {
				$term = ''
				try { if ($txtSearch -and $txtSearch.Text) { $term = $txtSearch.Text } } catch {}
				$term = $term.ToLower()
				$lv.Items.Clear()
				$rows = $script:QAllRows
				if ($term -and $term.Trim().Length -gt 0) {
					$rows = $rows | Where-Object { $_.ToLower() -like ("*" + $term + "*") }
				}
				foreach ($r in $rows) {
					$parts = $r.Split(',')
					if ($parts.Count -ge 3) {
						$item = New-Object System.Windows.Forms.ListViewItem($parts[0])
						[void]$item.SubItems.Add($parts[1])
						[void]$item.SubItems.Add($parts[2])
						$lv.Items.Add($item) | Out-Null
					}
				}
			} catch {}
		}

		$btnRefresh.Add_Click({ Get-QuarantineIndex; Set-QuarantineFilter })
		$txtSearch.Add_TextChanged({ Set-QuarantineFilter })
		$btnSelectAll.Add_Click({ try { foreach ($it in $lv.Items) { $it.Checked = $true } } catch {} })
		$btnInvert.Add_Click({ try { foreach ($it in $lv.Items) { $it.Checked = -not $it.Checked } } catch {} })
		$btnClose.Add_Click({ $formQ.Close() })

		$btnRestoreSel.Add_Click({
			try {
				$sel = @()
				foreach ($it in $lv.Items) { if ($it.Checked) { $sel += $it.SubItems[2].Text } }
				if ($sel.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Select items.','Info') | Out-Null; return }
				$scriptPath = Join-Path $PSScriptRoot 'OmniCleaner.ps1'
				$logPath = Join-Path $PSScriptRoot 'omnicleaner.log'
				$argItems = ($sel | ForEach-Object { '"' + $_ + '"' }) -join ' '
				$cmd = '"' + $scriptPath + '" -RestoreItems ' + $argItems + ' -LogPath ' + ('"' + $logPath + '"')
				Write-Log ('Restore selected: ' + ($sel -join ', '))
				Start-Job -ScriptBlock { param($c) powershell -NoProfile -ExecutionPolicy Bypass -Command $c 2>&1 } -ArgumentList $cmd | Out-Null
			} catch {}
		})

		$btnDeleteSel.Add_Click({
			try {
				$sel = @()
				foreach ($it in $lv.Items) { if ($it.Checked) { $sel += $it.SubItems[2].Text } }
				if ($sel.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Select items.','Info') | Out-Null; return }
				$scriptPath = Join-Path $PSScriptRoot 'OmniCleaner.ps1'
				$logPath = Join-Path $PSScriptRoot 'omnicleaner.log'
				$argItems = ($sel | ForEach-Object { '"' + $_ + '"' }) -join ' '
				$cmd = '"' + $scriptPath + '" -DeleteItems ' + $argItems + ' -LogPath ' + ('"' + $logPath + '"')
				Write-Log ('Delete selected: ' + ($sel -join ', '))
				Start-Job -ScriptBlock { param($c) powershell -NoProfile -ExecutionPolicy Bypass -Command $c 2>&1 } -ArgumentList $cmd | Out-Null
			} catch {}
		})

		$formQ.Controls.AddRange(@($txtSearch,$btnSelectAll,$btnInvert,$lv,$btnRefresh,$btnRestoreSel,$btnDeleteSel,$btnClose))
		Get-QuarantineIndex; Set-QuarantineFilter
		[void]$formQ.ShowDialog($form)
	} catch { Write-Log ("ERROR: Quarantine manager failed - " + $_.Exception.Message) }
}
