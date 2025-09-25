function Initialize-CleanTab {
	# Clean tab - Options
	$script:grpOptions = New-Object System.Windows.Forms.GroupBox
	$script:grpOptions.Text = 'Options'
	$script:grpOptions.Location = New-Object System.Drawing.Point(10,10)
	$script:grpOptions.Size = New-Object System.Drawing.Size(850,250)
	$script:grpOptions.Anchor = 'Top,Left,Right'
	Enable-TextRenderingIfAvailable $script:grpOptions

	# Scan scope checkboxes
	$script:chkScanServices = New-Object System.Windows.Forms.CheckBox
	$script:chkScanServices.Text = 'Scan services'
	$script:chkScanServices.AutoSize = $true
	$script:chkScanServices.Checked = $true
	$script:chkScanServices.Location = New-Object System.Drawing.Point(20,140)

	$script:chkScanShortcuts = New-Object System.Windows.Forms.CheckBox
	$script:chkScanShortcuts.Text = 'Scan shortcuts/autorun'
	$script:chkScanShortcuts.AutoSize = $true
	$script:chkScanShortcuts.Checked = $true
	$script:chkScanShortcuts.Location = New-Object System.Drawing.Point(320,140)

	$script:chkScanPayloads = New-Object System.Windows.Forms.CheckBox
	$script:chkScanPayloads.Text = 'Scan payload files'
	$script:chkScanPayloads.AutoSize = $true
	$script:chkScanPayloads.Checked = $true
	$script:chkScanPayloads.Location = New-Object System.Drawing.Point(620,140)

	$script:chkScanRegistry = New-Object System.Windows.Forms.CheckBox
	$script:chkScanRegistry.Text = 'Scan startup registry'
	$script:chkScanRegistry.AutoSize = $true
	$script:chkScanRegistry.Checked = $false
	$script:chkScanRegistry.Location = New-Object System.Drawing.Point(20,164)

	# Extra options
	$script:chkQuarantine = New-Object System.Windows.Forms.CheckBox
	$script:chkQuarantine.Text = 'Quarantine instead of delete'
	$script:chkQuarantine.AutoSize = $true
	$script:chkQuarantine.Checked = $false
	$script:chkQuarantine.Location = New-Object System.Drawing.Point(320,164)

	$script:chkUsbHeuristics = New-Object System.Windows.Forms.CheckBox
	$script:chkUsbHeuristics.Text = 'USB worm heuristics'
	$script:chkUsbHeuristics.AutoSize = $true
	$script:chkUsbHeuristics.Checked = $true
	$script:chkUsbHeuristics.Location = New-Object System.Drawing.Point(620,164)

	# Advanced scans
	$script:chkDoTasks = New-Object System.Windows.Forms.CheckBox
	$script:chkDoTasks.Text = 'Scan Scheduled Tasks'
	$script:chkDoTasks.AutoSize = $true
	$script:chkDoTasks.Checked = $true
	$script:chkDoTasks.Location = New-Object System.Drawing.Point(20,188)

	$script:chkDoWmi = New-Object System.Windows.Forms.CheckBox
	$script:chkDoWmi.Text = 'Scan WMI Subscriptions'
	$script:chkDoWmi.AutoSize = $true
	$script:chkDoWmi.Checked = $true
	$script:chkDoWmi.Location = New-Object System.Drawing.Point(320,188)

	$script:chkDoLnk = New-Object System.Windows.Forms.CheckBox
	$script:chkDoLnk.Text = 'Analyze LNK targets'
	$script:chkDoLnk.AutoSize = $true
	$script:chkDoLnk.Checked = $true
	$script:chkDoLnk.Location = New-Object System.Drawing.Point(620,188)

	$script:chkAllRemovable = New-Object System.Windows.Forms.CheckBox
	$script:chkAllRemovable.Text = 'All removable drives'
	$script:chkAllRemovable.AutoSize = $true
	$script:chkAllRemovable.Checked = $true
	$script:chkAllRemovable.Location = New-Object System.Drawing.Point(15,30)

	$script:chkAggressive = New-Object System.Windows.Forms.CheckBox
	$script:chkAggressive.Text = 'Aggressive (clean Run/Services)'
	$script:chkAggressive.AutoSize = $true
	$script:chkAggressive.Checked = $true
	$script:chkAggressive.Location = New-Object System.Drawing.Point(240,30)

	$script:chkIncludeFixed = New-Object System.Windows.Forms.CheckBox
	$script:chkIncludeFixed.Text = 'Include fixed disks'
	$script:chkIncludeFixed.AutoSize = $true
	$script:chkIncludeFixed.Checked = $false
	$script:chkIncludeFixed.Location = New-Object System.Drawing.Point(15,62)

	$script:chkIncludeSystem = New-Object System.Windows.Forms.CheckBox
	$script:chkIncludeSystem.Text = 'Include system drive (C:)'
	$script:chkIncludeSystem.AutoSize = $true
	$script:chkIncludeSystem.Checked = $false
	$script:chkIncludeSystem.Location = New-Object System.Drawing.Point(240,62)

	$script:chkWhatIf = New-Object System.Windows.Forms.CheckBox
	$script:chkWhatIf.Text = 'WhatIf (dry run)'
	$script:chkWhatIf.AutoSize = $true
	$script:chkWhatIf.Checked = $false
	$script:chkWhatIf.Location = New-Object System.Drawing.Point(500,62)

	$script:chkDarkTheme = New-Object System.Windows.Forms.CheckBox
	$script:chkDarkTheme.Text = 'Dark theme'
	$script:chkDarkTheme.AutoSize = $true
	$script:chkDarkTheme.Checked = $false
	$script:chkDarkTheme.Location = New-Object System.Drawing.Point(500,30)

	$script:chkSelectAll = New-Object System.Windows.Forms.CheckBox
	$script:chkSelectAll.Text = 'Select all'
	$script:chkSelectAll.AutoSize = $true
	$script:chkSelectAll.Checked = $false
	$script:chkSelectAll.Location = New-Object System.Drawing.Point(15,212)

	$script:lblDrives = New-Object System.Windows.Forms.Label
	$script:lblDrives.Text = 'Target drives (e.g., D E)'
	$script:lblDrives.AutoSize = $true
	$script:lblDrives.Location = New-Object System.Drawing.Point(15,104)
	Enable-TextRenderingIfAvailable $script:lblDrives

	$script:txtDrives = New-Object System.Windows.Forms.TextBox
	$script:txtDrives.Location = New-Object System.Drawing.Point(170,104)
	$script:txtDrives.Size = New-Object System.Drawing.Size(120,28)
	$script:txtDrives.Anchor = 'Top,Left,Right'

	# Drive status badges label
	$script:lblDriveStatus = New-Object System.Windows.Forms.Label
	$script:lblDriveStatus.Text = 'Available Drives:'
	$script:lblDriveStatus.AutoSize = $true
	$script:lblDriveStatus.Location = New-Object System.Drawing.Point(320,104)
	Enable-TextRenderingIfAvailable $script:lblDriveStatus

	$script:grpOptions.Controls.AddRange(@($script:chkAllRemovable,$script:chkAggressive,$script:chkIncludeFixed,$script:chkIncludeSystem,$script:chkWhatIf,$script:chkDarkTheme,$script:chkSelectAll,$script:lblDrives,$script:txtDrives,$script:lblDriveStatus,$script:chkScanServices,$script:chkScanShortcuts,$script:chkScanPayloads,$script:chkScanRegistry,$script:chkQuarantine,$script:chkUsbHeuristics,$script:chkDoTasks,$script:chkDoWmi,$script:chkDoLnk))

	# Clean tab - Tools and inline drive list
	$script:grpActions = New-Object System.Windows.Forms.GroupBox
	$script:grpActions.Text = 'Tools'
	$script:grpActions.Location = New-Object System.Drawing.Point(10,260)
	$script:grpActions.Size = New-Object System.Drawing.Size(800,360)
	$script:grpActions.Anchor = 'Top,Left,Right'
	Enable-TextRenderingIfAvailable $script:grpActions

	$script:btnListDrives = New-Object System.Windows.Forms.Button
	$script:btnListDrives.Text = 'List drives'
	$script:btnListDrives.AutoSize = $false
	$script:btnListDrives.Size = New-Object System.Drawing.Size(120,30)
	$script:btnListDrives.Location = New-Object System.Drawing.Point(20,32)
	Enable-TextRenderingIfAvailable $script:btnListDrives

	$script:btnScan = New-Object System.Windows.Forms.Button
	$script:btnScan.Text = 'Scan (dry run)'
	$script:btnScan.AutoSize = $false
	$script:btnScan.Size = New-Object System.Drawing.Size(120,30)
	$script:btnScan.Location = New-Object System.Drawing.Point(150,32)
	Enable-TextRenderingIfAvailable $script:btnScan

	$script:btnClean = New-Object System.Windows.Forms.Button
	$script:btnClean.Text = 'Clean'
	$script:btnClean.AutoSize = $false
	$script:btnClean.Size = New-Object System.Drawing.Size(120,30)
	$script:btnClean.Location = New-Object System.Drawing.Point(280,32)
	Enable-TextRenderingIfAvailable $script:btnClean

	$script:btnCancel = New-Object System.Windows.Forms.Button
	$script:btnCancel.Text = 'Cancel'
	$script:btnCancel.AutoSize = $false
	$script:btnCancel.Size = New-Object System.Drawing.Size(120,30)
	$script:btnCancel.Location = New-Object System.Drawing.Point(410,32)
	$script:btnCancel.Enabled = $false
	Enable-TextRenderingIfAvailable $script:btnCancel

	$script:btnOpenLog = New-Object System.Windows.Forms.Button
	$script:btnOpenLog.Text = 'Open log'
	$script:btnOpenLog.AutoSize = $false
	$script:btnOpenLog.Size = New-Object System.Drawing.Size(120,30)
	$script:btnOpenLog.Location = New-Object System.Drawing.Point(540,32)
	Enable-TextRenderingIfAvailable $script:btnOpenLog

	$script:btnClearLog = New-Object System.Windows.Forms.Button
	$script:btnClearLog.Text = 'Clear log'
	$script:btnClearLog.AutoSize = $false
	$script:btnClearLog.Size = New-Object System.Drawing.Size(120,30)
	$script:btnClearLog.Location = New-Object System.Drawing.Point(670,32)
	Enable-TextRenderingIfAvailable $script:btnClearLog

	$script:btnOpenExcl = New-Object System.Windows.Forms.Button
	$script:btnOpenExcl.Text = 'Open exclusions'
	$script:btnOpenExcl.AutoSize = $false
	$script:btnOpenExcl.Size = New-Object System.Drawing.Size(120,30)
	$script:btnOpenExcl.Location = New-Object System.Drawing.Point(20,72)
	Enable-TextRenderingIfAvailable $script:btnOpenExcl

	$script:btnOpenQ = New-Object System.Windows.Forms.Button
	$script:btnOpenQ.Text = 'Open quarantine'
	$script:btnOpenQ.AutoSize = $false
	$script:btnOpenQ.Size = New-Object System.Drawing.Size(120,30)
	$script:btnOpenQ.Location = New-Object System.Drawing.Point(150,72)
	Enable-TextRenderingIfAvailable $script:btnOpenQ

	$script:btnRestoreQ = New-Object System.Windows.Forms.Button
	$script:btnRestoreQ.Text = 'Restore quarantine'
	$script:btnRestoreQ.AutoSize = $false
	$script:btnRestoreQ.Size = New-Object System.Drawing.Size(120,30)
	$script:btnRestoreQ.Location = New-Object System.Drawing.Point(280,72)
	Enable-TextRenderingIfAvailable $script:btnRestoreQ

	$script:btnManageQ = New-Object System.Windows.Forms.Button
	$script:btnManageQ.Text = 'Manage quarantine'
	$script:btnManageQ.AutoSize = $false
	$script:btnManageQ.Size = New-Object System.Drawing.Size(120,30)
	$script:btnManageQ.Location = New-Object System.Drawing.Point(670,72)
	Enable-TextRenderingIfAvailable $script:btnManageQ

	$script:btnExportCsv = New-Object System.Windows.Forms.Button
	$script:btnExportCsv.Text = 'Export CSV'
	$script:btnExportCsv.AutoSize = $false
	$script:btnExportCsv.Size = New-Object System.Drawing.Size(120,30)
	$script:btnExportCsv.Location = New-Object System.Drawing.Point(410,72)
	Enable-TextRenderingIfAvailable $script:btnExportCsv

	$script:btnExportHtml = New-Object System.Windows.Forms.Button
	$script:btnExportHtml.Text = 'Export HTML'
	$script:btnExportHtml.AutoSize = $false
	$script:btnExportHtml.Size = New-Object System.Drawing.Size(120,30)
	$script:btnExportHtml.Location = New-Object System.Drawing.Point(540,72)
	Enable-TextRenderingIfAvailable $script:btnExportHtml

	$script:lstDrives = New-Object System.Windows.Forms.ListBox
	$script:lstDrives.Location = New-Object System.Drawing.Point(15,110)
	$script:lstDrives.Size = New-Object System.Drawing.Size(800,100)
	$script:lstDrives.Anchor = 'Top,Left,Right'

	# Inline log in Clean tab (under buttons)
	$script:txtInlineLog = New-Object System.Windows.Forms.RichTextBox
	$script:txtInlineLog.Multiline = $true
	$script:txtInlineLog.ScrollBars = 'Vertical'
	$script:txtInlineLog.ReadOnly = $true
	$script:txtInlineLog.DetectUrls = $false
	$script:txtInlineLog.WordWrap = $true
	$script:txtInlineLog.Location = New-Object System.Drawing.Point(15,200)
	$script:txtInlineLog.Size = New-Object System.Drawing.Size(800,150)
	$script:txtInlineLog.Anchor = 'Top,Left,Right'

	$script:grpActions.Controls.AddRange(@($script:btnListDrives,$script:btnOpenLog,$script:btnClearLog,$script:btnScan,$script:btnClean,$script:btnCancel,$script:btnOpenExcl,$script:btnOpenQ,$script:btnRestoreQ,$script:btnExportCsv,$script:btnExportHtml,$script:btnManageQ,$script:lstDrives,$script:txtInlineLog))
	$script:btnClean.BringToFront()

	# Status and bottom panel
	$script:bottomPanel = New-Object System.Windows.Forms.Panel
	$script:bottomPanel.Location = New-Object System.Drawing.Point(10,520)
	$script:bottomPanel.Size = New-Object System.Drawing.Size(800,100)
	$script:bottomPanel.Anchor = 'Left,Right,Bottom'

	$script:lblStatus = New-Object System.Windows.Forms.Label
	$script:lblStatus.AutoSize = $true
	$script:lblStatus.Text = 'Ready'
	$script:lblStatus.Location = New-Object System.Drawing.Point(10,20)
	Enable-TextRenderingIfAvailable $script:lblStatus

	$script:progress = New-Object System.Windows.Forms.ProgressBar
	$script:progress.Location = New-Object System.Drawing.Point(70,24)
	$script:progress.Size = New-Object System.Drawing.Size(800,50)
	$script:progress.Style = 'Continuous'
	$script:progress.Visible = $false
	$script:progress.Anchor = 'Left,Right'

	$script:bottomPanel.Controls.AddRange(@($script:lblStatus,$script:progress))

	$tabClean.Controls.AddRange(@($script:grpOptions,$script:grpActions,$script:bottomPanel))
}
