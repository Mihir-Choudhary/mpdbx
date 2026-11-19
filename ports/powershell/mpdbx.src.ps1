<#
.SYNOPSIS
  mpdbx (PowerShell edition) - MpEngineDB Explorer in one .ps1 for stock Windows PowerShell 5.1. No install, no exe.

.DESCRIPTION
  Reads a COPY of Microsoft Defender's engine database (Scans\mpenginedb.db + mpenginedb.db-wal), decrypts it in memory,
  replays the WAL with SQLite semantics and shows the same Findings / Timeline / Files & processes / Evidence layout as
  mpdbx.exe. Same rules as mpdbx, so event counts match it for the DB and WAL (Scans\History Store/Results files are read
  only by mpdbx.exe). SQLite is Windows' own winsqlite3.dll; the engine is C# compiled at start by Add-Type.

  Evidence safety: inputs are opened read-only; decrypted images live in memory; exports never overwrite an input.
  Add-Type compiles the engine with the .NET compiler, which writes short-lived files under %TEMP% (analysis machine only).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\mpdbx.ps1
  powershell -ExecutionPolicy Bypass -File .\mpdbx.ps1 D:\case\Scans
  powershell -ExecutionPolicy Bypass -File .\mpdbx.ps1 D:\case\Scans -Export D:\case\out        (no GUI)
  powershell -ExecutionPolicy Bypass -File .\mpdbx.ps1 D:\case\Scans -Info                      (no GUI)
#>
param(
    [Parameter(Position = 0)][string]$Path,
    [string]$Export,
    [switch]$Info,
    [string]$Tz = 'Z',
    [ValidateSet('findings', 'timeline', 'files', 'evidence')][string]$Tab = 'findings'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$EngineSource = @'
#ENGINE#
'@
if (-not ('Mpdbx.Case' -as [type])) {
    if (-not [Environment]::Is64BitProcess -and -not (Test-Path "$env:WINDIR\System32\winsqlite3.dll")) { throw 'winsqlite3.dll not found (Windows 10 or later required)' }
    Add-Type -TypeDefinition $EngineSource -ReferencedAssemblies System.Core, System.Web.Extensions
}

function Open-MpCase([string]$p, [int]$tzMin) {
    if (-not (Test-Path -LiteralPath $p)) { throw "not found: $p" }
    $full = (Resolve-Path -LiteralPath $p).ProviderPath
    try { return New-Object Mpdbx.Case -ArgumentList $full, $tzMin }
    catch { if ($_.Exception.InnerException) { throw $_.Exception.InnerException.Message } else { throw } }
}

# ---------------------------------------------------------------- command-line modes
if ($Export -or $Info) {
    if (-not $Path) { [Console]::Error.WriteLine('mpdbx: give the Scans folder or mpenginedb.db path'); exit 2 }
    $tzv = [Mpdbx.Fmt]::ParseTz($Tz)
    if ($null -eq $tzv) { [Console]::Error.WriteLine('mpdbx: -Tz must be Z or +HH:MM / -HH:MM'); exit 2 }
    $code = 0
    try {
        $case = $null
        try { $case = Open-MpCase $Path $tzv } catch { [Console]::Error.WriteLine("mpdbx: $_"); $code = 3 }
        if ($case -and $Info) {
            $case.EvidenceText()
            'Events by type:'
            $case.Events | Group-Object { [Mpdbx.Case]::KindLabel[$_.Kind] } | Sort-Object Count -Descending | ForEach-Object { '  {0,-32}{1}' -f $_.Name, $_.Count }
        }
        if ($case -and $Export) {
            try { $n = $case.ExportAll($Export); "wrote $n files to $Export" }
            catch { [Console]::Error.WriteLine("mpdbx: $(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_ })"); $code = 5 }
        }
    }
    finally { [Mpdbx.Sql]::Cleanup() }
    exit $code
}

# ---------------------------------------------------------------- GUI
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
Add-Type -Namespace MpdbxWin -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr SendMessage(System.IntPtr h, int msg, System.IntPtr w, string l);
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr h, int attr, ref int v, int size);
'@ -ErrorAction SilentlyContinue

$Themes = @{
    dark  = @{ bg = '#0f1520'; panel = '#151c28'; raised = '#1b2433'; input = '#0b1018'; border = '#2a3445'; text = '#e6edf3'; muted = '#8b98a9'; accent = '#3b82f6'; accentWeak = '#1e3a5f'; flag = '#f87171'; walonly = '#3a2f12'; walmod = '#2b2440'; removed = '#3a1d2a'; sel = '#1e3a5f'; mono = '#cbd5e1' }
    light = @{ bg = '#f6f8fa'; panel = '#ffffff'; raised = '#ffffff'; input = '#ffffff'; border = '#d0d7de'; text = '#1f2328'; muted = '#57606a'; accent = '#0969da'; accentWeak = '#ddf4ff'; flag = '#cf222e'; walonly = '#fff3c4'; walmod = '#efe6ff'; removed = '#ffe3e8'; sel = '#ddf4ff'; mono = '#24292f' }
}
$script:theme = 'dark'
function C([string]$k) { [System.Drawing.ColorTranslator]::FromHtml($Themes[$script:theme][$k]) }

$FontBase = New-Object System.Drawing.Font('Segoe UI', 10)
$FontSmall = New-Object System.Drawing.Font('Segoe UI', 9)
$FontBold = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$FontH1 = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$FontH2 = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$FontBig = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$FontMono = New-Object System.Drawing.Font('Consolas', 9.5)

$script:case = $null
$script:tzMin = [Mpdbx.Fmt]::ParseTz($Tz); if ($null -eq $script:tzMin) { $script:tzMin = 0 }
$script:curTab = 'Findings'
$script:facets = New-Object Mpdbx.Facets
$script:listTitle = 'All activity'
$script:showRoutine = $false
$script:tlEvents = New-Object 'System.Collections.Generic.List[Mpdbx.Event]'
$script:tlRows = New-Object 'System.Collections.Generic.List[string[]]'
$script:tlOrder = @()
$script:vRows = New-Object 'System.Collections.Generic.List[string[]]'
$script:vStatus = @()
$script:vFlag = @()
$script:vOrder = @()
$script:cardHits = @()
$StatusTint = @{ 'WAL-only' = 'walonly'; 'WAL-modified' = 'walmod'; 'Removed by WAL' = 'removed' }

$form = New-Object System.Windows.Forms.Form
$form.Text = 'mpdbx - MpEngineDB Explorer (PowerShell)'
$form.Size = New-Object System.Drawing.Size(1400, 880)
$form.MinimumSize = New-Object System.Drawing.Size(820, 560)
$form.StartPosition = 'CenterScreen'
$form.Font = $FontBase
$form.KeyPreview = $true

function New-Flat([string]$text, [System.Drawing.Font]$font = $FontBase) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0; $b.AutoSize = $true; $b.Font = $font
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand; $b.Padding = New-Object System.Windows.Forms.Padding(8, 2, 8, 2)
    $b.Margin = New-Object System.Windows.Forms.Padding(0, 0, 4, 0)
    $b.UseMnemonic = $false
    return $b
}

function Set-DoubleBuffered($ctl) {
    $ctl.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'Instance,NonPublic').SetValue($ctl, $true, $null)
}

# ---- top bar
$top = New-Object System.Windows.Forms.Panel; $top.Dock = 'Top'; $top.Height = 48; $top.Padding = New-Object System.Windows.Forms.Padding(10, 9, 10, 6)
$topFlow = New-Object System.Windows.Forms.FlowLayoutPanel; $topFlow.Dock = 'Left'; $topFlow.AutoSize = $true; $topFlow.WrapContents = $false
$topRight = New-Object System.Windows.Forms.FlowLayoutPanel; $topRight.Dock = 'Right'; $topRight.AutoSize = $true; $topRight.WrapContents = $false; $topRight.FlowDirection = 'RightToLeft'
$top.Controls.AddRange(@($topFlow, $topRight))

$btnOpen = New-Flat 'Open  ▾' $FontBold
$menuOpen = New-Object System.Windows.Forms.ContextMenuStrip
[void]$menuOpen.Items.Add('Scans folder…', $null, { $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = 'Copied Defender Scans folder'; if ($d.ShowDialog($form) -eq 'OK') { Load-Case $d.SelectedPath } })
[void]$menuOpen.Items.Add('mpenginedb.db file…', $null, { $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Filter = 'Defender engine DB (*.db)|*.db|All files|*.*'; if ($d.ShowDialog($form) -eq 'OK') { Load-Case $d.FileName } })
$btnOpen.Add_Click({ $menuOpen.Show($btnOpen, 0, $btnOpen.Height) })
$lblCase = New-Object System.Windows.Forms.Label; $lblCase.AutoSize = $true; $lblCase.Font = $FontH2; $lblCase.Margin = New-Object System.Windows.Forms.Padding(10, 6, 14, 0)
$txtSearch = New-Object System.Windows.Forms.TextBox; $txtSearch.Width = 400; $txtSearch.BorderStyle = 'FixedSingle'; $txtSearch.Margin = New-Object System.Windows.Forms.Padding(0, 4, 4, 0)
$btnHelp = New-Flat '?' $FontBold
$menuHelp = New-Object System.Windows.Forms.ContextMenuStrip
$examples = @(
    @('rustc.exe', 'anything mentioning a name'), @('path:c:\users\*', 'events under a folder (wildcards * and ?)'), @('name:*.ps1', 'by file name'),
    @('sha256:4510b0', 'a hash or hash prefix'), @('type:no-cert', 'one event type (no-cert, process, originalfilename …)'), @('src:wal-only', 'rows that exist only in the WAL'),
    @('after:2026-10-19 before:2026-10-20', 'a time range (display time zone)'), @('-module', 'exclude something (minus sign)'), @('/mimi.*katz/', 'regular expression'))
foreach ($ex in $examples) {
    $q = $ex[0]
    $it = $menuHelp.Items.Add(('{0}      —  {1}' -f $ex[0], $ex[1]))
    $it.Add_Click({ $txtSearch.Text = $q; $txtSearch.Focus() }.GetNewClosure())
}
$btnHelp.Add_Click({ $menuHelp.Show($btnHelp, 0, $btnHelp.Height) })
$topFlow.Controls.AddRange(@($btnOpen, $lblCase, $txtSearch, $btnHelp))

$btnSettings = New-Flat 'Settings  ▾'
$menuSettings = New-Object System.Windows.Forms.ContextMenuStrip
[void]$menuSettings.Items.Add('Time zone…', $null, { Set-TimeZone })
$miTheme = $menuSettings.Items.Add('Light theme'); $miTheme.CheckOnClick = $true
$miTheme.Add_Click({ $script:theme = if ($miTheme.Checked) { 'light' } else { 'dark' }; Apply-Theme })
$btnSettings.Add_Click({ $menuSettings.Show($btnSettings, 0, $btnSettings.Height) })
$btnExport = New-Flat 'Export  ▾'
$menuExport = New-Object System.Windows.Forms.ContextMenuStrip
[void]$menuExport.Items.Add('This list as CSV…   (Ctrl+E)', $null, { Export-List })
[void]$menuExport.Items.Add('Everything (all views + raw tables, CSV)…', $null, { Export-Everything })
$btnExport.Add_Click({ $menuExport.Show($btnExport, 0, $btnExport.Height) })
$lblStatus = New-Object System.Windows.Forms.Label; $lblStatus.AutoSize = $true; $lblStatus.Margin = New-Object System.Windows.Forms.Padding(0, 7, 12, 0)
$topRight.Controls.AddRange(@($btnSettings, $btnExport, $lblStatus))

# ---- tab strip
$tabs = New-Object System.Windows.Forms.FlowLayoutPanel; $tabs.Dock = 'Top'; $tabs.Height = 38; $tabs.Padding = New-Object System.Windows.Forms.Padding(10, 2, 10, 4)
$tabButtons = [ordered]@{}
foreach ($n in 'Findings', 'Timeline', 'Files & processes', 'Evidence') {
    $b = New-Flat $n $FontBold
    $name = $n
    $b.Add_Click({ Set-Tab $name }.GetNewClosure())
    $tabs.Controls.Add($b); $tabButtons[$n] = $b
}
$sep = New-Object System.Windows.Forms.Panel; $sep.Dock = 'Top'; $sep.Height = 1
$body = New-Object System.Windows.Forms.Panel; $body.Dock = 'Fill'

# ---- pages
$pages = @{}
foreach ($n in 'Empty', 'Findings', 'Timeline', 'Files & processes', 'Evidence') { $p = New-Object System.Windows.Forms.Panel; $p.Dock = 'Fill'; $p.Visible = $false; $body.Controls.Add($p); $pages[$n] = $p }

# empty page
$emptyLbl = New-Object System.Windows.Forms.Label; $emptyLbl.Dock = 'Fill'; $emptyLbl.TextAlign = 'MiddleCenter'; $emptyLbl.Font = $FontH2
$emptyLbl.Text = "Open a copy of Defender's Scans folder`n`nOpen ▾ (top left) → Scans folder… or mpenginedb.db file…`n`nCopy the Scans folder (mpenginedb.db, mpenginedb.db-wal and History) out of ONE VSS shadow copy,`nso the DB and its WAL belong together; separate esentutl /vss calls take separate snapshots."
$pages['Empty'].Controls.Add($emptyLbl)

# findings page: one owner-drawn canvas inside a scrolling panel
$fScroll = New-Object System.Windows.Forms.Panel; $fScroll.Dock = 'Fill'; $fScroll.AutoScroll = $true
$fCanvas = New-Object System.Windows.Forms.Panel; $fCanvas.Location = New-Object System.Drawing.Point(0, 0)
Set-DoubleBuffered $fCanvas
$fScroll.Controls.Add($fCanvas); $pages['Findings'].Controls.Add($fScroll)
$script:hoverCard = -1

function Fit-Text([System.Drawing.Graphics]$g, [string]$s, [System.Drawing.Font]$f, [float]$w) {
    if ($g.MeasureString($s, $f).Width -le $w) { return $s }
    while ($s.Length -gt 1 -and $g.MeasureString($s + '…', $f).Width -gt $w) { $s = $s.Substring(0, $s.Length - 1) }
    return $s + '…'
}

$fCanvas.Add_Paint({
        param($s, $e)
        $g = $e.Graphics; $g.TextRenderingHint = 'ClearTypeGridFit'; $g.SmoothingMode = 'AntiAlias'
        $g.Clear((C 'bg'))
        if (-not $script:case) { return }
        $W = $fScroll.ClientSize.Width
        $width = [Math]::Min($W - 32, 1320); $x0 = [int](($W - $width) / 2); $y = 18
        $txt = New-Object System.Drawing.SolidBrush (C 'text'); $mut = New-Object System.Drawing.SolidBrush (C 'muted')
        $g.DrawString('What stands out in this database', $FontH1, $txt, $x0, $y); $y += 36
        $g.DrawString('Click a card to see exactly those events.', $FontBase, $mut, $x0, $y); $y += 34
        $cards = $script:case.Findings()
        $hits = @($cards | Where-Object { $_.Level -eq 'flag' -and $_.Ids.Count -gt 0 })
        $clear = @($cards | Where-Object { $_.Level -eq 'flag' -and $_.Ids.Count -eq 0 })
        $info = @($cards | Where-Object { $_.Level -eq 'info' })
        $gap = 10; $H = 112; $ncol = [Math]::Max(1, [Math]::Min(3, [int][Math]::Floor(($width + $gap) / (300 + $gap))))
        $cw = [int](($width - $gap * ($ncol - 1)) / $ncol)
        $script:cardHits = @()
        $sections = @(@(($(if ($hits.Count) { 'Needs attention' } else { 'Needs attention: nothing flagged' })), 'flag', $hits), @('Overview', 'text', $info))
        foreach ($sec in $sections) {
            $hb = New-Object System.Drawing.SolidBrush (C $sec[1])
            $g.DrawString($sec[0], $FontH2, $hb, $x0, $y); $y += 28
            $i = 0
            foreach ($k in $sec[2]) {
                $col = $i % $ncol; $row = [Math]::Floor($i / $ncol)
                $cx = $x0 + $col * ($cw + $gap); $cy = $y + $row * ($H + $gap)
                $rect = New-Object System.Drawing.Rectangle($cx, $cy, $cw, $H)
                $idx = $script:cardHits.Count
                $acc = if ($k.Level -eq 'flag') { C 'flag' } else { C 'accent' }
                $fill = if ($script:hoverCard -eq $idx) { C 'input' } else { C 'raised' }
                $g.FillRectangle((New-Object System.Drawing.SolidBrush $fill), $rect)
                $pen = New-Object System.Drawing.Pen ($(if ($k.Level -eq 'flag' -or $script:hoverCard -eq $idx) { $acc } else { C 'border' }))
                $g.DrawRectangle($pen, $cx, $cy, $cw - 1, $H - 1)
                $g.FillRectangle((New-Object System.Drawing.SolidBrush $acc), $cx, $cy, 4, $H)
                $ab = New-Object System.Drawing.SolidBrush $acc
                $cnt = [string]$k.Ids.Count
                $g.DrawString($cnt, $FontBig, $ab, $cx + 14, $cy + 8)
                $cwid = $g.MeasureString($cnt, $FontBig).Width
                $g.DrawString((Fit-Text $g $k.Title $FontH2 ($cw - $cwid - 40)), $FontH2, $txt, $cx + 18 + $cwid, $cy + 15)
                $g.DrawString($k.Explain, $FontSmall, $mut, (New-Object System.Drawing.RectangleF(($cx + 16), ($cy + 48), ($cw - 30), 36)))
                if ($k.Examples.Count) { $g.DrawString((Fit-Text $g ('e.g. ' + ($k.Examples -join ' · ')) $FontMono ($cw - 30)), $FontMono, (New-Object System.Drawing.SolidBrush (C 'mono')), $cx + 16, $cy + $H - 24) }
                $script:cardHits += , @($rect, $k)
                $i++
            }
            $rows = [Math]::Ceiling($sec[2].Count / $ncol)
            $y += $rows * ($H + $gap) + 6
            if ($sec[1] -eq 'flag' -and $clear.Count) {
                $g.DrawString(('✓ Checked, nothing found:   ' + (($clear | ForEach-Object { $_.Title }) -join '   ·   ')), $FontBase, $mut, $x0, $y); $y += 34
            }
        }
        $need = $y + 20
        if ($fCanvas.Height -ne $need -or $fCanvas.Width -ne $W) { $fCanvas.Size = New-Object System.Drawing.Size($W, $need) }
    })
$fCanvas.Add_MouseMove({
        param($s, $e)
        $hit = -1
        for ($i = 0; $i -lt $script:cardHits.Count; $i++) { if ($script:cardHits[$i][0].Contains($e.Location)) { $hit = $i; break } }
        $fCanvas.Cursor = if ($hit -ge 0) { [System.Windows.Forms.Cursors]::Hand } else { [System.Windows.Forms.Cursors]::Default }
        if ($hit -ne $script:hoverCard) { $script:hoverCard = $hit; $fCanvas.Invalidate() }
    })
$fCanvas.Add_MouseClick({
        param($s, $e)
        foreach ($h in $script:cardHits) {
            if ($h[0].Contains($e.Location)) {
                $f = New-Object Mpdbx.Facets; $f.Only = $h[1].Ids
                Open-List $h[1].Title $f -ClearSearch; return
            }
        }
    })
$fScroll.Add_Resize({ $fCanvas.Width = $fScroll.ClientSize.Width; $fCanvas.Invalidate() })

# timeline page
$tlLeft = New-Object System.Windows.Forms.FlowLayoutPanel; $tlLeft.Dock = 'Left'; $tlLeft.Width = 236; $tlLeft.FlowDirection = 'TopDown'; $tlLeft.WrapContents = $false; $tlLeft.AutoScroll = $true
$tlLeft.Padding = New-Object System.Windows.Forms.Padding(8, 10, 8, 8)
$lblQuick = New-Object System.Windows.Forms.Label; $lblQuick.Text = 'Quick views'; $lblQuick.Font = $FontH2; $lblQuick.AutoSize = $true; $lblQuick.Margin = New-Object System.Windows.Forms.Padding(2, 0, 0, 6)
$tlLeft.Controls.Add($lblQuick)
$quickButtons = @{}
foreach ($qv in [Mpdbx.Case]::QuickViews()) {
    $b = New-Flat $qv.Key; $b.AutoSize = $false; $b.Width = 214; $b.Height = 30; $b.TextAlign = 'MiddleLeft'
    $title = $qv.Key; $fac = $qv.Value
    $b.Add_Click({ Open-List $title $fac.Clone() }.GetNewClosure())
    $tlLeft.Controls.Add($b); $quickButtons[$qv.Key] = $b
}
$chkRoutine = New-Object System.Windows.Forms.CheckBox; $chkRoutine.Text = 'Show routine events'; $chkRoutine.AutoSize = $true; $chkRoutine.Margin = New-Object System.Windows.Forms.Padding(4, 12, 0, 0)
$chkRoutine.Add_CheckedChanged({ $script:showRoutine = $chkRoutine.Checked; Refresh-Timeline })
$lblRoutine = New-Object System.Windows.Forms.Label; $lblRoutine.Text = 'module loads, file hashes, cache expiries…'; $lblRoutine.Font = $FontSmall; $lblRoutine.AutoSize = $true; $lblRoutine.Margin = New-Object System.Windows.Forms.Padding(20, 0, 0, 6)
$btnMore = New-Flat '▸  More filters'; $btnMore.AutoSize = $false; $btnMore.Width = 214; $btnMore.Height = 30; $btnMore.TextAlign = 'MiddleLeft'
$moreList = New-Object System.Windows.Forms.CheckedListBox; $moreList.Width = 214; $moreList.Height = 380; $moreList.CheckOnClick = $true; $moreList.BorderStyle = 'None'; $moreList.Visible = $false
$moreItems = @()
$moreItems += , @('flag', 'Flagged only (▲)', $false)
foreach ($k in [Mpdbx.Case]::KindLabel.Keys) { $moreItems += , @('kind', $k, $true) }
foreach ($s in 'DB', 'WAL-only', 'WAL-modified', 'Removed by WAL', 'unknown') { $moreItems += , @('status', $s, $true) }
foreach ($s in 'outside system dirs', 'system dir', 'unknown') { $moreItems += , @('cls', $s, $true) }
foreach ($m in $moreItems) {
    $label = switch ($m[0]) { 'kind' { 'Type: ' + [Mpdbx.Case]::KindLabel[$m[1]] } 'status' { 'Source: ' + $m[1] } 'cls' { 'Location: ' + $m[1] } default { $m[1] } }
    [void]$moreList.Items.Add($label, $m[2])
}
$script:suppressMore = $false
$moreList.Add_ItemCheck({
        if ($script:suppressMore) { return }
        $form.BeginInvoke([Action] { Apply-MoreFilters }) | Out-Null
    })
$btnMore.Add_Click({ $moreList.Visible = -not $moreList.Visible; $btnMore.Text = $(if ($moreList.Visible) { '▾  More filters' } else { '▸  More filters' }) })
$tlLeft.Controls.AddRange(@($chkRoutine, $lblRoutine, $btnMore, $moreList))

$tlMain = New-Object System.Windows.Forms.Panel; $tlMain.Dock = 'Fill'; $tlMain.Padding = New-Object System.Windows.Forms.Padding(10, 8, 6, 6)
$hist = New-Object System.Windows.Forms.Panel; $hist.Dock = 'Top'; $hist.Height = 70; Set-DoubleBuffered $hist
$tlHead = New-Object System.Windows.Forms.FlowLayoutPanel; $tlHead.Dock = 'Top'; $tlHead.Height = 34; $tlHead.WrapContents = $false
$lblTlTitle = New-Object System.Windows.Forms.Label; $lblTlTitle.AutoSize = $true; $lblTlTitle.Font = $FontH2; $lblTlTitle.Margin = New-Object System.Windows.Forms.Padding(0, 6, 6, 0)
$lblTlCount = New-Object System.Windows.Forms.Label; $lblTlCount.AutoSize = $true; $lblTlCount.Margin = New-Object System.Windows.Forms.Padding(0, 8, 10, 0)
$btnAll = New-Flat 'Show all activity'; $btnAll.Add_Click({ Open-List 'All activity' (New-Object Mpdbx.Facets) })
$lblTlErr = New-Object System.Windows.Forms.Label; $lblTlErr.AutoSize = $true; $lblTlErr.Margin = New-Object System.Windows.Forms.Padding(6, 8, 0, 0)
$tlHead.Controls.AddRange(@($lblTlTitle, $lblTlCount, $btnAll, $lblTlErr))
$split = New-Object System.Windows.Forms.SplitContainer; $split.Dock = 'Fill'; $split.Panel2Collapsed = $true; $split.SplitterWidth = 6

function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'; $g.ReadOnly = $true; $g.AllowUserToAddRows = $false; $g.AllowUserToDeleteRows = $false; $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false; $g.SelectionMode = 'FullRowSelect'; $g.MultiSelect = $false; $g.BorderStyle = 'None'; $g.VirtualMode = $true
    $g.EnableHeadersVisualStyles = $false; $g.ColumnHeadersHeightSizeMode = 'DisableResizing'; $g.ColumnHeadersHeight = 30
    $g.RowTemplate.Height = 23; $g.CellBorderStyle = 'None'; $g.AutoGenerateColumns = $false
    Set-DoubleBuffered $g
    return $g
}
$grid = New-Grid
$TlCols = @(@('Time', 235), @('What', 165), @('Name', 190), @('Details', 280), @('Path', 380), @('Source', 100))
foreach ($c in $TlCols) { $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $col.HeaderText = $c[0]; $col.Width = $c[1]; $col.SortMode = 'Programmatic'; [void]$grid.Columns.Add($col) }
$grid.Add_CellValueNeeded({
        param($s, $e)
        if ($e.RowIndex -lt $script:tlOrder.Count) { $e.Value = $script:tlRows[$script:tlOrder[$e.RowIndex]][$e.ColumnIndex] }
    })
$grid.Add_CellFormatting({
        param($s, $e)
        if ($e.RowIndex -ge $script:tlOrder.Count) { return }
        $ev = $script:tlEvents[$script:tlOrder[$e.RowIndex]]
        $t = $StatusTint[$ev.Status]
        if ($t) { $e.CellStyle.BackColor = C $t }
        if ($ev.Flag) { $e.CellStyle.ForeColor = C 'flag' }
        if ($e.ColumnIndex -eq 0 -or $e.ColumnIndex -eq 4) { $e.CellStyle.Font = $FontMono }
    })
$script:tlSort = @(0, $false)
$grid.Add_ColumnHeaderMouseClick({
        param($s, $e)
        $desc = ($script:tlSort[0] -eq $e.ColumnIndex) -and -not $script:tlSort[1]
        $script:tlSort = @($e.ColumnIndex, $desc)
        $selId = $null
        if ($grid.SelectedRows.Count -and $grid.SelectedRows[0].Index -lt $script:tlOrder.Count) { $selId = $script:tlEvents[$script:tlOrder[$grid.SelectedRows[0].Index]].Id }
        if ($e.ColumnIndex -eq 0) { $script:tlOrder = [Mpdbx.Ui]::OrderByTime($script:tlEvents, $desc) }
        else { $script:tlOrder = [Mpdbx.Ui]::Order($script:tlRows, $e.ColumnIndex, $desc) }
        if ($null -ne $selId) {
            for ($i = 0; $i -lt $script:tlOrder.Count; $i++) {
                if ($script:tlEvents[$script:tlOrder[$i]].Id -eq $selId) { $grid.CurrentCell = $grid.Rows[$i].Cells[0]; $grid.Rows[$i].Selected = $true; break }
            }
        }
        foreach ($c in $grid.Columns) { $c.HeaderCell.SortGlyphDirection = 'None' }
        $grid.Columns[$e.ColumnIndex].HeaderCell.SortGlyphDirection = $(if ($desc) { 'Descending' } else { 'Ascending' })
        $grid.Invalidate()
    })
$grid.Add_SelectionChanged({
        if ($grid.SelectedRows.Count -and $grid.SelectedRows[0].Index -lt $script:tlOrder.Count) { Show-Detail $script:tlEvents[$script:tlOrder[$grid.SelectedRows[0].Index]] }
    })
$detail = New-Object System.Windows.Forms.RichTextBox; $detail.Dock = 'Fill'; $detail.ReadOnly = $true; $detail.BorderStyle = 'None'; $detail.DetectUrls = $false
$split.Panel1.Controls.Add($grid); $split.Panel2.Controls.Add($detail)
$tlMain.Controls.AddRange(@($split, $tlHead, $hist))
$pages['Timeline'].Controls.AddRange(@($tlMain, $tlLeft))

$hist.Add_Paint({
        param($s, $e)
        $g = $e.Graphics; $g.Clear((C 'bg'))
        if ($script:tlEvents.Count -eq 0) { return }
        $W = $hist.ClientSize.Width; $n = [Math]::Max(10, [Math]::Min(240, [int]($W / 6)))
        $lo = 0L; $hi = 0L
        $counts = [Mpdbx.Ui]::Histogram($script:tlEvents, $n, [ref]$lo, [ref]$hi)
        $mx = ($counts | Measure-Object -Maximum).Maximum
        if (-not $mx) { return }
        $bw = $W / $n; $br = New-Object System.Drawing.SolidBrush (C 'accent')
        for ($i = 0; $i -lt $n; $i++) { if ($counts[$i]) { $h = [Math]::Max(2, 46 * $counts[$i] / $mx); $g.FillRectangle($br, [float]($i * $bw + 1), [float](48 - $h), [float]([Math]::Max(1, $bw - 2)), [float]$h) } }
        $mb = New-Object System.Drawing.SolidBrush (C 'muted')
        $g.DrawString([Mpdbx.Fmt]::Ft($lo, $script:tzMin).Substring(0, 16), $FontSmall, $mb, 0, 52)
        $hs = [Mpdbx.Fmt]::Ft($hi, $script:tzMin).Substring(0, 16)
        $g.DrawString($hs, $FontSmall, $mb, $W - $g.MeasureString($hs, $FontSmall).Width, 52)
    })
$hist.Add_Resize({ $hist.Invalidate() })

# files & processes page
$vList = New-Object System.Windows.Forms.ListBox; $vList.Dock = 'Left'; $vList.Width = 260; $vList.BorderStyle = 'None'; $vList.IntegralHeight = $false; $vList.DrawMode = 'OwnerDrawFixed'; $vList.ItemHeight = 22
$vMain = New-Object System.Windows.Forms.Panel; $vMain.Dock = 'Fill'; $vMain.Padding = New-Object System.Windows.Forms.Padding(10, 8, 6, 6)
$lblView = New-Object System.Windows.Forms.Label; $lblView.Dock = 'Top'; $lblView.Height = 30; $lblView.Font = $FontH2
$vGrid = New-Grid
$vMain.Controls.AddRange(@($vGrid, $lblView))
$pages['Files & processes'].Controls.AddRange(@($vMain, $vList))
$script:vEntries = @()
$vList.Add_DrawItem({
        param($s, $e)
        if ($e.Index -lt 0) { return }
        $ent = $script:vEntries[$e.Index]
        $selected = ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0
        $e.Graphics.FillRectangle((New-Object System.Drawing.SolidBrush ($(if ($selected -and $ent[0]) { C 'sel' } else { C 'panel' }))), $e.Bounds)
        $font = if ($ent[0]) { $FontBase } else { $FontBold }
        $color = if ($ent[0]) { C 'text' } else { C 'muted' }
        $e.Graphics.DrawString($ent[2], $font, (New-Object System.Drawing.SolidBrush $color), $e.Bounds.X + 6, $e.Bounds.Y + 2)
    })
$vList.Add_SelectedIndexChanged({ if ($vList.SelectedIndex -ge 0 -and $script:vEntries[$vList.SelectedIndex][0]) { Show-View $script:vEntries[$vList.SelectedIndex] } })
$vGrid.Add_CellValueNeeded({ param($s, $e) if ($e.RowIndex -lt $script:vOrder.Count) { $e.Value = $script:vRows[$script:vOrder[$e.RowIndex]][$e.ColumnIndex] } })
$vGrid.Add_CellFormatting({
        param($s, $e)
        if ($e.RowIndex -ge $script:vOrder.Count) { return }
        $i = $script:vOrder[$e.RowIndex]
        $t = $StatusTint[$script:vStatus[$i]]
        if ($t) { $e.CellStyle.BackColor = C $t }
        if ($script:vFlag[$i]) { $e.CellStyle.ForeColor = C 'flag' }
    })
$script:vSort = @(-1, $false)
$vGrid.Add_ColumnHeaderMouseClick({
        param($s, $e)
        $desc = ($script:vSort[0] -eq $e.ColumnIndex) -and -not $script:vSort[1]
        $script:vSort = @($e.ColumnIndex, $desc)
        $sub = New-Object 'System.Collections.Generic.List[string[]]'
        foreach ($i in $script:vOrder) { $sub.Add($script:vRows[$i]) }
        $perm = [Mpdbx.Ui]::Order($sub, $e.ColumnIndex, $desc)
        $script:vOrder = @($perm | ForEach-Object { $script:vOrder[$_] })
        foreach ($c in $vGrid.Columns) { $c.HeaderCell.SortGlyphDirection = 'None' }
        $vGrid.Columns[$e.ColumnIndex].HeaderCell.SortGlyphDirection = $(if ($desc) { 'Descending' } else { 'Ascending' })
        $vGrid.Invalidate()
    })

# evidence page
$evText = New-Object System.Windows.Forms.TextBox; $evText.Dock = 'Fill'; $evText.Multiline = $true; $evText.ReadOnly = $true; $evText.ScrollBars = 'Both'; $evText.WordWrap = $false
$evText.Font = $FontMono; $evText.BorderStyle = 'None'
$pages['Evidence'].Controls.Add($evText)

$form.Controls.AddRange(@($body, $sep, $tabs, $top))

# ---------------------------------------------------------------- behaviour
function Apply-Theme {
    $form.BackColor = C 'bg'; $form.ForeColor = C 'text'
    foreach ($c in @($top, $topFlow, $topRight, $tabs, $body, $tlMain, $tlHead, $hist, $vMain, $fScroll, $fCanvas, $split, $split.Panel1, $split.Panel2) + @($pages.Values)) { $c.BackColor = C 'bg'; $c.ForeColor = C 'text' }
    $sep.BackColor = C 'border'
    foreach ($c in @($tlLeft, $vList, $moreList, $detail)) { $c.BackColor = C 'panel'; $c.ForeColor = C 'text' }
    $evText.BackColor = C 'panel'; $evText.ForeColor = C 'text'
    $txtSearch.BackColor = C 'input'; $txtSearch.ForeColor = C 'text'
    foreach ($l in @($lblStatus, $lblTlCount, $lblRoutine, $emptyLbl)) { $l.ForeColor = C 'muted' }
    $lblTlErr.ForeColor = C 'flag'
    foreach ($b in @($btnOpen, $btnHelp, $btnSettings, $btnExport, $btnAll)) { $b.BackColor = C 'raised'; $b.ForeColor = C 'text'; $b.FlatAppearance.MouseOverBackColor = C 'accentWeak' }
    foreach ($b in @($tabButtons.Values) + @($quickButtons.Values) + @($btnMore)) { $b.FlatAppearance.MouseOverBackColor = C 'raised'; $b.ForeColor = C 'text' }
    foreach ($g in @($grid, $vGrid)) {
        $g.BackgroundColor = C 'panel'; $g.GridColor = C 'border'
        $g.DefaultCellStyle.BackColor = C 'panel'; $g.DefaultCellStyle.ForeColor = C 'text'; $g.DefaultCellStyle.SelectionBackColor = C 'sel'; $g.DefaultCellStyle.SelectionForeColor = C 'text'
        $g.ColumnHeadersDefaultCellStyle.BackColor = C 'raised'; $g.ColumnHeadersDefaultCellStyle.ForeColor = C 'text'; $g.ColumnHeadersDefaultCellStyle.Font = $FontBold
        $g.ColumnHeadersDefaultCellStyle.SelectionBackColor = C 'raised'
    }
    try { $v = [int]($script:theme -eq 'dark'); [void][MpdbxWin.Native]::DwmSetWindowAttribute($form.Handle, 20, [ref]$v, 4) } catch {}
    Update-Highlights
    $form.Refresh()
}

function Update-Highlights {
    foreach ($n in $tabButtons.Keys) { $tabButtons[$n].BackColor = $(if ($n -eq $script:curTab) { C 'accentWeak' } else { C 'bg' }) }
    foreach ($n in $quickButtons.Keys) { $quickButtons[$n].BackColor = $(if ($n -eq $script:listTitle) { C 'accentWeak' } else { C 'panel' }) }
    $btnMore.BackColor = C 'panel'
}

function Set-Tab([string]$n) {
    if (-not $script:case -and $n -ne 'Findings') { return }
    $script:curTab = $n
    foreach ($p in $pages.Values) { $p.Visible = $false }
    if (-not $script:case) { $pages['Empty'].Visible = $true } else { $pages[$n].Visible = $true; $pages[$n].BringToFront() }
    if ($n -eq 'Findings') { $fCanvas.Width = $fScroll.ClientSize.Width; $fCanvas.Invalidate() }
    Update-Highlights
    if ($script:case -and $n -eq 'Timeline') { Refresh-Timeline }
    if ($script:case -and $n -eq 'Files & processes' -and $vList.SelectedIndex -ge 0 -and $script:vEntries[$vList.SelectedIndex][0]) { Show-View $script:vEntries[$vList.SelectedIndex] }
}

function Reset-FilterControls {
    $script:suppressMore = $true
    for ($i = 0; $i -lt $moreItems.Count; $i++) { $moreList.SetItemChecked($i, $moreItems[$i][0] -ne 'flag') }
    $script:suppressMore = $false
}

function Open-List([string]$title, $facets, [switch]$ClearSearch) {
    $script:listTitle = $title; $script:facets = $facets
    Reset-FilterControls
    if ($ClearSearch -and $txtSearch.Text) { $txtSearch.Text = ''; $searchTimer.Stop() }
    if ($script:curTab -eq 'Timeline') { Refresh-Timeline } else { Set-Tab 'Timeline' }
}

function Apply-MoreFilters {
    $f = New-Object Mpdbx.Facets
    $kinds = New-Object 'System.Collections.Generic.HashSet[string]'; $stat = New-Object 'System.Collections.Generic.HashSet[string]'; $cls = New-Object 'System.Collections.Generic.HashSet[string]'
    $nk = 0; $ns = 0; $nc = 0
    for ($i = 0; $i -lt $moreItems.Count; $i++) {
        $on = $moreList.GetItemChecked($i); $m = $moreItems[$i]
        switch ($m[0]) {
            'flag' { $f.Flagged = $on }
            'kind' { $nk++; if ($on) { [void]$kinds.Add($m[1]) } }
            'status' { $ns++; if ($on) { [void]$stat.Add($m[1]) } }
            'cls' { $nc++; if ($on) { [void]$cls.Add($m[1]) } }
        }
    }
    if ($kinds.Count -ne $nk) { $f.Kinds = $kinds }
    if ($stat.Count -ne $ns) { $f.Status = $stat }
    if ($cls.Count -ne $nc) { $f.Cls = $cls }
    $script:facets = $f; $script:listTitle = 'Custom filter'
    Refresh-Timeline
}

function Get-SearchText { $t = $txtSearch.Text; return $t }

function Refresh-Timeline {
    if (-not $script:case) { return }
    try { $terms = $script:case.ParseSearch((Get-SearchText)); $lblTlErr.Text = '' }
    catch { $lblTlErr.Text = 'search: ' + $(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }); return }
    $evs = $script:case.Apply($script:facets, $terms, $script:showRoutine)
    $script:tlEvents = $evs
    $rows = New-Object 'System.Collections.Generic.List[string[]]'
    foreach ($e in $evs) {
        $p = $script:case.PathOf($e)
        $t0 = $(if ($e.Flag) { '▲ ' } else { '' }) + $script:case.TimeStr($e.Time)
        $rows.Add([string[]]@($t0, [Mpdbx.Case]::KindLabel[$e.Kind], [Mpdbx.Fmt]::Leaf($p), $script:case.Details($e), $p, $e.Status))
    }
    $script:tlRows = $rows
    $script:tlOrder = @(0..([Math]::Max(0, $rows.Count - 1)))
    if ($rows.Count -eq 0) { $script:tlOrder = @() }
    $script:tlSort = @(0, $false)
    foreach ($c in $grid.Columns) { $c.HeaderCell.SortGlyphDirection = 'None' }
    $grid.RowCount = 0; $grid.RowCount = $rows.Count
    $grid.ClearSelection()
    $split.Panel2Collapsed = $true
    $lblTlTitle.Text = $script:listTitle
    $lblTlCount.Text = "$($rows.Count) events"
    $btnAll.Visible = $script:listTitle -ne 'All activity'
    Update-Highlights
    $hist.Invalidate(); $grid.Invalidate()
}

function Add-Rtf([string]$text, $font = $FontBase, $color = $null) {
    $detail.SelectionStart = $detail.TextLength; $detail.SelectionLength = 0
    $detail.SelectionFont = $font; $detail.SelectionColor = $(if ($color) { $color } else { C 'text' })
    $detail.AppendText($text)
}

function Show-Detail([Mpdbx.Event]$e) {
    $c = $script:case
    if ($split.Panel2Collapsed) { $split.Panel2Collapsed = $false; $split.SplitterDistance = [Math]::Max(300, $split.Width - 420) }
    $detail.SuspendLayout(); $detail.Clear()
    Add-Rtf ([Mpdbx.Case]::KindLabel[$e.Kind] + "`n") $FontH2
    if ($e.Flag) { Add-Rtf "▲ red flag`n" $FontBold (C 'flag') }
    Add-Rtf ($e.Summary + "`n`n")
    Add-Rtf 'Time  ' $FontBase (C 'muted'); Add-Rtf ($c.TimeStr($e.Time) + "`n") $FontMono (C 'mono')
    if ($e.Loc -ge 0) { Add-Rtf 'Location  ' $FontBase (C 'muted'); Add-Rtf ($c.Cls($e.Loc) + "`n") }
    Add-Rtf "`nFields`n" $FontH2
    foreach ($f in $e.Fields) {
        Add-Rtf ($f.Name + "`n") $FontSmall (C 'muted')
        Add-Rtf ('  ' + $f.Display + "`n") $FontMono (C 'mono')
        if ($f.Raw -and $f.Raw -ne $f.Display) { Add-Rtf ('  raw: ' + $f.Raw + "`n") $FontSmall (C 'muted') }
    }
    Add-Rtf "`nWhere it came from`n" $FontH2
    Add-Rtf ($e.Table + '  ' + $c.KeyLabel($e.Key) + '  —  ' + $e.Status + "`n")
    if ($e.Old -and $e.Status -eq 'WAL-modified') {
        Add-Rtf "Values before the WAL:`n" $FontSmall (C 'muted')
        $cols = $c.Tables[$e.Table].Columns
        for ($i = 0; $i -lt $cols.Count -and $i -lt $e.Old.Count; $i++) { Add-Rtf ('  ' + $cols[$i] + ' = ' + [Mpdbx.Fmt]::Raw($e.Old[$i]) + "`n") $FontMono (C 'mono') }
    }
    if ($e.Loc -ge 0) {
        $others = @($c.Locations[$e.Loc].Events | Where-Object { $_ -ne $e.Id } | ForEach-Object { $c.Events[$_] })
        if ($others.Count) {
            Add-Rtf ("`nSame file (" + $others.Count + " other records)`n") $FontH2
            foreach ($o in ([Mpdbx.Case]::Sorted([Mpdbx.Event[]]$others) | Select-Object -First 40)) {
                Add-Rtf ($c.TimeStr($o.Time) + '  ') $FontMono (C 'mono'); Add-Rtf ([Mpdbx.Case]::KindLabel[$o.Kind] + "`n")
            }
        }
    }
    $detail.SelectionStart = 0; $detail.ScrollToCaret(); $detail.ResumeLayout()
}

function Fill-Views {
    $script:viewDefs = @{}
    $entries = @()
    foreach ($v in $script:case.Views()) { $script:viewDefs[$v.Name] = $v; $entries += , @('view', $v.Name, ('{0}  ({1})' -f $v.Name, $v.Rows.Count)) }
    $entries += , @($null, $null, ''); $entries += , @($null, $null, 'Raw tables')
    foreach ($t in ($script:case.Tables.Keys | Sort-Object)) { $entries += , @('raw', $t, ('   {0}  ({1})' -f $t, $script:case.Tables[$t].Rows.Count)) }
    $script:vEntries = $entries
    $vList.Items.Clear()
    foreach ($en in $entries) { [void]$vList.Items.Add($en[2]) }
    $vList.SelectedIndex = 1
}

function Show-View($entry) {
    $kind = $entry[0]; $name = $entry[1]
    if ($kind -eq 'view') {
        $v = $script:viewDefs[$name]
        if ($v.Events) { $script:vStatus = @($v.Events | ForEach-Object { $_.Status }); $script:vFlag = @($v.Events | ForEach-Object { $_.Flag }) }
        else { $script:vStatus = @($v.Rows | ForEach-Object { $_[-1] }); $script:vFlag = @($v.Rows | ForEach-Object { $false }) }
    }
    else {
        $v = $script:case.RawView($name)
        $script:vStatus = @($v.Rows | ForEach-Object { $_[-1] }); $script:vFlag = @($v.Rows | ForEach-Object { $false })
    }
    $script:vRows = $v.Rows; $script:vCols = $v.Columns
    $script:vOrder = @($script:case.FilterView($v, (Get-SearchText)))
    $lblView.Text = '{0}     {1} of {2} rows' -f $name, $script:vOrder.Count, $v.Rows.Count
    $vGrid.RowCount = 0; $vGrid.Columns.Clear()
    for ($i = 0; $i -lt $v.Columns.Count; $i++) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $col.HeaderText = $v.Columns[$i]; $col.SortMode = 'Programmatic'
        $sample = $v.Columns[$i].Length
        foreach ($r in ($v.Rows | Select-Object -First 200)) { if ($r[$i] -and $r[$i].Length -gt $sample) { $sample = $r[$i].Length } }
        $col.Width = [Math]::Min(420, [Math]::Max(80, $sample * 7 + 18))
        [void]$vGrid.Columns.Add($col)
    }
    $script:vSort = @(-1, $false)
    $vGrid.RowCount = $script:vOrder.Count
    $vGrid.Invalidate()
}

function Load-Case([string]$p) {
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $lblStatus.Text = 'loading…'; $form.Refresh()
    try { $c = Open-MpCase $p $script:tzMin }
    catch {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default; $lblStatus.Text = ''
        [void][System.Windows.Forms.MessageBox]::Show($form, "Could not open:`n$_", 'mpdbx', 'OK', 'Error'); return
    }
    $script:case = $c
    $lblCase.Text = Split-Path (Split-Path $c.Inputs[0][0] -Parent) -Leaf
    $lblStatus.Text = '{0} events · {1} WAL frames applied' -f $c.Events.Count, $c.Img.Wal.FramesApplied
    $evText.Text = $c.EvidenceText() -replace "`r?`n", "`r`n"
    $script:listTitle = 'All activity'; $script:facets = New-Object Mpdbx.Facets
    Reset-FilterControls
    Fill-Views
    Refresh-Timeline
    Set-Tab $(switch ($Tab) { 'timeline' { 'Timeline' } 'files' { 'Files & processes' } 'evidence' { 'Evidence' } default { 'Findings' } })
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
}

# The list on screen: the Files & processes grid when that tab is shown, otherwise the Timeline. A search still waiting
# for its debounce is applied first, so the export never holds stale rows.
function Export-List {
    if (-not $script:case) { return }
    $pending = $searchTimer.Enabled; $searchTimer.Stop()
    $onView = $script:curTab -eq 'Files & processes' -and $script:vCols -and $vList.SelectedIndex -ge 0
    # re-filter only when needed: a fresh refresh would also drop the order the analyst sorted the grid into
    if ($onView) { if ($pending) { Show-View $script:vEntries[$vList.SelectedIndex] } }
    elseif ($pending -or $script:curTab -ne 'Timeline') { Refresh-Timeline }
    $d = New-Object System.Windows.Forms.SaveFileDialog; $d.Filter = 'CSV (*.csv)|*.csv'; $d.FileName = $(if ($onView) { 'mpdbx-view.csv' } else { 'mpdbx-timeline.csv' })
    if ($d.ShowDialog($form) -ne 'OK') { return }
    try {
        if ($onView) {
            $rows = New-Object 'System.Collections.Generic.List[string[]]'
            foreach ($i in $script:vOrder) { $rows.Add($script:vRows[$i]) }
            $script:case.WriteCsv($d.FileName, [string[]]$script:vCols, $rows)
            $lblStatus.Text = "wrote $($rows.Count) rows to $($d.FileName)"
        }
        else {
            $ordered = @($script:tlOrder | ForEach-Object { $script:tlEvents[$_] })
            $script:case.WriteCsv($d.FileName, [Mpdbx.Case]::TimelineCols, $script:case.TimelineRows([Mpdbx.Event[]]$ordered))
            $lblStatus.Text = "wrote $($ordered.Count) rows to $($d.FileName)"
        }
    }
    catch { [void][System.Windows.Forms.MessageBox]::Show($form, "$_", 'mpdbx', 'OK', 'Error') }
}

function Export-Everything {
    if (-not $script:case) { return }
    $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = 'Folder for the CSV files'
    if ($d.ShowDialog($form) -ne 'OK') { return }
    try { $n = $script:case.ExportAll($d.SelectedPath); $lblStatus.Text = "wrote $n files to $($d.SelectedPath)" }
    catch { [void][System.Windows.Forms.MessageBox]::Show($form, "$_", 'mpdbx', 'OK', 'Error') }
}

function Set-TimeZone {
    $f = New-Object System.Windows.Forms.Form; $f.Text = 'Time zone'; $f.Size = New-Object System.Drawing.Size(320, 150); $f.StartPosition = 'CenterParent'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $l = New-Object System.Windows.Forms.Label; $l.Text = 'Display time zone (Z or ±HH:MM):'; $l.Location = New-Object System.Drawing.Point(12, 12); $l.AutoSize = $true
    $t = New-Object System.Windows.Forms.TextBox; $t.Text = [Mpdbx.Fmt]::TzSuffix($script:tzMin); $t.Location = New-Object System.Drawing.Point(12, 38); $t.Width = 120
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.Location = New-Object System.Drawing.Point(200, 70); $ok.DialogResult = 'OK'; $f.AcceptButton = $ok
    $f.Controls.AddRange(@($l, $t, $ok))
    if ($f.ShowDialog($form) -ne 'OK') { return }
    $tzv = [Mpdbx.Fmt]::ParseTz($t.Text)
    if ($null -eq $tzv) { [void][System.Windows.Forms.MessageBox]::Show($form, 'Use Z or ±HH:MM (at most 14:00)', 'mpdbx'); return }
    $script:tzMin = $tzv
    if ($script:case) { Load-Case $script:case.Path }
}

$searchTimer = New-Object System.Windows.Forms.Timer; $searchTimer.Interval = 250
$searchTimer.Add_Tick({
        $searchTimer.Stop()
        if (-not $script:case) { return }
        if ($txtSearch.Text -and $script:curTab -eq 'Findings') { Set-Tab 'Timeline' }
        if ($script:curTab -eq 'Files & processes') { if ($vList.SelectedIndex -ge 0) { Show-View $script:vEntries[$vList.SelectedIndex] } }
        else { Refresh-Timeline }
    })
$txtSearch.Add_TextChanged({ $searchTimer.Stop(); $searchTimer.Start() })

$form.Add_KeyDown({
        param($s, $e)
        if ($e.Control) {
            switch ($e.KeyCode) {
                'F' { $txtSearch.Focus(); $txtSearch.SelectAll(); $e.SuppressKeyPress = $true }
                'E' { Export-List; $e.SuppressKeyPress = $true }
                'D1' { Set-Tab 'Findings'; $e.SuppressKeyPress = $true }
                'D2' { Set-Tab 'Timeline'; $e.SuppressKeyPress = $true }
                'D3' { Set-Tab 'Files & processes'; $e.SuppressKeyPress = $true }
                'D4' { Set-Tab 'Evidence'; $e.SuppressKeyPress = $true }
            }
        }
    })
$form.AllowDrop = $true
$form.Add_DragEnter({ param($s, $e) if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' } })
$form.Add_DragDrop({ param($s, $e) $f = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop); if ($f) { Load-Case $f[0] } })
$form.Add_Shown({
        try { [void][MpdbxWin.Native]::SendMessage($txtSearch.Handle, 0x1501, [IntPtr]1, 'Search names, paths, hashes…   (Ctrl+F)') } catch {}
        Apply-Theme
        Set-Tab 'Findings'
        if ($Path) { Load-Case $Path }
    })
$form.Add_FormClosed({ [Mpdbx.Sql]::Cleanup() })
[void]$form.ShowDialog()
