#requires -version 5.1
<#
  Local-only GIDEON Player output mapping for Windows.

  This script intentionally has no Gateway address, Agent token, campaign
  content or remote command surface. It must be run elevated on the physical
  Windows console (normally from the GIDEON Agent tray) because the resulting
  map is a local administrator assertion of the Qt/VLC monitor order.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\GIDEONAgent",
    [string]$MediaRoot = "C:\GIDEON\Distribucion\Videos",
    [string]$OutputIdentity = "",
    [ValidateRange(0,24)][int]$ScreenNumber = 0,
    [switch]$List
)

$ErrorActionPreference = 'Stop'

function Test-GideonAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-GideonSafeDirectory([string]$Value, [string]$Label, [bool]$Create) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "PLAYER_OUTPUT_MAPPING_${Label}_MISSING" }
    $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Value))
    if ($Create -and -not (Test-Path -LiteralPath $full)) { New-Item -ItemType Directory -Path $full -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw "PLAYER_OUTPUT_MAPPING_${Label}_INVALID" }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "PLAYER_OUTPUT_MAPPING_${Label}_REPARSE_POINT" }
    return $item.FullName
}

function Get-GideonPlayerOutputs([string]$Root) {
    $python = Join-Path $Root 'runtime\python\python.exe'
    $module = Join-Path $Root 'gideon_agent_display_capability.py'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or -not (Test-Path -LiteralPath $module -PathType Leaf)) {
        throw 'PLAYER_OUTPUT_MAPPING_RUNTIME_UNAVAILABLE'
    }
    $code = 'import json,sys;sys.path.insert(0,sys.argv[1]);from gideon_agent_display_capability import detect_display_capability;print(json.dumps(detect_display_capability(),ensure_ascii=False))'
    $raw = & $python -c $code $Root
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($raw -join "`n"))) { throw 'PLAYER_OUTPUT_MAPPING_DISCOVERY_FAILED' }
    try { $document = ($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop } catch { throw 'PLAYER_OUTPUT_MAPPING_DISCOVERY_INVALID' }
    $result = @()
    foreach ($item in @($document.Outputs)) {
        if ($null -eq $item) { continue }
        if (-not [bool]$item.Physical -or -not [bool]$item.Connected -or -not [bool]$item.Enabled) { continue }
        $identity = ([string]$item.OutputIdentity).Trim()
        if ($identity -notmatch '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$') { continue }
        $result += [pscustomobject]@{
            Identity = $identity
            Label = ([string]$item.Label).Trim()
            Key = ([string]$item.OutputKey).Trim()
            Resolution = ([string]$item.Resolution).Trim()
            Index = [int]($item.Index)
        }
    }
    return @($result | Sort-Object Identity -Unique)
}

function Get-GideonExistingMap([string]$MapPath) {
    if (-not (Test-Path -LiteralPath $MapPath -PathType Leaf)) {
        return [pscustomobject]@{ Schema='gideon-player-output-map/v1'; Outputs=@() }
    }
    $item = Get-Item -LiteralPath $MapPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 65536) {
        throw 'PLAYER_OUTPUT_MAPPING_EXISTING_UNSAFE'
    }
    try { $document = Get-Content -LiteralPath $MapPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop } catch { throw 'PLAYER_OUTPUT_MAPPING_EXISTING_INVALID' }
    if ([string]$document.Schema -ne 'gideon-player-output-map/v1' -or $null -eq $document.Outputs) {
        throw 'PLAYER_OUTPUT_MAPPING_EXISTING_INVALID'
    }
    return $document
}

function Protect-GideonMapPath([string]$Directory, [string]$MapPath) {
    # SID form is locale-independent (works on Spanish Windows too). Users may
    # read the signed exchange, but cannot replace this administrator mapping.
    & icacls.exe $Directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'PLAYER_OUTPUT_MAPPING_ACL_DIRECTORY_FAILED' }
    if (Test-Path -LiteralPath $MapPath) {
        & icacls.exe $MapPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:R' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'PLAYER_OUTPUT_MAPPING_ACL_FILE_FAILED' }
    }
}

function Select-GideonOutputMapping([object[]]$Outputs) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object Windows.Forms.Form
    $form.Text = 'Gideon Rx Player · Asociar pantallas físicas'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object Drawing.Size(650,285)
    $form.MinimumSize = New-Object Drawing.Size(650,285)
    $form.MaximizeBox = $false
    $form.TopMost = $true
    $message = New-Object Windows.Forms.Label
    $message.Text = 'Seleccione una salida física detectada y el número de pantalla de Windows/VLC. Esta confirmación es local y no altera campañas ni el Agent.'
    $message.Location = New-Object Drawing.Point(20,18)
    $message.Size = New-Object Drawing.Size(600,52)
    $form.Controls.Add($message)
    $combo = New-Object Windows.Forms.ComboBox
    $combo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
    $combo.Location = New-Object Drawing.Point(20,94)
    $combo.Size = New-Object Drawing.Size(600,28)
    foreach ($output in $Outputs) {
        $display = [string]$output.Label
        if ([string]::IsNullOrWhiteSpace($display)) { $display = [string]$output.Key }
        $text = ('{0} · {1} · {2}' -f $display, $output.Resolution, $output.Identity)
        [void]$combo.Items.Add([pscustomobject]@{ Text=$text; Identity=$output.Identity })
    }
    $combo.DisplayMember = 'Text'
    if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }
    $form.Controls.Add($combo)
    $label = New-Object Windows.Forms.Label
    $label.Text = 'Número de pantalla (1 = primera pantalla que VLC enumera):'
    $label.Location = New-Object Drawing.Point(20,140)
    $label.Size = New-Object Drawing.Size(390,24)
    $form.Controls.Add($label)
    $number = New-Object Windows.Forms.NumericUpDown
    $number.Minimum = 1; $number.Maximum = [Math]::Min(24,[Math]::Max(1,$Outputs.Count)); $number.Value = 1
    $number.Location = New-Object Drawing.Point(430,137)
    $number.Size = New-Object Drawing.Size(90,28)
    $form.Controls.Add($number)
    $save = New-Object Windows.Forms.Button
    $save.Text = 'Guardar asociación'; $save.Location = New-Object Drawing.Point(372,190); $save.Size = New-Object Drawing.Size(150,34)
    $save.DialogResult = [Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $save; $form.Controls.Add($save)
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancelar'; $cancel.Location = New-Object Drawing.Point(532,190); $cancel.Size = New-Object Drawing.Size(88,34)
    $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancel; $form.Controls.Add($cancel)
    $dialog = $form.ShowDialog()
    if ($dialog -ne [Windows.Forms.DialogResult]::OK -or $null -eq $combo.SelectedItem) { return $null }
    return [pscustomobject]@{ Identity=[string]$combo.SelectedItem.Identity; ScreenNumber=[int]$number.Value }
}

if (-not (Test-GideonAdministrator)) { throw 'PLAYER_OUTPUT_MAPPING_ADMIN_REQUIRED' }
$InstallRoot = Resolve-GideonSafeDirectory $InstallRoot 'INSTALL_ROOT' $false
$MediaRoot = Resolve-GideonSafeDirectory $MediaRoot 'MEDIA_ROOT' $true
$outputs = @(Get-GideonPlayerOutputs $InstallRoot)
if ($outputs.Count -eq 0) { throw 'PLAYER_OUTPUT_MAPPING_NO_PHYSICAL_OUTPUTS' }

if ($List) {
    $outputs | Select-Object Identity,Label,Key,Resolution,Index | ConvertTo-Json -Depth 3
    exit 0
}

if ([string]::IsNullOrWhiteSpace($OutputIdentity) -or $ScreenNumber -eq 0) {
    $selected = Select-GideonOutputMapping $outputs
    if ($null -eq $selected) { exit 0 }
    $OutputIdentity = $selected.Identity
    $ScreenNumber = $selected.ScreenNumber
}
$OutputIdentity = $OutputIdentity.Trim()
if ($OutputIdentity -notmatch '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$') { throw 'PLAYER_OUTPUT_MAPPING_IDENTITY_INVALID' }
if (-not ($outputs.Identity -contains $OutputIdentity)) { throw 'PLAYER_OUTPUT_MAPPING_OUTPUT_NOT_CURRENT' }
if ($ScreenNumber -lt 1 -or $ScreenNumber -gt [Math]::Min(24,$outputs.Count)) { throw 'PLAYER_OUTPUT_MAPPING_SCREEN_NUMBER_INVALID' }

$publicRoot = Join-Path $MediaRoot '.gideon-player'
$publicRoot = Resolve-GideonSafeDirectory $publicRoot 'PUBLIC_ROOT' $true
$mapPath = Join-Path $publicRoot 'output-map.json'
$existing = Get-GideonExistingMap $mapPath
$newRows = @()
foreach ($row in @($existing.Outputs)) {
    $identity = ([string]$row.OutputIdentity).Trim()
    $number = [int]($row.VlcScreenNumber)
    if ($identity -eq $OutputIdentity) { continue }
    if ($number -eq $ScreenNumber) { throw 'PLAYER_OUTPUT_MAPPING_SCREEN_ALREADY_ASSIGNED' }
    if ($identity -notmatch '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$' -or $number -lt 1 -or $number -gt 24) { throw 'PLAYER_OUTPUT_MAPPING_EXISTING_INVALID' }
    $newRows += [ordered]@{ OutputIdentity=$identity; VlcScreenNumber=$number }
}
$newRows += [ordered]@{ OutputIdentity=$OutputIdentity; VlcScreenNumber=$ScreenNumber }
$document = [ordered]@{ Schema='gideon-player-output-map/v1'; Outputs=@($newRows | Sort-Object OutputIdentity) }
$temporary = Join-Path $publicRoot ('.output-map.{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllText($temporary, ($document | ConvertTo-Json -Depth 4 -Compress) + "`n", (New-Object Text.UTF8Encoding($false)))
Move-Item -LiteralPath $temporary -Destination $mapPath -Force
Protect-GideonMapPath $publicRoot $mapPath
Write-Output ('PLAYER_OUTPUT_MAPPING_SAVED identity={0} screen={1}' -f $OutputIdentity,$ScreenNumber)

