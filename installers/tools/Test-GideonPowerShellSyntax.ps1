[CmdletBinding()]
param(
    [string]$Root = ''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Robust root resolution:
# - Normally use the bundle root (parent of the installers\ directory).
# - If a caller supplies Root, strip accidental quotes/whitespace first.
# This specifically prevents a quoted "%~dp0" with a trailing backslash from
# arriving as C:\path\" and causing Resolve-Path "Illegal characters in path".
if([string]::IsNullOrWhiteSpace($Root)){
    $installerRoot = Split-Path -Parent $PSScriptRoot
    $Root = Split-Path -Parent $installerRoot
}else{
    $Root = $Root.Trim()
    $Root = $Root.Trim('"')
    $Root = $Root.TrimEnd('\','/')
}

try{
    $resolvedItem = Resolve-Path -LiteralPath $Root -ErrorAction Stop
    $resolved = [string]$resolvedItem.Path
}catch{
    Write-Host ''
    Write-Host 'POWERSHELL_SYNTAX_PRECHECK=FAIL' -ForegroundColor Red
    Write-Host 'PARSER_ERRORS=0'
    Write-Host 'ROOT_RESOLUTION=FAIL'
    Write-Host ("ROOT_RAW={0}" -f $Root)
    Write-Host ("MESSAGE={0}" -f $_.Exception.Message)
    exit 3
}

Write-Host ("[PRECHECK] Root PowerShell resuelto: {0}" -f $resolved)

$files=@(
    Get-ChildItem `
      -LiteralPath $resolved `
      -Recurse `
      -File `
      -ErrorAction Stop |
    Where-Object {$_.Extension -in @('.ps1','.psm1','.psd1')}
)

$failures=@()

foreach($file in $files){
    $tokens=$null
    $errors=$null

    [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null

    foreach($err in @($errors)){
        $failures += [pscustomobject]@{
            file=$file.FullName
            line=[int]$err.Extent.StartLineNumber
            column=[int]$err.Extent.StartColumnNumber
            error_id=[string]$err.ErrorId
            message=[string]$err.Message
            text=[string]$err.Extent.Text
        }
    }
}

if($failures.Count -gt 0){
    Write-Host ''
    Write-Host 'POWERSHELL_SYNTAX_PRECHECK=FAIL' -ForegroundColor Red
    Write-Host 'ROOT_RESOLUTION=PASS'
    Write-Host ("FILES_SCANNED={0}" -f $files.Count)
    Write-Host ("PARSER_ERRORS={0}" -f $failures.Count)

    foreach($failure in $failures){
        Write-Host ''
        Write-Host ("FILE={0}" -f $failure.file) -ForegroundColor Yellow
        Write-Host ("LINE={0} COLUMN={1}" -f $failure.line,$failure.column)
        Write-Host ("ERROR_ID={0}" -f $failure.error_id)
        Write-Host ("MESSAGE={0}" -f $failure.message)
        Write-Host ("TEXT={0}" -f $failure.text)
    }

    exit 2
}

Write-Host 'ROOT_RESOLUTION=PASS'
Write-Host ("POWERSHELL_SYNTAX_PRECHECK=PASS files={0}" -f $files.Count) -ForegroundColor Green
exit 0
