[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$InstallRoot,
  [Parameter(Mandatory=$true)][string]$DataRoot,
  [Parameter(Mandatory=$true)][string]$WebHost,
  [string]$GatewayHost='',
  [Parameter(Mandatory=$true)][string]$Email,
  [ValidateSet('production','staging')][string]$Environment='production',
  [string]$WinAcmeZipPath='',
  [switch]$SkipIssue
)

$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:AcmeUrl='https://github.com/win-acme/win-acme/releases/download/v2.2.9.1701/win-acme.v2.2.9.1701.x64.trimmed.zip'
$script:AcmeSha256='f4dc3b144841ffdb a391ce168c273d7a686d45a359075e30ee4bf4ee186857d6'.Replace(' ','')
$script:Python=''

function Fail([string]$Message,[int]$Code=1){throw (New-Object System.Exception("GIDEON_ACME_FAIL[$Code]: $Message"))}
function Say([string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Cyan){Write-Host "[GIDEON ACME] $Message" -ForegroundColor $Color}
function EnsureDir([string]$Path){if(-not(Test-Path -LiteralPath $Path -PathType Container)){New-Item -ItemType Directory -Path $Path -Force | Out-Null}}
function Resolve-Host([string]$Value,[string]$Label){
  $hostName=$Value.Trim().TrimEnd('.')
  if([string]::IsNullOrWhiteSpace($hostName) -or $hostName -match '(?i)^(localhost|127\.0\.0\.1|::1)$' -or $hostName -notmatch '\.' -or $hostName.Length -gt 253 -or $hostName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$'){
    Fail "$Label debe ser un FQDN público (ejemplo: $Label.example.com); Lets Encrypt no emite para localhost ni IPs." 10
  }
  return $hostName.ToLowerInvariant()
}
function Resolve-Email([string]$Value){
  $emailValue=$Value.Trim()
  if($emailValue -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$'){Fail 'Email ACME inválido.' 11}
  return $emailValue
}
function Test-PortFree([int]$Port){
  if(Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue){
    $listeners=@(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if($listeners.Count -gt 0){Fail "El puerto TCP $Port ya está ocupado. win-acme necesita TCP/80 para HTTP-01 self-hosting." 12}
  }
}
function Resolve-Python {
  $candidates=@(
    (Join-Path $InstallRoot 'venv\Scripts\python.exe'),
    (Join-Path $InstallRoot 'runtime\python-base\python.exe'),
    (Join-Path $InstallRoot 'runtime\python\python.exe')
  )
  foreach($candidate in $candidates){if(Test-Path -LiteralPath $candidate -PathType Leaf){$script:Python=$candidate;return}}
  $found=Get-Command python.exe -ErrorAction SilentlyContinue
  if($found){$script:Python=$found.Source;return}
  Fail "No se encontró el runtime Python de GIDEON en $InstallRoot." 13
}
function Get-Sha256([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Install-WinAcme {
  $clientDir=Join-Path $InstallRoot 'tools\win-acme'
  $wacs=Join-Path $clientDir 'wacs.exe'
  if(Test-Path -LiteralPath $wacs -PathType Leaf){
    Say "win-acme existente: $wacs";return $wacs
  }
  $cache=Join-Path $DataRoot 'acme\cache'
  EnsureDir $cache
  $zip=if($WinAcmeZipPath){[IO.Path]::GetFullPath($WinAcmeZipPath)}else{Join-Path $cache 'win-acme.v2.2.9.1701.x64.trimmed.zip'}
  if(-not(Test-Path -LiteralPath $zip -PathType Leaf)){
    Say "Descargando win-acme fijado por SHA-256 desde $script:AcmeUrl";Invoke-WebRequest -Uri $script:AcmeUrl -OutFile $zip -UseBasicParsing
  }
  if((Get-Sha256 $zip) -ne $script:AcmeSha256){Fail "SHA-256 de win-acme inválido. Esperado=$script:AcmeSha256 Actual=$(Get-Sha256 $zip)" 14}
  $stage=Join-Path ([IO.Path]::GetTempPath()) ('gideon-win-acme-'+[guid]::NewGuid().ToString('N'))
  try{
    EnsureDir $stage;Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force
    $source=Get-ChildItem -LiteralPath $stage -Filter 'wacs.exe' -Recurse -File | Select-Object -First 1
    if(-not $source){Fail 'El ZIP de win-acme no contiene wacs.exe.' 15}
    EnsureDir $clientDir
    Copy-Item -LiteralPath (Join-Path $source.DirectoryName '*') -Destination $clientDir -Recurse -Force
  }finally{Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue}
  if(-not(Test-Path -LiteralPath $wacs -PathType Leaf)){Fail "No se pudo instalar wacs.exe en $clientDir." 16}
  return $wacs
}
function Save-State([string]$ClientDir,[string]$CertDir,[string]$HookPath){
  $statePath=Join-Path $DataRoot 'config\windows-letsencrypt.json'
  $state=[ordered]@{
    schema_version=1;enabled=$true;environment=$Environment;web_host=$WebHost;gateway_host=$GatewayHost
    email=$Email;client_dir=$ClientDir;certificate_dir=$CertDir;certificate_name='gideon-public';hook_path=$HookPath
    configured_utc=[DateTime]::UtcNow.ToString('o');http01_port=80;renewal='win-acme scheduled task'
  }
  EnsureDir (Split-Path -Parent $statePath)
  $json=$state|ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText($statePath,$json,(New-Object Text.UTF8Encoding($false)))
  return $statePath
}
function Add-Http01FirewallRule {
  $display='GIDEON Let''s Encrypt HTTP-01'
  if(-not(Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -or -not(Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)){
    Fail 'El módulo NetSecurity de Windows no está disponible; no se puede preparar TCP/80 para HTTP-01.' 22
  }
  if(-not(Get-NetFirewallRule -DisplayName $display -ErrorAction SilentlyContinue)){
    New-NetFirewallRule -DisplayName $display -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Any -Group 'GIDEON Remote Control' | Out-Null
    Say "Regla de firewall creada: TCP/80 ($display)" [ConsoleColor]::Yellow
  }else{Say 'Regla de firewall HTTP-01 ya existe.'}
}
function Invoke-AcmeHook {
  param([string]$Root)
  $helper=Join-Path $InstallRoot 'app\deploy\windows\gideon_windows_acme.py'
  if(-not(Test-Path -LiteralPath $helper -PathType Leaf)){Fail "Helper ACME ausente: $helper" 17}
  & $script:Python $helper renew-hook --data-root $Root --install-root $InstallRoot
  if($LASTEXITCODE -ne 0){Fail 'El hook ACME no pudo activar el certificado en WebAdmin/Gateway.' 18}
}

try{
  if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){Fail 'Este integrador sólo se ejecuta en Windows.' 20}
  $WebHost=Resolve-Host $WebHost 'WebAdmin'
  if([string]::IsNullOrWhiteSpace($GatewayHost)){$GatewayHost=$WebHost}else{$GatewayHost=Resolve-Host $GatewayHost 'Gateway'}
  $Email=Resolve-Email $Email
  $DataRoot=[IO.Path]::GetFullPath($DataRoot);$InstallRoot=[IO.Path]::GetFullPath($InstallRoot)
  $certDir=Join-Path $DataRoot 'acme\certs';$hookPath=Join-Path $InstallRoot 'app\deploy\windows\Apply-GIDEONWindowsLetsEncrypt.ps1'
  EnsureDir $certDir;EnsureDir (Join-Path $DataRoot 'acme\logs');EnsureDir (Join-Path $DataRoot 'acme\backups')
  Resolve-Python
  $wacs=Install-WinAcme
  $statePath=Save-State (Split-Path -Parent $wacs) $certDir $hookPath
  if(-not $SkipIssue){
    Test-PortFree 80
    Add-Http01FirewallRule
    $hosts="$WebHost,$GatewayHost"
    $args=@('--source','manual','--host',$hosts,'--validation','selfhosting','--store','pemfiles','--pemfilespath',$certDir,'--pemfilesname','gideon-public','--installation','script','--script',$hookPath,'--scriptparameters',("-DataRoot `"{0}`" -InstallRoot `"{1}`"" -f $DataRoot,$InstallRoot),'--emailaddress',$Email,'--accepttos')
    if($Environment -eq 'staging'){$args += '--test'}
    Say "Solicitando certificado ACME para $hosts ($Environment)..." [ConsoleColor]::Yellow
    & $wacs @args
    if($LASTEXITCODE -ne 0){Fail "win-acme terminó con rc=$LASTEXITCODE. Revise el log de win-acme y DNS/TCP 80." 19}
    Invoke-AcmeHook -Root $DataRoot
  }else{Say 'Configuración guardada sin emitir certificado (-SkipIssue).' [ConsoleColor]::Yellow}
  & $script:Python (Join-Path $InstallRoot 'app\deploy\windows\gideon_windows_acme.py') validate --data-root $DataRoot
  if($LASTEXITCODE -ne 0 -and -not $SkipIssue){Fail 'La validación final de la integración ACME falló.' 21}
  Write-Host "GIDEON_LETSENCRYPT=PASS state=$statePath client=$wacs" -ForegroundColor Green
  exit 0
}catch{
  Write-Error $_.Exception.Message
  exit 1
}
