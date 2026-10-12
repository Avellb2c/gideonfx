[CmdletBinding()]
param(
  [string]$LockFile='',
  [string]$Root='',
  [string]$ArtifactId=''
)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$installerRoot=Split-Path -Parent $PSScriptRoot
$bundleRoot=Split-Path -Parent $installerRoot
if([string]::IsNullOrWhiteSpace($LockFile)){$LockFile=Join-Path $installerRoot 'config\dependency-lock.json'}
if([string]::IsNullOrWhiteSpace($Root)){$Root=$bundleRoot}
Import-Module (Join-Path $installerRoot 'common\GIDEON.Common.psm1') -Force
if(-not(Test-Path -LiteralPath $LockFile)){throw "Lock no encontrado: $LockFile"}
$lock=Read-GideonJson $LockFile
$artifacts=@($lock.artifacts)
if($ArtifactId){$artifacts=@($artifacts|Where-Object{[string]$_.id -eq $ArtifactId})}
if($artifacts.Count -eq 0){throw "Dependencia no encontrada en lock: $ArtifactId"}

$oldProtocol=[Net.ServicePointManager]::SecurityProtocol
try{
  [Net.ServicePointManager]::SecurityProtocol=$oldProtocol -bor [Net.SecurityProtocolType]::Tls12
  foreach($a in $artifacts){
    $id=[string]$a.id
    $url=[string]$a.url
    $sha=([string]$a.sha256).ToLowerInvariant()
    $dest=Join-Path $Root ([string]$a.destination)
    if($url -match 'REQUIRED' -or $sha -match 'REQUIRED'){throw "Dependencia $id no está fijada. Defina URL y SHA-256."}
    if($url -notmatch '^https://'){throw "Dependencia $id usa una URL no HTTPS: $url"}
    New-GideonDirectory (Split-Path -Parent $dest)
    if(Test-Path -LiteralPath $dest){
      if((Get-GideonSha256 $dest) -eq $sha){Write-GideonPass "$id ya está cacheado"; continue}
      throw "Dependencia cacheada $id no coincide con el SHA-256 fijado. No se reemplazará automáticamente: $dest"
    }
    Write-GideonInfo "Descargando $id desde fuente fijada..."
    $tmp="$dest.download-$([guid]::NewGuid().ToString('N'))"
    try{
      Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
      $actual=Get-GideonSha256 $tmp
      if($actual -ne $sha){throw "SHA-256 inválido para $id. Esperado=$sha Actual=$actual"}
      Move-Item -LiteralPath $tmp -Destination $dest
    }finally{
      if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
    }
    Write-GideonPass "$id descargado y verificado"
  }
}finally{
  [Net.ServicePointManager]::SecurityProtocol=$oldProtocol
}
