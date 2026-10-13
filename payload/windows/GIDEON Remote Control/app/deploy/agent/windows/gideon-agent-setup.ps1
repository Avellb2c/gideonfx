param(
    [string]$InstallRoot = "C:\Program Files\GIDEONAgent",
    [string]$SiteCode = "",
    [string]$SiteName = "",
    [string]$AgentName = "",
    [string]$Gateway = "",
    [string]$EnrollmentSecret = "",
    [switch]$Silent
)
$ErrorActionPreference='Stop'
$TargetAgentVersion='2.4.56'
# RC30.95.21 VISIBLE_FAILURE_DIAGNOSTIC + TRANSACTIONAL_BOOTSTRAP_REQUIRED
$InstallLogRoot = Join-Path $env:ProgramData 'GIDEONAgent'
New-Item -ItemType Directory -Path $InstallLogRoot -Force | Out-Null
$InstallLog = Join-Path $InstallLogRoot 'install.log'
function Write-GideonInstallLog([string]$Message) {
    try {
        $stamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Add-Content -LiteralPath $InstallLog -Value ("[{0}] {1}" -f $stamp,$Message) -Encoding UTF8
    } catch {}
}

function Test-GideonInstallerPayloadContract([string]$Root) {
    $contractPath=Join-Path $Root 'installer.contract.json'
    $templatePath=Join-Path $Root 'agent.template.json'
    $runtimeContractPath=Join-Path $Root 'runtime.contract.json'
    if(-not (Test-Path -LiteralPath $contractPath)){ throw 'INSTALLER_CONTRACT_FILE_MISSING' }
    if(-not (Test-Path -LiteralPath $templatePath)){ throw 'INSTALLER_TEMPLATE_FILE_MISSING' }
    if(-not (Test-Path -LiteralPath (Join-Path $Root 'gideon_agent.py'))){ throw 'INSTALLER_AGENT_SCRIPT_MISSING' }
    $contract=Get-Content -LiteralPath $contractPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$contract.schema -ne 'gideon-agent-installer-contract/v2'){ throw 'INSTALLER_CONTRACT_SCHEMA_MISMATCH' }
    if([string]$contract.status -ne 'PASS'){ throw 'INSTALLER_CONTRACT_STATUS_NOT_PASS' }
    if([string]$contract.platform -ne 'windows'){ throw 'INSTALLER_CONTRACT_PLATFORM_MISMATCH' }
    if([string]$contract.agent_version -ne $TargetAgentVersion){ throw ('INSTALLER_CONTRACT_VERSION_MISMATCH expected='+$TargetAgentVersion+' got='+[string]$contract.agent_version) }
    foreach($rel in @($contract.required_files)){
        if([string]::IsNullOrWhiteSpace([string]$rel)){ continue }
        if(-not (Test-Path -LiteralPath (Join-Path $Root ([string]$rel)))){ throw ('INSTALLER_CONTRACT_REQUIRED_FILE_MISSING: '+[string]$rel) }
    }
    if($null -ne $contract.required_file_sha256){
        foreach($prop in @($contract.required_file_sha256.PSObject.Properties)){
            $rel=[string]$prop.Name
            $want=([string]$prop.Value).ToLowerInvariant()
            $file=Join-Path $Root $rel
            if(-not (Test-Path -LiteralPath $file)){ throw ('INSTALLER_CONTRACT_HASH_FILE_MISSING: '+$rel) }
            $got=((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash).ToLowerInvariant()
            if($got -ne $want){ throw ('INSTALLER_CONTRACT_HASH_MISMATCH: '+$rel) }
        }
    }
    $template=Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$template.agent_version -ne $TargetAgentVersion){ throw ('INSTALLER_TEMPLATE_VERSION_MISMATCH expected='+$TargetAgentVersion+' got='+[string]$template.agent_version) }
    if(-not (Test-Path -LiteralPath $runtimeContractPath)){ throw 'RUNTIME_CONTRACT_FILE_MISSING' }
    $runtimeContract=Get-Content -LiteralPath $runtimeContractPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$runtimeContract.agent_version -ne $TargetAgentVersion){ throw 'RUNTIME_CONTRACT_VERSION_MISMATCH' }
    Write-GideonInstallLog ('INSTALLER_CONTRACT PASS: target='+[string]$contract.target_id+' version='+$TargetAgentVersion+' service=windows-scm-service')
    return $contract
}

function Merge-GideonIdentityFromRuntime([object]$Existing,[string]$RequestedSiteCode) {
    if($null -eq $Existing){ return $Existing }
    $runtimeCandidates=New-Object System.Collections.Generic.List[string]
    try {
        $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$Existing.data_dir)
        if(-not [string]::IsNullOrWhiteSpace($dataRoot)){ $runtimeCandidates.Add((Join-Path $dataRoot 'agent.runtime.json')) }
    } catch {}
    $runtimeCandidates.Add((Join-Path $InstallLogRoot 'agent.runtime.json'))
    foreach($runtimePath in @($runtimeCandidates | Select-Object -Unique)){
        if(-not (Test-Path -LiteralPath $runtimePath)){ continue }
        try {
            $rt=Get-Content -LiteralPath $runtimePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $rtSite=([string]$rt.site_code).Trim()
            if(-not [string]::IsNullOrWhiteSpace($rtSite) -and -not [string]::IsNullOrWhiteSpace($RequestedSiteCode) -and
               -not $rtSite.Equals($RequestedSiteCode.Trim(),[StringComparison]::OrdinalIgnoreCase)){
                continue
            }
            $recovered=New-Object System.Collections.Generic.List[string]
            foreach($name in @('site_code','site_name','agent_name','agent_id','agent_token')){
                $oldValue=''
                if($Existing.PSObject.Properties.Name -contains $name){ $oldValue=[string]$Existing.$name }
                $rtValue=''
                if($rt.PSObject.Properties.Name -contains $name){ $rtValue=[string]$rt.$name }
                if([string]::IsNullOrWhiteSpace($oldValue) -and -not [string]::IsNullOrWhiteSpace($rtValue)){
                    if($Existing.PSObject.Properties.Name -contains $name){ $Existing.$name=$rtValue }
                    else { $Existing | Add-Member -NotePropertyName $name -NotePropertyValue $rtValue -Force }
                    $recovered.Add($name)
                }
            }
            if($recovered.Count -gt 0){ Write-GideonInstallLog ('RUNTIME_IDENTITY_RECOVERED: '+([string]::Join(',',@($recovered)))+' from '+$runtimePath) }
            return $Existing
        } catch {
            Write-GideonInstallLog ('WARN runtime identity recovery: '+[string]$_.Exception.Message)
        }
    }
    return $Existing
}

function New-GideonInstallDiagnostic([string]$Reason,[string]$Stage='installer') {
    $diagDir=Join-Path $InstallLogRoot 'diagnostics'
    New-Item -ItemType Directory -Path $diagDir -Force | Out-Null
    $diag=Join-Path $diagDir ("install-error-{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $lines=New-Object System.Collections.Generic.List[string]
    $lines.Add('============================================================')
    $lines.Add('GIDEON RX AGENT - WINDOWS INSTALLATION DIAGNOSTIC')
    $lines.Add('============================================================')
    $lines.Add(('Timestamp: '+(Get-Date).ToString('o')))
    $lines.Add(('Reason: '+$Reason))
    $lines.Add(('Stage: '+$Stage))
    $lines.Add(('Agent target version: '+$TargetAgentVersion))
    $lines.Add('')
    $lines.Add('=== OS ===')
    try {
        $os=Get-CimInstance Win32_OperatingSystem
        $lines.Add(('Caption: '+[string]$os.Caption))
        $lines.Add(('Version: '+[string]$os.Version))
        $lines.Add(('Build: '+[string]$os.BuildNumber))
        $lines.Add(('Architecture: '+[string]$os.OSArchitecture))
    } catch { $lines.Add(('OS read error: '+[string]$_.Exception.Message)) }
    $lines.Add('')
    $lines.Add('=== CONFIG (SANITIZED FIELDS ONLY) ===')
    $cfgPath=Join-Path $InstallRoot 'agent.json'
    try {
        if(Test-Path -LiteralPath $cfgPath){
            $c=Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $lines.Add(('site_code: '+[string]$c.site_code))
            $lines.Add(('site_name: '+[string]$c.site_name))
            $lines.Add(('agent_name: '+[string]$c.agent_name))
            $lines.Add(('agent_version: '+[string]$c.agent_version))
            $lines.Add(('gateway: '+[string]$c.control_plane.base_url))
            $lines.Add(('reverse_tunnel.enabled: '+[string]$c.reverse_tunnel.enabled))
            $lines.Add(('reverse_tunnel.transport: '+[string]$c.reverse_tunnel.transport))
        } else { $lines.Add('agent.json: MISSING') }
    } catch { $lines.Add(('Config read error: '+[string]$_.Exception.Message)) }
    $lines.Add('')
    $lines.Add('=== SERVICES ===')
    foreach($svcName in @('GIDEONAgent','TermService')){
        try {
            $svc=Get-Service -Name $svcName -ErrorAction Stop
            $lines.Add(('{0}: Status={1}; StartType={2}' -f $svcName,$svc.Status,$svc.StartType))
        } catch { $lines.Add(('{0}: NOT FOUND / {1}' -f $svcName,$_.Exception.Message)) }
    }
    $lines.Add('')
    $lines.Add('=== PORT 3389 ===')
    try {
        $rows=Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction Stop
        foreach($r in @($rows)){ $lines.Add(('{0}:{1} PID={2}' -f $r.LocalAddress,$r.LocalPort,$r.OwningProcess)) }
    } catch { $lines.Add(('Listener query: '+[string]$_.Exception.Message)) }
    $lines.Add('')
    $lines.Add('=== AGENT STATUS ===')
    try {
        $statusCandidates=@(
            (Join-Path $InstallLogRoot 'agent.status.json'),
            (Join-Path $InstallRoot 'agent.status.json')
        )
        foreach($sp in $statusCandidates){
            if(Test-Path -LiteralPath $sp){
                $s=Get-Content -LiteralPath $sp -Raw -Encoding UTF8 | ConvertFrom-Json
                $lines.Add(('status_file: '+$sp))
                $lines.Add(('process_pid: '+[string]$s.process_pid))
                break
            }
        }
    } catch { $lines.Add(('Status read error: '+[string]$_.Exception.Message)) }
    $lines.Add('')
    $lines.Add('=== INSTALL LOG (LAST 180) ===')
    try {
        foreach($line in @(Get-Content -LiteralPath $InstallLog -Tail 180 -ErrorAction SilentlyContinue)){
            $safe=[string]$line
            $safe=$safe -replace '(?i)(enrollment[_ -]?secret\s*[:=]\s*)\S+','$1***REDACTED***'
            $safe=$safe -replace '(?i)(token\s*[:=]\s*)\S+','$1***REDACTED***'
            $safe=$safe -replace '(?i)(password\s*[:=]\s*)\S+','$1***REDACTED***'
            $safe=$safe -replace '(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+','$1***REDACTED***'
            $lines.Add($safe)
        }
    } catch {}
    $hostLog=Join-Path $InstallLogRoot 'service-host.log'
    if(Test-Path -LiteralPath $hostLog){
        $lines.Add('')
        $lines.Add('=== SERVICE HOST LOG (LAST 120) ===')
        foreach($line in @(Get-Content -LiteralPath $hostLog -Tail 120 -ErrorAction SilentlyContinue)){ $lines.Add([string]$line) }
    }
    $lines.Add('')
    $lines.Add('============================================================')
    $lines.Add('END DIAGNOSTIC')
    $lines.Add('============================================================')
    [IO.File]::WriteAllLines($diag,$lines,(New-Object Text.UTF8Encoding($false)))
    return $diag
}

function Show-GideonDiagnosticError([string]$Summary,[string]$DiagnosticPath) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form=New-Object System.Windows.Forms.Form
    $form.Text=($BrandAgentProduct+' · Error completo')
    $form.StartPosition='CenterScreen'
    $form.Size=New-Object System.Drawing.Size(900,650)
    $form.MinimumSize=New-Object System.Drawing.Size(700,480)
    $form.TopMost=$true

    $title=New-Object System.Windows.Forms.Label
    $title.Text='La instalación no terminó correctamente'
    $title.Font=New-Object System.Drawing.Font('Segoe UI',14,[System.Drawing.FontStyle]::Bold)
    $title.Location=New-Object System.Drawing.Point(18,16)
    $title.Size=New-Object System.Drawing.Size(840,30)
    $form.Controls.Add($title)

    $hint=New-Object System.Windows.Forms.Label
    $hint.Text='El diagnóstico de abajo es completo, seleccionable y copiable. Envíelo íntegro para revisar el fallo.'
    $hint.Location=New-Object System.Drawing.Point(20,52)
    $hint.Size=New-Object System.Drawing.Size(840,36)
    $form.Controls.Add($hint)

    $box=New-Object System.Windows.Forms.TextBox
    $box.Multiline=$true
    $box.ReadOnly=$true
    $box.ScrollBars='Both'
    $box.WordWrap=$false
    $box.Font=New-Object System.Drawing.Font('Consolas',9)
    $box.Location=New-Object System.Drawing.Point(20,92)
    $box.Size=New-Object System.Drawing.Size(842,455)
    $box.Anchor='Top,Bottom,Left,Right'
    try {
        $diagText=Get-Content -LiteralPath $DiagnosticPath -Raw -Encoding UTF8
    } catch { $diagText=$Summary+"`r`n`r`nNo se pudo leer "+$DiagnosticPath }
    $box.Text=("ERROR:`r`n"+$Summary+"`r`n`r`nARCHIVO: "+$DiagnosticPath+"`r`n`r`n"+$diagText)
    $form.Controls.Add($box)

    $copy=New-Object System.Windows.Forms.Button
    $copy.Text='Copiar todo'
    $copy.Location=New-Object System.Drawing.Point(612,560)
    $copy.Size=New-Object System.Drawing.Size(110,34)
    $copy.Anchor='Bottom,Right'
    $copy.Add_Click({
        try { [System.Windows.Forms.Clipboard]::SetText($box.Text); $hint.Text='Diagnóstico copiado al portapapeles.' } catch {}
    })
    $form.Controls.Add($copy)

    $folder=New-Object System.Windows.Forms.Button
    $folder.Text='Abrir carpeta'
    $folder.Location=New-Object System.Drawing.Point(492,560)
    $folder.Size=New-Object System.Drawing.Size(110,34)
    $folder.Anchor='Bottom,Right'
    $folder.Add_Click({ try { Start-Process explorer.exe -ArgumentList ('/select,"'+$DiagnosticPath+'"') } catch {} })
    $form.Controls.Add($folder)

    $close=New-Object System.Windows.Forms.Button
    $close.Text='Cerrar'
    $close.Location=New-Object System.Drawing.Point(732,560)
    $close.Size=New-Object System.Drawing.Size(130,34)
    $close.Anchor='Bottom,Right'
    $close.Add_Click({ $form.Close() })
    $form.Controls.Add($close)

    [void]$form.ShowDialog()
}

function Test-GideonFinalAcceptanceWindows([string]$ConfigPath,[string]$ServiceName='GIDEONAgent') {
    Write-GideonInstallLog 'FINAL_ACCEPTANCE_STAGE Windows: verificando instalación completa.'
    [void](Test-GideonInstallerPayloadContract $InstallRoot)
    foreach($required in @('gideon_agent.py','agent.template.json','runtime.contract.json','installer.contract.json','GIDEONAgentServiceHost.exe')){
        if(-not (Test-Path -LiteralPath (Join-Path $InstallRoot $required))){ throw ('FINAL_PAYLOAD_FILE_MISSING: '+$required) }
    }

    $svc=Get-Service -Name $ServiceName -ErrorAction Stop
    if([string]$svc.Status -ne 'Running'){ throw 'FINAL_SERVICE_NOT_ACTIVE: GIDEONAgent no está Running.' }
    try {
        $svcInfo=Get-CimInstance Win32_Service -Filter ("Name='"+$ServiceName+"'") -ErrorAction Stop
        if(([string]$svcInfo.PathName) -notmatch '(?i)GIDEONAgentServiceHost\.exe'){ throw ('FINAL_SERVICE_BINARY_MISMATCH: '+[string]$svcInfo.PathName) }
    } catch { if($_.Exception.Message -like 'FINAL_SERVICE_BINARY_MISMATCH*'){ throw } }

    $cfg=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$cfg.agent_version -ne $TargetAgentVersion){ throw ('FINAL_CONFIG_VERSION_MISMATCH expected='+$TargetAgentVersion+' got='+[string]$cfg.agent_version) }
    if([string]::IsNullOrWhiteSpace([string]$cfg.site_code)){ throw 'FINAL_IDENTITY_MISSING: site_code vacío.' }
    $template=Get-Content -LiteralPath (Join-Path $InstallRoot 'agent.template.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]$template.agent_version -ne $TargetAgentVersion){ throw 'FINAL_TEMPLATE_VERSION_MISMATCH' }

    $privatePython=Join-Path $InstallRoot 'runtime\python\python.exe'
    if(-not (Test-Path -LiteralPath $privatePython)){ throw 'FINAL_PRIVATE_PYTHON_MISSING' }
    $versionOut=& $privatePython -c ("import sys;sys.path.insert(0,r'"+$InstallRoot.Replace("'","''")+"');import gideon_agent;print(gideon_agent.VERSION)") 2>&1
    if($LASTEXITCODE -ne 0 -or ([string]$versionOut).Trim() -ne $TargetAgentVersion){ throw ('FINAL_RUNTIME_VERSION_MISMATCH: '+([string]$versionOut).Trim()) }

    $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$cfg.data_dir)
    if([string]::IsNullOrWhiteSpace($dataRoot)){ $dataRoot=$InstallLogRoot }
    $runtime=Join-Path $dataRoot 'agent.runtime.json'
    $status=Join-Path $dataRoot 'agent.status.json'
    if(-not (Test-Path -LiteralPath $runtime)){ throw ('FINAL_RUNTIME_FILE_MISSING: '+$runtime) }
    if(-not (Test-Path -LiteralPath $status)){ throw ('FINAL_STATUS_FILE_MISSING: '+$status) }
    $rt=Get-Content -LiteralPath $runtime -Raw -Encoding UTF8 | ConvertFrom-Json
    if([string]::IsNullOrWhiteSpace([string]$rt.agent_id)){ throw 'FINAL_RUNTIME_AGENT_ID_MISSING' }
    if([string]::IsNullOrWhiteSpace([string]$rt.agent_token)){ throw 'FINAL_RUNTIME_AGENT_TOKEN_MISSING' }
    if(-not [string]::IsNullOrWhiteSpace([string]$rt.site_code) -and ([string]$rt.site_code).Trim() -ne ([string]$cfg.site_code).Trim()){ throw 'FINAL_RUNTIME_SITE_MISMATCH' }
    $s=Get-Content -LiteralPath $status -Raw -Encoding UTF8 | ConvertFrom-Json
    $pidValue=[int]$s.process_pid
    if($pidValue -le 0 -or -not (Get-Process -Id $pidValue -ErrorAction SilentlyContinue)){ throw 'FINAL_AGENT_PROCESS_NOT_ALIVE' }

    $remoteRequired=$false
    $remoteState='not-configured'
    $remoteReason=''
    if($null -ne $cfg.remote_access){
        try { $remoteRequired=([bool]$cfg.remote_access.enabled -and [bool]$cfg.remote_access.require_ready) } catch {}
        try {
            if($cfg.remote_access.PSObject.Properties.Name -contains 'support_state'){
                $remoteState=([string]$cfg.remote_access.support_state).Trim()
            } elseif([bool]$cfg.remote_access.enabled) {
                $remoteState='configured'
            } else {
                $remoteState='disabled'
            }
        } catch {}
        try {
            if($cfg.remote_access.PSObject.Properties.Name -contains 'support_reason'){
                $remoteReason=([string]$cfg.remote_access.support_reason).Trim()
            }
        } catch {}
    }

    if($remoteRequired){
        $rdpListeners=@(Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue)
        if($rdpListeners.Count -lt 1){ throw 'FINAL_RDP_LISTENER_MISSING: remote_access requiere RDP pero no existe listener TCP/3389.' }
        Write-GideonInstallLog ('FINAL_ACCEPTANCE RDP listener: '+(($rdpListeners|ForEach-Object{([string]$_.LocalAddress)+':'+([string]$_.LocalPort)}) -join ', '))
        $remoteState='ready'
    } else {
        Write-GideonInstallLog ('FINAL_ACCEPTANCE REMOTE_ACCESS OPTIONAL: support_state='+$remoteState+' reason='+$remoteReason+'. Agent core acceptance continues.')
    }

    Write-GideonInstallLog ('FINAL_ACCEPTANCE PASS: version='+$TargetAgentVersion+' payload + identity + runtime + SCM + process; remote_access='+$remoteState+'.')
}

function Invoke-GideonSelfTest([string]$PythonExe,[string]$AgentScript,[string]$ConfigPath) {
    $stdout = Join-Path $env:TEMP ("gideon-agent-selftest-{0}.out" -f ([guid]::NewGuid().ToString('N')))
    $stderr = Join-Path $env:TEMP ("gideon-agent-selftest-{0}.err" -f ([guid]::NewGuid().ToString('N')))
    try {
        $argLine = ('"{0}" --config "{1}" --self-test' -f $AgentScript,$ConfigPath)
        $proc = Start-Process -FilePath $PythonExe -ArgumentList $argLine -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $outText = $(if(Test-Path -LiteralPath $stdout){ Get-Content -LiteralPath $stdout -Raw -Encoding UTF8 }else{ '' })
        $errText = $(if(Test-Path -LiteralPath $stderr){ Get-Content -LiteralPath $stderr -Raw -Encoding UTF8 }else{ '' })
        return [pscustomobject]@{ ExitCode=[int]$proc.ExitCode; Stdout=[string]$outText; Stderr=[string]$errText }
    } finally {
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}
function Get-GideonSelfTestSummary([string]$Stdout,[string]$Stderr,[int]$ExitCode) {
    $raw = ($(if(-not [string]::IsNullOrWhiteSpace($Stderr)){$Stderr}else{$Stdout})).Trim()
    if([string]::IsNullOrWhiteSpace($raw)){ return ("Self-test terminó con código {0} sin detalle." -f $ExitCode) }
    try {
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if($obj -and $obj.Ok -eq $false){
            $category=[string]$obj.Category
            $advice=''
            switch($category){
                'TLS_CA_MISMATCH' { $advice='La CA incluida en este instalador no corresponde al certificado que está sirviendo el Gateway. Sincronice/Repare TLS en la consola y genere nuevamente el EXE.' }
                'TLS_HOSTNAME' { $advice='El certificado TLS no incluye la IP/DNS configurada del Gateway. Use Gateway central > Regenerar TLS (renueva solo el certificado servidor, conserva la CA).' }
                'TLS_EXPIRED' { $advice='El certificado del Gateway está vencido. Use Gateway central > Regenerar TLS y vuelva a probar.' }
                'TLS_CA_LOCAL' { $advice='La CA local del instalador falta o fue modificada. Genere nuevamente el EXE desde la consola actual.' }
                'TLS_CERTIFICATE' { $advice='La validación TLS falló. No desactive TLS: ejecute Probar Gateway, repare TLS y regenere el instalador si la CA cambió.' }
                'DNS' { $advice='El endpoint no resolvió el DNS del Gateway. Use una IP/FQDN enrutable por las tiendas o corrija DNS/VPN antes de regenerar el instalador.' }
                'CONNECTIVITY' { $advice='DNS resolvió, pero no se completó la conexión al Gateway/API. Verifique ruta VPN, puerto TCP del Gateway (por defecto 29443), listener y firewall del servidor.' }
                'CONFIGURATION' { $advice='La URL del Gateway embebida no es válida para producción. Regenera el instalador con un endpoint HTTPS enrutable.' }
                'ENROLLMENT' { $advice='La conectividad llegó al Gateway, pero la credencial temporal de enrolamiento fue rechazada o ya no es válida. Genere un instalador/grant nuevo.' }
            }
            $base=("{0} · etapa {1}: {2}" -f $category,([string]$obj.Stage),([string]$obj.Error))
            if(-not [string]::IsNullOrWhiteSpace($advice)){ return ($base + "`n`nAcción recomendada: " + $advice) }
            return $base
        }
    } catch {}
    $lines = @($raw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if($lines.Count -gt 0){ return [string]$lines[$lines.Count-1] }
    return $raw
}
$BrandCompany='Gideon Rx Project'
$BrandAgentProduct='Gideon Rx Agent'
try {
    $brandPath=Join-Path $InstallRoot 'branding.json'
    if(Test-Path -LiteralPath $brandPath){
        $brand=Get-Content -LiteralPath $brandPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if(-not [string]::IsNullOrWhiteSpace([string]$brand.company_name)){$BrandCompany=[string]$brand.company_name}
        if(-not [string]::IsNullOrWhiteSpace([string]$brand.agent_product_name)){$BrandAgentProduct=[string]$brand.agent_product_name}
    }
} catch {}

function Test-GideonBundledRuntimeIntegrity([string]$Root) {
    $manifestPath=Join-Path $Root 'runtime\runtime-manifest.json'
    $runtimeRoot=Join-Path $Root 'runtime\python'
    if(-not (Test-Path -LiteralPath $manifestPath)){ return $false }
    try {
        $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if([string]$manifest.schema -ne 'gideon-agent-windows-runtime/v1'){ throw 'schema de runtime no reconocido' }
        foreach($prop in @($manifest.files.PSObject.Properties)){
            $rel=[string]$prop.Name
            if([string]::IsNullOrWhiteSpace($rel) -or $rel.Contains('..')){ throw ('Ruta inválida en runtime-manifest: '+$rel) }
            $path=Join-Path $runtimeRoot ($rel.Replace('/','\'))
            if(-not (Test-Path -LiteralPath $path -PathType Leaf)){ throw ('Archivo runtime faltante: '+$rel) }
            $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            $expected=([string]$prop.Value).ToLowerInvariant()
            if($actual -ne $expected){ throw ('SHA-256 runtime no coincide: '+$rel) }
        }
        Write-GideonInstallLog ('Runtime privado verificado: CPython '+[string]$manifest.python_version+' · '+@($manifest.files.PSObject.Properties).Count+' archivos.')
        return $true
    } catch {
        throw ('El runtime Python privado incluido está dañado o fue alterado: '+[string]$_.Exception.Message)
    }
}

function Test-GideonPythonVersion([string]$Path) {
    if([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)){ return $false }
    try {
        $v=& $Path -c "import sys;print(int(sys.version_info >= (3,11)))" 2>$null
        return ($LASTEXITCODE -eq 0 -and (($v|Select-Object -Last 1).Trim() -eq '1'))
    } catch { return $false }
}

function Get-GideonPython {
    $bundled=Join-Path $InstallRoot 'runtime\python\python.exe'
    if(-not (Test-Path -LiteralPath $bundled -PathType Leaf)){
        Write-GideonInstallLog 'ERROR SELF_CONTAINED_RUNTIME_MISSING: falta runtime\python\python.exe.'
        throw 'SELF_CONTAINED_RUNTIME_MISSING: este instalador está incompleto. RC30 no usa py.exe/python.exe del equipo ni descarga Python en la PC final. Genere nuevamente el Agent desde WebAdmin.'
    }
    [void](Test-GideonBundledRuntimeIntegrity $InstallRoot)
    if(-not (Test-GideonPythonVersion $bundled)){ throw 'SELF_CONTAINED_RUNTIME_INVALID: el CPython privado incluido no puede ejecutarse o es menor a 3.11.' }
    Write-GideonInstallLog ('Usando runtime Python PRIVADO incluido: '+$bundled)
    return $bundled
}

function Get-GideonBootstrapSecret([string]$Root) {
    $path = Join-Path $Root 'bootstrap.enrollment'
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    try { return ([string](Get-Content -LiteralPath $path -Raw -Encoding UTF8)).Trim() } catch { return '' }
}

function Resolve-GideonEnrollmentSecret([string]$Root,[string]$Explicit='') {
    foreach($candidate in @([string]$Explicit,[string]$env:GIDEON_AGENT_ENROLL_SECRET,[string](Get-GideonBootstrapSecret $Root))){
        if(-not [string]::IsNullOrWhiteSpace($candidate)){ return $candidate.Trim() }
    }
    return ''
}
function Test-GideonBootstrapContract([string]$Root,[string]$ResolvedSecret) {
    $marker=Join-Path $Root 'bootstrap.required.json'
    if(-not (Test-Path -LiteralPath $marker)){ return }
    try{$required=[bool]((Get-Content -LiteralPath $marker -Raw -Encoding UTF8|ConvertFrom-Json).required)}catch{
        throw ('BOOTSTRAP_CONTRACT_INVALID: '+[string]$_.Exception.Message)
    }
    if($required -and [string]::IsNullOrWhiteSpace($ResolvedSecret)){
        throw 'BOOTSTRAP_REQUIRED_MISSING: el EXE fue generado con grant temporal obligatorio, pero la credencial no llegó al instalador.'
    }
}

function Register-GideonUninstallEntry([string]$Root) {
    try {
        # Inno Setup already owns the canonical ARP entry. Only create our manual
        # fallback for IExpress/direct PowerShell installations.
        if(Get-ChildItem -LiteralPath $Root -Filter 'unins*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1){ return }
        $uninstallScript=Join-Path $Root 'gideon-agent-uninstall.ps1'
        if(-not (Test-Path -LiteralPath $uninstallScript)){ return }
        $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControlAgent'
        New-Item -Path $key -Force | Out-Null
        $version=$TargetAgentVersion
        try { $version=[string]((Get-Content -LiteralPath (Join-Path $Root 'agent.template.json') -Raw -Encoding UTF8 | ConvertFrom-Json).agent_version) } catch {}
        $uninstall=('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -RemoveData -RemoveLegacy' -f $uninstallScript,$Root)
        New-ItemProperty -Path $key -Name DisplayName -Value $BrandAgentProduct -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name DisplayVersion -Value $version -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name Publisher -Value $BrandCompany -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name InstallLocation -Value $Root -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name UninstallString -Value $uninstall -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name QuietUninstallString -Value ($uninstall + ' -Quiet') -PropertyType String -Force | Out-Null
        $ico=Join-Path $Root 'gideon_agent_tray.ico'; if(Test-Path $ico){ New-ItemProperty -Path $key -Name DisplayIcon -Value $ico -PropertyType String -Force | Out-Null }
        New-ItemProperty -Path $key -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
    } catch { Write-GideonInstallLog ('WARN Appwiz: ' + [string]$_.Exception.Message) }
}

function Register-GideonTray([string]$Root,[string]$Config,[string]$VenvPython) {
    try {
        $pythonw = Join-Path (Split-Path $VenvPython -Parent) 'pythonw.exe'
        if (-not (Test-Path $pythonw)) { $pythonw = $VenvPython }
        $tray = Join-Path $Root 'gideon_agent_tray.py'
        if (-not (Test-Path $tray)) { return }
        $runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        New-Item -Path $runKey -Force | Out-Null
        $command = ('"{0}" "{1}" --config "{2}"' -f $pythonw,$tray,$Config)
        New-ItemProperty -Path $runKey -Name 'GIDEONAgentTray' -Value $command -PropertyType String -Force | Out-Null
        # Mostrar el indicador inmediatamente en la sesión del instalador, sin consola.
        try { Start-Process -FilePath $pythonw -ArgumentList @($tray,'--config',$Config) -WindowStyle Hidden | Out-Null } catch {}
    } catch {
        # El indicador es auxiliar: nunca debe impedir que el agente/servicio se instale.
    }
}


function Register-GideonAgentWindowsService(
    [string]$ServiceName,
    [string]$InstallRoot
) {
    if([string]::IsNullOrWhiteSpace($ServiceName)){ throw 'ServiceName vacío.' }
    $hostExe=Join-Path $InstallRoot 'GIDEONAgentServiceHost.exe'
    if(-not (Test-Path -LiteralPath $hostExe)){
        throw ('SERVICE_HOST_MISSING: ' + $hostExe)
    }

    $sc="$env:WINDIR\System32\sc.exe"
    Write-GideonInstallLog ('SERVICE_STAGE prepare: name={0}; host={1}' -f $ServiceName,$hostExe)

    # Remove any old Scheduled Task only as migration hygiene. New Agents never
    # use Task Scheduler as their runtime host.
    try { Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

    # Recreate service deterministically.
    try { & $sc stop $ServiceName 2>$null | Out-Null } catch {}
    Start-Sleep -Milliseconds 400
    try { & $sc delete $ServiceName 2>$null | Out-Null } catch {}
    Start-Sleep -Milliseconds 500

    $binPath=('"{0}"' -f $hostExe)
    $createArgs=@(
        'create',$ServiceName,
        'binPath=',$binPath,
        'start=','auto',
        'obj=','LocalSystem',
        'DisplayName=','Gideon Rx Agent'
    )
    $createOut=@(& $sc @createArgs 2>&1)
    $createExit=$LASTEXITCODE
    if($createOut){Write-GideonInstallLog ('SERVICE_SC_CREATE: '+([string]::Join(' | ',@($createOut))))}
    if($createExit-ne 0){throw ('SC_CREATE_FAILED exit='+$createExit+' output='+([string]::Join(' | ',@($createOut))))}

    $descOut=@(& $sc description $ServiceName "Gideon Rx Agent · secure outbound control channel" 2>&1)
    if($descOut){Write-GideonInstallLog ('SERVICE_SC_DESCRIPTION: '+([string]::Join(' | ',@($descOut))))}

    # Delayed automatic start improves boot reliability on store endpoints while
    # the network stack/VPN is still coming online.
    $cfgOut=@(& $sc config $ServiceName 'start=' 'delayed-auto' 2>&1)
    if($cfgOut){Write-GideonInstallLog ('SERVICE_SC_CONFIG: '+([string]::Join(' | ',@($cfgOut))))}

    # SCM-native recovery: 5s, 15s, 60s.
    $failureOut=@(& $sc failure $ServiceName 'reset=' '86400' 'actions=' 'restart/5000/restart/15000/restart/60000' 2>&1)
    if($failureOut){Write-GideonInstallLog ('SERVICE_SC_FAILURE: '+([string]::Join(' | ',@($failureOut))))}
    $flagOut=@(& $sc failureflag $ServiceName 1 2>&1)
    if($flagOut){Write-GideonInstallLog ('SERVICE_SC_FAILUREFLAG: '+([string]::Join(' | ',@($flagOut))))}

    $startOut=@(& $sc start $ServiceName 2>&1)
    $startExit=$LASTEXITCODE
    if($startOut){Write-GideonInstallLog ('SERVICE_SC_START: '+([string]::Join(' | ',@($startOut))))}
    if($startExit-ne 0 -and $startExit-ne 1056){
        throw ('SC_START_FAILED exit='+$startExit+' output='+([string]::Join(' | ',@($startOut))))
    }

    $running=$false
    for($i=0;$i-lt 20;$i++){
        Start-Sleep -Milliseconds 500
        try{
            $svc=Get-Service -Name $ServiceName -ErrorAction Stop
            if($svc.Status -eq 'Running'){$running=$true;break}
        }catch{}
    }
    if(-not $running){throw ('SERVICE_NOT_RUNNING: '+$ServiceName)}
    Write-GideonInstallLog 'SERVICE_STAGE running: Windows SCM confirmó RUNNING.'
}

function Get-GideonExistingAgentConfigCandidates {
    $rows = [ordered]@{}
    function Add-GideonConfigCandidate([string]$Value) {
        if([string]::IsNullOrWhiteSpace($Value)){ return }
        try { $full=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Value.Trim('"'))) } catch { return }
        $key=$full.ToLowerInvariant()
        if(-not $rows.Contains($key)){ $rows[$key]=$full }
    }
    Add-GideonConfigCandidate (Join-Path $InstallRoot 'agent.json')
    foreach($base in @((Join-Path $env:ProgramData 'GIDEONAgent'),(Join-Path $env:ProgramFiles 'GIDEONAgent'),${env:ProgramFiles(x86)})){
        if(-not [string]::IsNullOrWhiteSpace([string]$base)){
            $candidate=$(if(([string]$base).EndsWith('GIDEONAgent')){Join-Path $base 'agent.json'}else{Join-Path (Join-Path $base 'GIDEONAgent') 'agent.json'})
            Add-GideonConfigCandidate $candidate
        }
    }
    foreach($regPath in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControlAgent','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControlAgent','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GIDEONRemoteControlAgent')){
        try {
            $item=Get-ItemProperty -Path $regPath -ErrorAction Stop
            if(-not [string]::IsNullOrWhiteSpace([string]$item.InstallLocation)){ Add-GideonConfigCandidate (Join-Path ([string]$item.InstallLocation) 'agent.json') }
        } catch {}
    }
    try {
        $task=Get-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction Stop
        foreach($action in @($task.Actions)){
            $args=[string]$action.Arguments
            $match=[regex]::Match($args,'--config\s+(?:"([^"]+agent\.json)"|([^\s]+agent\.json))',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if($match.Success){ Add-GideonConfigCandidate $(if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}) }
            if(-not [string]::IsNullOrWhiteSpace([string]$action.WorkingDirectory)){ Add-GideonConfigCandidate (Join-Path ([string]$action.WorkingDirectory) 'agent.json') }
        }
    } catch {}
    return @($rows.Values)
}

function Find-GideonExistingAgentConfig {
    $best=$null; $bestScore=-1
    foreach($candidate in @(Get-GideonExistingAgentConfigCandidates)){
        if(-not (Test-Path -LiteralPath $candidate -PathType Leaf)){ continue }
        try {
            $cfg=Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 | ConvertFrom-Json
            $score=1
            if(-not [string]::IsNullOrWhiteSpace([string]$cfg.site_code)){ $score+=2 }
            if(-not [string]::IsNullOrWhiteSpace([string]$cfg.site_name)){ $score+=2 }
            if(-not [string]::IsNullOrWhiteSpace([string]$cfg.agent_name)){ $score+=1 }
            $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$cfg.data_dir)
            if([string]::IsNullOrWhiteSpace($dataRoot)){ $dataRoot=(Split-Path $candidate -Parent) }
            $runtime=Join-Path $dataRoot 'agent.runtime.json'
            if(Test-Path -LiteralPath $runtime){
                try { $rt=Get-Content -LiteralPath $runtime -Raw -Encoding UTF8 | ConvertFrom-Json; if(-not [string]::IsNullOrWhiteSpace([string]$rt.agent_token)){ $score+=10 } } catch {}
            }
            if($score -gt $bestScore){ $bestScore=$score; $best=[pscustomobject]@{Path=$candidate;Config=$cfg;Score=$score;Root=(Split-Path $candidate -Parent)} }
        } catch { Write-GideonInstallLog ('WARN agent.json previo inválido '+$candidate+': '+[string]$_.Exception.Message) }
    }
    return $best
}

function Import-GideonExistingAgentConfig([object]$State) {
    if($null -eq $State){ return '' }
    $target=Join-Path $InstallRoot 'agent.json'
    $source=[string]$State.Path
    if(-not [IO.Path]::GetFullPath($source).Equals([IO.Path]::GetFullPath($target),[StringComparison]::OrdinalIgnoreCase)){
        Copy-Item -LiteralPath $source -Destination $target -Force
        Write-GideonInstallLog ('MIGRACIÓN IN-PLACE: identidad previa importada desde '+$source+' hacia '+$target+'.')
    } else { Write-GideonInstallLog ('UPGRADE IN-PLACE: identidad previa detectada en '+$target+'.') }
    return $target
}

function Get-GideonExistingRuntimeToken([string]$ConfigPath) {
    try {
        if(-not (Test-Path -LiteralPath $ConfigPath)){ return '' }
        $cfg=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$cfg.data_dir)
        if([string]::IsNullOrWhiteSpace($dataRoot)){ $dataRoot=$InstallLogRoot }
        $runtime=Join-Path $dataRoot 'agent.runtime.json'
        if(Test-Path -LiteralPath $runtime){
            $rt=Get-Content -LiteralPath $runtime -Raw -Encoding UTF8 | ConvertFrom-Json
            return [string]$rt.agent_token
        }
    } catch { Write-GideonInstallLog ('WARN leyendo identidad runtime previa: ' + [string]$_.Exception.Message) }
    return ''
}

function Test-GideonRuntimeImports([string]$PythonExe,[string]$Root) {
    # Do not inject Root into sys.path: this must reproduce the exact private-runtime
    # startup used by the scheduled task and catch broken python311._pth payloads.
    $code = "import cryptography,PIL,pystray,gideon_agent,gideon_reverse_tunnel,gideon_agent_http,gideon_agent_security,gideon_agent_worker,gideon_common;assert gideon_reverse_tunnel.TUNNEL_API_VERSION == gideon_agent.REVERSE_TUNNEL_API_REQUIRED;print(gideon_agent.VERSION, gideon_reverse_tunnel.TUNNEL_API_VERSION)"
    $stdout = Join-Path $env:TEMP ("gideon-agent-import-{0}.out" -f ([guid]::NewGuid().ToString('N')))
    $stderr = Join-Path $env:TEMP ("gideon-agent-import-{0}.err" -f ([guid]::NewGuid().ToString('N')))
    try {
        $proc=Start-Process -FilePath $PythonExe -ArgumentList @('-c',('"{0}"' -f ($code -replace '"','\"'))) -WorkingDirectory $Root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if($proc.ExitCode -ne 0){
            $detail=$(if(Test-Path $stderr){Get-Content $stderr -Raw -Encoding UTF8}else{''})
            throw ("El runtime instalado está incompleto. Import smoke-test exit {0}: {1}" -f $proc.ExitCode,$detail)
        }
    } finally { Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue }
}


function Test-GideonExistingAgentOrphan {
    $reasons=New-Object System.Collections.Generic.List[string]
    $state=$null
    try { $state=Find-GideonExistingAgentConfig } catch {}
    if($null -eq $state){
        # Partial/legacy footprints without a valid config are also orphan candidates.
        foreach($p in @(
            'C:\Program Files\GIDEONAgent',
            'C:\Program Files\GIDEON Remote Control Agent',
            (Join-Path $env:ProgramData 'GIDEONAgent')
        )){
            if(Test-Path -LiteralPath $p){ $reasons.Add('PARTIAL_INSTALL='+$p) }
        }
        return [pscustomobject]@{ IsOrphan=($reasons.Count -gt 0); Reasons=@($reasons); ConfigPath=''; SiteCode='' }
    }

    $configPath=''
    $siteCode=''
    try {
        $configPath=Import-GideonExistingAgentConfig $state
        $cfg=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $siteCode=([string]$cfg.site_code).Trim()
        if([string]::IsNullOrWhiteSpace($siteCode)){ $reasons.Add('SITE_CODE_MISSING') }
        if([string]$cfg.agent_version -ne $TargetAgentVersion){ $reasons.Add('CONFIG_VERSION='+[string]$cfg.agent_version) }
        $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$cfg.data_dir)
        if([string]::IsNullOrWhiteSpace($dataRoot)){ $dataRoot=$InstallLogRoot }
        $runtime=Join-Path $dataRoot 'agent.runtime.json'
        $status=Join-Path $dataRoot 'agent.status.json'
        if(-not (Test-Path -LiteralPath $runtime)){ $reasons.Add('RUNTIME_IDENTITY_MISSING') }
        if(-not (Test-Path -LiteralPath $status)){ $reasons.Add('STATUS_MISSING') }
        if(Test-Path -LiteralPath $status){
            try {
                $s=Get-Content -LiteralPath $status -Raw -Encoding UTF8 | ConvertFrom-Json
                $pidValue=[int]$s.process_pid
                if($pidValue-le 0 -or -not (Get-Process -Id $pidValue -ErrorAction SilentlyContinue)){ $reasons.Add('STATUS_PROCESS_DEAD') }
            } catch { $reasons.Add('STATUS_INVALID') }
        }
    } catch { $reasons.Add('CONFIG_INVALID='+[string]$_.Exception.Message) }

    foreach($required in @('gideon_agent.py','agent.template.json','runtime.contract.json','installer.contract.json','GIDEONAgentServiceHost.exe')){
        if(-not (Test-Path -LiteralPath (Join-Path $InstallRoot $required))){ $reasons.Add('PAYLOAD_FILE_MISSING='+$required) }
    }
    try {
        $tp=Join-Path $InstallRoot 'agent.template.json'
        if(Test-Path -LiteralPath $tp){
            $tv=[string]((Get-Content -LiteralPath $tp -Raw -Encoding UTF8 | ConvertFrom-Json).agent_version)
            if($tv -ne $TargetAgentVersion){ $reasons.Add('TEMPLATE_VERSION='+$tv) }
        }
    } catch { $reasons.Add('TEMPLATE_INVALID') }

    $svc=Get-Service -Name GIDEONAgent -ErrorAction SilentlyContinue
    if($null-eq $svc){ $reasons.Add('SCM_SERVICE_MISSING') }
    elseif([string]$svc.Status-ne'Running'){ $reasons.Add('SCM_SERVICE_NOT_RUNNING') }

    try {
        $task=Get-ScheduledTask -TaskName GIDEONAgent -ErrorAction SilentlyContinue
        if($null-ne $task){ $reasons.Add('LEGACY_SCHEDULED_TASK') }
    } catch {}

    return [pscustomobject]@{
        IsOrphan=($reasons.Count -gt 0)
        Reasons=@($reasons)
        ConfigPath=$configPath
        SiteCode=$siteCode
    }
}

function Merge-GideonConfigCurrentSchema([object]$Existing,[object]$Template,[string]$ExplicitGateway='') {
    # Start from current template so all package-owned policy/configuration is current.
    $json=$Template | ConvertTo-Json -Depth 40
    $merged=$json | ConvertFrom-Json

    # Preserve endpoint identity.
    foreach($name in @('site_code','site_name','agent_name','agent_id','agent_token')){
        if($Existing.PSObject.Properties.Name -contains $name){
            $value=$Existing.$name
            if($null-ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)){
                if($merged.PSObject.Properties.Name -contains $name){ $merged.$name=$value }
                else { $merged | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force }
            }
        }
    }

    # Current package control-plane/TLS schema wins. Explicit GUI Gateway can override URL.
    if(-not [string]::IsNullOrWhiteSpace($ExplicitGateway)){
        $newGw=$ExplicitGateway.TrimEnd('/')
        $merged.control_plane.base_url=$newGw
        $rows=@($merged.control_plane.endpoints)
        if($rows.Count-gt 0){ $rows[0].url=$newGw; $rows[0].role='primary'; $rows[0].priority=10 }
        else { $rows=@([pscustomobject]@{url=$newGw;role='primary';priority=10;label='Installer'}) }
        $merged.control_plane.endpoints=$rows
    }
    return $merged
}

function Get-GideonNormalizedGatewayUrl([string]$Value) {
    if([string]::IsNullOrWhiteSpace($Value)){ return '' }
    return $Value.Trim().TrimEnd('/').ToLowerInvariant()
}

function Reset-GideonStaleTokenForReenrollment([string]$ConfigPath,[string]$EnrollmentSecret) {
    if([string]::IsNullOrWhiteSpace($EnrollmentSecret)){ return $false }
    $cfg=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$cfg.data_dir)
    if([string]::IsNullOrWhiteSpace($dataRoot)){ $dataRoot=$InstallLogRoot }
    $runtime=Join-Path $dataRoot 'agent.runtime.json'

    if($cfg.PSObject.Properties.Name -contains 'agent_token'){ $cfg.agent_token='' }
    if($cfg.PSObject.Properties.Name -contains 'enrollment_secret'){ $cfg.enrollment_secret=$EnrollmentSecret }
    else { $cfg | Add-Member -NotePropertyName enrollment_secret -NotePropertyValue $EnrollmentSecret -Force }
    [IO.File]::WriteAllText($ConfigPath,($cfg|ConvertTo-Json -Depth 40),(New-Object Text.UTF8Encoding($false)))

    if(Test-Path -LiteralPath $runtime){
        try {
            $rt=Get-Content -LiteralPath $runtime -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach($name in @('agent_token','enrolled_at','last_gateway_success_at','current_gateway_endpoint','last_known_good_endpoint')){
                if($rt.PSObject.Properties.Name -contains $name){ $rt.PSObject.Properties.Remove($name) }
            }
            [IO.File]::WriteAllText($runtime,($rt|ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))
        } catch {
            Write-GideonInstallLog ('WARN limpiando token runtime huérfano: '+[string]$_.Exception.Message)
        }
    }
    Write-GideonInstallLog 'GATEWAY_MIGRATION_REENROLL: token anterior descartado; AgentId e identidad de sede preservados cuando estaban disponibles.'
    return $true
}


function Prepare-GideonManualInstallState([string]$RequestedSiteCode) {
    $result=[ordered]@{
        Mode='FRESH'
        ExistingSiteCode=''
        ExistingConfig=''
        Backup=''
        IsOrphan=$false
        OrphanReasons=@()
    }

    $orphanAssessment=Test-GideonExistingAgentOrphan
    $result.IsOrphan=[bool]$orphanAssessment.IsOrphan
    $result.OrphanReasons=@($orphanAssessment.Reasons)
    if($result.IsOrphan){
        Write-GideonInstallLog ('ORPHAN_DETECTED: '+([string]::Join(' | ',@($result.OrphanReasons))))
    }

    # Stop/remove all known old host mechanisms BEFORE reusing/replacing identity.
    $sc="$env:WINDIR\System32\sc.exe"
    try { & $sc stop GIDEONAgent 2>$null | Out-Null } catch {}
    Start-Sleep -Milliseconds 300
    try { Stop-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName 'GIDEONAgent' -Confirm:$false -ErrorAction SilentlyContinue } catch {}

    # If an older runtime is still alive outside service/task tracking, terminate only
    # GIDEONAgent Python processes whose command line points into a GIDEONAgent install root.
    try {
        Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $cmd=[string]$_.CommandLine
                $cmd -match '(?i)\\GIDEONAgent\\gideon_agent\.py'
            } |
            ForEach-Object {
                try { Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
            }
    } catch {}

    # Migrate/detect previous config if it lives in a legacy root.
    $state=$null
    try { $state=Find-GideonExistingAgentConfig } catch {
        Write-GideonInstallLog ('WARN buscando instalación previa: '+[string]$_.Exception.Message)
    }
    if($null -ne $state){
        try {
            $target=Import-GideonExistingAgentConfig $state
            $cfg=Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
            $existingCode=([string]$cfg.site_code).Trim()
            $result.ExistingSiteCode=$existingCode
            $result.ExistingConfig=$target

            $stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
            $backup=Join-Path $InstallLogRoot ("reinstall-backup_"+$stamp)
            New-Item -ItemType Directory -Path $backup -Force | Out-Null
            Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'agent.json') -Force -ErrorAction SilentlyContinue

            $dataRoot=[Environment]::ExpandEnvironmentVariables([string]$cfg.data_dir)
            if([string]::IsNullOrWhiteSpace($dataRoot)){ $dataRoot=$InstallLogRoot }
            $runtime=Join-Path $dataRoot 'agent.runtime.json'
            if(Test-Path -LiteralPath $runtime){
                Copy-Item -LiteralPath $runtime -Destination (Join-Path $backup 'agent.runtime.json') -Force -ErrorAction SilentlyContinue
            }
            $result.Backup=$backup

            if(-not [string]::IsNullOrWhiteSpace($existingCode) -and
               $existingCode.Equals($RequestedSiteCode.Trim(),[StringComparison]::OrdinalIgnoreCase)){
                if($result.IsOrphan){
                    $result.Mode='ORPHAN_REPAIR_SAME_SITE'
                    Write-GideonInstallLog ("ORPHAN_REPAIR same-site: {0}. Se conserva AgentId cuando existe; se migra config y se reconstruye runtime/SCM." -f $existingCode)
                } else {
                    $result.Mode='REINSTALL_SAME_SITE'
                    Write-GideonInstallLog ("MANUAL_REINSTALL same-site: {0}. Se conserva AgentId/token; runtime y servicio se sobrescriben." -f $existingCode)
                }
            } else {
                $result.Mode='REPLACE_IDENTITY'
                Write-GideonInstallLog ("MANUAL_REINSTALL replace-identity: anterior={0}; solicitado={1}. Se elimina identidad/token anterior y se enrola de nuevo." -f $existingCode,$RequestedSiteCode)

                # New generated installer is authoritative when site differs.
                Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $runtime -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath (Join-Path $dataRoot 'agent.status.json') -Force -ErrorAction SilentlyContinue
            }
        } catch {
            $result.Mode='ORPHAN_REPAIR_CORRUPT'
            Write-GideonInstallLog ('ORPHAN_REPAIR config previa inválida: se reconstruirá desde plantilla actual y se intentará recuperar identidad runtime: '+[string]$_.Exception.Message)
            try { Remove-Item -LiteralPath (Join-Path $InstallRoot 'agent.json') -Force -ErrorAction SilentlyContinue } catch {}
            $rtPath=Join-Path $InstallLogRoot 'agent.runtime.json'
            if(Test-Path -LiteralPath $rtPath){
                try {
                    $rt=Get-Content -LiteralPath $rtPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $rtCode=([string]$rt.site_code).Trim()
                    if(-not [string]::IsNullOrWhiteSpace($rtCode) -and $rtCode.Equals($RequestedSiteCode.Trim(),[StringComparison]::OrdinalIgnoreCase)){
                        Write-GideonInstallLog ('ORPHAN_RUNTIME_IDENTITY_PRESERVED same-site='+$rtCode)
                    } else {
                        Remove-Item -LiteralPath $rtPath -Force -ErrorAction SilentlyContinue
                        Remove-Item -LiteralPath (Join-Path $InstallLogRoot 'agent.status.json') -Force -ErrorAction SilentlyContinue
                        Write-GideonInstallLog ('ORPHAN_RUNTIME_IDENTITY_PURGED site mismatch runtime='+$rtCode+' requested='+$RequestedSiteCode)
                    }
                } catch {
                    Remove-Item -LiteralPath $rtPath -Force -ErrorAction SilentlyContinue
                    Write-GideonInstallLog 'ORPHAN_RUNTIME_IDENTITY_PURGED invalid runtime.'
                }
            }
        }
    }

    # Remove obsolete task-era launchers/caches unconditionally.
    Remove-Item -LiteralPath (Join-Path $InstallRoot 'gideon-agent-task.cmd') -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $InstallRoot '__pycache__') -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $InstallRoot 'GIDEONAgent.previous-task.xml') -Force -ErrorAction SilentlyContinue

    return [pscustomobject]$result
}

function Set-GideonRemoteAccessProperty([object]$Object,[string]$Name,$Value) {
    if($null -eq $Object){ return }
    if($Object.PSObject.Properties.Name -contains $Name){
        $Object.PSObject.Properties[$Name].Value=$Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

function Set-GideonRemoteAccessUnsupportedWindows([string]$ConfigPath,[string]$Edition,[string]$Reason='windows-edition-no-rdp-host') {
    if(-not (Test-Path -LiteralPath $ConfigPath)){ return }
    try {
        $cfg=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if($null -eq $cfg.remote_access){
            $cfg | Add-Member -NotePropertyName remote_access -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $ra=$cfg.remote_access
        Set-GideonRemoteAccessProperty $ra 'enabled' $false
        Set-GideonRemoteAccessProperty $ra 'managed_by_installer' $true
        Set-GideonRemoteAccessProperty $ra 'require_ready' $false
        Set-GideonRemoteAccessProperty $ra 'mode' 'unavailable'
        Set-GideonRemoteAccessProperty $ra 'protocol' 'RDP'
        Set-GideonRemoteAccessProperty $ra 'target_host' '127.0.0.1'
        Set-GideonRemoteAccessProperty $ra 'target_port' 3389
        Set-GideonRemoteAccessProperty $ra 'server' 'windows-rdp'
        Set-GideonRemoteAccessProperty $ra 'firewall_policy' 'do-not-open-inbound'
        Set-GideonRemoteAccessProperty $ra 'support_state' 'unsupported'
        Set-GideonRemoteAccessProperty $ra 'support_reason' $Reason
        Set-GideonRemoteAccessProperty $ra 'support_detail' ('Windows edition '+$Edition+' does not provide the supported Microsoft inbound RDP host.')
        [IO.File]::WriteAllText($ConfigPath,($cfg|ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))
    } catch {
        throw ('REMOTE_ACCESS_CONFIG_WRITE_FAILED: '+[string]$_.Exception.Message)
    }
}

function Enable-GideonManagedRemoteAccessWindows([string]$ConfigPath) {
    Write-GideonInstallLog 'REMOTE_ACCESS_STAGE windows-rdp: preparando RDP administrado por GIDEON.'

    # Windows Home/Core editions do not provide the supported inbound Microsoft RDP host.
    # This is a capability limitation, NOT an Agent installation failure. The Agent,
    # heartbeat, jobs and reverse tunnel remain installed and operational. GIDEON does not
    # install a third-party VNC/RDP server implicitly.
    $edition=''
    $caption=''
    try { $edition=[string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).EditionID } catch {}
    try { $caption=[string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
    if($edition -match '(?i)^(Core|Home)' -or $caption -match '(?i)Windows\s+\d+\s+Home|Windows\s+Home'){
        $editionLabel=$(if(-not [string]::IsNullOrWhiteSpace($edition)){$edition}else{$caption})
        Set-GideonRemoteAccessUnsupportedWindows $ConfigPath $editionLabel 'windows-edition-no-rdp-host'
        Write-GideonInstallLog ('REMOTE_ACCESS_UNSUPPORTED_CONTINUE windows-rdp edition='+$editionLabel+
            '; Agent installation continues. Remote desktop is unavailable on this OS edition; no third-party VNC/RDP server was installed.')
        return
    }

    $ts='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    # Enable listener. Keep NLA enabled and Negotiate security for compatibility
    # with current guacd security=any while retaining authenticated RDP.
    Set-ItemProperty -LiteralPath $ts -Name fDenyTSConnections -Type DWord -Value 0 -Force
    Set-ItemProperty -LiteralPath $rdp -Name UserAuthentication -Type DWord -Value 1 -Force
    Set-ItemProperty -LiteralPath $rdp -Name SecurityLayer -Type DWord -Value 1 -Force

    Set-Service -Name TermService -StartupType Automatic
    $svc=Get-Service TermService
    if($svc.Status -ne 'Running'){
        Start-Service TermService
        (Get-Service TermService).WaitForStatus('Running',(New-TimeSpan -Seconds 20))
    }

    # SECURITY: the Agent uses Reverse Tunnel -> 127.0.0.1:3389.
    # GIDEON intentionally does NOT enable Windows Firewall inbound RDP rules.
    # Existing firewall state is preserved instead of broadening LAN exposure.
    try {
        $enabledRules=@(
            Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
            Where-Object Enabled -eq 'True'
        ).Count
        Write-GideonInstallLog ('REMOTE_ACCESS firewall: GIDEON no abre reglas inbound. Reglas Remote Desktop ya habilitadas por el sistema/admin='+$enabledRules)
    } catch {
        Write-GideonInstallLog 'REMOTE_ACCESS firewall: no se pudo leer reglas; GIDEON no realizó apertura inbound.'
    }

    $ready=$false
    for($i=0;$i-lt 20;$i++){
        Start-Sleep -Milliseconds 500
        $listeners=@(Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue)
        if($listeners.Count -gt 0){$ready=$true;break}
    }
    if(-not $ready){
        throw 'REMOTE_ACCESS_RDP_NOT_LISTENING: TermService está configurado pero no existe listener TCP/3389.'
    }

    if(Test-Path -LiteralPath $ConfigPath){
        try{
            $cfg=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if($null -eq $cfg.remote_access){
                $cfg | Add-Member NoteProperty remote_access ([pscustomobject]@{}) -Force
            }
            $ra=$cfg.remote_access
            Set-GideonRemoteAccessProperty $ra 'enabled' $true
            Set-GideonRemoteAccessProperty $ra 'managed_by_installer' $true
            Set-GideonRemoteAccessProperty $ra 'require_ready' $true
            Set-GideonRemoteAccessProperty $ra 'mode' 'tunnel-only'
            Set-GideonRemoteAccessProperty $ra 'protocol' 'RDP'
            Set-GideonRemoteAccessProperty $ra 'target_host' '127.0.0.1'
            Set-GideonRemoteAccessProperty $ra 'target_port' 3389
            Set-GideonRemoteAccessProperty $ra 'server' 'windows-rdp'
            Set-GideonRemoteAccessProperty $ra 'firewall_policy' 'do-not-open-inbound'
            Set-GideonRemoteAccessProperty $ra 'support_state' 'ready'
            Set-GideonRemoteAccessProperty $ra 'support_reason' ''
            Set-GideonRemoteAccessProperty $ra 'support_detail' ''
            [IO.File]::WriteAllText($ConfigPath,($cfg|ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))
        }catch{
            throw ('REMOTE_ACCESS_CONFIG_WRITE_FAILED: '+[string]$_.Exception.Message)
        }
    }

    Write-GideonInstallLog 'REMOTE_ACCESS_READY windows-rdp 127.0.0.1:3389 NLA=ON SecurityLayer=Negotiate firewall-inbound-not-opened-by-GIDEON.'
    return
}

function Install-GideonAgentIdentity([string]$Code,[string]$Name,[string]$DisplayName,[string]$Gw,[string]$Enroll){
    if ([string]::IsNullOrWhiteSpace($Code) -or [string]::IsNullOrWhiteSpace($Name)) { throw 'SiteCode y SiteName son obligatorios.' }
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $env:COMPUTERNAME }
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { throw 'El nombre del agente es obligatorio.' }
    $existingConfig = Join-Path $InstallRoot 'agent.json'
    $previousGateway=''
    if(Test-Path -LiteralPath $existingConfig){
        try {
            $beforeCfg=Get-Content -LiteralPath $existingConfig -Raw -Encoding UTF8 | ConvertFrom-Json
            $previousGateway=[string]$beforeCfg.control_plane.base_url
        } catch {}
    }
    $manualState=Prepare-GideonManualInstallState $Code
    $existingToken = Get-GideonExistingRuntimeToken $existingConfig
    $gatewayChanged=(-not [string]::IsNullOrWhiteSpace($previousGateway) -and
        -not [string]::IsNullOrWhiteSpace($Gw) -and
        (Get-GideonNormalizedGatewayUrl $previousGateway) -ne (Get-GideonNormalizedGatewayUrl $Gw) -and
        (Test-Path -LiteralPath $existingConfig))
    if ([string]::IsNullOrWhiteSpace($Enroll) -and ($gatewayChanged -or [string]::IsNullOrWhiteSpace($existingToken))) {
        $Enroll = Resolve-GideonEnrollmentSecret $InstallRoot $EffectiveEnrollmentSecret
    }
    if ($gatewayChanged -and [string]::IsNullOrWhiteSpace($Enroll)) {
        throw 'GATEWAY_MIGRATION_REQUIRES_ENROLLMENT: el Gateway cambió y el token anterior no es válido en la nube nueva. Regenera el instalador desde WebAdmin.'
    }
    if ([string]::IsNullOrWhiteSpace($Enroll) -and [string]::IsNullOrWhiteSpace($existingToken)) {
        throw 'Falta la credencial de enrolamiento y no existe token previo reutilizable. Regenera el instalador desde la consola/Gateway o ingresa la credencial de contingencia.'
    }
    # Reinstalación segura: detener la instancia anterior antes de reemplazar
    # configuración o ejecutar el self-test para evitar dos agentes simultáneos.
    Stop-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction SilentlyContinue
    $template = Join-Path $InstallRoot 'agent.template.json'
    $config = Join-Path $InstallRoot 'agent.json'
    if (-not (Test-Path $template)) { throw "No existe $template" }
    $templateCfg = Get-Content -LiteralPath $template -Raw -Encoding UTF8 | ConvertFrom-Json
    if (Test-Path -LiteralPath $config) {
        $existingCfg = Get-Content -LiteralPath $config -Raw -Encoding UTF8 | ConvertFrom-Json
        $existingCfg = Merge-GideonIdentityFromRuntime $existingCfg $Code
        $cfg = Merge-GideonConfigCurrentSchema $existingCfg $templateCfg $Gw
        if($manualState.IsOrphan){
            Write-GideonInstallLog 'ORPHAN_CONFIG_MIGRATION: configuración antigua normalizada contra plantilla actual; identidad preservada.'
        } else {
            Write-GideonInstallLog 'MANUAL_REINSTALL SAME_SITE: esquema actualizado desde plantilla actual; identidad preservada.'
        }
    } else {
        $cfg = $templateCfg
        $cfg = Merge-GideonIdentityFromRuntime $cfg $Code
        if($manualState.IsOrphan){ Write-GideonInstallLog 'ORPHAN_CONFIG_REBUILT: plantilla actual + identidad runtime recuperable.' }
    }
    $cfg.site_code = $Code.Trim()
    $cfg.site_name = $Name.Trim()
    if ($cfg.PSObject.Properties.Name -contains 'agent_name') { $cfg.agent_name = $DisplayName.Trim() }
    else { $cfg | Add-Member -NotePropertyName agent_name -NotePropertyValue $DisplayName.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($Gw)) {
        $newGw = $Gw.TrimEnd('/')
        $oldGw = [string]$cfg.control_plane.base_url
        $cfg.control_plane.base_url = $newGw
        $rows = @()
        $replaced = $false
        if ($cfg.control_plane.PSObject.Properties.Name -contains 'endpoints') {
            foreach($ep in @($cfg.control_plane.endpoints)) {
                if (-not $replaced -and (([string]$ep.role).ToLowerInvariant() -eq 'primary' -or ([string]$ep.url).TrimEnd('/') -eq $oldGw.TrimEnd('/'))) {
                    $ep.url = $newGw; $ep.role = 'primary'; $ep.priority = 10; $replaced = $true
                }
                $rows += $ep
            }
        }
        if (-not $replaced) { $rows = @([pscustomobject]@{url=$newGw;role='primary';priority=10;label='Configurado en instalación'}) + $rows }
        if ($cfg.control_plane.PSObject.Properties.Name -contains 'endpoints') { $cfg.control_plane.endpoints = $rows }
        else { $cfg.control_plane | Add-Member -NotePropertyName endpoints -NotePropertyValue $rows }
    }
    if (-not [string]::IsNullOrWhiteSpace($Enroll)) {
        if ($cfg.PSObject.Properties.Name -contains 'enrollment_secret') { $cfg.enrollment_secret = $Enroll }
        else { $cfg | Add-Member -NotePropertyName enrollment_secret -NotePropertyValue $Enroll }
    }
    $jsonText = $cfg | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($config, $jsonText, $utf8NoBom)
    if($gatewayChanged){
        Write-GideonInstallLog ('PACKAGE_GATEWAY_AUTHORITY: migrando Gateway anterior='+$previousGateway+' nuevo='+$Gw+'.')
        if(-not (Reset-GideonStaleTokenForReenrollment $config $Enroll)){
            throw 'GATEWAY_MIGRATION_REENROLL_FAILED: no se pudo preparar el re-enrolamiento contra el Gateway nuevo.'
        }
        $cfg=Get-Content -LiteralPath $config -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    $python = Get-GideonPython
    $privatePython=Join-Path $InstallRoot 'runtime\python\python.exe'
    # RC30 fail-closed: Get-GideonPython únicamente devuelve el CPython privado
    # empacado por el builder y validado contra runtime-manifest.json. La PC final
    # nunca usa py.exe/python.exe del sistema, venv, pip ni descargas de Internet.
    $vpython=$privatePython
    Test-GideonRuntimeImports $vpython $InstallRoot
    Write-GideonInstallLog 'Import smoke-test OK: gideon_agent + dependencias runtime (incluido gideon_common).'

    # No declarar éxito hasta demostrar enrolamiento + heartbeat contra el Gateway.
    # Start-Process + redirección a archivos evita que Windows PowerShell 5.1
    # convierta la primera línea de stderr ("Traceback...") en un error nativo
    # truncado y nos permite conservar el diagnóstico completo sin abrir consola.
    Enable-GideonManagedRemoteAccessWindows $config
    Write-GideonInstallLog ("Self-test: agente={0}; sede={1}; gateway={2}" -f $DisplayName,$Code,$cfg.control_plane.base_url)
    $probe = Invoke-GideonSelfTest $vpython (Join-Path $InstallRoot 'gideon_agent.py') $config
    $probeCode = [int]$probe.ExitCode
    $detail = (([string]$probe.Stdout) + [Environment]::NewLine + ([string]$probe.Stderr)).Trim()
    if(-not [string]::IsNullOrWhiteSpace($detail)){ Write-GideonInstallLog $detail }
    if ($probeCode -ne 0 -and $manualState.IsOrphan) {
        $recoverySecret=$Enroll
        if([string]::IsNullOrWhiteSpace($recoverySecret)){ $recoverySecret=Resolve-GideonEnrollmentSecret $InstallRoot $EffectiveEnrollmentSecret }
        if(-not [string]::IsNullOrWhiteSpace($recoverySecret)){
            Write-GideonInstallLog ('ORPHAN_SELFTEST_RETRY: primer self-test falló exit='+$probeCode+'; intentando re-enrolamiento con AgentId preservado.')
            if(Reset-GideonStaleTokenForReenrollment $config $recoverySecret){
                $probe = Invoke-GideonSelfTest $vpython (Join-Path $InstallRoot 'gideon_agent.py') $config
                $probeCode=[int]$probe.ExitCode
                $detail2=(([string]$probe.Stdout)+[Environment]::NewLine+([string]$probe.Stderr)).Trim()
                if(-not [string]::IsNullOrWhiteSpace($detail2)){ Write-GideonInstallLog $detail2 }
                if($probeCode-eq 0){ Write-GideonInstallLog 'ORPHAN_RECOVERED: re-enrolamiento + heartbeat OK.' }
            }
        }
    }
    if ($probeCode -ne 0) {
        $summary = Get-GideonSelfTestSummary ([string]$probe.Stdout) ([string]$probe.Stderr) $probeCode
        # Installation connectivity validation must not strand an upgraded Agent
        # in STOPPED state. Register/start the real SCM host before returning the
        # diagnostic error so it can keep retrying the Gateway.
        try {
            Write-GideonInstallLog ('SELF_TEST_FAILED exit='+$probeCode+': registrando GIDEONAgent SCM para reintentos automáticos.')
            Register-GideonAgentWindowsService -ServiceName 'GIDEONAgent' -InstallRoot $InstallRoot
            Remove-Item -LiteralPath (Join-Path $InstallRoot 'bootstrap.enrollment') -Force -ErrorAction SilentlyContinue
            Write-GideonInstallLog 'DEGRADED_CONNECTIVITY: GIDEONAgent SCM quedó RUNNING; continuará reintentando Gateway.'
        } catch {
            Write-GideonInstallLog ('DEGRADED_CONNECTIVITY: no se pudo dejar GIDEONAgent SCM RUNNING: '+[string]$_.Exception.Message)
        }
        throw ("El agente quedó instalado y configurado, pero NO pudo completar DNS/TCP/TLS + enrolamiento/heartbeat contra el Gateway.`n`nCausa: {0}`n`nEl servicio GIDEONAgent fue dejado activo cuando fue posible para reintentar automáticamente.`n`nLog completo: {1}" -f $summary,$InstallLog)
    }
    Write-GideonInstallLog 'Self-test OK: enrolamiento + heartbeat confirmados.'
    $verifiedCfg = Get-Content -LiteralPath $config -Raw -Encoding UTF8 | ConvertFrom-Json
    $dataRoot = [Environment]::ExpandEnvironmentVariables([string]$verifiedCfg.data_dir)
    if ([string]::IsNullOrWhiteSpace($dataRoot)) { $dataRoot = $InstallRoot }
    $runtime = Join-Path $dataRoot 'agent.runtime.json'
    if (-not (Test-Path -LiteralPath $runtime)) { throw ("El Gateway respondió, pero no se generó agent.runtime.json en {0}. El enrolamiento no quedó confirmado." -f $dataRoot) }
    Remove-Item -LiteralPath (Join-Path $InstallRoot 'bootstrap.enrollment') -Force -ErrorAction SilentlyContinue

    $service='GIDEONAgent'
    Write-GideonInstallLog 'SERVICE_STAGE begin: registrando GIDEONAgent como servicio Windows SCM.'
    Register-GideonAgentWindowsService `
        -ServiceName $service `
        -InstallRoot $InstallRoot

    # Do not declare success only because SCM says RUNNING. Confirm the REAL Agent
    # process emitted status and the PID still exists.
    $runtimeReady=$false
    $statusPath=Join-Path $dataRoot 'agent.status.json'
    for($i=0;$i -lt 20;$i++){
        Start-Sleep -Seconds 1
        try {
            if(Test-Path -LiteralPath $statusPath){
                $agentStatus=Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 | ConvertFrom-Json
                $pidValue=[int]$agentStatus.process_pid
                $serviceState=[string](Get-Service -Name $service -ErrorAction SilentlyContinue).Status
                if($serviceState -eq 'Running' -and $pidValue -gt 0 -and (Get-Process -Id $pidValue -ErrorAction SilentlyContinue)){
                    $runtimeReady=$true; break
                }
            }
        } catch {}
    }
    if(-not $runtimeReady){
        throw ("El servicio GIDEONAgent fue creado, pero no se confirmó un proceso Agent activo. Revise {0} y C:\ProgramData\GIDEONAgent\service-host.log." -f $InstallLog)
    }
    Write-GideonInstallLog 'Runtime OK: proceso Agent activo y agent.status.json confirmado.'
    Test-GideonFinalAcceptanceWindows $config $service
    Register-GideonTray $InstallRoot $config $vpython
    Register-GideonUninstallEntry $InstallRoot
}

$EffectiveEnrollmentSecret=''
$PackagedGateway=''
try {
    Write-GideonInstallLog 'PRE_GUI_VALIDATION_STAGE: validando payload/contrato/bootstrap antes de abrir identificación.'
    [void](Test-GideonInstallerPayloadContract $InstallRoot)
    $EffectiveEnrollmentSecret=Resolve-GideonEnrollmentSecret $InstallRoot $EnrollmentSecret
    Test-GideonBootstrapContract $InstallRoot $EffectiveEnrollmentSecret
    $packageTemplate=Get-Content -LiteralPath (Join-Path $InstallRoot 'agent.template.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $PackagedGateway=([string]$packageTemplate.control_plane.base_url).Trim().TrimEnd('/')
    if([string]::IsNullOrWhiteSpace($PackagedGateway) -or -not $PackagedGateway.ToLowerInvariant().StartsWith('https://')){
        throw 'PACKAGE_GATEWAY_INVALID: agent.template.json no contiene un Gateway HTTPS válido.'
    }
    # PACKAGE_GATEWAY_AUTHORITY: el endpoint emitido por WebAdmin gana sobre una
    # instalación previa. Un -Gateway explícito sigue siendo una anulación válida.
    if([string]::IsNullOrWhiteSpace($Gateway)){ $Gateway=$PackagedGateway }
    elseif(-not $Gateway.Trim().ToLowerInvariant().StartsWith('https://')){ throw 'EXPLICIT_GATEWAY_INVALID: Gateway debe usar https://.' }
    else { $Gateway=$Gateway.Trim().TrimEnd('/') }
    if(-not [string]::IsNullOrWhiteSpace($EffectiveEnrollmentSecret)){
        Write-GideonInstallLog 'Bootstrap temporal detectado y precargado automáticamente.'
    }
    Write-GideonInstallLog 'PRE_GUI_VALIDATION PASS.'
} catch {
    $message=[string]$_.Exception.Message
    Write-GideonInstallLog ('PRE_GUI_VALIDATION FAILED: '+$message)
    $diag=New-GideonInstallDiagnostic $message 'pre-gui validation'
    Write-GideonInstallLog ('DIAGNOSTIC_FILE='+$diag)
    Write-Host ('GIDEON_DIAGNOSTIC_FILE='+$diag)
    if(-not $Silent){
        try { Show-GideonDiagnosticError $message $diag } catch {
            try { [System.Windows.Forms.MessageBox]::Show(($message+"`r`n`r`nDiagnóstico: "+$diag),'GIDEON Agent · Error',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)|Out-Null } catch {}
        }
    }
    exit 1
}
# RC30.95.6 MANUAL GENERATED INSTALLER POLICY:
# - Never auto-skip the identity screen just because an old Agent exists.
# - Detect old identity only to prefill the screen.
# - Install click decides SAME_SITE preserve vs DIFFERENT_SITE clean replacement.
$DetectedExistingState=$null
$DetectedExistingCode=''
$DetectedExistingName=''
try {
    $DetectedExistingState=Find-GideonExistingAgentConfig
    if($null -ne $DetectedExistingState){
        $existingConfigPath=Import-GideonExistingAgentConfig $DetectedExistingState
        $existingCfg=Get-Content -LiteralPath $existingConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $DetectedExistingCode=([string]$existingCfg.site_code).Trim()
        $DetectedExistingName=([string]$existingCfg.site_name).Trim()
        $existingAgentName=([string]$existingCfg.agent_name).Trim()
        $existingGateway=([string]$existingCfg.control_plane.base_url).Trim()
        if(-not [string]::IsNullOrWhiteSpace($existingAgentName)){ $AgentName=$existingAgentName }
        Write-GideonInstallLog ("INSTALACIÓN PREVIA DETECTADA: {0} · {1}. Gateway anterior={2}; Gateway del instalador={3}. El instalador mostrará la identidad antes de reemplazar/adaptar." -f $DetectedExistingCode,$DetectedExistingName,$existingGateway,$Gateway)
    }
} catch {
    Write-GideonInstallLog ('WARN detectando instalación previa: '+[string]$_.Exception.Message)
}

if (-not [string]::IsNullOrWhiteSpace($SiteCode) -and -not [string]::IsNullOrWhiteSpace($SiteName)) {
    if ([string]::IsNullOrWhiteSpace($AgentName)) { $AgentName=$env:COMPUTERNAME }
    try {
        Install-GideonAgentIdentity $SiteCode $SiteName $AgentName $Gateway $EffectiveEnrollmentSecret
        exit 0
    } catch {
        $message=[string]$_.Exception.Message
        Write-GideonInstallLog ('ERROR direct/silent install: '+$message)
        $diag=New-GideonInstallDiagnostic $message 'direct-or-silent install'
        Write-Host ('GIDEON_DIAGNOSTIC_FILE='+$diag)
        if(-not $Silent){ Show-GideonDiagnosticError $message $diag }
        throw ($message+"`n`nDiagnóstico completo: "+$diag)
    }
}
if ($Silent) { throw 'Instalación silenciosa requiere SiteCode y SiteName. AgentName es opcional y usa COMPUTERNAME por defecto.' }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object System.Windows.Forms.Form
$form.Text = ($BrandAgentProduct + ' · Identificación crucial del dispositivo')
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(680,610)
$form.MinimumSize = $form.Size
$form.MaximizeBox = $false
$form.FormBorderStyle = 'FixedDialog'
$iconPath=Join-Path $InstallRoot 'gideon_agent_tray.ico'
if(Test-Path $iconPath){ try { $form.Icon=New-Object System.Drawing.Icon($iconPath) } catch {} }

$title = New-Object System.Windows.Forms.Label
$title.Text = ('Identificación del agente · ' + $BrandCompany)
$title.Font = New-Object System.Drawing.Font('Segoe UI',15,[System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true; $title.Location = New-Object System.Drawing.Point(24,18); $form.Controls.Add($title)
$critical = New-Object System.Windows.Forms.Label
$critical.Text = ('CRUCIAL: estos datos identifican el dispositivo en la consola principal de ' + $BrandCompany + '. Verifique nombre del agente, código y sede antes de continuar.')
$critical.ForeColor = [System.Drawing.Color]::FromArgb(196,72,20)
$critical.Font = New-Object System.Drawing.Font('Segoe UI',9.5,[System.Drawing.FontStyle]::Bold)
$critical.Size = New-Object System.Drawing.Size(620,48); $critical.Location = New-Object System.Drawing.Point(26,56); $form.Controls.Add($critical)
function Add-Label($text,$x,$y){ $l=New-Object System.Windows.Forms.Label; $l.Text=$text; $l.AutoSize=$true; $l.Location=New-Object System.Drawing.Point($x,$y); $form.Controls.Add($l); return $l }

Add-Label 'Nombre del agente en este equipo' 26 112 | Out-Null
$agent = New-Object System.Windows.Forms.TextBox; $agent.Location=New-Object System.Drawing.Point(26,134); $agent.Size=New-Object System.Drawing.Size(610,27); $agent.Text=($(if($AgentName){$AgentName}else{$env:COMPUTERNAME})); $form.Controls.Add($agent)

Add-Label 'Sede registrada' 26 174 | Out-Null
$combo = New-Object System.Windows.Forms.ComboBox
$combo.DropDownStyle='DropDownList'; $combo.Location=New-Object System.Drawing.Point(26,196); $combo.Size=New-Object System.Drawing.Size(610,28); $form.Controls.Add($combo)
$catalog = Join-Path $InstallRoot 'site-catalog.csv'
$sites = @()
if (Test-Path $catalog) { $sites = @(Import-Csv -LiteralPath $catalog | Where-Object {$_.SiteCode -and $_.SiteName}) }
[void]$combo.Items.Add('Seleccione una sede…')
foreach($s in $sites){ [void]$combo.Items.Add(('{0} · {1}' -f $s.SiteCode,$s.SiteName)) }
[void]$combo.Items.Add('Otra sede / ingreso manual')
$combo.SelectedIndex=0

Add-Label 'Código de sede' 26 238 | Out-Null
$code = New-Object System.Windows.Forms.TextBox; $code.Location=New-Object System.Drawing.Point(26,260); $code.Size=New-Object System.Drawing.Size(190,27); $form.Controls.Add($code)
Add-Label 'Nombre de sede' 234 238 | Out-Null
$name = New-Object System.Windows.Forms.TextBox; $name.Location=New-Object System.Drawing.Point(234,260); $name.Size=New-Object System.Drawing.Size(402,27); $form.Controls.Add($name)
$code.ReadOnly=$true; $name.ReadOnly=$true

$template = Join-Path $InstallRoot 'agent.template.json'
$defaultGateway=''
try { $defaultGateway=[string]((Get-Content -LiteralPath $template -Raw -Encoding UTF8 | ConvertFrom-Json).control_plane.base_url) } catch {}
Add-Label 'Gateway HTTPS' 26 300 | Out-Null
$gw = New-Object System.Windows.Forms.TextBox; $gw.Location=New-Object System.Drawing.Point(26,322); $gw.Size=New-Object System.Drawing.Size(610,27); $gw.Text=($(if($Gateway){$Gateway}else{$defaultGateway})); $form.Controls.Add($gw)
Add-Label 'Secreto de enrolamiento (se elimina después del enrolamiento)' 26 362 | Out-Null
$secret = New-Object System.Windows.Forms.TextBox; $secret.Location=New-Object System.Drawing.Point(26,384); $secret.Size=New-Object System.Drawing.Size(610,27); $secret.UseSystemPasswordChar=$true; $secret.Text=$EffectiveEnrollmentSecret; $form.Controls.Add($secret)
if (-not [string]::IsNullOrWhiteSpace($secret.Text)) { $secret.ReadOnly=$true; $secret.BackColor=[System.Drawing.SystemColors]::Control }

$status = New-Object System.Windows.Forms.Label
$status.Text = $(if(-not [string]::IsNullOrWhiteSpace($secret.Text)){'Credencial temporal incluida automáticamente. Se validará enrolamiento + heartbeat antes de finalizar.'}else{'Ingrese la credencial de enrolamiento. El instalador no finalizará hasta validar el Gateway.'})
$status.ForeColor = [System.Drawing.Color]::DimGray
$status.Size = New-Object System.Drawing.Size(610,38); $status.Location=New-Object System.Drawing.Point(26,424); $form.Controls.Add($status)

$combo.Add_SelectedIndexChanged({
    $i=$combo.SelectedIndex
    if($i -gt 0 -and $i -le $sites.Count){
        $s=$sites[$i-1]; $code.Text=[string]$s.SiteCode; $name.Text=[string]$s.SiteName; $code.ReadOnly=$true; $name.ReadOnly=$true
    } elseif($i -eq ($combo.Items.Count-1)){
        $code.Text='';$name.Text='';$code.ReadOnly=$false;$name.ReadOnly=$false;$code.Focus()
    } else { $code.Text='';$name.Text='';$code.ReadOnly=$true;$name.ReadOnly=$true }
})

if(-not [string]::IsNullOrWhiteSpace($DetectedExistingCode)){
    $matchIndex=0
    for($j=0;$j-lt $sites.Count;$j++){
        if(([string]$sites[$j].SiteCode).Trim().Equals($DetectedExistingCode,[StringComparison]::OrdinalIgnoreCase)){
            $matchIndex=$j+1
            break
        }
    }
    if($matchIndex -gt 0){
        $combo.SelectedIndex=$matchIndex
    } else {
        $combo.SelectedIndex=$combo.Items.Count-1
        $code.Text=$DetectedExistingCode
        $name.Text=$DetectedExistingName
    }
    $status.Text=('Instalación previa detectada: '+$DetectedExistingCode+' · '+$DetectedExistingName+
        '. Misma sede = conserva identidad y actualiza Gateway; sede diferente = reemplazo limpio.')
}

$cancel=New-Object System.Windows.Forms.Button; $cancel.Text='Cancelar'; $cancel.Location=New-Object System.Drawing.Point(418,500); $cancel.Size=New-Object System.Drawing.Size(100,34); $cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel; $form.Controls.Add($cancel)
$ok=New-Object System.Windows.Forms.Button; $ok.Text='Instalar agente'; $ok.Location=New-Object System.Drawing.Point(528,500); $ok.Size=New-Object System.Drawing.Size(110,34); $form.Controls.Add($ok)
$form.CancelButton=$cancel
$ok.Add_Click({
    if([string]::IsNullOrWhiteSpace($agent.Text)){ [System.Windows.Forms.MessageBox]::Show('Ingrese el nombre del agente para identificar este equipo.','GIDEON Agent') | Out-Null; return }
    if([string]::IsNullOrWhiteSpace($code.Text) -or [string]::IsNullOrWhiteSpace($name.Text)){ [System.Windows.Forms.MessageBox]::Show('Seleccione una sede o complete código y nombre.','GIDEON Agent') | Out-Null; return }
    if([string]::IsNullOrWhiteSpace($gw.Text) -or -not $gw.Text.Trim().ToLowerInvariant().StartsWith('https://')){ [System.Windows.Forms.MessageBox]::Show('El Gateway debe usar https://','GIDEON Agent') | Out-Null; return }
    $confirm=[System.Windows.Forms.MessageBox]::Show(("Confirme la identidad:`r`n`r`nAgente: {0}`r`nSede: {1} · {2}`r`nGateway: {3}`r`n`r`nEstos datos se mostrarán en la consola principal.`r`n`r`nSi existe un Agent previo: misma sede conserva identidad y actualiza el Gateway; sede distinta la reemplaza." -f $agent.Text,$code.Text,$name.Text,$gw.Text),'GIDEON Agent · Confirmación crucial',[System.Windows.Forms.MessageBoxButtons]::OKCancel,[System.Windows.Forms.MessageBoxIcon]::Warning)
    if($confirm -ne [System.Windows.Forms.DialogResult]::OK){ return }
    $ok.Enabled=$false; $cancel.Enabled=$false; $status.Text='Configurando agente y servicio…'
    try {
        Install-GideonAgentIdentity $code.Text $name.Text $agent.Text $gw.Text $secret.Text
        $successText=('Agente {0} instalado y asignado a {1} · {2}.' -f $agent.Text,$code.Text,$name.Text)
        try {
            $installedCfg=Get-Content -LiteralPath (Join-Path $InstallRoot 'agent.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if($null -ne $installedCfg.remote_access -and
               ($installedCfg.remote_access.PSObject.Properties.Name -contains 'support_state') -and
               ([string]$installedCfg.remote_access.support_state -eq 'unsupported')){
                $successText += "`r`n`r`nAcceso remoto de escritorio: NO DISPONIBLE en esta edición de Windows. El Agent, heartbeat, jobs y reverse tunnel quedaron instalados. GIDEON no instaló VNC/RDP de terceros."
            }
        } catch {}
        [System.Windows.Forms.MessageBox]::Show($successText,'GIDEON Agent',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        $form.DialogResult=[System.Windows.Forms.DialogResult]::OK; $form.Close()
    } catch {
        $message=[string]$_.Exception.Message
        $where=[string]$_.InvocationInfo.PositionMessage
        $stack=[string]$_.ScriptStackTrace
        Write-GideonInstallLog ('ERROR instalador: ' + $message)
        if(-not [string]::IsNullOrWhiteSpace($where)){ Write-GideonInstallLog ('ERROR posicion: ' + ($where -replace "`r?`n",' | ')) }
        if(-not [string]::IsNullOrWhiteSpace($stack)){ Write-GideonInstallLog ('ERROR stack: ' + ($stack -replace "`r?`n",' | ')) }
        $diag=New-GideonInstallDiagnostic $message 'GUI install'
        Write-GideonInstallLog ('DIAGNOSTIC_FILE='+$diag)
        Show-GideonDiagnosticError $message $diag
        $ok.Enabled=$true; $cancel.Enabled=$true; $status.Text=('No se completó. Diagnóstico: ' + $diag)
    }
})
$result=$form.ShowDialog()
if($result -ne [System.Windows.Forms.DialogResult]::OK){ throw 'Instalación cancelada antes de asignar la identidad del agente.' }
