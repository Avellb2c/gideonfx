(()=>{
  const form=document.getElementById('remoteSessionForm'); if(!form) return;
  const type=document.getElementById('remoteSourceType'), id=document.getElementById('remoteSourceId');
  const ip=document.getElementById('remoteTargetIp'), label=document.getElementById('remoteSelectedTarget');
  const routeHelp=document.getElementById('remoteRouteHelp'), preflight=document.getElementById('remotePreflight');
  const sourceSearch=document.getElementById('remoteSourceSearch'), sourceFilterStatus=document.getElementById('remoteSourceFilterStatus');
  const platformFilter=document.getElementById('remotePlatformFilter'), availabilityFilter=document.getElementById('remoteAvailabilityFilter');
  const tunnelFilter=document.getElementById('remoteTunnelFilter');
  const protocol=document.getElementById('remoteProtocol'), port=document.getElementById('remoteTargetPort');
  const credential=document.getElementById('remoteCredential'), summary=document.getElementById('remoteAutoSummary');
  const fileTransfer=document.getElementById('remoteFileTransferEnabled');
  const fileTransferHelp=document.getElementById('remoteFileTransferHelp');
  const protocolHelp=document.getElementById('remoteProtocolHelp');
  const desktopKind=document.getElementById('remoteDesktopKind'), desktopKindPanel=document.getElementById('remoteDesktopKindPanel');
  const desktopKindHelp=document.getElementById('remoteDesktopKindHelp');
  const sessionMode=document.getElementById('remoteSessionMode'), sessionModePanel=document.getElementById('remoteSessionModePanel');
  const sessionModeHelp=document.getElementById('remoteSessionModeHelp');
  const vaultPanel=document.getElementById('remoteVaultCredentialPanel'), interactivePanel=document.getElementById('remoteInteractivePanel');
  const privacy=document.getElementById('remoteCredentialPrivacy');
  const dialog=document.getElementById('remoteCredentialDialog'), dialogTitle=document.getElementById('remoteCredentialDialogTitle');
  const dialogSubtitle=document.getElementById('remoteCredentialDialogSubtitle');
  const interactiveFields=document.getElementById('remoteInteractiveFields'), mfaFields=document.getElementById('remoteMfaFields');
  const mfaReuseNotice=document.getElementById('remoteMfaReuseNotice');
  const interactiveUser=document.getElementById('remoteInteractiveUsername'), interactivePassword=document.getElementById('remoteInteractivePassword');
  const interactiveDomain=document.getElementById('remoteInteractiveDomain'), interactiveCompatibility=document.getElementById('remoteInteractiveCompatibility');
  const passwordToggle=document.getElementById('remoteInteractivePasswordToggle');
  const mfa=document.getElementById('remoteMfaCode'), dialogError=document.getElementById('remoteDialogError');
  const dialogClose=document.getElementById('remoteDialogClose'), dialogCancel=document.getElementById('remoteDialogCancel');
  const dialogContinue=document.getElementById('remoteDialogContinue');
  const intentPicker=document.getElementById('remoteIntentPicker'), intentHelp=document.getElementById('remoteIntentHelp');
  const impactAcknowledgement=document.getElementById('remoteIntentAcknowledgement');
  const impactAcknowledged=document.getElementById('remoteIntentAcknowledged');
  const impactAcknowledgementText=document.getElementById('remoteIntentAcknowledgementText');
  const remoteStepUpClientId=(()=>{
    const key='gideon.remote.stepup.client.v2', legacyKey='gideon.remote.stepup.client.v1';
    try{
      let value=String(localStorage.getItem(key)||sessionStorage.getItem(legacyKey)||'').trim();
      if(!/^[A-Za-z0-9._:-]{16,128}$/.test(value)){
        value=(globalThis.crypto&&typeof crypto.randomUUID==='function')
          ?crypto.randomUUID()
          :`gideon-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
      }
      localStorage.setItem(key,value);
      sessionStorage.removeItem(legacyKey);
      return value;
    }catch(_){
      return `gideon-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
    }
  })();
  const stepUpClientInput=document.getElementById('remoteStepUpClientId');
  if(stepUpClientInput) stepUpClientInput.value=remoteStepUpClientId;
  const interactiveUsernameKey='gideon.remote.interactive.username.v1';
  try{
    if(interactiveUser&&!interactiveUser.value.trim()) interactiveUser.value=String(localStorage.getItem(interactiveUsernameKey)||'').trim().slice(0,256);
  }catch(_){}

  let stepUpActive=false;
  let stepUpRemainingSeconds=0;
  let stepUpProbeInFlight=null;
  let stepUpProbeTimer=null;
  const defaultRdpSecurity=String(form.dataset.rdpSecurity||'nla').toLowerCase();
  let rdpSecurity=defaultRdpSecurity;
  let rdpSecurityDetected=false;
  let selectedSessionCapability={product:'',model:'unknown',concurrent:false,concurrentLicensed:false,admin:false,screenShare:false,background:false,activeUser:'',activeDomain:'',activeSession:''};
  let selectedRemoteProfile={known:false,platform:'',protocol:'RDP',protocols:['RDP'],port:3389,server:'',ports:{RDP:3389,VNC:5900},servers:{},readyMap:{},passwordRequired:{RDP:true,VNC:true},sessionKinds:{},ready:null,reason:'',fileTransfer:true};
  let selectedSourceFilter='ALL';
  const parseJsonMap=value=>{try{const parsed=JSON.parse(String(value||'{}'));return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?parsed:{};}catch(_){return {};}};
  const isPasswordlessPhysical=()=>protocol.value==='VNC'&&selectedRemoteProfile.sessionKinds?.VNC==='physical-console'&&selectedRemoteProfile.passwordRequired?.VNC===false;

  const sessionModeText=()=>({
    STANDARD:'Acceso RDP normal',
    RESUME:'Continuar sesión del mismo usuario',
    ADMIN:'Consola administrativa',
    SEPARATE:'Sesión separada con RDS',
    SHARE:'Compartir pantalla física'
  })[String(sessionMode?.value||'STANDARD')]||'Acceso RDP normal';

  const selectedIntent=()=>document.querySelector('input[name="connection_intent"]:checked')?.value||'';
  const activeIdentityText=()=>selectedSessionCapability.activeUser
    ?`${selectedSessionCapability.activeDomain?`${selectedSessionCapability.activeDomain}\\`:''}${selectedSessionCapability.activeUser}`
    :'';
  const normalizeIdentity=value=>String(value||'').trim().toLocaleLowerCase()
    .replace(/^.*\\/,'').replace(/^.*\//,'').replace(/@.*$/,'');
  const requestedIdentity=()=>{
    if(mode()==='INTERACTIVE') return normalizeIdentity(interactiveUser?.value||'');
    const option=credential?.selectedOptions?.[0];
    return normalizeIdentity(option?.dataset.vaultUsername||'');
  };
  const isPhysicalConsoleAvailable=()=>type.value==='AGENT'
    && selectedRemoteProfile.sessionKinds?.VNC==='physical-console'
    && selectedRemoteProfile.readyMap?.VNC===true;
  const isIndependentSessionAvailable=()=>{
    if(type.value!=='AGENT'||selectedRemoteProfile.readyMap?.RDP!==true) return false;
    const kind=String(selectedRemoteProfile.sessionKinds?.RDP||'').toLowerCase();
    const server=String(selectedRemoteProfile.servers?.RDP||selectedRemoteProfile.server||'').toLowerCase();
    return kind==='independent-desktop'||kind==='xrdp-desktop'||server.includes('xrdp')||selectedSessionCapability.concurrent;
  };
  const isAdminConsoleAvailable=()=>type.value==='AGENT'
    && selectedRemoteProfile.platform==='windows'
    && selectedRemoteProfile.readyMap?.RDP===true
    && selectedSessionCapability.admin;
  const intentDefinitions=()=>({
    PHYSICAL_CONSOLE:{
      available:isPhysicalConsoleAvailable(), protocol:'VNC', sessionMode:'STANDARD',
      detail:isPhysicalConsoleAvailable()
        ?'Disponible: el Agent anunció VNC de consola física. Verá y controlará el monitor real.'
        :'No disponible: sólo se habilita cuando el Agent anuncia VNC con SessionKind=physical-console. RDP/Guacamole no puede prometer compartir la consola física.'
    },
    INDEPENDENT_SESSION:{
      available:isIndependentSessionAvailable(), protocol:'RDP', sessionMode:selectedSessionCapability.concurrent?'SEPARATE':'STANDARD',
      detail:isIndependentSessionAvailable()
        ?(selectedSessionCapability.concurrent
          ?'Disponible con RDP. El Agent reporta host multi-sesión; las licencias RDS deben estar activas.'
          :'Disponible con XRDP. Abrirá un escritorio independiente, no el monitor físico.')
        :'No disponible: requiere XRDP anunciado o Windows Server/RDS reportado por el Agent.'
    },
    ADMIN_CONSOLE:{
      available:isAdminConsoleAvailable(), protocol:'RDP', sessionMode:'ADMIN',
      detail:isAdminConsoleAvailable()
        ?'Disponible: abre la consola administrativa RDP. No representa ni comparte el monitor físico.'
        :'No disponible: requiere Windows con RDP administrativo anunciado por el Agent.'
    },
    STANDARD_ACCESS:{
      available:type.value==='HOST', protocol:String(protocol?.value||'RDP').toUpperCase(), sessionMode:'STANDARD',
      detail:'Host directo: GIDEON probará el servicio indicado, pero no dispone de telemetría de usuarios, túnel, consentimiento ni impacto local.'
    }
  });
  const intentLabel=value=>({
    PHYSICAL_CONSOLE:'Controlar pantalla física',
    INDEPENDENT_SESSION:'Abrir sesión independiente',
    ADMIN_CONSOLE:'Consola administrativa',
    STANDARD_ACCESS:'Acceso directo de compatibilidad'
  })[String(value||'')]||'Intención no seleccionada';
  const currentImpact=()=>{
    const intent=selectedIntent();
    const active=activeIdentityText();
    const requested=requestedIdentity();
    const activeShort=normalizeIdentity(selectedSessionCapability.activeUser);
    if(type.value==='HOST') return {
      kind:'DIRECT_HOST_UNKNOWN', requiresAck:true,
      text:'El host directo no publica telemetría de sesión. Su impacto local y consentimiento no pueden verificarse antes de abrir.',
      consent:'No compatible: sin Agent no hay telemetría ni consentimiento administrado por GIDEON.'
    };
    if(intent==='PHYSICAL_CONSOLE') return {
      kind:'PHYSICAL_CONSOLE_VISIBLE', requiresAck:true,
      text:'Controlará la pantalla física visible en el monitor. La persona frente al equipo verá la misma interacción.',
      consent:'Autorización del operador requerida. El Agent no confirma consentimiento humano para esta consola física.'
    };
    if(intent==='INDEPENDENT_SESSION') return {
      kind:'INDEPENDENT_SESSION', requiresAck:false,
      text:'El método anunciado crea un escritorio independiente; no debe sustituir la pantalla física.',
      consent:'No aplica cambio de sesión local según la capacidad anunciada.'
    };
    if(selectedRemoteProfile.platform==='windows'&&selectedSessionCapability.model==='single-interactive-session'&&active){
      const sameIdentity=Boolean(requested&&activeShort&&requested===activeShort);
      if(sameIdentity) return {
        kind:'RESUME_SAME_USER', requiresAck:false,
        text:`Se reanudará la sesión de ${active}; la pantalla local puede bloquearse al transferirse a RDP.`,
        consent:'No se solicitó sustituir a otra cuenta. Windows puede requerir su flujo normal de reanudación.'
      };
      return {
        kind:'POSSIBLE_SESSION_HANDOFF', requiresAck:true,
        text:`Hay una sesión de ${active}. Otra cuenta puede bloquearla, transferirla o desconectarla para abrir RDP.`,
        consent:'Windows puede mostrar una confirmación. El Agent intentará aceptar sólo el diálogo RDP identificado durante 35 s; eso es automatización autorizada por el operador, no consentimiento humano verificable.'
      };
    }
    return {
      kind:intent==='ADMIN_CONSOLE'?'ADMIN_CONSOLE':'NO_LOCAL_IMPACT', requiresAck:false,
      text:intent==='ADMIN_CONSOLE'
        ?'La consola administrativa no afirma compartir el monitor físico. El impacto real depende de la política del Windows remoto.'
        :'No se reporta una afectación de otra sesión para esta elección.',
      consent:'No aplica un cambio de sesión reportado por el Agent.'
    };
  };
  const renderImpactAcknowledgement=()=>{
    if(!impactAcknowledgement) return;
    const impact=currentImpact();
    impactAcknowledgement.hidden=!impact.requiresAck;
    if(!impact.requiresAck&&impactAcknowledged) impactAcknowledged.checked=false;
    if(impactAcknowledgementText) impactAcknowledgementText.textContent=impact.requiresAck
      ?`${impact.text} GIDEON registrará esta autorización del operador; no equivale a consentimiento verificable de una persona frente al equipo.`
      :'No se requiere confirmación adicional para el impacto reportado.';
  };
  const renderIntentPicker=(chooseDefault=false)=>{
    if(!intentPicker) return;
    if(!type.value||!id.value){intentPicker.hidden=true;return;}
    intentPicker.hidden=false;
    const definitions=intentDefinitions();
    Object.entries(definitions).forEach(([value,definition])=>{
      const card=document.querySelector(`[data-intent-card="${value}"]`);
      const input=card?.querySelector('input[name="connection_intent"]');
      const detail=card?.querySelector('[data-intent-detail]');
      if(card) card.hidden=value==='STANDARD_ACCESS'&&type.value!=='HOST';
      if(input) input.disabled=!definition.available;
      if(detail) detail.textContent=definition.detail;
    });
    let intent=selectedIntent();
    if(chooseDefault&&(!definitions[intent]?.available)){
      const fallback=type.value==='HOST'
        ?'STANDARD_ACCESS'
        :(definitions.INDEPENDENT_SESSION.available?'INDEPENDENT_SESSION'
          :definitions.ADMIN_CONSOLE.available?'ADMIN_CONSOLE'
          :definitions.PHYSICAL_CONSOLE.available?'PHYSICAL_CONSOLE':'');
      const input=fallback?document.querySelector(`input[name="connection_intent"][value="${fallback}"]`):null;
      if(input){input.checked=true;intent=fallback;}
    }
    const definition=definitions[intent];
    if(intentHelp){
      intentHelp.textContent=definition
        ?`${intentLabel(intent)} · ${definition.detail}`
        :'Este destino no tiene una intención guiada compatible. Revise su Agent, túnel y servicio remoto.';
      intentHelp.className=`alert ${definition?.available?'info':'warning'}`;
    }
    renderImpactAcknowledgement();
  };
  const applyIntent=value=>{
    const definition=intentDefinitions()[String(value||'')];
    if(!definition?.available) return false;
    if(protocol) protocol.value=definition.protocol;
    if(sessionMode) sessionMode.value=definition.sessionMode;
    if(port) port.dataset.userEdited='';
    setCredentialFilter();
    renderIntentPicker(false);
    return true;
  };

  const renderSessionMode=()=>{
    if(!sessionMode) return;
    const isRdp=protocol.value==='RDP';
    if(sessionModePanel) sessionModePanel.hidden=!isRdp;
    if(!isRdp){sessionMode.value='STANDARD';return;}
    const separate=[...sessionMode.options].find(option=>option.value==='SEPARATE');
    const share=[...sessionMode.options].find(option=>option.value==='SHARE');
    if(separate) separate.disabled=!selectedSessionCapability.concurrent;
    // Screen sharing needs GIDEON's future interactive capture/control transport;
    // the existing Guacamole RDP path cannot safely impersonate that feature.
    if(share) share.disabled=true;
    if(sessionMode.selectedOptions?.[0]?.disabled) sessionMode.value='STANDARD';
    if(!sessionModeHelp) return;
    const product=selectedSessionCapability.product||'Windows no identificado';
    const background=selectedSessionCapability.background?' Agent residente y túnel disponibles antes del inicio de sesión.':'';
    let message=''; let css='info';
    switch(sessionMode.value){
      case 'RESUME':
        const activeIdentity=selectedSessionCapability.activeUser
          ?`${selectedSessionCapability.activeDomain?`${selectedSessionCapability.activeDomain}\\`:''}${selectedSessionCapability.activeUser}`
          :'la cuenta que está abierta en la consola';
        message=`Use exactamente ${activeIdentity}. ${product} intentará reanudar esa sesión, pero la pantalla local se bloqueará o transferirá a RDP; no es una visualización compartida.${background}`;
        css='warning'; break;
      case 'ADMIN':
        message=`Solicita la consola administrativa mediante Guacamole. En ${product} no crea concurrencia ni comparte la pantalla física.${background}`;
        css='warning'; break;
      case 'SEPARATE':
        message=`${product} reporta capacidad de host multi-sesión. El administrador debe confirmar que el rol RDS y sus licencias estén activos.${background}`;
        css='success'; break;
      default:
        if(selectedSessionCapability.concurrent){
          message=`${product} permite iniciar una sesión RDP normal; la concurrencia efectiva depende del rol y licencias RDS.${background}`;
        }else if(selectedSessionCapability.model==='single-interactive-session'){
          message=`${product} admite una sola sesión interactiva. La misma cuenta puede reanudar su sesión; otra cuenta sustituirá o desconectará el escritorio local.${background}`;
          css='warning';
        }else{
          message=`No hay telemetría suficiente para prometer una sesión paralela. GIDEON usará RDP normal y bloqueará el modo separado.${background}`;
          css='warning';
        }
    }
    sessionModeHelp.textContent=message;
    sessionModeHelp.className=`alert ${css}`;
  };

  const renderMfaRequirement=active=>{
    const reuse=Boolean(active);
    if(mfaFields){
      mfaFields.hidden=reuse;
      mfaFields.classList.toggle('gideon-hidden',reuse);
      mfaFields.style.setProperty('display',reuse?'none':'grid','important');
    }
    if(mfaReuseNotice){
      mfaReuseNotice.hidden=!reuse;
      mfaReuseNotice.classList.toggle('gideon-hidden',!reuse);
    }
    if(mfa){
      mfa.disabled=reuse;
      if(reuse) mfa.value='';
    }
  };

  const applyStepUpState=(active,remainingSeconds=0)=>{
    stepUpActive=Boolean(active);
    stepUpRemainingSeconds=Math.max(0,Number(remainingSeconds||0));
    form.dataset.stepUpActive=stepUpActive?'1':'0';
    form.dataset.stepUpRemainingSeconds=String(stepUpRemainingSeconds);
    renderMfaRequirement(stepUpActive);
    const card=document.getElementById('remoteStepUpStatus');
    if(card){
      card.classList.toggle('success',stepUpActive);
      card.classList.toggle('warning',!stepUpActive);
      const strong=card.querySelector('strong');
      const detail=card.querySelector('span');
      if(stepUpActive){
        const mins=Math.max(1,Math.ceil(stepUpRemainingSeconds/60));
        if(strong) strong.textContent='MFA remoto activo';
        if(detail) detail.textContent=`${mins} min restantes · puede abrir nuevas conexiones sin volver a ingresar MFA.`;
      }else{
        if(strong) strong.textContent='MFA remoto requerido';
        if(detail) detail.textContent='Se pedirá una sola vez y se reutilizará durante 15 minutos para otros servidores/listas en este navegador.';
      }
    }
  };

  const refreshStepUpState=async()=>{
    if(stepUpProbeInFlight) return stepUpProbeInFlight;
    stepUpProbeInFlight=(async()=>{
      try{
        const response=await fetch('/remote/step-up-status',{
          method:'GET',
          credentials:'same-origin',
          cache:'no-store',
          headers:{
            'Accept':'application/json',
            'X-GIDEON-StepUp-Client':remoteStepUpClientId
          }
        });
        if(!response.ok){applyStepUpState(false,0);return false;}
        const status=await response.json();
        const active=Boolean(status?.active);
        const remaining=Math.max(0,Number(status?.remaining_seconds||0));
        applyStepUpState(active,remaining);
        if(window.GIDEON_STEP_UP&&typeof window.GIDEON_STEP_UP==='object'){
          window.GIDEON_STEP_UP.active=active;
          window.GIDEON_STEP_UP.remaining_seconds=remaining;
        }
        return active;
      }catch(_){
        // Fail closed for UX too: if the authoritative status cannot be read,
        // ask for MFA instead of trusting stale state from the page.
        applyStepUpState(false,0);
        return false;
      }finally{
        stepUpProbeInFlight=null;
      }
    })();
    return stepUpProbeInFlight;
  };

  const scheduleStepUpRefresh=()=>{
    clearTimeout(stepUpProbeTimer);
    stepUpProbeTimer=setTimeout(()=>{refreshStepUpState();},500);
    setTimeout(()=>{refreshStepUpState();},1500);
    setTimeout(()=>{refreshStepUpState();},3000);
  };
  let preparedViewerWindow=null;
  let preparedViewerWindowName='';

  const prepareViewerWindow=()=>{
    if(preparedViewerWindow&&!preparedViewerWindow.closed&&preparedViewerWindowName){
      form.target=preparedViewerWindowName;
      try{preparedViewerWindow.focus();}catch(_){}
      return true;
    }
    const stamp=Date.now().toString(36);
    const random=Math.random().toString(36).slice(2,8);
    const name=`gideonRemoteSession_${stamp}_${random}`;
    const availW=Math.max(960,Number(screen?.availWidth||1400));
    const availH=Math.max(640,Number(screen?.availHeight||900));
    const width=Math.max(900,Math.min(availW-40,1680));
    const height=Math.max(620,Math.min(availH-50,980));
    const left=Math.max(0,Math.floor(Number(screen?.availLeft||0)+(availW-width)/2));
    const top=Math.max(0,Math.floor(Number(screen?.availTop||0)+(availH-height)/2));
    const features=`popup=yes,resizable=yes,scrollbars=no,width=${width},height=${height},left=${left},top=${top}`;
    const child=window.open('about:blank',name,features);
    if(!child){
      form.removeAttribute('target');
      label.textContent='Chrome bloqueó la ventana separada. La sesión se abrirá en esta pestaña; luego puede usar “Ventana aparte”.';
      label.className='alert warning';
      return false;
    }
    preparedViewerWindow=child;
    preparedViewerWindowName=name;
    form.target=name;
    try{
      child.document.title='GIDEON Remote Session · Conectando';
      child.document.body.style.cssText='margin:0;background:#081118;color:#eaf2f6;font:14px Segoe UI,Arial,sans-serif;display:grid;place-items:center;min-height:100vh';
      child.document.body.textContent='Abriendo sesión remota GIDEON…';
    }catch(_){}
    return true;
  };

  const mode=()=>document.querySelector('input[name="credential_mode"]:checked')?.value||'VAULT';
  const compatibleCredentials=proto=>[...credential.options].filter((o,i)=>i>0&&o.dataset.protocol===proto&&!o.disabled);
  const showDialogError=msg=>{dialogError.textContent=msg||'';dialogError.hidden=!msg;};
  const setPasswordVisible=visible=>{
    if(!interactivePassword||!passwordToggle) return;
    interactivePassword.type=visible?'text':'password';
    passwordToggle.textContent=visible?'Ocultar':'Mostrar';
    passwordToggle.setAttribute('aria-pressed',visible?'true':'false');
    passwordToggle.setAttribute('aria-label',visible?'Ocultar contraseña':'Mostrar contraseña');
  };
  const selectedRouteText=()=>{
    if(type.value==='AGENT') return `Túnel inverso · ${protocol.value||'RDP'} local:${port.value||'—'}`;
    return `${ip.value||'Host del inventario'}:${port.value||'—'}`;
  };
  const renderPreflight=()=>{
    if(!preflight) return;
    if(!type.value||!id.value){preflight.hidden=true;preflight.replaceChildren();return;}
    const heading=document.createElement('strong');
    heading.textContent=type.value==='AGENT'?'Preflight verificado por Agent':'Preflight de host directo';
    const route=document.createElement('span');route.id='remotePreflightRoute';route.className='chip info';route.textContent=selectedRouteText();
    const capability=document.createElement('span');capability.className=`chip ${selectedRemoteProfile.ready===false?'danger':'success'}`;
    capability.textContent=type.value==='AGENT'?(selectedRemoteProfile.ready===false?'SERVICIO NO LISTO':'SERVICIO ANUNCIADO'):'RUTA DIRECTA';
    const detail=document.createElement('p');detail.className='muted';
    const impact=currentImpact();
    detail.id='remotePreflightImpact';
    detail.textContent=impact.text;
    const meta=document.createElement('div');meta.className='remote-preflight-meta';
    const protocolMeta=document.createElement('span');protocolMeta.id='remotePreflightProtocol';protocolMeta.textContent=`Protocolo real: ${protocol.value||'RDP'}${selectedRemoteProfile.server?` · ${selectedRemoteProfile.server}`:''}`;
    const user=document.createElement('span');user.id='remotePreflightUser';user.textContent=type.value==='AGENT'
      ?`Usuario activo: ${activeIdentityText()||'sin usuario reportado por el Agent'}`
      :'Usuario activo: no disponible en un host directo';
    const session=document.createElement('span');session.textContent=`Intención: ${intentLabel(selectedIntent())} · ${sessionModeText()}`;
    const transfer=document.createElement('span');transfer.textContent=`Archivos: ${fileTransfer?.disabled?'no disponibles':fileTransfer?.checked?'habilitados':'deshabilitados'}`;
    const consent=document.createElement('span');consent.id='remotePreflightConsent';consent.textContent=`Consentimiento: ${impact.consent}`;
    const freshness=document.createElement('span');freshness.id='remotePreflightFreshness';freshness.textContent=type.value==='AGENT'
      ?'Telemetría: último heartbeat autenticado del Agent'
      :'Telemetría: no disponible; GIDEON realizará una sonda de red antes de abrir';
    meta.append(protocolMeta,user,session,transfer,consent,freshness);
    const top=document.createElement('div');top.className='remote-preflight-top';top.append(heading,route,capability);
    preflight.replaceChildren(top,detail,meta);preflight.hidden=false;
    renderImpactAcknowledgement();
  };
  const renderSummary=()=>{
    if(!summary) return;
    const primary=document.createElement('strong');
    primary.textContent=`${protocol.value||'RDP'} · ${selectedRouteText()}`;
    const secondary=document.createElement('span');
    secondary.className='muted';
    if(mode()==='INTERACTIVE'){
      secondary.textContent=`Sesión interactiva · ${sessionModeText()} · credencial temporal`;
      summary.replaceChildren(primary,secondary);
      renderPreflight();
      return;
    }
    const cred=credential.selectedOptions?.[0];
    const credText=cred&&cred.value?cred.textContent.trim():'Sin perfil compatible';
    secondary.textContent=`${sessionModeText()} · ${credText}`;
    summary.replaceChildren(primary,secondary);
    renderPreflight();
  };
  const setCredentialFilter=()=>{
    const proto=protocol.value||'RDP'; let first='';
    const allowed=new Set((selectedRemoteProfile.protocols||['RDP']).map(value=>String(value).toUpperCase()));
    [...protocol.options].forEach(option=>{option.disabled=type.value==='AGENT'&&selectedRemoteProfile.known&&!allowed.has(option.value);});
    if(protocol.selectedOptions?.[0]?.disabled){protocol.value=selectedRemoteProfile.protocol||'RDP';}
    const activeProto=protocol.value||'RDP';
    if(fileTransfer){
      fileTransfer.disabled=activeProto!=='RDP'||(type.value==='AGENT'&&selectedRemoteProfile.known&&!selectedRemoteProfile.fileTransfer);
      if(fileTransfer.disabled) fileTransfer.checked=false;
      else if(!fileTransfer.dataset.userEdited) fileTransfer.checked=true;
    }
    if(fileTransferHelp){
      if(activeProto!=='RDP') fileTransferHelp.textContent='La transferencia de archivos sólo está disponible sobre RDP.';
      else if(type.value==='AGENT'&&selectedRemoteProfile.known&&!selectedRemoteProfile.fileTransfer) fileTransferHelp.textContent=selectedRemoteProfile.fileTransferReason||'El Agent no anunció xrdp-chansrv/RDPDR; use Transferencias para enviar el archivo por HTTPS/PULL.';
      else fileTransferHelp.textContent='Activa la unidad temporal GIDEON Transfer del equipo remoto.';
    }
    [...credential.options].forEach((opt,index)=>{
      if(index===0){opt.hidden=false;return;}
      const visible=opt.dataset.protocol===activeProto; opt.hidden=!visible; opt.disabled=!visible;
      if(visible&&!first) first=opt.value;
    });
    if(mode()==='VAULT'&&(!credential.value||credential.selectedOptions[0]?.dataset.protocol!==activeProto)) credential.value=first||'';
    if(!port.dataset.userEdited) port.value=type.value==='AGENT'&&selectedRemoteProfile.known
      ?String(selectedRemoteProfile.ports?.[activeProto]||selectedRemoteProfile.port|| (activeProto==='VNC'?'5900':'3389'))
      :(activeProto==='VNC'?'5900':'3389');
    if(protocolHelp){
      if(type.value==='AGENT'&&selectedRemoteProfile.known){
        const activeReady=selectedRemoteProfile.readyMap?.[activeProto]??selectedRemoteProfile.ready;
        const activeServer=selectedRemoteProfile.servers?.[activeProto]||selectedRemoteProfile.server;
        const state=activeReady?'listo':'no listo';
        protocolHelp.textContent=`${activeProto}${activeServer?' · '+activeServer:''} · puerto ${selectedRemoteProfile.ports?.[activeProto]||port.value} · ${state}${selectedRemoteProfile.reason?' · '+selectedRemoteProfile.reason:''}`;
      }else protocolHelp.textContent='El Agent anunciará el protocolo y puerto local disponibles.';
    }
    if(desktopKind){
      desktopKind.value=activeProto;
      [...desktopKind.options].forEach(option=>{option.disabled=!allowed.has(option.value);});
      const agentDesktopChoice=type.value==='AGENT'&&(isPhysicalConsoleAvailable()||isIndependentSessionAvailable());
      desktopKindPanel.hidden=!agentDesktopChoice;
      if(desktopKindHelp&&agentDesktopChoice){
        desktopKindHelp.textContent=isPasswordlessPhysical()
          ?'Pantalla física: el Agent anunció un VNC de consola física. Verá y controlará exactamente el escritorio conectado al monitor.'
          :'Sesión independiente: el Agent anunció XRDP/RDS. No representa la pantalla que ve el usuario frente al monitor.';
        desktopKindHelp.className=`alert ${isPasswordlessPhysical()?'success':'info'}`;
      }
    }
    if(isPasswordlessPhysical()){
      const interactiveChoice=document.querySelector('input[name="credential_mode"][value="INTERACTIVE"]');
      if(interactiveChoice&&!interactiveChoice.checked){interactiveChoice.checked=true;renderCredentialMode();}
    }
    if(interactiveCompatibility) interactiveCompatibility.open=activeProto==='VNC'||activeProto==='RDP';
    renderSessionMode();
    renderSummary();
  };
  const renderCredentialMode=()=>{
    const interactive=mode()==='INTERACTIVE';
    vaultPanel.hidden=interactive; interactivePanel.hidden=!interactive;
    credential.required=!interactive;
    if(privacy) privacy.textContent=interactive
      ?(isPasswordlessPhysical()?'La pantalla física se autoriza con su sesión WebAdmin, MFA, mTLS y un ticket de un solo uso; no se solicita ni almacena una clave VNC.':'Se recuerda solo el usuario en este navegador. MFA autoriza nuevas conexiones durante 15 minutos; el código TOTP nunca se guarda.')
      :'El secreto del perfil Vault se descifra únicamente en el servidor al establecer la sesión.';
    renderSummary();
  };
  const selectSource=radio=>{
    if(!radio) return;
    type.value=radio.dataset.sourceType||''; id.value=radio.dataset.sourceId||'';
    rdpSecurity=String(radio.dataset.rdpSecurity||defaultRdpSecurity).toLowerCase();
    rdpSecurityDetected=radio.dataset.rdpDetected==='1';
    selectedSessionCapability={
      product:String(radio.dataset.rdpProductName||'').trim(),
      model:String(radio.dataset.rdpSessionModel||'unknown').trim(),
      concurrent:radio.dataset.rdpConcurrent==='1',
      concurrentLicensed:radio.dataset.rdpConcurrentLicensed==='1',
      admin:radio.dataset.rdpAdmin==='1',
      screenShare:radio.dataset.rdpScreenShare==='1',
      background:radio.dataset.agentBackground==='1',
      activeUser:String(radio.dataset.activeConsoleUser||'').trim(),
      activeDomain:String(radio.dataset.activeConsoleDomain||'').trim(),
      activeSession:String(radio.dataset.activeConsoleSession||'').trim()
    };
    if(impactAcknowledged) impactAcknowledged.checked=false;
    label.textContent=`Destino: ${radio.dataset.sourceLabel||radio.value}`; label.className='alert success';
    let ips=[]; try{ips=JSON.parse(radio.dataset.targetIps||'[]');}catch(_){ips=[];}
    const advertised=String(radio.dataset.remoteProtocols||'').split(',').map(value=>value.trim().toUpperCase()).filter(value=>value==='RDP'||value==='VNC');
    selectedRemoteProfile={
      known:type.value==='AGENT'&&radio.dataset.remoteReady!=='',
      platform:String(radio.dataset.platform||'').toLowerCase(),
      protocol:String(radio.dataset.remoteProtocol||'RDP').toUpperCase(),
      protocols:advertised.length?advertised:['RDP'],
      port:Number(radio.dataset.remotePort||3389)||3389,
      server:String(radio.dataset.remoteServer||''),
      ready:radio.dataset.remoteReady==='1',
      reason:String(radio.dataset.remoteReason||''),
      fileTransfer:String(radio.dataset.remoteFileTransfer||'0')==='1',
      fileTransferReason:String(radio.dataset.remoteFileTransferReason||''),
      ports:parseJsonMap(radio.dataset.remotePorts),
      servers:parseJsonMap(radio.dataset.remoteServers),
      readyMap:parseJsonMap(radio.dataset.remoteReadyMap),
      passwordRequired:parseJsonMap(radio.dataset.remotePasswordRequired),
      sessionKinds:parseJsonMap(radio.dataset.remoteSessionKinds)
    };
    ip.replaceChildren();
    if(type.value==='AGENT'){
      const o=document.createElement('option');o.value='';o.textContent='Túnel inverso administrado por GIDEON';ip.append(o);
      ip.disabled=true;
      if(routeHelp) routeHelp.textContent='La IP privada no se usa ni se expone en esta sesión. GIDEON reserva un túnel al servicio local anunciado por el Agent.';
    }else{
      ip.disabled=false;
      if(!ips.length){const o=document.createElement('option');o.value='';o.textContent='Sin IP disponible';ip.append(o);}
      else ips.forEach(value=>{const o=document.createElement('option');o.value=value;o.textContent=value;ip.append(o);});
      if(routeHelp) routeHelp.textContent='GIDEON valida la ruta directa contra el host registrado en inventario.';
    }
    protocol.value=selectedRemoteProfile.protocol||'RDP'; port.dataset.userEdited=''; setCredentialFilter();
    renderIntentPicker(true);
    if(selectedIntent()) applyIntent(selectedIntent());
    else renderSummary();
  };
  const openDialog=()=>{
    const interactive=mode()==='INTERACTIVE';
    interactiveFields.hidden=!interactive||isPasswordlessPhysical();
    renderMfaRequirement(stepUpActive);
    dialogTitle.textContent=interactive?'Credencial para esta sesión':'Confirmar acceso remoto';
    const impact=currentImpact();
    dialogSubtitle.textContent=interactive
      ?(isPasswordlessPhysical()
        ?`Intención: ${intentLabel(selectedIntent())}. ${impact.text} La autorización se limita al túnel mTLS y a este ticket de un solo uso.`
        :protocol.value==='RDP'
        ?`${intentLabel(selectedIntent())}. ${rdpSecurityDetected?'El Agent detectó':'GIDEON iniciará con'} ${rdpSecurity.toUpperCase()}: ingrese usuario y contraseña de Windows; GIDEON probará automáticamente los modos autorizados sin guardar la clave. ${impact.text}`
        :'Ingrese la credencial temporal requerida por el equipo remoto.')
      :`${intentLabel(selectedIntent())}. El perfil guardado se tomará del Vault GIDEON. ${impact.text}`;
    showDialogError('');
    setPasswordVisible(false);
    if(typeof dialog.showModal==='function') dialog.showModal(); else dialog.setAttribute('open','');
    setTimeout(()=>{if(interactive) interactiveUser.focus(); else if(!stepUpActive) mfa.focus();},0);
  };
  const closeDialog=()=>{showDialogError(''); if(typeof dialog.close==='function') dialog.close(); else dialog.removeAttribute('open');};
  const validateBeforeOpen=()=>{
    if(!type.value||!id.value){label.textContent='Seleccione un equipo antes de abrir la sesión.';label.className='alert danger';return false;}
    const intent=selectedIntent(), definition=intentDefinitions()[intent];
    if(!intent||!definition?.available){label.textContent='Seleccione una intención compatible con la capacidad real del destino.';label.className='alert danger';return false;}
    if(currentImpact().requiresAck&&!impactAcknowledged?.checked){label.textContent='Confirme la autorización del operador para el impacto indicado antes de abrir la sesión.';label.className='alert danger';impactAcknowledged?.focus();return false;}
    if(mode()==='VAULT'&&!credential.value){label.textContent='Seleccione un perfil GIDEON compatible con el protocolo.';label.className='alert danger';return false;}
    if(protocol.value==='RDP'&&sessionMode?.value==='SEPARATE'&&!selectedSessionCapability.concurrent){label.textContent='Este equipo no reporta Windows Server/RDS; no se puede crear una sesión separada sin afectar al usuario local.';label.className='alert danger';return false;}
    return true;
  };
  const confirmDialog=async()=>{
    if(mode()==='INTERACTIVE'){
      if(protocol.value==='RDP'&&!interactiveUser.value.trim()){showDialogError('Ingrese el usuario remoto.');interactiveUser.focus();return;}
      if(protocol.value==='VNC'&&!interactivePassword.value&&!isPasswordlessPhysical()){showDialogError('VNC requiere una contraseña de conexión.');interactiveCompatibility.open=true;interactivePassword.focus();return;}
      if(protocol.value==='RDP'&&!interactivePassword.value){showDialogError('Ingrese la contraseña real de Windows para que GIDEON pueda comprobar automáticamente la negociación RDP. La contraseña no se guardará.');interactiveCompatibility.open=true;interactivePassword.focus();return;}
    }
    if(currentImpact().requiresAck&&!impactAcknowledged?.checked){showDialogError('Confirme la autorización del operador para el impacto indicado.');impactAcknowledged?.focus();return;}
    const active=await refreshStepUpState();
    if(!active&&!mfa.value.trim()){showDialogError('Ingrese el código MFA.');mfaFields.hidden=false;mfa.focus();return;}
    form.dataset.confirmed='1';
    prepareViewerWindow();
    closeDialog();
    form.requestSubmit();
  };

  const filterRemoteSources=()=>{
    const query=String(sourceSearch?.value||'').trim().toLocaleLowerCase();
    const selectedPlatform=String(platformFilter?.value||'ALL').toLocaleLowerCase();
    const selectedAvailability=String(availabilityFilter?.value||'ALL').toUpperCase();
    const selectedTunnel=String(tunnelFilter?.value||'ALL').toUpperCase();
    let visible=0;
    const sourceRows=[...document.querySelectorAll('.remote-source-row')];
    // "Todos" is a fail-open inventory view.  Browser back/forward cache and
    // form restoration can preserve a previous `hidden` attribute even after
    // the controls visibly return to their defaults.  Do not let that stale
    // presentation state make enrolled Agents disappear from the picker.
    const defaultInventoryView=selectedSourceFilter==='ALL'
      &&selectedPlatform==='all'&&selectedAvailability==='ALL'
      &&selectedTunnel==='ALL'&&!query;
    if(defaultInventoryView){
      sourceRows.forEach(row=>{row.hidden=false;});
      document.querySelectorAll('[data-remote-source-section]').forEach(section=>{section.hidden=false;});
      if(sourceFilterStatus) sourceFilterStatus.textContent=`${sourceRows.length} destino${sourceRows.length===1?'':'s'} visible${sourceRows.length===1?'':'s'}`;
      return;
    }
    sourceRows.forEach(row=>{
      const radio=row.querySelector('input[name="remote_source_pick"]');
      const sourceType=String(radio?.dataset.sourceType||'').toUpperCase();
      const matchesType=selectedSourceFilter==='ALL'||sourceType===selectedSourceFilter;
      const sourcePlatform=String(radio?.dataset.sourcePlatform||radio?.dataset.platform||'unknown').toLocaleLowerCase();
      const platformText=[sourcePlatform,row.textContent].join(' ').toLocaleLowerCase();
      const matchesPlatform=selectedPlatform==='ALL'
        ||(selectedPlatform==='raspberry'?(platformText.includes('raspberry')||platformText.includes('rpi')):sourcePlatform===selectedPlatform)
        ||(selectedPlatform==='other'&&!['windows','linux','unknown'].includes(sourcePlatform));
      const sourceReady=String(radio?.dataset.sourceReady||'0')==='1';
      const sourceStatus=String(radio?.dataset.sourceStatus||'').toUpperCase();
      const sourceTunnel=String(radio?.dataset.sourceTunnel||'').toUpperCase();
      const matchesAvailability=selectedAvailability==='ALL'
        ||(selectedAvailability==='READY'&&sourceReady)
        ||(selectedAvailability==='NOT_READY'&&sourceStatus==='NOT_READY');
      const matchesTunnel=selectedTunnel==='ALL'||sourceTunnel===selectedTunnel;
      const haystack=[row.textContent,radio?.dataset.sourceLabel,sourcePlatform,radio?.dataset.remoteProtocol].join(' ').toLocaleLowerCase();
      const show=matchesType&&matchesPlatform&&matchesAvailability&&matchesTunnel&&(!query||haystack.includes(query));
      row.hidden=!show;
      if(show) visible++;
    });
    // A browser may restore an old form state after this script has run.  The
    // default picker must never report an empty inventory merely because a
    // stale hidden attribute survived the page restoration.  With no active
    // filter every enrolled Agent/host is intentionally visible, including
    // entries whose connection is disabled for safety.
    document.querySelectorAll('[data-remote-source-section]').forEach(section=>{
      section.hidden=!section.querySelector('.remote-source-row:not([hidden])');
    });
    if(sourceFilterStatus) sourceFilterStatus.textContent=`${visible} destino${visible===1?'':'s'} visible${visible===1?'':'s'}`;
  };
  document.querySelectorAll('[data-remote-source-filter]').forEach(button=>button.addEventListener('click',()=>{
    selectedSourceFilter=String(button.dataset.remoteSourceFilter||'ALL').toUpperCase();
    document.querySelectorAll('[data-remote-source-filter]').forEach(item=>{
      const selected=item===button;
      item.classList.toggle('btn-primary',selected);
      item.setAttribute('aria-pressed',selected?'true':'false');
    });
    filterRemoteSources();
  }));
  sourceSearch?.addEventListener('input',filterRemoteSources);
  platformFilter?.addEventListener('change',filterRemoteSources);
  availabilityFilter?.addEventListener('change',filterRemoteSources);
  tunnelFilter?.addEventListener('change',filterRemoteSources);

  document.querySelectorAll('input[name="remote_source_pick"]').forEach(r=>r.addEventListener('change',()=>selectSource(r)));
  document.querySelectorAll('input[name="connection_intent"]').forEach(r=>r.addEventListener('change',()=>{
    if(impactAcknowledged) impactAcknowledged.checked=false;
    renderIntentPicker(false);
    applyIntent(r.value);
  }));
  document.querySelectorAll('input[name="credential_mode"]').forEach(r=>r.addEventListener('change',renderCredentialMode));
  const invalidateIntentForTechnicalChange=()=>{
    const checked=document.querySelector('input[name="connection_intent"]:checked');
    if(checked) checked.checked=false;
    if(impactAcknowledged) impactAcknowledged.checked=false;
    renderIntentPicker(false);
    renderSummary();
  };
  protocol?.addEventListener('change',()=>{port.dataset.userEdited='';setCredentialFilter();invalidateIntentForTechnicalChange();});
  desktopKind?.addEventListener('change',()=>{protocol.value=desktopKind.value;port.dataset.userEdited='';setCredentialFilter();renderCredentialMode();invalidateIntentForTechnicalChange();});
  fileTransfer?.addEventListener('change',()=>{fileTransfer.dataset.userEdited='1';});
  sessionMode?.addEventListener('change',()=>{renderSessionMode();invalidateIntentForTechnicalChange();});
  port?.addEventListener('input',()=>{port.dataset.userEdited='1';renderSummary();});
  ip?.addEventListener('change',renderSummary); credential?.addEventListener('change',()=>{renderSummary();renderIntentPicker(false);});
  interactiveUser?.addEventListener('input',()=>{renderSummary();renderImpactAcknowledgement();});
  dialogClose?.addEventListener('click',closeDialog); dialogCancel?.addEventListener('click',closeDialog); dialogContinue?.addEventListener('click',confirmDialog);
  passwordToggle?.addEventListener('click',()=>setPasswordVisible(interactivePassword.type==='password'));
  dialog?.addEventListener('cancel',e=>{e.preventDefault();closeDialog();});

  form.addEventListener('submit',async e=>{
    if(form.dataset.confirmed==='1'){
      if(!preparedViewerWindowName) prepareViewerWindow();
      if(mode()==='INTERACTIVE'&&interactiveUser?.value.trim()){
        try{localStorage.setItem(interactiveUsernameKey,interactiveUser.value.trim().slice(0,256));}catch(_){}
      }
      // The parent remains on Control remoto while the POST/redirect is loaded
      // in the named popup. Reset confirmation so a second session can be opened.
      setTimeout(()=>{
        form.dataset.confirmed='0';
        form.removeAttribute('target');
        preparedViewerWindow=null;
        preparedViewerWindowName='';
        if(interactivePassword) interactivePassword.value='';
        if(mfa) mfa.value='';
        scheduleStepUpRefresh();
      },500);
      return;
    }
    e.preventDefault();
    if(!validateBeforeOpen()) return;
    const active=await refreshStepUpState();
    // Vault + active step-up needs no extra prompt. Interactive sessions always
    // open the modal because the remembered remote username must be confirmed,
    // but an already-active 15-minute step-up window hides/skips the MFA field.
    if(mode()==='VAULT'&&active){form.dataset.confirmed='1';prepareViewerWindow();form.requestSubmit();return;}
    openDialog();
  });

  window.addEventListener('focus',()=>{refreshStepUpState();});
  window.addEventListener('pageshow',()=>{filterRemoteSources();});
  document.addEventListener('visibilitychange',()=>{if(!document.hidden) refreshStepUpState();});

  setCredentialFilter(); renderCredentialMode(); renderSessionMode(); applyStepUpState(false,0); filterRemoteSources();
  refreshStepUpState();
  const initial=document.querySelector('input[name="remote_source_pick"]:checked')||document.querySelector('input[name="remote_source_pick"]:not(:disabled)');
  if(initial){initial.checked=true;selectSource(initial);}
})();
