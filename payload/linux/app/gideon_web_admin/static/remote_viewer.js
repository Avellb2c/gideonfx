(()=>{
  'use strict';
  const VERSION='RC30.96.6';
  const viewport=document.getElementById('remoteViewport');
  const displayRoot=document.getElementById('remoteDisplay');
  const status=document.getElementById('remoteStatus');
  const detail=document.getElementById('remoteStatusDetail');
  const disconnect=document.getElementById('remoteDisconnect');
  const refitButton=document.getElementById('remoteRefitDisplay');
  const popoutButton=document.getElementById('remotePopout');
  const fullscreenButton=document.getElementById('remoteFullscreen');
  const copyButton=document.getElementById('remoteCopy');
  const pasteButton=document.getElementById('remotePaste');
  const sendFileButton=document.getElementById('remoteSendFile');
  const fileInput=document.getElementById('remoteFileInput');
  const transferStatus=document.getElementById('remoteTransferStatus');
  const diagCard=document.getElementById('remoteDiagnosticCard');
  const diagToggle=document.getElementById('remoteDiagnosticsToggle');
  const diagSummary=document.getElementById('remoteDiagnosticSummary');
  const diagServer=document.getElementById('remoteDiagServerStatus');
  const diagClass=document.getElementById('remoteDiagClassification');
  const diagGuacd=document.getElementById('remoteDiagGuacd');
  const diagGraphics=document.getElementById('remoteDiagGraphics');
  const diagRecommendation=document.getElementById('remoteDiagnosticRecommendation');
  const diagDetail=document.getElementById('remoteDiagnosticDetail');
  const refreshDiag=document.getElementById('remoteRefreshDiagnostics');
  const copyDiag=document.getElementById('remoteCopyDiagnostics');
  const closeDiag=document.getElementById('remoteCloseDiagnostics');
  const retryPanel=document.getElementById('remoteCredentialRetryPanel');
  const retryTitle=document.getElementById('remoteRetryTitle');
  const retryText=document.getElementById('remoteRetryText');
  const retryOpen=document.getElementById('remoteRetryOpen');
  const retryDialog=document.getElementById('remoteRetryCredentialDialog');
  const retryDialogTitle=document.getElementById('remoteRetryDialogTitle');
  const retryDialogSubtitle=document.getElementById('remoteRetryDialogSubtitle');
  const retryForm=document.getElementById('remoteRetryForm');
  const retryUsername=document.getElementById('remoteRetryUsername');
  const retryPassword=document.getElementById('remoteRetryPassword');
  const retryDomain=document.getElementById('remoteRetryDomain');
  const retryPasswordToggle=document.getElementById('remoteRetryPasswordToggle');
  const retryError=document.getElementById('remoteRetryError');
  const retryClose=document.getElementById('remoteRetryClose');
  const retryCancel=document.getElementById('remoteRetryCancel');
  const retrySubmit=document.getElementById('remoteRetrySubmit');
  if(!viewport||!displayRoot) return;
  try{
    if(retryUsername&&!retryUsername.value.trim()) retryUsername.value=String(localStorage.getItem('gideon.remote.interactive.username.v1')||'').trim().slice(0,256);
  }catch(_){}

  const sessionId=viewport.dataset.sessionId||'';
  const source=viewport.dataset.source||'-';
  const targetHost=viewport.dataset.targetHost||'-';
  const targetPort=viewport.dataset.targetPort||'-';
  const protocol=viewport.dataset.protocol||'-';
  const rdpSessionMode=viewport.dataset.sessionMode||'STANDARD';
  const clipboardEnabled=viewport.dataset.clipboardEnabled!=='0';
  const fileTransferEnabled=viewport.dataset.fileTransferEnabled!=='0'&&String(protocol).toUpperCase()==='RDP';
  // Only Windows/RDP can change WinStation while the desktop is starting.
  // VNC desktops can legitimately stay visually idle for long periods and
  // must never enter the RDP handoff/reconnect path.
  const supportsWindowsHandoff=String(protocol).toUpperCase()==='RDP';
  const connectable=viewport.dataset.connectable!=='0';
  const csrf=viewport.dataset.csrf||'';
  const browserErrors=[];
  const graphics={sync:0,size:0,rect:0,cfill:0,copy:0,png:0,jpeg:0,img:0,blob:0,visual:0,displayWidth:0,displayHeight:0,lastSync:'',lastOpcode:''};
  const VISUAL_OPCODES=new Set(['arc','cfill','close','copy','cstroke','curve','distort','identity','img','jpeg','lfill','line','lstroke','move','png','pop','push','put','rect','reset','shade','transfer','transform']);
  const renderedOps=()=>Number(graphics.visual||0);
  const dom={viewportWidth:0,viewportHeight:0,rootWidth:0,rootHeight:0,elementWidth:0,elementHeight:0,canvasCount:0,visibleCanvasCount:0,scale:1,displayStyle:'',visibility:'',opacity:'',overflow:'',lastFitReason:''};
  let clientState=0;
  let serverDiag=null;
  let diagnosticsFetchError='';
  let terminal=false;
  let automaticRetryStarted=false;
  let handoffReconnectStarted=false;
  let handoffReconnectTimer=null;
  let connectedAt=0;
  let lastVisualAt=0;
  let lastInputAt=0;
  let livenessTimer=null;
  let diagnosticsRequested=false;
  let handoffChallengeCount=0;
  let noImageTimer=null;
  let graphicsConfirmed=false;
  let operatorDisconnectRequested=false;
  let activeKeyboard=null;
  let keyboardTarget=null;
  let keyboardDocument=null;
  let lastRemoteClipboard='';
  let clipboardGeneration=0;
  const MAX_CLIPBOARD_BYTES=1024*1024;
  const MAX_FILE_BYTES=100*1024*1024;
  const fullscreenDocuments=new WeakSet();
  let popoutWindow=null;
  let popoutStage=null;
  let popoutPlaceholder=null;
  let popoutReturning=false;
  const openedAsDedicatedWindow=/^gideonRemoteSession_/i.test(String(window.name||''));

  const activateDedicatedViewerLayout=()=>{
    if(!openedAsDedicatedWindow) return;
    document.documentElement.classList.add('gideon-remote-dedicated-mode');
    document.body.classList.add('gideon-remote-dedicated-mode');
    document.title=`${source} · GIDEON Remote Session`;
    if(popoutButton){
      popoutButton.hidden=true;
      popoutButton.disabled=true;
      popoutButton.setAttribute('aria-pressed','true');
    }
    // The popup is already the dedicated window. Keep only the compact session
    // chrome + viewer, not the WebAdmin navigation shell.
    requestAnimationFrame(()=>requestAnimationFrame(()=>{
      try{window.focus();}catch(_){}
    }));
  };
  activateDedicatedViewerLayout();

  // The compact dedicated viewer keeps its header intentionally clipped so
  // it never covers the remote desktop. Toolbar disclosures are the one
  // exception: when open, their popover must escape that compact header and
  // remain reachable. Keep the native <details>/<summary> interaction (it
  // works with keyboard and assistive technology) and only manage its shared
  // transient state here.
  const toolbarMenus=Array.from(document.querySelectorAll('.remote-toolbar-menu'));
  const toolbarSummary=menu=>menu?.querySelector(':scope > summary')||null;
  const positionToolbarPopover=menu=>{
    if(!openedAsDedicatedWindow||!menu?.open)return;
    const summary=toolbarSummary(menu);
    if(!summary)return;
    const summaryRect=summary.getBoundingClientRect();
    const statusRect=document.querySelector('.remote-viewer-status')?.getBoundingClientRect();
    const viewportWidth=Math.max(document.documentElement.clientWidth||0,window.innerWidth||0);
    const top=Math.max(12,Math.ceil(summaryRect.bottom+7),Math.ceil(Number(statusRect?.bottom||0)+6));
    const right=Math.max(12,Math.ceil(viewportWidth-summaryRect.right));
    menu.style.setProperty('--gideon-toolbar-popover-top',`${top}px`);
    menu.style.setProperty('--gideon-toolbar-popover-right',`${right}px`);
  };
  const syncToolbarMenus=()=>{
    const active=toolbarMenus.find(menu=>menu.open)||null;
    document.body.classList.toggle('gideon-remote-toolbar-menu-open',Boolean(active));
    toolbarMenus.forEach(menu=>{
      const summary=toolbarSummary(menu);
      if(summary)summary.setAttribute('aria-expanded',menu.open?'true':'false');
      if(menu!==active){
        menu.style.removeProperty('--gideon-toolbar-popover-top');
        menu.style.removeProperty('--gideon-toolbar-popover-right');
      }
    });
    if(active)positionToolbarPopover(active);
  };
  const closeToolbarMenus=(except=null,returnFocus=false)=>{
    let focusTarget=null;
    toolbarMenus.forEach(menu=>{
      if(menu===except||!menu.open)return;
      if(returnFocus&&!focusTarget)focusTarget=toolbarSummary(menu);
      menu.open=false;
    });
    syncToolbarMenus();
    if(focusTarget){
      try{focusTarget.focus({preventScroll:true});}catch(_){focusTarget.focus();}
    }
  };
  toolbarMenus.forEach(menu=>{
    const summary=toolbarSummary(menu);
    if(summary)summary.setAttribute('aria-expanded',menu.open?'true':'false');
    menu.addEventListener('toggle',()=>{
      if(menu.open)closeToolbarMenus(menu);
      syncToolbarMenus();
    });
  });
  document.addEventListener('pointerdown',event=>{
    const target=event.target;
    if(target instanceof Node&&toolbarMenus.some(menu=>menu.contains(target)))return;
    closeToolbarMenus();
  },true);
  document.addEventListener('keydown',event=>{
    if(event.key!=='Escape'||!toolbarMenus.some(menu=>menu.open))return;
    event.preventDefault();
    event.stopPropagation();
    closeToolbarMenus(null,true);
  },true);
  // ui_state intentionally remembers normal <details> disclosures. These
  // action menus are not a persistent preference: reset them after ui_state
  // has restored its page state and also on browser back/forward restoration.
  const resetTransientToolbarMenus=()=>closeToolbarMenus();
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>setTimeout(resetTransientToolbarMenus,0),{once:true});
  else setTimeout(resetTransientToolbarMenus,0);
  window.addEventListener('pageshow',()=>setTimeout(resetTransientToolbarMenus,0));

  const setState=(code,message,css='info')=>{
    if(status){status.textContent=code;status.className=`chip ${css}`;}
    if(detail) detail.textContent=message||'';
  };
  const setDiagnosticsVisible=open=>{
    diagnosticsRequested=Boolean(open);
    if(diagCard) diagCard.hidden=!diagnosticsRequested;
    if(diagToggle) diagToggle.setAttribute('aria-expanded',diagnosticsRequested?'true':'false');
  };
  const markInput=()=>{
    const now=Date.now();
    const shouldRender=now-lastInputAt>1000;
    lastInputAt=now;
    // Mouse movement can arrive at a gaming-mouse rate. Liveness needs the
    // timestamp, not a DOM write for every pointer event.
    if(shouldRender&&clientState===3&&graphicsConfirmed&&!terminal) setState('INTERACTIVA','Imagen e interacción remotas activas.','success');
  };
  const refreshLiveness=()=>{
    if(clientState!==3||terminal||!graphicsConfirmed||!lastVisualAt) return;
    const now=Date.now();
    const visualIdle=Math.max(0,Math.floor((now-lastVisualAt)/1000));
    if(visualIdle>=45){
      setState('SIN CAMBIOS',`Conexión abierta; último cambio de imagen hace ${visualIdle} s.`,'warning');
      return;
    }
    if(lastInputAt&&now-lastInputAt<15000){
      setState('INTERACTIVA',`Imagen recibida; última interacción enviada hace ${Math.max(0,Math.floor((now-lastInputAt)/1000))} s.`,'success');
      return;
    }
    setState('IMAGEN ACTIVA',`Último cambio de imagen hace ${visualIdle} s.`,'success');
  };
  const startLiveness=()=>{
    if(livenessTimer) clearInterval(livenessTimer);
    livenessTimer=setInterval(refreshLiveness,5000);
    refreshLiveness();
  };
  const stopLiveness=()=>{if(livenessTimer){clearInterval(livenessTimer);livenessTimer=null;}};
  const recordError=(kind,message)=>{
    const row=`${new Date().toISOString()} [${kind}] ${String(message||'')}`;
    browserErrors.push(row);
    if(browserErrors.length>30) browserErrors.shift();
  };
  const safeText=value=>String(value??'').replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,5000);
  const showRetryError=message=>{if(!retryError)return;retryError.textContent=message||'';retryError.hidden=!message;};
  const setTransferStatus=(message,isError=false)=>{
    const text=safeText(message||'');
    if(transferStatus){transferStatus.textContent=text;transferStatus.style.color=isError?'#ff9aa8':'';}
    if(popoutWindow&&!popoutWindow.closed){
      const item=popoutWindow.document.getElementById('gideonPopoutState');
      if(item){item.textContent=text||'Sesión remota activa';item.style.color=isError?'#ff9aa8':'';}
    }
  };
  const setRetryPasswordVisible=visible=>{
    if(!retryPassword||!retryPasswordToggle) return;
    retryPassword.type=visible?'text':'password';
    retryPasswordToggle.textContent=visible?'Ocultar':'Mostrar';
    retryPasswordToggle.setAttribute('aria-pressed',visible?'true':'false');
    retryPasswordToggle.setAttribute('aria-label',visible?'Ocultar contraseña':'Mostrar contraseña');
  };
  const closeRetryDialog=()=>{
    showRetryError('');
    if(retryPassword){retryPassword.value='';setRetryPasswordVisible(false);}
    if(typeof retryDialog?.close==='function') retryDialog.close(); else retryDialog?.removeAttribute('open');
    setTimeout(()=>displayRoot?.focus(),0);
  };
  const openRetryDialog=()=>{
    showRetryError('');
    setRetryPasswordVisible(false);
    if(typeof retryDialog?.showModal==='function') retryDialog.showModal(); else retryDialog?.setAttribute('open','');
    try{activeKeyboard?.reset?.();}catch(_){}
    setTimeout(()=>{const target=retryUsername?.value.trim()?retryPassword:retryUsername;target?.focus();},0);
  };

  if(!window.Guacamole||!Guacamole.Client||!Guacamole.WebSocketTunnel){
    setState('ERROR','guacamole-common-js no está disponible.','danger');
    recordError('CLIENT','guacamole-common-js no está disponible');
    return;
  }

  // Guacamole 1.6.0 blocks the display flush (and therefore the protocol sync
  // acknowledgement) while an asynchronous image decode is pending. Its
  // createImageBitmap/ImageDecoder paths do not unblock that queue when the
  // browser rejects a frame. Prefer Guacamole's established HTML Image/DataURI
  // fallbacks, which handle both load and error and cannot strand the session.
  const rendererCompatibility={createImageBitmap:false,imageDecoder:false};
  const disableAsyncDecoder=name=>{
    try{
      if(typeof window[name]!=='function') return false;
      Object.defineProperty(window,name,{value:undefined,writable:true,configurable:true});
      return typeof window[name]!=='function';
    }catch(error){
      recordError('RENDERER_COMPAT',`${name}: ${safeText(error?.message||error)}`);
      return false;
    }
  };
  rendererCompatibility.createImageBitmap=disableAsyncDecoder('createImageBitmap');
  rendererCompatibility.imageDecoder=disableAsyncDecoder('ImageDecoder');
  window.addEventListener('unhandledrejection',event=>{
    const message=safeText(event?.reason?.message||event?.reason||'Promise rechazada sin detalle');
    recordError('UNHANDLED_PROMISE',message);
  });

  const wsScheme=location.protocol==='https:'?'wss':'ws';
  // Negotiate the desktop at the browser's real usable size before RDP/XRDP
  // starts. This fills the viewer without a disruptive mid-session resize.
  const initialViewport=viewport.getBoundingClientRect();
  const initialWidth=Math.max(640,Math.min(3840,Math.floor(Number(initialViewport.width||viewport.clientWidth||1440)/2)*2));
  const initialHeight=Math.max(480,Math.min(2160,Math.floor(Number(initialViewport.height||viewport.clientHeight||900)/2)*2));
  const viewportQuery=new URLSearchParams({width:String(initialWidth),height:String(initialHeight),dpi:'96'});
  const tunnel=new Guacamole.WebSocketTunnel(`${wsScheme}://${location.host}/remote/ws/${encodeURIComponent(sessionId)}?${viewportQuery}`);
  const client=new Guacamole.Client(tunnel);
  const display=client.getDisplay();
  const displayElement=display.getElement();
  displayElement.classList.add('gideon-guacamole-surface');
  displayElement.setAttribute('data-gideon-guacamole-surface','1');
  // Keep a single authoritative Guacamole surface.  The previous generic
  // anti-overflow CSS could shrink Guacamole's internal canvas layers to 0px.
  displayRoot.replaceChildren(displayElement);

  const writeLocalClipboard=async text=>{
    const value=String(text||'');
    if(!value) throw new Error('El equipo remoto aún no publicó texto para copiar. Seleccione texto y vuelva a pulsar Copiar.');
    const ownerDocument=displayRoot.ownerDocument||document;
    const clipboard=ownerDocument.defaultView?.navigator?.clipboard||navigator.clipboard;
    if(clipboard?.writeText){await clipboard.writeText(value);return;}
    const area=ownerDocument.createElement('textarea');
    area.value=value;area.setAttribute('readonly','');area.style.position='fixed';area.style.opacity='0';
    ownerDocument.body.append(area);area.select();
    const copied=ownerDocument.execCommand('copy');area.remove();
    if(!copied) throw new Error('El navegador bloqueó el portapapeles local.');
  };
  const sendRemoteShortcut=keysym=>{
    markInput();
    client.sendKeyEvent(1,0xFFE3);
    client.sendKeyEvent(1,keysym);
    client.sendKeyEvent(0,keysym);
    client.sendKeyEvent(0,0xFFE3);
  };
  const sendClipboardText=text=>{
    markInput();
    const value=String(text??'');
    if(!clipboardEnabled) throw new Error('El portapapeles está deshabilitado para esta sesión.');
    if(new TextEncoder().encode(value).byteLength>MAX_CLIPBOARD_BYTES) throw new Error('El texto excede el límite de portapapeles de 1 MiB.');
    const stream=client.createClipboardStream('text/plain');
    const writer=new Guacamole.StringWriter(stream);
    writer.sendText(value);
    writer.sendEnd();
  };
  const markRemoteShortcutSent=error=>{
    const normalized=error instanceof Error?error:new Error(String(error||'Error de portapapeles remoto'));
    normalized.gideonRemoteShortcutSent=true;
    return normalized;
  };
  const copyFromRemote=async()=>{
    if(!clipboardEnabled) throw new Error('El portapapeles está deshabilitado para esta sesión.');
    const generation=clipboardGeneration;
    sendRemoteShortcut(0x63);
    try{
      for(let i=0;i<12&&clipboardGeneration===generation;i++) await new Promise(resolve=>setTimeout(resolve,100));
      if(clipboardGeneration===generation) throw new Error('El equipo remoto no publicó texto nuevo para copiar. El atajo Ctrl+C sí se envió al escritorio remoto.');
      await writeLocalClipboard(lastRemoteClipboard);
      setTransferStatus('Texto remoto copiado al portapapeles local.');
    }catch(error){
      // Ctrl+C was already delivered to the desktop.  Mark that fact so the
      // keyboard fallback never emits a second destructive/duplicate shortcut.
      throw markRemoteShortcutSent(error);
    }
  };
  const pasteIntoRemote=async()=>{
    let remoteShortcutSent=false;
    try{
      const clipboard=displayRoot.ownerDocument?.defaultView?.navigator?.clipboard||navigator.clipboard;
      if(!clipboard?.readText) throw new Error('El navegador no concedió acceso de lectura al portapapeles. Use HTTPS y permita Portapapeles para este sitio.');
      const text=await clipboard.readText();
      sendClipboardText(text);
      await new Promise(resolve=>setTimeout(resolve,120));
      sendRemoteShortcut(0x76);
      remoteShortcutSent=true;
      setTransferStatus('Texto local pegado en el equipo remoto.');
    }catch(error){
      if(remoteShortcutSent) throw markRemoteShortcutSent(error);
      throw error;
    }
  };
  const arrayBufferToBase64=buffer=>{
    const bytes=new Uint8Array(buffer);let binary='';
    for(let i=0;i<bytes.length;i++) binary+=String.fromCharCode(bytes[i]);
    return btoa(binary);
  };
  const uploadFileToRemote=file=>new Promise((resolve,reject)=>{
    if(!fileTransferEnabled){reject(new Error('La transferencia de archivos está deshabilitada para esta sesión.'));return;}
    if(!file||!file.name){reject(new Error('Seleccione un archivo válido.'));return;}
    if(file.size>MAX_FILE_BYTES){reject(new Error('El archivo excede el límite de 100 MiB por transferencia.'));return;}
    const safeName=String(file.name).replace(/[\\/\u0000-\u001f\u007f]/g,'_').slice(0,240)||'archivo.bin';
    const stream=client.createFileStream(file.type||'application/octet-stream',safeName);
    let offset=0;let waiting=false;let finished=false;
    let timer=0;
    const armTimer=()=>{clearTimeout(timer);timer=setTimeout(()=>{if(!finished){finished=true;reject(new Error('guacd no confirmó la transferencia durante 30 segundos.'));}},30000);};
    armTimer();
    const fail=message=>{if(finished)return;finished=true;clearTimeout(timer);try{stream.sendEnd();}catch(_){}reject(new Error(message));};
    const sendNext=async()=>{
      if(finished||waiting)return;
      if(offset>=file.size){finished=true;clearTimeout(timer);stream.sendEnd();resolve({name:safeName,size:file.size});return;}
      waiting=true;
      try{
        const end=Math.min(file.size,offset+48*1024);
        const buffer=await file.slice(offset,end).arrayBuffer();
        stream.sendBlob(arrayBufferToBase64(buffer));
        offset=end;
        armTimer();
        setTransferStatus(`Enviando ${safeName}: ${Math.floor((offset/Math.max(1,file.size))*100)}%`);
      }catch(error){fail(error?.message||String(error));}
    };
    stream.onack=status=>{
      if(finished)return;
      if(status?.isError?.()){fail(status.message||'El destino rechazó el archivo.');return;}
      waiting=false;
      armTimer();
      void sendNext();
    };
    // The first acknowledgement arrives only after a blob is sent. Starting
    // here avoids a self-blocking upload that waits for its own first ACK.
    void sendNext();
  });
  const handleSelectedFile=async file=>{
    if(!file)return;
    try{const result=await uploadFileToRemote(file);setTransferStatus(`${result.name} enviado. Ábralo desde Este equipo > GIDEON Transfer.`);}catch(error){setTransferStatus(error?.message||error,true);}
  };
  const chooseRemoteFile=(ownerDocument=document)=>{
    if(ownerDocument===document){fileInput?.click();return;}
    const input=ownerDocument.createElement('input');input.type='file';input.hidden=true;
    input.addEventListener('change',()=>{const file=input.files?.[0];input.remove();void handleSelectedFile(file);},{once:true});
    ownerDocument.body.append(input);input.click();
  };
  client.onclipboard=(stream,mimetype)=>{
    if(!clipboardEnabled||!String(mimetype||'').toLowerCase().startsWith('text/')){try{stream.sendAck('Tipo de portapapeles no permitido.',0x0100);}catch(_){}return;}
    const reader=new Guacamole.StringReader(stream);let text='';let size=0;
    reader.ontext=chunk=>{size+=new TextEncoder().encode(String(chunk||'')).byteLength;if(size<=MAX_CLIPBOARD_BYTES)text+=String(chunk||'');};
    reader.onend=()=>{if(size<=MAX_CLIPBOARD_BYTES){lastRemoteClipboard=text;clipboardGeneration++;setTransferStatus('Texto remoto listo para copiar.');}else setTransferStatus('El texto remoto excedió 1 MiB y fue descartado.',true);};
  };
  client.onfile=(stream,mimetype,filename)=>{
    if(!fileTransferEnabled){try{stream.sendAck('Transferencia no permitida.',0x0100);}catch(_){}return;}
    const safeName=String(filename||'archivo.bin').replace(/[\\/\u0000-\u001f\u007f]/g,'_').slice(0,240)||'archivo.bin';
    const reader=new Guacamole.BlobReader(stream,mimetype||'application/octet-stream');
    reader.onprogress=length=>setTransferStatus(`Recibiendo ${safeName}: ${Math.round(Number(length||0)/1024)} KiB`);
    reader.onend=()=>{
      const blob=reader.getBlob();
      if(blob.size>MAX_FILE_BYTES){setTransferStatus('El archivo remoto excedió 100 MiB y fue descartado.',true);return;}
      const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=safeName;
      document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
      setTransferStatus(`${safeName} descargado desde el equipo remoto.`);
    };
  };

  // Guacamole.Client owns tunnel.oninstruction. Wrap it after construction so
  // instrumentation observes opcodes without changing Guacamole behavior.
  const originalInstruction=tunnel.oninstruction;
  if(typeof originalInstruction==='function'){
    tunnel.oninstruction=(opcode,parameters)=>{
      const op=String(opcode||'').toLowerCase();
      try{
        graphics.lastOpcode=op;
        if(Object.prototype.hasOwnProperty.call(graphics,op) && typeof graphics[op]==='number') graphics[op]++;
        if(op==='sync') graphics.lastSync=String((parameters||[])[0]||'');
      }catch(_){/* diagnostics must never break the tunnel */}
      const result=originalInstruction.call(tunnel,opcode,parameters);
      if(VISUAL_OPCODES.has(op)){
        graphics.visual++;
        lastVisualAt=Date.now();
        if(!graphicsConfirmed){
          graphicsConfirmed=true;
          if(noImageTimer){clearTimeout(noImageTimer);noImageTimer=null;}
          requestAnimationFrame(()=>{
            updateDisplayMetrics();
            // A delayed first frame is a recovery, not a failure. Emit the
            // explicit active state before the richer liveness wording so the
            // operator never remains on a stale "SIN IMAGEN" message.
            if(clientState===3&&!terminal) setState('ACTIVO','Sesión remota activa; imagen recibida.','success');
            if(clientState===3&&!terminal) refreshLiveness();
            if(diagCard&&!diagCard.hidden) renderDiagnostics();
          });
        }
        else if(clientState===3&&!terminal&&status?.textContent==='SIN CAMBIOS') refreshLiveness();
      }
      // Only a size instruction changes the remote surface geometry. A sync is
      // emitted for virtually every frame; fitting on sync causes forced layout
      // work at video cadence and can starve Guacamole's renderer.
      if(op==='size') queueVisualFit('opcode:size',32);
      return result;
    };
  }

  const readDomMetrics=()=>{
    try{
      const vr=viewport.getBoundingClientRect();
      const rr=displayRoot.getBoundingClientRect();
      const er=displayElement.getBoundingClientRect();
      const style=getComputedStyle(displayElement);
      const rootStyle=getComputedStyle(displayRoot);
      const canvases=[...displayElement.querySelectorAll('canvas')];
      let visible=0;
      for(const canvas of canvases){
        const cr=canvas.getBoundingClientRect();
        const cs=getComputedStyle(canvas);
        if(cr.width>1&&cr.height>1&&cs.display!=='none'&&cs.visibility!=='hidden'&&Number(cs.opacity||1)>0) visible++;
      }
      dom.viewportWidth=Math.round(vr.width); dom.viewportHeight=Math.round(vr.height);
      dom.rootWidth=Math.round(rr.width); dom.rootHeight=Math.round(rr.height);
      dom.elementWidth=Math.round(er.width); dom.elementHeight=Math.round(er.height);
      dom.canvasCount=canvases.length; dom.visibleCanvasCount=visible;
      dom.displayStyle=style.display; dom.visibility=style.visibility; dom.opacity=style.opacity; dom.overflow=rootStyle.overflow;
    }catch(error){recordError('DISPLAY_METRICS',error?.message||error);}
  };

  const updateDisplayMetrics=()=>{
    try{
      graphics.displayWidth=Number(display.getWidth?.()||0);
      graphics.displayHeight=Number(display.getHeight?.()||0);
      dom.scale=Number(display.getScale?.()||dom.scale||1);
    }catch(_){/* optional metrics */}
    readDomMetrics();
    if(diagGraphics){
      const rendered=renderedOps();
      diagGraphics.textContent=`${graphics.displayWidth}×${graphics.displayHeight} · ${rendered} ops · canvas ${dom.visibleCanvasCount}/${dom.canvasCount} · scale ${Number(dom.scale||1).toFixed(3)}`;
    }
  };

  let fitRaf=0;
  let fitTimer=0;
  let pendingFitReason='layout';
  let lastFitGeometry='';
  const fitDisplay=(reason='manual')=>{
    try{
      const naturalW=Number(display.getWidth?.()||0);
      const naturalH=Number(display.getHeight?.()||0);
      // Scale against the actual viewport, never against Guacamole's surface.
      // The latter changes size when display.scale() runs and can create a
      // ResizeObserver feedback loop.
      const host=(displayRoot.ownerDocument!==document&&popoutStage)?popoutStage:viewport;
      const hostRect=host.getBoundingClientRect();
      const availableW=Math.max(1,Math.floor(hostRect.width||host.clientWidth||0));
      const availableH=Math.max(1,Math.floor(hostRect.height||host.clientHeight||0));
      dom.lastFitReason=reason;
      if(naturalW>0&&naturalH>0&&availableW>1&&availableH>1){
        const targetScale=Math.round(Math.max(0.10,Math.min(4,Math.min(availableW/naturalW,availableH/naturalH)))*10000)/10000;
        const geometry=`${naturalW}x${naturalH}:${availableW}x${availableH}:${targetScale}`;
        // Avoid invalidating every Guacamole layer when neither the surface nor
        // its host changed. This keeps long-running/static Linux sessions fluid.
        if(geometry!==lastFitGeometry){
          display.scale(targetScale);
          lastFitGeometry=geometry;
        }
        dom.scale=Number(display.getScale?.()||targetScale);
      }
      // The display itself must stay visible.  Guacamole controls its internal
      // layers/canvases; GIDEON only owns the outer surface and scale.
      displayElement.style.visibility='visible';
      displayElement.style.opacity='1';
      displayElement.style.transformOrigin='0 0';
      updateDisplayMetrics();
    }catch(error){recordError('DISPLAY_FIT',error?.message||error);}
  };
  function scheduleFit(reason='scheduled'){
    if(fitRaf) cancelAnimationFrame(fitRaf);
    fitRaf=requestAnimationFrame(()=>{fitRaf=0;fitDisplay(reason);});
  }
  function queueVisualFit(reason='layout',delay=60){
    pendingFitReason=reason;
    // Coalesce bursts instead of restarting the timer. Continuous protocol or
    // ResizeObserver traffic must never postpone the first fit indefinitely.
    if(fitTimer) return;
    fitTimer=setTimeout(()=>{fitTimer=0;scheduleFit(pendingFitReason);},Math.max(0,Number(delay)||0));
  }
  if(display) display.onresize=()=>queueVisualFit('display-resize',32);

  const fullscreenTargetForDocument=doc=>{
    if(popoutWindow&&!popoutWindow.closed&&doc===popoutWindow.document&&popoutStage) return popoutStage;
    return viewport;
  };
  const setFullscreenButtonLabel=doc=>{
    const active=Boolean(doc?.fullscreenElement);
    if(fullscreenButton&&doc===document) fullscreenButton.textContent=active?'Salir de pantalla completa (F11)':'Pantalla completa (F11)';
    if(popoutWindow&&!popoutWindow.closed&&doc===popoutWindow.document){
      const b=doc.getElementById('gideonPopoutFullscreen');
      if(b) b.textContent=active?'Salir de pantalla completa (F11)':'Pantalla completa (F11)';
    }
  };
  async function toggleFullscreen(doc=document){
    try{
      if(doc.fullscreenElement){
        await doc.exitFullscreen();
        return;
      }
      const target=fullscreenTargetForDocument(doc);
      if(!target?.requestFullscreen) throw new Error('La API Fullscreen no está disponible en este navegador.');
      try{await target.requestFullscreen({navigationUI:'hide'});}catch(_){await target.requestFullscreen();}
    }catch(error){
      recordError('FULLSCREEN',error?.message||error);
      setState('FULLSCREEN',`No se pudo cambiar a pantalla completa: ${safeText(error?.message||error)}`,'warning');
    }
  }
  function installFullscreenKeys(doc){
    if(!doc||fullscreenDocuments.has(doc)) return;
    fullscreenDocuments.add(doc);
    doc.addEventListener('keydown',event=>{
      const isF11=event.key==='F11'||event.code==='F11'||Number(event.keyCode)===122;
      if(isF11){
        event.preventDefault();
        event.stopImmediatePropagation();
        void toggleFullscreen(doc);
        return;
      }
      if(event.key==='Escape'&&doc.fullscreenElement){
        event.preventDefault();
        event.stopImmediatePropagation();
        void doc.exitFullscreen();
      }
    },true);
    doc.addEventListener('keyup',event=>{
      const isF11=event.key==='F11'||event.code==='F11'||Number(event.keyCode)===122;
      if(isF11){event.preventDefault();event.stopImmediatePropagation();}
    },true);
    doc.addEventListener('fullscreenchange',()=>{
      setFullscreenButtonLabel(doc);
      queueVisualFit('fullscreenchange',80);
    });
  }
  function bindKeyboard(){
    const ownerDocument=displayRoot.ownerDocument||document;
    // Moving the display into/out of a popup adopts the element into another
    // document.  Recreate Guacamole.Keyboard in that case; retaining the old
    // object can leave key listeners attached to the previous browsing context.
    if(activeKeyboard&&keyboardTarget===displayRoot&&keyboardDocument===ownerDocument) return;
    if(activeKeyboard){activeKeyboard.onkeydown=null;activeKeyboard.onkeyup=null;try{activeKeyboard.reset?.();}catch(_){}}
    const keyboard=new Guacamole.Keyboard(displayRoot);
    keyboard.onkeydown=(keysym)=>{markInput();client.sendKeyEvent(1,keysym);return false;};
    keyboard.onkeyup=(keysym)=>{markInput();client.sendKeyEvent(0,keysym);return false;};
    activeKeyboard=keyboard;
    keyboardTarget=displayRoot;
    keyboardDocument=ownerDocument;
  }
  function ensurePopoutPlaceholder(){
    if(popoutPlaceholder&&popoutPlaceholder.isConnected) return popoutPlaceholder;
    popoutPlaceholder=document.createElement('div');
    popoutPlaceholder.className='remote-popout-placeholder';
    const copy=document.createElement('div');
    const title=document.createElement('strong');
    title.textContent='La sesión está abierta en una ventana separada.';
    const body=document.createElement('span');
    body.textContent='Cierre la ventana remota o use “Traer aquí” para devolver el escritorio a esta página.';
    const bring=document.createElement('button');
    bring.type='button'; bring.className='btn'; bring.textContent='Traer aquí';
    bring.addEventListener('click',()=>returnFromPopout(false));
    copy.append(title,body,bring);
    popoutPlaceholder.append(copy);
    viewport.append(popoutPlaceholder);
    return popoutPlaceholder;
  }
  function buildPopoutDocument(pop){
    const doc=pop.document;
    doc.open();
    doc.write('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GIDEON Remote Session</title></head><body><header id="gideonPopoutToolbar"><div><strong id="gideonPopoutTitle"></strong><span id="gideonPopoutState">Sesión remota activa</span></div><nav><button id="gideonPopoutCopy" type="button">Copiar</button><button id="gideonPopoutPaste" type="button">Pegar</button><button id="gideonPopoutFile" type="button">Enviar archivo</button><button id="gideonPopoutRefit" type="button">Ajustar</button><button id="gideonPopoutFullscreen" type="button">Pantalla completa (F11)</button><button id="gideonPopoutReturn" type="button">Traer a WebAdmin</button><button id="gideonPopoutDisconnect" class="danger" type="button">Desconectar</button></nav></header><main id="gideonPopoutStage"></main></body></html>');
    doc.close();
    const style=doc.createElement('style');
    style.textContent=`*{box-sizing:border-box}html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#000;color:#eaf2f6;font:13px \"Segoe UI\",Arial,sans-serif}#gideonPopoutToolbar{height:54px;display:flex;align-items:center;justify-content:space-between;gap:14px;padding:7px 10px;background:#0b151c;border-bottom:1px solid #263743;position:fixed;inset:0 0 auto 0;z-index:20}#gideonPopoutToolbar>div{display:flex;flex-direction:column;min-width:0;gap:2px}#gideonPopoutTitle{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}#gideonPopoutState{color:#91a5b2;font-size:11px}#gideonPopoutToolbar nav{display:flex;gap:7px;flex-wrap:nowrap}#gideonPopoutToolbar button{border:1px solid #38505f;background:#12222c;color:#eef6fa;border-radius:7px;padding:7px 10px;cursor:pointer;font:inherit;white-space:nowrap}#gideonPopoutToolbar button:hover{border-color:#2bb7e9}.danger{border-color:#8f3341!important;color:#ffabb7!important}#gideonPopoutStage{position:fixed;inset:54px 0 0 0;background:#000;overflow:hidden}#gideonPopoutStage:fullscreen{inset:0}.remote-display{position:absolute!important;inset:0!important;display:block!important;width:auto!important;height:auto!important;min-width:0!important;min-height:0!important;overflow:hidden!important;background:#000!important;outline:none}.remote-display>.gideon-guacamole-surface{position:relative!important;display:block!important;visibility:visible!important;opacity:1!important;transform-origin:0 0!important;max-width:none!important;max-height:none!important}.remote-display canvas,.remote-display>.gideon-guacamole-surface canvas{max-width:none!important;max-height:none!important}@media(max-width:820px){#gideonPopoutToolbar{height:64px;align-items:flex-start}#gideonPopoutStage{inset:64px 0 0}#gideonPopoutToolbar nav{overflow:auto;max-width:62vw}}`;
    doc.head.append(style);
    const title=doc.getElementById('gideonPopoutTitle');
    if(title) title.textContent=`${source} · ${targetHost}:${targetPort}`;
    return doc.getElementById('gideonPopoutStage');
  }
  function returnFromPopout(fromClosing=false){
    if(!popoutWindow&&displayRoot.ownerDocument===document) return;
    const pop=popoutWindow;
    popoutReturning=true;
    try{document.adoptNode(displayRoot);}catch(_){}
    try{
      popoutPlaceholder?.remove();
      viewport.append(displayRoot);
      bindKeyboard(document);
      installFullscreenKeys(document);
      if(popoutButton){popoutButton.textContent='Ventana aparte';popoutButton.setAttribute('aria-pressed','false');} if(fullscreenButton) fullscreenButton.disabled=false;
      if(!fromClosing&&pop&&!pop.closed) pop.close();
    }catch(error){recordError('POPOUT_RETURN',error?.message||error);}
    popoutWindow=null; popoutStage=null; popoutReturning=false;
    setTimeout(()=>{queueVisualFit('popout-return',0);displayRoot.focus();},80);
  }
  function openPopout(){
    if(openedAsDedicatedWindow){
      try{window.focus();}catch(_){}
      return;
    }
    if(popoutWindow&&!popoutWindow.closed){try{popoutWindow.focus();}catch(_){}return;}
    const availW=Math.max(960,Number(screen?.availWidth||1400));
    const availH=Math.max(640,Number(screen?.availHeight||900));
    const width=Math.max(900,Math.min(availW-40,1680));
    const height=Math.max(620,Math.min(availH-50,980));
    const left=Math.max(0,Math.floor(((Number(screen?.availLeft||0)+availW)-width)/2));
    const top=Math.max(0,Math.floor(((Number(screen?.availTop||0)+availH)-height)/2));
    const pop=window.open('about:blank',`gideonRemoteDetached_${Date.now().toString(36)}`,`popup=yes,resizable=yes,scrollbars=no,width=${width},height=${height},left=${left},top=${top}`);
    if(!pop){
      setState('POPUP BLOQUEADO','Chrome bloqueó la ventana separada. Permita ventanas emergentes para este WebAdmin.','warning');
      return;
    }
    popoutWindow=pop; popoutReturning=false;
    try{
      popoutStage=buildPopoutDocument(pop);
      ensurePopoutPlaceholder();
      popoutStage.append(displayRoot);
      installFullscreenKeys(pop.document);
      bindKeyboard(pop.document);
      pop.document.getElementById('gideonPopoutCopy')?.addEventListener('click',()=>void copyFromRemote().catch(error=>setTransferStatus(error?.message||error,true)));
      pop.document.getElementById('gideonPopoutPaste')?.addEventListener('click',()=>void pasteIntoRemote().catch(error=>setTransferStatus(error?.message||error,true)));
      pop.document.getElementById('gideonPopoutFile')?.addEventListener('click',()=>chooseRemoteFile(pop.document));
      pop.document.getElementById('gideonPopoutRefit')?.addEventListener('click',()=>queueVisualFit('popout-refit',0));
      pop.document.getElementById('gideonPopoutFullscreen')?.addEventListener('click',()=>void toggleFullscreen(pop.document));
      pop.document.getElementById('gideonPopoutReturn')?.addEventListener('click',()=>returnFromPopout(false));
      pop.document.getElementById('gideonPopoutDisconnect')?.addEventListener('click',()=>{operatorDisconnectRequested=true;try{client.disconnect();}finally{try{pop.close();}catch(_){}}});
      pop.addEventListener('resize',()=>queueVisualFit('popout-resize',90));
      pop.addEventListener('pagehide',()=>{if(!popoutReturning) returnFromPopout(true);},{once:true});
      if(popoutButton){popoutButton.textContent='Traer aquí';popoutButton.setAttribute('aria-pressed','true');} if(fullscreenButton) fullscreenButton.disabled=true;
      setTimeout(()=>{queueVisualFit('popout-open',0);displayRoot.focus();},80);
      pop.focus();
    }catch(error){
      recordError('POPOUT_OPEN',error?.message||error);
      try{pop.close();}catch(_){}
      popoutWindow=null;popoutStage=null;
      returnFromPopout(true);
    }
  }

  const diagnosticUrl=`/remote/session/${encodeURIComponent(sessionId)}/diagnostics.json`;
  async function fetchDiagnostics(show=true){
    try{
      const controller=new AbortController();
      const timer=setTimeout(()=>controller.abort(),5000);
      const response=await fetch(diagnosticUrl,{credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:{'Accept':'application/json'}});
      clearTimeout(timer);
      if(!response.ok) throw new Error(`HTTP ${response.status}`);
      serverDiag=await response.json();
      diagnosticsFetchError='';
      renderDiagnostics({open:show});
      return serverDiag;
    }catch(error){
      diagnosticsFetchError=error?.name==='AbortError'?'TIMEOUT':safeText(error?.message||error);
      recordError('SERVER_DIAGNOSTICS',diagnosticsFetchError);
      renderDiagnostics({open:show});
      return null;
    }
  }

  async function startAutomaticSecurityRetry(nextSecurity,credentialRound,securityAttempt,maxSecurityAttempts){
    if(automaticRetryStarted) return;
    automaticRetryStarted=true;
    const mode=safeText(nextSecurity||'compatible').toUpperCase();
    setState('REINTENTANDO',`Probando ${mode} automáticamente con la misma contraseña…`,'warning');
    if(retryTitle) retryTitle.textContent='Prueba automática de seguridad RDP';
    if(retryText) retryText.textContent=`Contraseña ${credentialRound}: modo ${securityAttempt} de ${maxSecurityAttempts}. GIDEON está probando ${mode}; no necesita volver a escribirla.`;
    if(retryOpen) retryOpen.hidden=true;
    const data=new FormData();data.set('csrf',csrf);
    try{
      const response=await fetch(`/remote/session/${encodeURIComponent(sessionId)}/auto-retry`,{method:'POST',body:data,credentials:'same-origin',headers:{'Accept':'application/json'}});
      let payload={};try{payload=await response.json();}catch(_){payload={};}
      if(!response.ok||!payload.ok) throw new Error(payload.detail||payload.message||`HTTP ${response.status}`);
      location.replace(payload.url);
    }catch(error){
      const message=safeText(error?.message||error||'No se pudo iniciar la prueba automática.');
      recordError('AUTOMATIC_SECURITY_RETRY',message);
      setState('REINTENTO PENDIENTE',message,'danger');
      if(retryTitle) retryTitle.textContent='No se pudo continuar automáticamente';
      if(retryText) retryText.textContent=`${message} Recargue esta página para volver a intentarlo.`;
    }
  }

  async function startAutomaticHandoffReconnect(){
    if(handoffReconnectStarted) return;
    handoffReconnectStarted=true;
    if(handoffReconnectTimer){clearTimeout(handoffReconnectTimer);handoffReconnectTimer=null;}
    setState('REENGANCHANDO','Windows cambió la sesión; reconstruyendo el canal RDP automáticamente…','warning');
    setTransferStatus('No cierre esta ventana. GIDEON está retomando la sesión con la misma credencial efímera.');
    const data=new FormData();data.set('csrf',csrf);
    try{
      const response=await fetch(`/remote/session/${encodeURIComponent(sessionId)}/handoff-reconnect`,{method:'POST',body:data,credentials:'same-origin',headers:{'Accept':'application/json'}});
      let payload={};try{payload=await response.json();}catch(_){payload={};}
      if(!response.ok||!payload.ok) throw new Error(payload.detail||payload.message||`HTTP ${response.status}`);
      location.replace(payload.url);
    }catch(error){
      handoffReconnectStarted=false;
      const message=safeText(error?.message||error||'No se pudo reenganchar la sesión de Windows.');
      recordError('AUTOMATIC_HANDOFF_RECONNECT',message);
      setState('REENGANCHE PENDIENTE',message,'danger');
      setTransferStatus('La sesión cambió, pero el reenganche automático no pudo completarse. Vuelva a Control remoto e intente abrirla otra vez.',true);
    }
  }

  async function probeAutomaticHandoffReconnect(){
    if(!supportsWindowsHandoff||handoffReconnectStarted||operatorDisconnectRequested||!graphicsConfirmed) return;
    const now=Date.now();
    const connectedAge=now-connectedAt;
    const visualIdle=now-lastVisualAt;
    // During a Windows workstation logon/handoff the first RDP transport can
    // remain attached to the old WinStation.  Probe only inside that initial
    // transition window and only after graphics have actually stopped.
    if(connectedAge<18000||connectedAge>180000) return;
    if(visualIdle<9000){
      handoffReconnectTimer=setTimeout(()=>void probeAutomaticHandoffReconnect(),Math.max(3000,10000-visualIdle));
      return;
    }
    const visualBefore=renderedOps();
    handoffChallengeCount++;
    // Visual-only liveness probe. A server-side resize can terminate XRDP on
    // ARM and must never be used as an autoscale mechanism.
    queueVisualFit('windows-session-handoff-probe',0);
    await new Promise(resolve=>setTimeout(resolve,4500));
    if(handoffReconnectStarted||operatorDisconnectRequested||terminal||clientState!==3) return;
    if(renderedOps()>visualBefore||Date.now()-lastVisualAt<4000){
      if(Date.now()-connectedAt<180000) handoffReconnectTimer=setTimeout(()=>void probeAutomaticHandoffReconnect(),10000);
      return;
    }
    recordError('RDP_SESSION_STALL',`Sin cambios gráficos tras ${Math.round((Date.now()-lastVisualAt)/1000)}s y resize challenge ${handoffChallengeCount}`);
    const diagnostic=await fetchDiagnostics(false);
    if(Boolean(diagnostic?.retry?.handoff_reconnect_eligible)){
      await startAutomaticHandoffReconnect();
    }
  }

  function renderDiagnostics({open=false}={}){
    updateDisplayMetrics();
    if(open) setDiagnosticsVisible(true);
    const rendered=renderedOps();
    const serverStatus=safeText(serverDiag?.server_status||'UNKNOWN');
    const liveWithoutRuntimeError=['ACTIVE','ISSUED'].includes(serverStatus.toUpperCase())&&!serverDiag?.end_reason&&!serverDiag?.runtime_error;
    const classification=liveWithoutRuntimeError
      ?(serverStatus.toUpperCase()==='ACTIVE'?'REMOTE_SESSION_ACTIVE':'REMOTE_SESSION_PENDING')
      :safeText(serverDiag?.classification||(rendered===0?'NO_GRAPHICS_YET':'CLIENT_ONLY'));
    const guacd=serverDiag?.guacd||{};
    if(diagServer) diagServer.textContent=serverStatus+(serverDiag?.end_reason?` · ${safeText(serverDiag.end_reason)}`:'');
    if(diagClass) diagClass.textContent=classification;
    if(diagGuacd) diagGuacd.textContent=guacd.online===true?`ONLINE · ${guacd.latency_ms||0} ms`:guacd.online===false?'OFFLINE':'—';
    if(diagSummary){
      if(diagnosticsFetchError) diagSummary.textContent=`No se pudo leer diagnóstico del servidor: ${diagnosticsFetchError}`;
      else if(serverDiag?.runtime_error) diagSummary.textContent='El servidor registró una causa concreta para el cierre de la sesión.';
      else if(rendered===0) diagSummary.textContent='El túnel abrió, pero todavía no se recibió un frame gráfico del escritorio remoto.';
      else if(dom.rootWidth<2||dom.rootHeight<2||dom.elementWidth<2||dom.elementHeight<2||dom.visibleCanvasCount===0) diagSummary.textContent='RDP entregó gráficos, pero la superficie Guacamole no es visible en el DOM. Use Ajustar imagen; el visor intentará repararlo automáticamente.';
      else diagSummary.textContent='La sesión entregó instrucciones gráficas y la superficie Guacamole es visible en el navegador.';
    }
    const recommendation=liveWithoutRuntimeError?'':safeText(serverDiag?.recommendation||'');
    if(diagRecommendation){diagRecommendation.hidden=!recommendation;diagRecommendation.textContent=recommendation;}
    const retry=serverDiag?.retry||{};
    const securityFailure=String(serverDiag?.classification||'')==='RDP_SECURITY_NEGOTIATION';
    const authFailure=securityFailure||['RDP_AUTHENTICATION_FAILED','RDP_AUTHENTICATION','RDP_NLA_PASSWORD_REQUIRED'].includes(String(serverDiag?.classification||''));
    if(retryPanel){
      retryPanel.hidden=!authFailure;
      if(authFailure){
        const remaining=Number(retry.remaining||0);
        const attempt=Number(retry.attempt||1);
        const maximum=Number(retry.max_attempts||1);
        const credentialRound=Number(retry.credential_round||1);
        const maxCredentialRounds=Number(retry.max_credential_rounds||1);
        const securityAttempt=Number(retry.security_attempt||1);
        const maxSecurityAttempts=Number(retry.max_security_attempts||1);
        const automaticEligible=Boolean(retry.automatic_eligible);
        const credentialEligible=Boolean(retry.credential_eligible??retry.eligible);
        const currentSecurity=safeText(retry.rdp_security||guacd.rdp_security||'—').toUpperCase();
        const nextSecurity=safeText(retry.next_rdp_security||'').toUpperCase();
        if(automaticEligible){
          if(retryTitle) retryTitle.textContent='Prueba automática de seguridad RDP';
          if(retryText) retryText.textContent=`El modo ${currentSecurity} falló. GIDEON probará ${nextSecurity||'el siguiente modo'} con la misma contraseña (${securityAttempt+1}/${maxSecurityAttempts}).`;
          if(retryOpen){retryOpen.hidden=true;retryOpen.disabled=true;}
          setTimeout(()=>void startAutomaticSecurityRetry(nextSecurity,credentialRound,securityAttempt+1,maxSecurityAttempts),350);
        }else if(credentialEligible){
          if(retryTitle) retryTitle.textContent='Ingrese otra contraseña';
          if(retryText) retryText.textContent=`La contraseña ${credentialRound} de ${maxCredentialRounds} falló con los ${maxSecurityAttempts} modos autorizados. Ingrese una nueva; GIDEON repetirá las pruebas automáticamente.`;
          if(retryDialogTitle) retryDialogTitle.textContent='Nueva contraseña RDP';
          if(retryDialogSubtitle) retryDialogSubtitle.textContent=`Se iniciará el ciclo de contraseña ${credentialRound+1} de ${maxCredentialRounds}.`;
          if(retryOpen){retryOpen.textContent='Ingresar otra contraseña';retryOpen.hidden=false;retryOpen.disabled=false;}
        }else{
          if(retryTitle) retryTitle.textContent='Conexión RDP no compatible';
          if(retryText) retryText.textContent=`Se probaron ${credentialRound} contraseña(s) y todos los modos autorizados sin éxito. Revise la configuración RDP efectiva del equipo.`;
          if(retryOpen){retryOpen.hidden=true;retryOpen.disabled=true;}
        }
      }
    }
    const lines=[];
    if(serverDiag?.runtime_error) lines.push(`SERVER_RUNTIME_ERROR=${safeText(serverDiag.runtime_error)}`);
    if(guacd.rdp_security) lines.push(`RDP_SECURITY=${safeText(guacd.rdp_security)} ignore_cert=${String(Boolean(guacd.rdp_ignore_cert))}`);
    if(guacd.error) lines.push(`GUACD_HEALTH_ERROR=${safeText(guacd.error)}`);
    for(const row of serverDiag?.audit||[]){
      lines.push(`${safeText(row.created_at)} ${safeText(row.action)} ${safeText(row.result)} ${safeText(row.detail)}`);
    }
    if(diagDetail){diagDetail.hidden=lines.length===0;diagDetail.textContent=lines.join('\n');}
  }

  function buildReport(){
    updateDisplayMetrics();
    const g=graphics;
    const d=serverDiag||{};
    const guacd=d.guacd||{};
    const rendered=renderedOps();
    const rows=[
      `GIDEON REMOTE SESSION ERROR REPORT · ${VERSION}`,
      `generated=${new Date().toISOString()}`,
      `session=${sessionId}`,
      `clientState=${clientState}`,
      `tunnelState=${String(tunnel.state??'-')}`,
      `serverStatus=${safeText(d.server_status||'UNKNOWN')}`,
      `source=${source}`,
      `target=${targetHost}:${targetPort}`,
      `protocol=${protocol}`,
      `sessionMode=${rdpSessionMode}`,
      `intent=${safeText(d.connection_intent||'STANDARD_ACCESS')} localImpact=${safeText(d.local_session_impact||'-')} operatorAcknowledged=${String(Boolean(d.operator_acknowledged))} consentState=${safeText(d.consent_state||'NOT_APPLICABLE')}`,
      `endReason=${safeText(d.end_reason||'-')}`,
      `classification=${safeText(d.classification||'-')}`,
      `clientClassification=${rendered>0&&!d.runtime_error?'GRAPHICS_RECEIVED_CHECK_DISPLAY_VISIBILITY':rendered===0?'NO_GRAPHICS_RECEIVED':'-'}`,
      `viewerWindow=${openedAsDedicatedWindow?'DEDICATED_POPUP':popoutWindow&&!popoutWindow.closed?'DETACHED_LIVE':'WEBADMIN_PAGE'} dedicatedLayout=${String(document.body.classList.contains('gideon-remote-dedicated-mode'))} fullscreen=${String(Boolean((displayRoot.ownerDocument||document).fullscreenElement))} autoscale=visual-only fit=${safeText(dom.lastFitReason||'-')}`,
      `credentialRetry=${d.retry?`connection ${safeText(d.retry.attempt||'-')}/${safeText(d.retry.max_attempts||'-')} credential ${safeText(d.retry.credential_round||'-')}/${safeText(d.retry.max_credential_rounds||'-')} security ${safeText(d.retry.security_attempt||'-')}/${safeText(d.retry.max_security_attempts||'-')} auto=${String(Boolean(d.retry.automatic_eligible))} requestCredential=${String(Boolean(d.retry.credential_eligible))} rdpSecurity=${safeText(d.retry.rdp_security||'-')} next=${safeText(d.retry.next_rdp_security||'-')} handoff=${safeText(d.retry.handoff_reconnect_attempt??'-')}/${safeText(d.retry.max_handoff_reconnects??'-')} handoffEligible=${String(Boolean(d.retry.handoff_reconnect_eligible))}`:'-'}`,
      `serverDiagnosticsFetchError=${diagnosticsFetchError||'-'}`,
      '',
      '[GRAPHICS]',
      `sync=${g.sync} size=${g.size} rect=${g.rect} cfill=${g.cfill} copy=${g.copy} png=${g.png} jpeg=${g.jpeg} img=${g.img} blob=${g.blob} visual=${g.visual} rendered=${rendered} display=${g.displayWidth}x${g.displayHeight} lastOpcode=${g.lastOpcode||'-'} lastSync=${g.lastSync||'-'}`,
      `renderer=html-image-fallback createImageBitmapDisabled=${String(rendererCompatibility.createImageBitmap)} imageDecoderDisabled=${String(rendererCompatibility.imageDecoder)}`,
      '',
      '[DISPLAY_DOM]',
      `viewport=${dom.viewportWidth}x${dom.viewportHeight} root=${dom.rootWidth}x${dom.rootHeight} element=${dom.elementWidth}x${dom.elementHeight} canvases=${dom.canvasCount} visibleCanvases=${dom.visibleCanvasCount} scale=${Number(dom.scale||1).toFixed(4)} lastFit=${safeText(dom.lastFitReason||'-')}`,
      `display=${safeText(dom.displayStyle||'-')} visibility=${safeText(dom.visibility||'-')} opacity=${safeText(dom.opacity||'-')} rootOverflow=${safeText(dom.overflow||'-')}`,
      '',
      '[SERVER]',
      `runtimeError=${safeText(d.runtime_error||'-')}`,
      `recommendation=${safeText(d.recommendation||'-')}`,
      `guacd=${guacd.online===true?'ONLINE':guacd.online===false?'OFFLINE':'UNKNOWN'} ${safeText(guacd.host||'-')}:${safeText(guacd.port||'-')} latencyMs=${safeText(guacd.latency_ms||'-')} rdpSecurity=${safeText(guacd.rdp_security||'-')} ignoreCert=${String(Boolean(guacd.rdp_ignore_cert))}`,
      '',
      '[BROWSER_ERRORS]',
      ...(browserErrors.length?browserErrors:['NONE']),
      '',
      '[SERVER_AUDIT]',
      ...((d.audit||[]).length?(d.audit||[]).map(r=>`${safeText(r.created_at)} [${safeText(r.action)}] ${safeText(r.result)} ${safeText(r.detail)}`):['NONE'])
    ];
    return rows.join('\n');
  }

  async function showTerminalDiagnostics(kind,message){
    terminal=true;
    stopLiveness();
    if(noImageTimer) clearTimeout(noImageTimer);
    if(message) recordError(kind,message);
    await new Promise(resolve=>setTimeout(resolve,250));
    await fetchDiagnostics(true);
  }

  const armNoImageTimer=()=>{
    if(noImageTimer) clearTimeout(noImageTimer);
    noImageTimer=setTimeout(async()=>{
      noImageTimer=null;
      updateDisplayMetrics();
      if(renderedOps()===0&&!terminal&&clientState===3){
        recordError('NO_GRAPHICS','La sesión RDP permanece activa sin instrucciones visuales durante 15 segundos');
        setState('SIN IMAGEN','Sesión activa sin frame gráfico; revisando diagnóstico del servidor…','warning');
        // A missing first image deserves investigation, but the technical card
        // must not cover a desktop that may become visible a moment later.
        await fetchDiagnostics(false);
      }
    },15000);
  };

  client.onerror=(error)=>{
    const message=error?.message||String(error||'Error Guacamole');
    setState('ERROR',message,'danger');
    void showTerminalDiagnostics('GUACAMOLE_CLIENT',message);
  };
  client.onstatechange=(state)=>{
    clientState=Number(state);
    const stateMap={
      0:['IDLE','Esperando…','info'],
      1:['CONECTANDO','Negociando sesión…','warning'],
      2:['ESPERANDO','Esperando respuesta de guacd/RDP…','warning'],
      3:['ACTIVO','Sesión remota activa','success'],
      4:['DESCONECTANDO','Cerrando sesión…','warning'],
      5:['DESCONECTADO','Sesión finalizada','info']
    };
    const row=stateMap[state]||['ESTADO',String(state),'info'];
    setState(...row);
    if(Number(state)===3){
      if(!connectedAt) connectedAt=Date.now();
      // Autoscale is browser-side only. Changing the server-side resolution
      // while XRDP is establishing its desktop can tear down ARM sessions.
      queueVisualFit('connected',0);
      setTimeout(()=>queueVisualFit('connected-stable-1',0),180);
      setTimeout(()=>queueVisualFit('connected-stable-2',0),650);
      if(!graphicsConfirmed) armNoImageTimer();
      startLiveness();
      if(handoffReconnectTimer) clearTimeout(handoffReconnectTimer);
      if(supportsWindowsHandoff) handoffReconnectTimer=setTimeout(()=>void probeAutomaticHandoffReconnect(),18000);
    }
    if(Number(state)===5 && !terminal){
      stopLiveness();
      if(handoffReconnectTimer){clearTimeout(handoffReconnectTimer);handoffReconnectTimer=null;}
      if(operatorDisconnectRequested) setState('DESCONECTADO','Sesión cerrada por el operador.','info');
      void showTerminalDiagnostics('GUACAMOLE_TUNNEL',operatorDisconnectRequested?'Cierre solicitado por el operador':'Sesión remota finalizada');
    }
  };

  const mouse=new Guacamole.Mouse(displayElement);
  // Guacamole.Mouse reports coordinates on the scaled DOM surface. Passing
  // true makes Guacamole.Client map them back through Display.getScale().
  // Coalesce motion to the browser paint cadence. Gaming/high-polling mice can
  // otherwise enqueue hundreds of redundant VNC PointerEvents per second,
  // forcing physical-console servers to generate avoidable update bursts.
  // Button transitions remain immediate and are never coalesced.
  let pendingMouseState=null;
  let pendingMouseFrame=0;
  const flushMouseMotion=()=>{
    pendingMouseFrame=0;
    if(!pendingMouseState)return;
    const state=pendingMouseState;pendingMouseState=null;
    markInput();
    client.sendMouseState(state,true);
  };
  mouse.onmousemove=(mouseState)=>{
    pendingMouseState=mouseState;
    if(!pendingMouseFrame)pendingMouseFrame=requestAnimationFrame(flushMouseMotion);
  };
  mouse.onmousedown=mouse.onmouseup=(mouseState)=>{
    pendingMouseState=null;
    if(pendingMouseFrame){cancelAnimationFrame(pendingMouseFrame);pendingMouseFrame=0;}
    markInput();
    client.sendMouseState(mouseState,true);
  };
  displayRoot.addEventListener('keydown',event=>{
    if(!(event.ctrlKey||event.metaKey)||event.altKey)return;
    const key=String(event.key||'').toLowerCase();
    if(key!=='c'&&key!=='v')return;
    // If GIDEON clipboard bridging is unavailable, do not consume the native
    // shortcut: Guacamole.Keyboard must deliver Ctrl+C/Ctrl+V to the desktop.
    if(!clipboardEnabled) return;
    event.preventDefault();event.stopImmediatePropagation();
    const keysym=key==='c'?0x63:0x76;
    const action=key==='c'?copyFromRemote:pasteIntoRemote;
    void action().catch(error=>{
      // A failed local browser clipboard permission must not swallow the
      // operator's normal remote shortcut.  Copy already sends Ctrl+C before
      // it waits for the remote clipboard, so it is explicitly marked above.
      if(!error?.gideonRemoteShortcutSent){
        try{
          sendRemoteShortcut(keysym);
          setTransferStatus(`No se pudo sincronizar el portapapeles local; Ctrl+${key.toUpperCase()} se envió al escritorio remoto.`,true);
          return;
        }catch(fallbackError){
          setTransferStatus(safeText(fallbackError?.message||fallbackError),true);
          return;
        }
      }
      setTransferStatus(safeText(error?.message||error),true);
    });
  },true);
  installFullscreenKeys(document);
  bindKeyboard(document);
  if(copyButton) copyButton.disabled=!clipboardEnabled;
  if(pasteButton) pasteButton.disabled=!clipboardEnabled;
  if(sendFileButton) sendFileButton.disabled=!fileTransferEnabled;
  const observer=new ResizeObserver(()=>queueVisualFit('resize-observer',80));
  // Observe only the containing viewport. Observing displayRoot would react to
  // display.scale() itself and continually rescale/re-negotiate the desktop.
  observer.observe(viewport);
  displayRoot.addEventListener('click',()=>displayRoot.focus());
  refitButton?.addEventListener('click',()=>queueVisualFit('operator-refit',0));
  copyButton?.addEventListener('click',()=>void copyFromRemote().catch(error=>setTransferStatus(error?.message||error,true)));
  pasteButton?.addEventListener('click',()=>void pasteIntoRemote().catch(error=>setTransferStatus(error?.message||error,true)));
  sendFileButton?.addEventListener('click',()=>chooseRemoteFile(document));
  fileInput?.addEventListener('change',async()=>{
    const file=fileInput.files?.[0];fileInput.value='';if(!file)return;
    await handleSelectedFile(file);
  });
  fullscreenButton?.addEventListener('click',()=>void toggleFullscreen(document));
  popoutButton?.addEventListener('click',()=>{if(popoutWindow&&!popoutWindow.closed)returnFromPopout(false);else openPopout();});
  window.addEventListener('resize',()=>{queueVisualFit('window-resize',80);syncToolbarMenus();});
  window.visualViewport?.addEventListener('resize',()=>{queueVisualFit('visual-viewport-resize',80);syncToolbarMenus();});
  disconnect?.addEventListener('click',()=>{operatorDisconnectRequested=true;stopLiveness();if(handoffReconnectTimer){clearTimeout(handoffReconnectTimer);handoffReconnectTimer=null;}try{client.disconnect();}finally{setState('DESCONECTADO','Sesión cerrada por el operador.','info');try{popoutWindow?.close();}catch(_){}}});
  window.addEventListener('beforeunload',()=>{stopLiveness();try{popoutWindow?.close();}catch(_){} try{client.disconnect();}catch(_){}});
  diagToggle?.addEventListener('click',()=>{
    const opening=!diagnosticsRequested;
    setDiagnosticsVisible(opening);
    if(opening) void fetchDiagnostics(false);
  });
  closeDiag?.addEventListener('click',()=>setDiagnosticsVisible(false));
  refreshDiag?.addEventListener('click',()=>void fetchDiagnostics(false));
  copyDiag?.addEventListener('click',async()=>{
    await fetchDiagnostics(false);
    const report=buildReport();
    try{await navigator.clipboard.writeText(report);copyDiag.textContent='Copiado';setTimeout(()=>copyDiag.textContent='Copiar reporte',1200);}catch(_){
      if(diagDetail){setDiagnosticsVisible(true);diagDetail.hidden=false;diagDetail.textContent=report;}
    }
  });
  retryOpen?.addEventListener('click',openRetryDialog);
  retryClose?.addEventListener('click',closeRetryDialog);
  retryCancel?.addEventListener('click',closeRetryDialog);
  retryPasswordToggle?.addEventListener('click',()=>setRetryPasswordVisible(retryPassword?.type==='password'));
  retryDialog?.addEventListener('cancel',event=>{event.preventDefault();closeRetryDialog();});
  retryForm?.addEventListener('submit',async event=>{
    event.preventDefault();
    if(!retryUsername?.value.trim()){showRetryError('Ingrese el usuario remoto.');retryUsername?.focus();return;}
    if(!retryPassword?.value){showRetryError('Ingrese la contraseña.');retryPassword?.focus();return;}
    const data=new FormData();
    data.set('csrf',csrf);
    data.set('interactive_username',retryUsername.value.trim());
    data.set('interactive_password',retryPassword.value);
    data.set('interactive_domain',retryDomain?.value.trim()||'');
    showRetryError('');
    if(retrySubmit){retrySubmit.disabled=true;retrySubmit.textContent='Conectando…';}
    try{
      const response=await fetch(`/remote/session/${encodeURIComponent(sessionId)}/retry`,{method:'POST',body:data,credentials:'same-origin',headers:{'Accept':'application/json'}});
      let payload={};try{payload=await response.json();}catch(_){payload={};}
      if(!response.ok||!payload.ok) throw new Error(payload.detail||payload.message||`HTTP ${response.status}`);
      retryPassword.value='';
      location.assign(payload.url);
    }catch(error){
      retryPassword.value='';
      setRetryPasswordVisible(false);
      showRetryError(safeText(error?.message||error||'No se pudo iniciar el reintento.'));
      if(retrySubmit){retrySubmit.disabled=false;retrySubmit.textContent='Reintentar conexión';}
    }
  });

  if(!connectable){
    terminal=true;
    setState('FINALIZADA','La sesión ya terminó. Mostrando diagnóstico del servidor.','warning');
    void fetchDiagnostics(true);
    return;
  }

  setState('CONECTANDO','Abriendo túnel WSS seguro…','warning');
  client.connect('');
  setTimeout(()=>queueVisualFit('connect-250ms',0),250);
  setTimeout(()=>queueVisualFit('connect-900ms',0),900);
  setTimeout(()=>queueVisualFit('connect-1800ms',0),1800);
  setTimeout(()=>{
    updateDisplayMetrics();
    const rendered=renderedOps();
    if(rendered>0&&(dom.rootWidth<2||dom.rootHeight<2||dom.elementWidth<2||dom.elementHeight<2||dom.visibleCanvasCount===0)){
      recordError('DISPLAY_VISIBILITY','Se recibieron gráficos, pero la superficie/canvas Guacamole no era visible; se aplicó reparación de layout y escala.');
      setState('AJUSTANDO IMAGEN','RDP está enviando gráficos; corrigiendo la superficie del visor…','warning');
      fitDisplay('auto-visibility-repair');
      setTimeout(()=>{updateDisplayMetrics();if(clientState===3)setState('ACTIVO','Sesión remota activa','success');},350);
    }
  },2600);
})();
