(()=>{
  const html=document.documentElement;
  const saved=localStorage.getItem('gideon-theme');
  if(saved) html.dataset.theme=saved;

  const text=(el,value)=>{if(el) el.textContent=value??''};
  const formEncoded=(form,extra={})=>{
    const body=new URLSearchParams();
    if(form){new FormData(form).forEach((v,k)=>{if(typeof v==='string') body.set(k,v)});}
    Object.entries(extra).forEach(([k,v])=>body.set(k,String(v??'')));
    return body;
  };
  const postForm=async(url,form,extra={})=>{
    const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:formEncoded(form,extra)});
    const data=await response.json();
    if(!response.ok) throw new Error(data.detail||`HTTP ${response.status}`);
    return data;
  };

  function enhanceErrorCopy(){
    document.querySelectorAll('.alert.danger,.auth-error').forEach((box,index)=>{
      if(box.dataset.errorCopyReady==='1') return;
      box.dataset.errorCopyReady='1';
      const payload=(box.querySelector('[data-error-text]')?.textContent||box.textContent||'').trim();
      if(!payload) return;
      const row=document.createElement('div'); row.className='error-copy-row';
      const btn=document.createElement('button');
      btn.type='button'; btn.className='btn btn-small error-copy-btn'; btn.textContent='Copiar error completo';
      btn.dataset.copyValue=payload;
      row.append(btn);
      box.append(row);
    });
  }

  function readBuilderCatalog(){
    const node=document.getElementById('agentBuilderCatalog');
    if(!node) return null;
    try{return JSON.parse(node.textContent||'{}');}catch(_){return null;}
  }

  function builderElements(){
    const form=document.getElementById('agentBuilderForm');
    if(!form) return null;
    return {
      form,
      catalog:readBuilderCatalog(),
      profile:document.getElementById('builderProfileSelect'),
      family:document.getElementById('builderOsFamily'),
      variant:document.getElementById('builderOsVariant'),
      architecture:document.getElementById('builderArchitecture'),
      packageChoice:document.getElementById('builderPackageChoice'),
      packageDetail:document.getElementById('builderPackageDetail'),
      targetCompat:document.getElementById('targetPackageCompat'),
      connectivity:document.getElementById('builderConnectivityMode'),
      nameMode:document.getElementById('builderAgentNameMode'),
      agentName:document.getElementById('builderAgentName'),
      enrollment:document.getElementById('builderEnrollmentMode'),
      enrollmentHelp:document.getElementById('builderEnrollmentHelp'),
      maxUses:document.getElementById('builderMaxUses'),
      vlcDelivery:document.getElementById('builderVlcDelivery'),
      vlcDeliveryHelp:document.getElementById('builderVlcDeliveryHelp'),
      vlcDeliveryNotice:document.getElementById('builderVlcDeliveryNotice'),
      vlcDeliveryChip:document.getElementById('builderVlcDeliveryChip'),
      resultTitle:document.getElementById('builderResultTitle'),
      resultNotes:document.getElementById('builderResultNotes'),
      resultTarget:document.getElementById('builderResultTarget'),
      resultFormat:document.getElementById('builderResultFormat'),
      resultBackend:document.getElementById('builderResultBackend')
    };
  }

  const replaceOptions=(select,rows,valueKey='id',labelKey='label')=>{
    if(!select) return;
    const previous=select.value;
    select.replaceChildren();
    (rows||[]).forEach(row=>{
      const option=document.createElement('option');
      option.value=String(row[valueKey]??'');
      option.textContent=String(row[labelKey]??row[valueKey]??'');
      select.append(option);
    });
    if([...select.options].some(o=>o.value===previous)) select.value=previous;
  };

  function builderFamily(b){return (b?.catalog?.families||[]).find(x=>x.id===b.family?.value);}
  function builderVariant(b){return (builderFamily(b)?.variants||[]).find(x=>x.id===b.variant?.value);}
  function builderPackage(b){return (builderVariant(b)?.package_options||[]).find(x=>x.value===b.packageChoice?.value);}

  function updateBuilderPreview(b){
    if(!b) return;
    const family=builderFamily(b), variant=builderVariant(b), pkg=builderPackage(b);
    if(!variant){
      text(b.resultTitle,'—'); text(b.resultNotes,'Seleccione una plataforma.');
      text(b.resultTarget,'TARGET —'); text(b.resultFormat,'FORMATO —'); text(b.resultBackend,'BACKEND —');
      if(b.targetCompat) b.targetCompat.value='';
      updateVlcDelivery(b);
      return;
    }
    text(b.resultTitle,`${family?.label||''} · ${variant.label} · ${variant.architecture_label||variant.architecture}`);
    text(b.resultNotes,variant.notes||'');
    text(b.resultTarget,`TARGET ${variant.target_id}`);
    text(b.resultFormat,pkg?String(pkg.label||pkg.resolved||pkg.value).toUpperCase():'FORMATO —');
    text(b.resultBackend,pkg?String(pkg.backend||'Backend GIDEON').toUpperCase():'BACKEND —');
    if(b.packageDetail) b.packageDetail.textContent=pkg?.detail||'Formato disponible en el backend actual.';
    if(b.targetCompat) b.targetCompat.value=pkg?`${variant.target_id}|${pkg.value}`:'';
    updateVlcDelivery(b);
  }

  function updateVlcDelivery(b){
    if(!b?.vlcDelivery) return;
    if(!['detached','bundled'].includes(b.vlcDelivery.value)) b.vlcDelivery.value='detached';
    const reduced=b.vlcDelivery.value==='detached';
    if(b.vlcDeliveryHelp){
      b.vlcDeliveryHelp.textContent=reduced
        ?'Recomendado: instala y reproduce normalmente; el ZIP legal de fuentes se descarga y conserva por separado.'
        :'Kit autocontenido de mayor tamaño: incluye VLC, avisos y fuentes correspondientes dentro del instalador.';
    }
    if(b.vlcDeliveryNotice) b.vlcDeliveryNotice.hidden=!reduced;
    if(b.vlcDeliveryChip){
      b.vlcDeliveryChip.textContent=reduced?'Operativo + fuentes separadas':'Kit completo autocontenido';
      b.vlcDeliveryChip.className='chip success';
    }
  }

  function populateBuilderPackages(b){
    const variant=builderVariant(b);
    if(!b?.packageChoice) return;
    b.packageChoice.replaceChildren();
    (variant?.package_options||[]).forEach(row=>{
      const option=document.createElement('option');
      option.value=String(row.value||'');
      option.textContent=`${row.label||row.resolved||row.value}${row.ready?'':' · No disponible'}`;
      option.disabled=!row.ready;
      option.dataset.resolved=String(row.resolved||'');
      option.dataset.backend=String(row.backend||'');
      option.dataset.detail=String(row.detail||'');
      b.packageChoice.append(option);
    });
    const preferred=[...b.packageChoice.options].find(o=>!o.disabled);
    if(preferred) b.packageChoice.value=preferred.value;
    updateBuilderPreview(b);
  }

  function populateBuilderVariant(b){
    const variant=builderVariant(b);
    if(!variant) return;
    replaceOptions(b.architecture,[{id:variant.architecture,label:variant.architecture_label||variant.architecture}]);
    b.architecture.value=variant.architecture;
    populateBuilderPackages(b);
  }

  function populateBuilderFamily(b,preferredVariant=''){
    const family=builderFamily(b);
    replaceOptions(b.variant,family?.variants||[]);
    if(preferredVariant&&[...b.variant.options].some(o=>o.value===preferredVariant)) b.variant.value=preferredVariant;
    populateBuilderVariant(b);
  }

  function markBuilderCustom(b){
    if(!b?.profile) return;
    if(b.profile.value!=='custom') b.profile.value='custom';
  }

  function applyBuilderProfile(b){
    if(!b?.catalog||!b.profile) return;
    const profile=(b.catalog.profiles||[]).find(x=>x.id===b.profile.value);
    if(!profile||profile.id==='custom') return;
    if(profile.os_family&&[...b.family.options].some(o=>o.value===profile.os_family)){
      b.family.value=profile.os_family;
      populateBuilderFamily(b,profile.os_variant||'');
    }
    if(b.connectivity&&profile.connectivity_mode) b.connectivity.value=profile.connectivity_mode;
    applyConnectivityMode(b.connectivity?.value||'automatic');
    updateBuilderPreview(b);
  }

  function updateAgentNameMode(b){
    if(!b?.agentName||!b.nameMode) return;
    const custom=b.nameMode.value==='custom';
    b.agentName.disabled=!custom;
    b.agentName.required=custom;
    if(!custom) b.agentName.value='';
  }

  function updateEnrollmentMode(b){
    if(!b?.enrollment||!b.maxUses) return;
    const row=(b.catalog?.enrollment_modes||[]).find(x=>x.id===b.enrollment.value);
    if(!row) return;
    b.maxUses.min=String(row.min_uses??1);
    b.maxUses.max=String(row.max_uses??100);
    b.maxUses.value=String(row.default_uses??1);
    b.maxUses.readOnly=row.id==='individual';
    text(b.enrollmentHelp,row.description||'');
  }

  function selectLanGateway(){
    const g=gatewayElements(); if(!g) return false;
    const index=[...g.select.options].findIndex(o=>!o.disabled&&o.dataset.role==='INTERNAL'&&o.dataset.localTest!=='1');
    if(index<0){if(g.detail) g.detail.textContent='No hay un endpoint LAN detectado. Puede usar Personalizado e introducir una URL HTTPS interna.';return false;}
    g.select.selectedIndex=index; applyGatewaySelection(); return true;
  }

  function applyConnectivityMode(mode){
    const clean=String(mode||'automatic');
    if(clean==='local_test'){selectLocalGateway();return;}
    if(clean==='lan'){selectLanGateway();return;}
    if(clean==='automatic'||clean==='production') selectDefaultRemoteGateway();
  }

  function initUnifiedBuilder(){
    const b=builderElements(); if(!b?.catalog) return;
    replaceOptions(b.family,b.catalog.families||[]);
    populateBuilderFamily(b);
    if(b.profile&&[...b.profile.options].some(o=>o.value==='windows_server_2022_pulse')) b.profile.value='windows_server_2022_pulse';
    applyBuilderProfile(b);
    updateAgentNameMode(b);
    updateEnrollmentMode(b);
    updateVlcDelivery(b);

    b.profile?.addEventListener('change',()=>applyBuilderProfile(b));
    b.family?.addEventListener('change',()=>{populateBuilderFamily(b);markBuilderCustom(b);updateBuilderPreview(b);});
    b.variant?.addEventListener('change',()=>{populateBuilderVariant(b);markBuilderCustom(b);updateBuilderPreview(b);});
    b.architecture?.addEventListener('change',()=>{markBuilderCustom(b);updateBuilderPreview(b);});
    b.packageChoice?.addEventListener('change',()=>{markBuilderCustom(b);updateBuilderPreview(b);});
    b.connectivity?.addEventListener('change',()=>{applyConnectivityMode(b.connectivity.value);});
    b.nameMode?.addEventListener('change',()=>updateAgentNameMode(b));
    b.enrollment?.addEventListener('change',()=>updateEnrollmentMode(b));
    b.vlcDelivery?.addEventListener('change',()=>updateVlcDelivery(b));
  }

  function gatewayElements(){
    const select=document.getElementById('gatewayEndpointSelect');
    if(!select) return null;
    const form=select.closest('form');
    return {
      select,form,
      input:document.getElementById('gatewayUrlInput'),
      mode:document.getElementById('gatewayModeInput'),
      role:document.getElementById('gatewayRuntimeRole'),
      source:document.getElementById('gatewayRuntimeSource'),
      status:document.getElementById('gatewayRuntimeStatus'),
      tls:document.getElementById('gatewayRuntimeTls'),
      latency:document.getElementById('gatewayRuntimeLatency'),
      checked:document.getElementById('gatewayRuntimeChecked'),
      url:document.getElementById('gatewayRuntimeUrl'),
      detail:document.getElementById('gatewayProbeDetail'),
      localBanner:document.getElementById('localTestBanner'),
      localBox:document.getElementById('localDiagnostics'),
      localStatus:document.getElementById('localDiagnosticStatus'),
      localChecks:document.getElementById('localDiagnosticChecks'),
      localMeta:document.getElementById('localDiagnosticMeta')
    };
  }

  function applyGatewaySelection(){
    const g=gatewayElements(); if(!g) return;
    const opt=g.select.options[g.select.selectedIndex]; if(!opt) return;
    const manual=opt.value==='manual';
    const url=manual?(g.input?.value||''):(opt.dataset.url||'');
    if(g.input){
      if(!manual) g.input.value=url;
      g.input.readOnly=!manual;
      g.input.classList.toggle('gateway-manual-active',manual);
    }
    if(g.mode) g.mode.value=opt.dataset.mode||'production';
    text(g.role,manual?'Gateway manual':(opt.dataset.role||'Gateway'));
    text(g.source,opt.dataset.source||'Operador');
    text(g.url,url||'—');
    text(g.status,opt.dataset.status||'NO PROBADO');
    text(g.tls,opt.dataset.tls||'NO PROBADO');
    text(g.latency,opt.dataset.latency?`${opt.dataset.latency} ms`:'—');
    text(g.checked,opt.dataset.lastChecked||'—');
    if(g.localBanner) g.localBanner.hidden=opt.dataset.localTest!=='1';
    if(g.localBox && opt.dataset.localTest!=='1') g.localBox.hidden=true;
    if(g.detail) g.detail.textContent='';
  }

  function selectLocalGateway(){
    const g=gatewayElements(); if(!g) return false;
    const index=[...g.select.options].findIndex(o=>o.dataset.localTest==='1'&&!o.disabled);
    if(index<0){
      if(g.detail) g.detail.textContent='No se detectó un puerto local del Gateway. Revise la configuración runtime instalada.';
      return false;
    }
    g.select.selectedIndex=index;
    applyGatewaySelection();
    return true;
  }

  function selectDefaultRemoteGateway(){
    const g=gatewayElements(); if(!g) return;
    const index=[...g.select.options].findIndex(o=>!o.disabled&&o.value!=='manual'&&o.dataset.localTest!=='1'&&['ADVERTISED','SAVED'].includes(o.dataset.role));
    if(index>=0) g.select.selectedIndex=index; else g.select.value='manual';
    applyGatewaySelection();
  }

  async function testGateway(){
    const g=gatewayElements(); if(!g) return;
    if(g.status){g.status.textContent='PROBANDO';g.status.className='chip warning';}
    try{
      const data=await postForm('/installers/gateway/test',g.form);
      text(g.status,data.status||'ERROR');
      text(g.tls,data.tls||'—');
      text(g.latency,data.latency_ms!=null?`${data.latency_ms} ms`:'—');
      text(g.checked,data.last_checked||'—');
      text(g.detail,data.detail||'');
      if(g.status) g.status.className=`chip ${data.status==='ONLINE'?'success':'danger'}`;
      const opt=g.select.options[g.select.selectedIndex];
      if(opt){
        opt.dataset.status=data.status||'ERROR';
        opt.dataset.tls=data.tls||'';
        opt.dataset.latency=data.latency_ms??'';
        opt.dataset.lastChecked=data.last_checked||'';
      }
    }catch(err){
      if(g.status){g.status.textContent='ERROR';g.status.className='chip danger';}
      text(g.detail,err.message||String(err));
    }
  }

  async function saveGateway(){
    const g=gatewayElements(); if(!g) return;
    const opt=g.select.options[g.select.selectedIndex];
    if(!opt||opt.value!=='manual'){
      text(g.detail,"'Guardar como Gateway configurado' se utiliza únicamente para una URL introducida manualmente.");
      return;
    }
    try{
      const data=await postForm('/installers/gateway/save',g.form,{gateway_label:'Gateway manual'});
      if(!data.ok) throw new Error(data.detail||'No se pudo guardar');
      text(g.detail,`Gateway guardado: ${data.url}. Recargue la página para verlo en la lista detectada.`);
    }catch(err){text(g.detail,err.message||String(err));}
  }

  async function localDiagnostics(){
    const g=gatewayElements(); if(!g) return;
    if(!selectLocalGateway()) return;
    if(g.localBox) g.localBox.hidden=false;
    if(g.localStatus){g.localStatus.textContent='PROBANDO';g.localStatus.className='chip warning';}
    if(g.localChecks) g.localChecks.replaceChildren();
    try{
      const data=await postForm('/installers/gateway/local-diagnostics',g.form);
      if(g.localStatus){g.localStatus.textContent=data.ok?'LISTO':'REQUIERE ATENCIÓN';g.localStatus.className=`chip ${data.ok?'success':'warning'}`;}
      (data.checks||[]).forEach(row=>{
        const item=document.createElement('div'); item.className='gateway-check-row';
        const mark=document.createElement('span'); mark.className=`chip ${row.ok?'success':'danger'}`; mark.textContent=row.ok?'OK':'FALLA';
        const body=document.createElement('div');
        const name=document.createElement('strong'); name.textContent=row.name||'Comprobación';
        const detail=document.createElement('small'); detail.textContent=row.detail||'';
        body.append(name,detail); item.append(mark,body); g.localChecks?.append(item);
      });
      text(g.localMeta,`Local: ${data.local_url||'—'} · Anunciado: ${data.advertised_endpoint||'—'} · ${data.checked_at||''}`);
    }catch(err){
      if(g.localStatus){g.localStatus.textContent='ERROR';g.localStatus.className='chip danger';}
      text(g.localMeta,err.message||String(err));
    }
  }

  const initialGateway=gatewayElements();
  if(initialGateway){
    applyGatewaySelection();
    initialGateway.select.addEventListener('change',applyGatewaySelection);
    initialGateway.input?.addEventListener('input',()=>{
      const opt=initialGateway.select.options[initialGateway.select.selectedIndex];
      if(opt?.value==='manual'){
        text(initialGateway.url,initialGateway.input.value||'—');
        if(initialGateway.mode) initialGateway.mode.value='manual';
      }
    });
  }

  document.addEventListener('click',e=>{
    const back=e.target.closest('[data-gideon-back]');
    if(back){
      e.preventDefault();
      const fallback=back.dataset.backFallback||back.getAttribute('href')||'/';
      let sameOrigin=false;
      try{sameOrigin=Boolean(document.referrer)&&new URL(document.referrer).origin===location.origin;}catch(_){sameOrigin=false;}
      const refPath=(()=>{try{return new URL(document.referrer).pathname;}catch(_){return '';}})();
      const unsafe=!sameOrigin||!refPath||refPath==='/login'||refPath==='/logout'||refPath===location.pathname;
      if(unsafe){location.assign(fallback);}else{history.back();}
      return;
    }
    const theme=e.target.closest('[data-theme-toggle]');
    if(theme){const next=html.dataset.theme==='dark'?'light':'dark';html.dataset.theme=next;localStorage.setItem('gideon-theme',next);}
    const menu=e.target.closest('[data-menu-toggle]');
    if(menu){document.querySelector('.sidebar')?.classList.toggle('open');document.querySelector('.backdrop')?.classList.toggle('open');}
    if(e.target.matches('.backdrop')){document.querySelector('.sidebar')?.classList.remove('open');e.target.classList.remove('open');}
    const copyValue=e.target.closest('[data-copy-value]');
    if(copyValue){navigator.clipboard?.writeText(copyValue.dataset.copyValue||'');const old=copyValue.textContent;copyValue.textContent='Copiado';setTimeout(()=>copyValue.textContent=old,1200);}
    const copy=e.target.closest('[data-copy]');
    if(copy){const sel=copy.getAttribute('data-copy');const el=document.querySelector(sel);if(el){navigator.clipboard?.writeText(el.textContent||'');const old=copy.textContent;copy.textContent='Copiado';setTimeout(()=>copy.textContent=old,1200);}}
    const all=e.target.closest('[data-select-all]');
    if(all){document.querySelectorAll(all.dataset.selectAll).forEach(x=>x.checked=true)}
    const none=e.target.closest('[data-select-none]');
    if(none){document.querySelectorAll(none.dataset.selectNone).forEach(x=>x.checked=false)}
    const members=e.target.closest('[data-select-members]');
    if(members){
      const ids=new Set((members.dataset.selectMembers||'').split('|').filter(Boolean));
      const selector=members.dataset.target||"input[name='agent_id']";
      document.querySelectorAll(selector).forEach(x=>x.checked=ids.has(x.value));
    }
    if(e.target.closest('[data-gateway-test]')) testGateway();
    if(e.target.closest('[data-use-local-test]')){const b=builderElements();if(b?.connectivity)b.connectivity.value='local_test';selectLocalGateway();localDiagnostics();}
    if(e.target.closest('[data-local-diagnostics]')) localDiagnostics();
    if(e.target.closest('[data-disable-local-test]')){const b=builderElements();if(b?.connectivity)b.connectivity.value='automatic';selectDefaultRemoteGateway();}
    if(e.target.closest('[data-save-gateway]')) saveGateway();
  });

  // The dedicated local-build submit always switches the visible form to the
  // explicit local endpoint before the browser serializes it.
  document.querySelectorAll('button[name="build_action"][value="local_test"]').forEach(btn=>{
    btn.addEventListener('click',e=>{const b=builderElements();if(b?.connectivity)b.connectivity.value='local_test';if(!selectLocalGateway()) e.preventDefault();});
  });

  enhanceErrorCopy();
  initUnifiedBuilder();

  const autoRefresh=document.querySelector('[data-auto-refresh]');
  if(autoRefresh){
    if(autoRefresh.dataset.partialRefreshUrl && window.GIDEONLive) window.GIDEONLive.start(autoRefresh);
    else {const ms=Math.max(1500,Math.min(15000,Number(autoRefresh.dataset.autoRefresh||3500)));setTimeout(()=>location.reload(),ms);}
  }

  // RC30.95.9 · Releases live refresh + stable viewport + sidebar scroll UX.
  const RELEASE_ROOT='#releasesLiveRoot';
  const NAV_SCROLL_KEY='gideon-sidebar-nav-scroll-v1';
  const RELEASE_SCROLL_KEY='gideon-releases-window-scroll-v1';

  function rememberSidebarScroll(){
    const nav=document.querySelector('.sidebar .nav');
    if(!nav) return;
    try{
      const saved=Number(sessionStorage.getItem(NAV_SCROLL_KEY)||0);
      if(Number.isFinite(saved)&&saved>0) nav.scrollTop=saved;
    }catch(_){}
    let raf=0;
    nav.addEventListener('scroll',()=>{
      if(raf) return;
      raf=requestAnimationFrame(()=>{
        raf=0;
        try{sessionStorage.setItem(NAV_SCROLL_KEY,String(Math.round(nav.scrollTop)));}catch(_){}
      });
    },{passive:true});
  }

  function rememberReleasesReloadScroll(){
    if(location.pathname!=='/releases') return;
    const navEntry=performance.getEntriesByType?.('navigation')?.[0];
    const navType=String(navEntry?.type||'');
    try{
      if(navType==='reload'||navType==='back_forward'){
        const saved=Number(sessionStorage.getItem(RELEASE_SCROLL_KEY)||0);
        if(Number.isFinite(saved)&&saved>0){
          requestAnimationFrame(()=>requestAnimationFrame(()=>window.scrollTo({top:saved,left:0,behavior:'auto'})));
        }
      }
    }catch(_){}
    let raf=0;
    window.addEventListener('scroll',()=>{
      if(raf) return;
      raf=requestAnimationFrame(()=>{
        raf=0;
        try{sessionStorage.setItem(RELEASE_SCROLL_KEY,String(Math.round(window.scrollY)));}catch(_){}
      });
    },{passive:true});
  }

  const releaseFormIdentity=(form)=>{
    if(!form) return '';
    const fd=new FormData(form);
    const pick=(name)=>String(fd.get(name)||'').trim();
    const action=(()=>{try{return new URL(form.action,location.href).pathname;}catch(_){return form.getAttribute('action')||'';}})();
    return [
      action,
      pick('target_id'),
      pick('platform'),
      pick('architecture'),
      pick('channel'),
      pick('version')
    ].join('|');
  };

  const releaseAnchor=(form)=>form?.closest('tr')||form?.closest('.card')||form;

  function showReleaseToast(message,kind='success'){
    let toast=document.querySelector('.gideon-release-toast');
    if(!toast){
      toast=document.createElement('div');
      toast.className='gideon-release-toast';
      toast.setAttribute('role','status');
      toast.setAttribute('aria-live','polite');
      document.body.append(toast);
    }
    toast.classList.remove('success','danger','show');
    toast.classList.add(kind);
    toast.textContent=message;
    requestAnimationFrame(()=>toast.classList.add('show'));
    clearTimeout(showReleaseToast._timer);
    showReleaseToast._timer=setTimeout(()=>toast.classList.remove('show'),2200);
  }

  function setReleaseBusy(root,busy,label='Actualizando…'){
    if(!root) return;
    root.dataset.liveBusy=busy?'1':'0';
    const status=root.querySelector('[data-release-live-status]');
    if(status){
      status.hidden=!busy;
      const textNode=status.querySelector('[data-release-live-text]');
      if(textNode) textNode.textContent=label;
    }
  }

  function setButtonBusy(button,busy){
    if(!button) return;
    if(busy){
      if(!button.dataset.liveOriginalText) button.dataset.liveOriginalText=button.textContent||'';
      button.disabled=true;
      button.classList.add('is-busy');
      button.setAttribute('aria-busy','true');
      button.textContent='Procesando…';
    }else{
      button.disabled=false;
      button.classList.remove('is-busy');
      button.removeAttribute('aria-busy');
      if(button.dataset.liveOriginalText){
        button.textContent=button.dataset.liveOriginalText;
        delete button.dataset.liveOriginalText;
      }
    }
  }

  function findReleaseFormByIdentity(root,identity){
    if(!root||!identity) return null;
    return [...root.querySelectorAll('form')].find(f=>releaseFormIdentity(f)===identity)||null;
  }

  async function submitReleaseLive(form,submitter){
    const root=form.closest(RELEASE_ROOT);
    if(!root) return false;

    const identity=releaseFormIdentity(form);
    const beforeAnchor=releaseAnchor(form);
    const beforeTop=beforeAnchor?.getBoundingClientRect?.().top ?? null;
    const beforeWindowY=window.scrollY;
    const beforeNav=document.querySelector('.sidebar .nav')?.scrollTop||0;

    setButtonBusy(submitter,true);
    setReleaseBusy(root,true,'Aplicando cambio…');

    try{
      const response=await fetch(form.action||location.href,{
        method:(form.method||'POST').toUpperCase(),
        body:new FormData(form),
        credentials:'same-origin',
        redirect:'follow',
        headers:{
          'X-GIDEON-Live-Refresh':'releases',
          'Accept':'text/html'
        }
      });

      const htmlText=await response.text();
      const parsed=new DOMParser().parseFromString(htmlText,'text/html');
      const incoming=parsed.querySelector(RELEASE_ROOT);

      // Session expired or route returned a page outside Releases.
      if(!incoming){
        if(response.redirected&&response.url){
          location.assign(response.url);
          return true;
        }
        throw new Error(`Respuesta inesperada HTTP ${response.status}`);
      }

      const imported=document.importNode(incoming,true);
      root.replaceWith(imported);
      enhanceErrorCopy();

      // Keep the exact row/card in the same visual position whenever possible.
      const newForm=findReleaseFormByIdentity(imported,identity);
      const newAnchor=releaseAnchor(newForm);
      if(beforeTop!==null&&newAnchor){
        const afterTop=newAnchor.getBoundingClientRect().top;
        window.scrollBy({top:afterTop-beforeTop,left:0,behavior:'auto'});
      }else{
        window.scrollTo({top:beforeWindowY,left:0,behavior:'auto'});
      }

      const nav=document.querySelector('.sidebar .nav');
      if(nav) nav.scrollTop=beforeNav;

      // HTTP 4xx may still return a Releases page containing the actual error.
      if(!response.ok){
        showReleaseToast(`No se pudo aplicar el cambio (HTTP ${response.status})`,'danger');
      }else{
        showReleaseToast('Vista actualizada','success');
      }
      return true;
    }catch(err){
      setButtonBusy(submitter,false);
      setReleaseBusy(root,false);
      showReleaseToast(err?.message||'No se pudo actualizar la vista','danger');
      return true;
    }
  }

  rememberSidebarScroll();
  rememberReleasesReloadScroll();

  // Delegated submit handling survives the partial DOM replacement.
  document.addEventListener('submit',e=>{
    const form=e.target instanceof HTMLFormElement?e.target:null;
    if(!form) return;

    const isReleaseLive=Boolean(form.closest(RELEASE_ROOT));
    if(form.dataset.confirm&&!confirm(form.dataset.confirm)){
      e.preventDefault();
      return;
    }

    if(isReleaseLive){
      e.preventDefault();
      submitReleaseLive(form,e.submitter||form.querySelector('button[type="submit"],button:not([type])'));
    }
  });

  // RC30.95.11 · Global visual / interaction polish.
  const globalProgress=document.querySelector('[data-global-progress]');

  function startGlobalProgress(){
    if(!globalProgress) return;
    globalProgress.classList.add('is-active');
  }
  function stopGlobalProgress(){
    globalProgress?.classList.remove('is-active');
  }

  function updateThemeUX(){
    const btn=document.querySelector('[data-theme-toggle]');
    if(!btn) return;
    const dark=html.dataset.theme==='dark';
    const label=dark?'Cambiar a tema claro':'Cambiar a tema oscuro';
    btn.setAttribute('aria-label',label);
    btn.setAttribute('title',label);
    const meta=document.querySelector('meta[name="theme-color"]');
    if(meta) meta.setAttribute('content',dark?'#071e2b':'#004c6d');
  }

  function updateTopbarShadow(){
    const topbar=document.querySelector('.topbar');
    if(topbar) topbar.classList.toggle('is-scrolled',window.scrollY>6);
  }

  function keepActiveNavVisible(){
    const nav=document.querySelector('.sidebar .nav');
    const active=nav?.querySelector('.nav-link.active');
    if(!nav||!active) return;
    active.setAttribute('aria-current','page');
    const navBox=nav.getBoundingClientRect();
    const itemBox=active.getBoundingClientRect();
    if(itemBox.top<navBox.top+8){
      nav.scrollTop-=Math.ceil((navBox.top+8)-itemBox.top);
    }else if(itemBox.bottom>navBox.bottom-8){
      nav.scrollTop+=Math.ceil(itemBox.bottom-(navBox.bottom-8));
    }
  }

  function setMenuExpanded(open){
    const sidebar=document.querySelector('.sidebar');
    const backdrop=document.querySelector('.backdrop');
    const button=document.querySelector('.mobile-menu[data-menu-toggle]');
    sidebar?.classList.toggle('open',open);
    backdrop?.classList.toggle('open',open);
    button?.setAttribute('aria-expanded',open?'true':'false');
    button?.setAttribute('aria-label',open?'Cerrar menú':'Abrir menú');
  }

  function initPasswordUX(){
    document.querySelectorAll('[data-password-toggle]').forEach(btn=>{
      const field=btn.closest('.password-field');
      const input=field?.querySelector('[data-password-input]');
      if(!input) return;
      btn.addEventListener('click',()=>{
        const show=input.type==='password';
        input.type=show?'text':'password';
        btn.textContent=show?'Ocultar':'Ver';
        btn.setAttribute('aria-label',show?'Ocultar contraseña':'Mostrar contraseña');
        btn.setAttribute('title',show?'Ocultar contraseña':'Mostrar contraseña');
        input.focus({preventScroll:true});
      });
    });

    const password=document.querySelector('[data-password-input]');
    const warning=document.querySelector('[data-caps-warning]');
    if(password&&warning){
      const sync=e=>{
        const caps=Boolean(e.getModifierState?.('CapsLock'));
        warning.hidden=!caps;
      };
      password.addEventListener('keydown',sync);
      password.addEventListener('keyup',sync);
      password.addEventListener('blur',()=>{warning.hidden=true});
    }
  }

  function initScrollableRegions(){
    document.querySelectorAll('.table-wrap,.checkbox-list,.codebox').forEach(el=>{
      if(!el.hasAttribute('tabindex')) el.tabIndex=0;
    });
  }

  // Visible page entry only after CSS/JS is ready.
  requestAnimationFrame(()=>document.body.classList.add('ui-ready'));

  updateThemeUX();
  updateTopbarShadow();
  keepActiveNavVisible();
  initPasswordUX();
  initScrollableRegions();

  let topbarRaf=0;
  window.addEventListener('scroll',()=>{
    if(topbarRaf) return;
    topbarRaf=requestAnimationFrame(()=>{
      topbarRaf=0;
      updateTopbarShadow();
    });
  },{passive:true});

  // Keep the theme control semantic state in sync with the existing theme handler.
  document.addEventListener('click',e=>{
    if(e.target.closest('[data-theme-toggle]')){
      requestAnimationFrame(updateThemeUX);
    }
    const link=e.target.closest('.sidebar .nav-link');
    if(link&&window.matchMedia('(max-width:760px)').matches){
      setMenuExpanded(false);
    }
  });

  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'&&document.querySelector('.sidebar.open')){
      setMenuExpanded(false);
      document.querySelector('.mobile-menu')?.focus({preventScroll:true});
    }
  });

  // Sync aria-expanded after the original mobile-menu click handler runs.
  document.addEventListener('click',e=>{
    if(e.target.closest('[data-menu-toggle]')){
      requestAnimationFrame(()=>{
        const open=Boolean(document.querySelector('.sidebar')?.classList.contains('open'));
        const button=document.querySelector('.mobile-menu[data-menu-toggle]');
        button?.setAttribute('aria-expanded',open?'true':'false');
        button?.setAttribute('aria-label',open?'Cerrar menú':'Abrir menú');
      });
    }
  });

  // Global navigation progress only for actual page navigations.
  document.addEventListener('click',e=>{
    if(e.defaultPrevented||e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey) return;
    const a=e.target.closest('a[href]');
    if(!a||a.target==='_blank'||a.hasAttribute('download')||a.hasAttribute('data-gideon-back')) return;
    let url;
    try{url=new URL(a.href,location.href)}catch(_){return}
    if(url.origin!==location.origin) return;
    if(url.pathname===location.pathname&&url.search===location.search&&url.hash) return;
    startGlobalProgress();
  });

  // Existing Releases live forms preventDefault before this listener, so they keep
  // their own in-place spinner and never trigger the page-navigation progress.
  document.addEventListener('submit',e=>{
    if(e.defaultPrevented) return;
    const form=e.target instanceof HTMLFormElement?e.target:null;
    if(!form) return;
    const button=e.submitter||form.querySelector('button[type="submit"],button:not([type]),input[type="submit"]');
    if(button&&button instanceof HTMLElement){
      button.classList.add('is-submitting');
      button.setAttribute('aria-busy','true');
    }
    startGlobalProgress();
  });

  window.addEventListener('pageshow',()=>{
    stopGlobalProgress();
    document.querySelectorAll('.btn.is-submitting').forEach(btn=>{
      btn.classList.remove('is-submitting');
      btn.removeAttribute('aria-busy');
    });
  });


  // RC30.95.12 · Premium smooth wheel engine.
  const premiumScrollMotion=window.matchMedia?.('(prefers-reduced-motion: reduce)');

  function gideonScrollableAncestor(start,dx,dy){
    const root=document.scrollingElement||document.documentElement;
    const horizontal=Math.abs(dx)>Math.abs(dy);
    let node=start instanceof Element?start:null;

    while(node&&node!==document.body&&node!==document.documentElement){
      const style=getComputedStyle(node);
      const oy=style.overflowY;
      const ox=style.overflowX;
      const canY=node.scrollHeight>node.clientHeight+1&&/(auto|scroll|overlay)/.test(oy);
      const canX=node.scrollWidth>node.clientWidth+1&&/(auto|scroll|overlay)/.test(ox);

      if(horizontal&&canX){
        const max=node.scrollWidth-node.clientWidth;
        if((dx<0&&node.scrollLeft>0)||(dx>0&&node.scrollLeft<max)) return node;
      }
      if(!horizontal&&canY){
        const max=node.scrollHeight-node.clientHeight;
        if((dy<0&&node.scrollTop>0)||(dy>0&&node.scrollTop<max)) return node;
      }
      node=node.parentElement;
    }
    return root;
  }

  const gideonScrollStates=new WeakMap();
  function gideonClamp(v,min,max){return Math.max(min,Math.min(max,v));}
  function gideonEaseOutCubic(t){return 1-Math.pow(1-t,3);}

  function gideonSmoothScrollBy(el,dx,dy){
    const root=document.scrollingElement||document.documentElement;
    const isRoot=el===root;
    const currentX=isRoot?window.scrollX:el.scrollLeft;
    const currentY=isRoot?window.scrollY:el.scrollTop;
    const maxX=Math.max(0,(isRoot?root.scrollWidth:el.scrollWidth)-(isRoot?window.innerWidth:el.clientWidth));
    const maxY=Math.max(0,(isRoot?root.scrollHeight:el.scrollHeight)-(isRoot?window.innerHeight:el.clientHeight));

    let state=gideonScrollStates.get(el);
    if(!state){
      state={raf:0,targetX:currentX,targetY:currentY,startX:currentX,startY:currentY,start:0};
      gideonScrollStates.set(el,state);
    }

    state.startX=currentX;
    state.startY=currentY;
    state.targetX=gideonClamp((state.raf?state.targetX:currentX)+dx,0,maxX);
    state.targetY=gideonClamp((state.raf?state.targetY:currentY)+dy,0,maxY);
    state.start=performance.now();

    if(state.raf) cancelAnimationFrame(state.raf);

    const distance=Math.hypot(state.targetX-currentX,state.targetY-currentY);
    const duration=gideonClamp(150+distance*.12,160,280);

    const frame=now=>{
      const p=gideonClamp((now-state.start)/duration,0,1);
      const eased=gideonEaseOutCubic(p);
      const x=state.startX+(state.targetX-state.startX)*eased;
      const y=state.startY+(state.targetY-state.startY)*eased;

      if(isRoot) window.scrollTo(x,y);
      else{
        el.scrollLeft=x;
        el.scrollTop=y;
      }

      if(p<1) state.raf=requestAnimationFrame(frame);
      else state.raf=0;
    };
    state.raf=requestAnimationFrame(frame);
  }

  document.addEventListener('wheel',e=>{
    if(e.defaultPrevented||e.ctrlKey||e.metaKey) return;
    if(premiumScrollMotion?.matches) return;

    const target=e.target instanceof Element?e.target:null;
    if(!target) return;

    if(target.closest(
      '.remote-display,.remote-viewer-shell,#remoteViewport,'+
      'textarea,select,input[type="range"],input[type="number"],iframe,canvas,'+
      '[data-native-scroll],[contenteditable="true"]'
    )) return;

    let dx=e.deltaX;
    let dy=e.deltaY;

    if(e.shiftKey&&Math.abs(dx)<Math.abs(dy)){
      dx=dy;
      dy=0;
    }

    if(e.deltaMode===1){
      dx*=18;dy*=18;
    }else if(e.deltaMode===2){
      dx*=window.innerWidth;dy*=window.innerHeight;
    }

    if(Math.abs(dx)<.01&&Math.abs(dy)<.01) return;

    const scroller=gideonScrollableAncestor(target,dx,dy);
    if(!scroller) return;

    e.preventDefault();
    gideonSmoothScrollBy(scroller,dx,dy);
  },{passive:false,capture:true});

})();
