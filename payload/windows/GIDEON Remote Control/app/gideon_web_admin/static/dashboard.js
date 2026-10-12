(()=>{
  const root=document.querySelector('[data-resource-dashboard]');
  if(!root) return;
  const endpoint=root.dataset.endpoint||'/api/dashboard/resources';
  const refreshButton=document.querySelector('[data-resource-refresh]');
  const updatedNode=document.querySelector('[data-resource-updated]');
  const resourceIndicator=document.querySelector('[data-resource-indicator]');
  const liveBadge=root.querySelector('.live-badge');
  const liveBadgeLabel=root.querySelector('[data-resource-live-label]');
  let loading=false;
  let timer=0;
  let lastSuccessfulAt='';

  const finite=value=>Number.isFinite(Number(value));
  const percent=value=>finite(value)?`${Number(value).toFixed(1)}%`:'Calculando…';
  const set=(name,value)=>document.querySelectorAll(`[data-resource-value="${name}"]`).forEach(node=>{node.textContent=String(value??'—')});
  const setProgress=(name,value)=>document.querySelectorAll(`[data-resource-bar="${name}"]`).forEach(node=>{
    const clean=finite(value)?Math.max(0,Math.min(100,Number(value))):0;
    node.value=clean;
    node.textContent=`${clean.toFixed(1)}%`;
    node.setAttribute('aria-label',`${name}: ${clean.toFixed(1)}%`);
  });
  const timestamp=value=>{
    const parsed=new Date(value||'');
    return Number.isNaN(parsed.getTime())?'':parsed.toLocaleTimeString('es-PE',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  };
  function setFreshness({available,pending=false}={}){
    const stamp=timestamp(lastSuccessfulAt);
    if(updatedNode){
      if(pending) updatedNode.textContent=stamp?`Actualización pendiente · última lectura ${stamp}`:'Sin lectura correcta todavía';
      else updatedNode.textContent=stamp?`Actualizado ${stamp}`:(available?'Métricas disponibles':'Métricas pendientes');
    }
    if(resourceIndicator){
      resourceIndicator.className=available&&!pending?'ok':'warn';
    }
    if(liveBadgeLabel) liveBadgeLabel.textContent=pending?(stamp?'Datos anteriores':'Sin lectura'):(available?'En vivo':'Parcial');
    if(liveBadge) liveBadge.classList.toggle('is-degraded',pending||!available);
  }

  function renderServices(rows){
    const container=document.querySelector('[data-resource-services]');
    if(!container||!Array.isArray(rows)) return;
    const fragment=document.createDocumentFragment();
    rows.forEach(row=>{
      const item=document.createElement('div'); item.className='service-item';
      const state=document.createElement('span'); state.className=`service-state ${row.active?'online':'offline'}`;
      const name=document.createElement('div'); name.className='service-name';
      const title=document.createElement('strong'); title.textContent=String(row.label||row.component||'Servicio GIDEON');
      const substate=document.createElement('span'); substate.textContent=String(row.substate||row.state||'unknown');
      name.append(title,substate);
      const cpu=document.createElement('div'); cpu.className='service-stat';
      const cpuLabel=document.createElement('small'); cpuLabel.textContent='CPU';
      const cpuValue=document.createElement('strong'); cpuValue.textContent=percent(row.cpu_percent);
      cpu.append(cpuLabel,cpuValue);
      const memory=document.createElement('div'); memory.className='service-stat';
      const memoryLabel=document.createElement('small'); memoryLabel.textContent='RAM';
      const memoryValue=document.createElement('strong'); memoryValue.textContent=String(row.memory_display||'—');
      memory.append(memoryLabel,memoryValue);
      item.append(state,name,cpu,memory); fragment.append(item);
    });
    if(!fragment.childNodes.length){
      const empty=document.createElement('div'); empty.className='empty compact';
      const title=document.createElement('strong'); title.textContent='Métricas no disponibles';
      empty.append(title,document.createTextNode('El host no informó servicios administrados por GIDEON.'));
      fragment.append(empty);
    }
    container.replaceChildren(fragment);
  }

  function render(data){
    const host=data?.host||{};
    const gideon=data?.gideon||{};
    set('host-cpu',percent(host.cpu_percent));
    set('gideon-cpu',percent(gideon.cpu_percent));
    set('gideon-cpu-large',percent(gideon.cpu_percent));
    set('host-memory-percent',percent(host.memory_percent));
    set('host-memory-summary',`${host.memory_used_display||'—'} usados de ${host.memory_total_display||'—'}`);
    set('gideon-memory',gideon.memory_display||'—');
    set('gideon-memory-large',gideon.memory_display||'—');
    set('gideon-memory-percent',percent(gideon.memory_percent));
    set('host-disk-percent',percent(host.disk_percent));
    set('host-disk-summary',`${host.disk_used_display||'—'} usados · ${host.disk_free_display||'—'} libres`);
    set('host-disk-total',host.disk_total_display||'—');
    set('gideon-tasks',gideon.tasks??'—');
    set('gideon-services',`${gideon.active_services??0}/${gideon.total_services??0}`);
    set('host-name',host.hostname||'—');
    set('host-vendor',host.vendor||'—');
    set('host-os',host.os||'—');
    set('host-cpu-model',host.cpu_model||'—');
    set('host-cpu-count',host.cpu_logical??'—');
    set('host-memory-total',host.memory_total_display||'—');
    set('host-disk-free',host.disk_free_display||'—');
    set('host-uptime',host.uptime_display||'—');
    setProgress('host-cpu',host.cpu_percent);
    setProgress('host-memory',host.memory_percent);
    setProgress('host-disk',host.disk_percent);
    renderServices(gideon.services||[]);

    lastSuccessfulAt=data.generated_at_utc||new Date().toISOString();
    setFreshness({available:Boolean(data.available)});
  }

  async function refresh(){
    if(loading||document.hidden) return;
    loading=true;
    refreshButton?.setAttribute('aria-busy','true');
    root.setAttribute('aria-busy','true');
    const controller=new AbortController();
    const timeout=window.setTimeout(()=>controller.abort(),8000);
    try{
      const response=await fetch(endpoint,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'},signal:controller.signal});
      if(!response.ok) throw new Error(`HTTP ${response.status}`);
      render(await response.json());
    }catch(_){
      setFreshness({available:false,pending:true});
    }finally{
      window.clearTimeout(timeout);
      refreshButton?.removeAttribute('aria-busy');
      root.removeAttribute('aria-busy');
      loading=false;
    }
  }

  refreshButton?.addEventListener('click',refresh);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden) refresh()});
  timer=window.setInterval(refresh,10000);
  window.addEventListener('pagehide',()=>window.clearInterval(timer),{once:true});
  window.setTimeout(refresh,1200);
})();
