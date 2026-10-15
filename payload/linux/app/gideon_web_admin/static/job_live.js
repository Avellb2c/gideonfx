(()=>{
  const marker=document.querySelector('[data-job-live]');
  if(!marker) return;
  const jobId=marker.dataset.jobLive;
  const ms=Math.max(1500,Math.min(10000,Number(marker.dataset.pollMs||2500)));
  const terminal=new Set(['COMPLETED','COMPLETED_WITH_WARNINGS','COMPLETED_WITH_ERRORS','COMPLETED_WITH_SKIPPED','PARTIAL','FAILED','LAUNCH_FAILED','ACTION_REQUIRED','CANCELLED','CANCELLED_WITH_ERRORS','INTERRUPTED']);
  let stopped=false, inflight=false;
  const classify=(el,state)=>{
    if(!el) return;
    el.classList.remove('success','danger','warning','info');
    if(['COMPLETED','COLLECTED','RESULT_READY'].includes(state)) el.classList.add('success');
    else if(['FAILED','CANCELLED','INTERRUPTED','DISPATCH_FAILED','PREFLIGHT_FAILED'].includes(state)) el.classList.add('danger');
    else if(['ACTION_REQUIRED','PARTIAL'].includes(state)) el.classList.add('warning');
    else el.classList.add('info');
  };
  async function tick(){
    if(stopped||inflight) return;
    inflight=true;
    const ctl=new AbortController(); const timer=setTimeout(()=>ctl.abort(),2200);
    try{
      const r=await fetch(`/jobs/${encodeURIComponent(jobId)}/status.json`,{cache:'no-store',credentials:'same-origin',signal:ctl.signal,headers:{'Accept':'application/json'}});
      if(!r.ok) throw new Error(`HTTP ${r.status}`);
      const d=await r.json();
      const chip=document.getElementById('jobStatusChip');
      if(chip){chip.textContent=d.status||'STARTING';classify(chip,d.status||'');}
      const phase=document.getElementById('transferJobPhase'); if(phase) phase.textContent=d.phase||'-';
      const scan=document.getElementById('transferJobScan'); if(scan) scan.textContent=d.scan_status||'PENDING';
      const engine=document.getElementById('transferJobEngine'); if(engine) engine.textContent=d.scan_engine||'-';
      const duration=document.getElementById('transferJobDuration'); if(duration) duration.textContent=d.scan_duration_ms==null?'Pendiente':`${Number(d.scan_duration_ms)} ms`;
      const progress=document.getElementById('transferJobProgress'); if(progress) progress.textContent=`${Number(d.queued_count||0)}/${Number(d.target_count||0)}`;
      const updated=document.getElementById('transferJobUpdated'); if(updated) updated.textContent=d.updated_at||'-';
      const detail=document.getElementById('transferJobDetail'); if(detail&&d.detail) detail.lastChild.textContent=d.detail;
      const error=document.getElementById('transferJobError'); if(error){error.textContent=d.error||'';error.hidden=!d.error;}
      for(const [code,row] of Object.entries(d.sites||{})){
        const tr=document.querySelector(`[data-job-site="${CSS.escape(String(code))}"]`); if(!tr) continue;
        const remote=tr.querySelector('[data-live-remote]');
        if(remote){remote.textContent=row.remote||'PENDING';classify(remote,row.remote||'');}
        const transfer=tr.querySelector('[data-live-transfer]'); if(transfer) transfer.textContent=row.transfer||'-';
        const collection=tr.querySelector('[data-live-collection]'); if(collection) collection.textContent=row.collection||'-';
        const err=tr.querySelector('[data-live-error]'); if(err){err.textContent=row.error||'-';err.title=row.error||'';}
      }
      marker.dataset.lastUpdate=d.updated_at||'';
      if(d.terminal||terminal.has(d.status)){
        stopped=true;
        const partialMarker = marker.dataset.partialRefreshUrl && window.GIDEONLive ? marker : null;
        if(partialMarker) setTimeout(() => { void window.GIDEONLive.refreshPartial(partialMarker); }, 250);
        else marker.dataset.terminalRefresh = 'not-needed';
        return;
      }
    }catch(e){
      // Keep the page usable; transient polling failures do not force a reload.
      marker.dataset.pollError=String(e&&e.message||e);
    }finally{
      clearTimeout(timer); inflight=false;
    }
    if(!stopped) setTimeout(tick,ms);
  }
  setTimeout(tick,500);
})();
