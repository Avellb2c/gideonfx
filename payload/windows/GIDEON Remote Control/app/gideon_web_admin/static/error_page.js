(()=>{
  const retry=document.querySelector('[data-error-retry]');
  retry?.addEventListener('click',()=>window.location.reload());

  const copy=document.querySelector('[data-copy-incident]');
  const detail=document.querySelector('[data-error-detail]');
  const incident=String(detail?.textContent||'').match(/\bweb-[a-f0-9]{16}\b/i)?.[0]||'';
  if(copy&&!incident) copy.hidden=true;
  copy?.addEventListener('click',async()=>{
    if(!incident) return;
    try{
      await navigator.clipboard.writeText(incident);
      copy.textContent='Referencia copiada';
    }catch(_){
      const selection=window.getSelection();
      const range=document.createRange();
      range.selectNodeContents(detail);
      selection?.removeAllRanges();
      selection?.addRange(range);
      copy.textContent='Referencia seleccionada';
    }
    window.setTimeout(()=>{copy.textContent='Copiar referencia'},1800);
  });
})();
