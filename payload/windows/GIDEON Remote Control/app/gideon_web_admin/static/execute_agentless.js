(() => {
  const sel = document.getElementById('sshIdentitySelect');
  const user = document.getElementById('sshUsername');
  const port = document.getElementById('sshPort');
  const state = document.getElementById('sshProfileState');
  if (!sel || !user || !port || !state) return;
  const validated = Array.from(sel.options).filter(o => o.value && o.dataset.verified === '1' && (o.dataset.username||'').trim());
  if (!sel.value && validated.length === 1) sel.value = validated[0].value;
  const apply = () => {
    const opt = sel.selectedOptions && sel.selectedOptions[0];
    if (!opt || !opt.value) {
      user.value=''; port.value='22'; state.className='alert warning';
      state.innerHTML='<strong>Identidad requerida</strong>Valide una identidad SSH global antes de ejecutar.'; return;
    }
    user.value=(opt.dataset.username||'').trim(); port.value=(opt.dataset.port||'22').trim()||'22';
    const ok=opt.dataset.verified==='1' && Boolean(user.value);
    state.className=ok?'alert success':'alert warning';
    state.innerHTML=ok
      ? `<strong>Perfil global listo</strong>${user.value}@*:${port.value} · se aplicará a todas las sedes. GIDEON validará SSH/SFTP por destino antes del fan-out.`
      : '<strong>Perfil no validado</strong>Abra Claves y secretos y pruebe esta identidad una vez.';
  };
  sel.addEventListener('change',apply); apply();
})();
