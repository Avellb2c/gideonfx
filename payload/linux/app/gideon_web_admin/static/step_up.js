(() => {
  const state = window.GIDEON_STEP_UP || {};
  const until = Number(state.until_unix || 0);
  const badge = document.querySelector('[data-stepup-badge]');
  const remaining = document.querySelector('[data-stepup-remaining]');

  const authInputs = () => Array.from(document.querySelectorAll('input[name="current_password"], input[name="mfa_code"]'))
    .filter(input => !input.closest('form[data-stepup-fresh]'));
  const containerFor = input => input.closest('.field') || input.closest('label') || input;

  function activate(){
    authInputs().forEach(input => {
      const box = containerFor(input);
      input.required = false;
      input.value = '';
      input.dataset.stepupHidden = '1';
      box.dataset.stepupContainer = '1';
      box.hidden = true;
    });
    document.querySelectorAll('form').forEach(form => {
      if (!form.querySelector('input[data-stepup-hidden="1"]') || form.querySelector('[data-stepup-note]')) return;
      const note = document.createElement('div');
      note.className = 'alert success';
      note.dataset.stepupNote = '1';
      note.innerHTML = '<strong>MFA reforzado activo</strong>Esta sesión ya fue autorizada. No necesita volver a ingresar contraseña/MFA hasta que venza el contador.';
      form.appendChild(note);
    });
  }
  function deactivate(){
    document.querySelectorAll('[data-stepup-container="1"]').forEach(box => { box.hidden = false; delete box.dataset.stepupContainer; });
    authInputs().forEach(input => { if (input.dataset.stepupHidden === '1') { delete input.dataset.stepupHidden; input.required = true; } });
    document.querySelectorAll('[data-stepup-note]').forEach(n => n.remove());
    if (badge) badge.remove();
  }
  function tick(){
    if (!until) return;
    const seconds = Math.max(0, until - Math.floor(Date.now()/1000));
    if (remaining) remaining.textContent = `${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,'0')}`;
    if (seconds <= 0) deactivate();
  }
  if (state.active && until > Math.floor(Date.now()/1000)) { activate(); tick(); setInterval(tick, 1000); }

  document.querySelectorAll('form[data-ssh-profile-form]').forEach(form => {
    form.addEventListener('submit', () => {
      const hiddenUser = form.querySelector('input[type="hidden"][name="username"]');
      const hiddenPort = form.querySelector('input[type="hidden"][name="port"]');
      const userOverride = form.querySelector('[name="username_override"]');
      const portOverride = form.querySelector('[name="port_override"]');
      if (hiddenUser && userOverride && String(userOverride.value || '').trim()) hiddenUser.value = userOverride.value.trim();
      if (hiddenPort && portOverride && String(portOverride.value || '').trim()) hiddenPort.value = portOverride.value.trim();
    });
  });
})();
