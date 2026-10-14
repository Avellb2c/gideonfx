'use strict';
(() => {
  const root = document.getElementById('tls-root');
  if (!root) return;
  const prepare = document.getElementById('tls-prepare');
  const actionForm = document.getElementById('tls-action');
  const feedback = document.getElementById('tls-feedback');
  const jobs = document.getElementById('tls-jobs');
  let timer;
  function message(text, bad = false) {
    feedback.className = bad ? 'alert danger' : 'alert';
    feedback.textContent = text;
  }
  function modeChanged() {
    const mode = prepare.elements.mode.value;
    prepare.querySelectorAll('[data-tls-mode]').forEach(section => {
      section.hidden = !section.dataset.tlsMode.split(' ').includes(mode);
      section.querySelectorAll('input').forEach(input => { input.disabled = section.hidden; });
    });
  }
  prepare.elements.mode.addEventListener('change', modeChanged);
  modeChanged();
  async function post(action, payload) {
    const response = await fetch('/infrastructure/tls/' + action, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': root.dataset.csrf },
      credentials: 'same-origin', body: JSON.stringify(payload)
    });
    if (!(response.headers.get('content-type') || '').includes('application/json')) {
      throw new Error('No se pudo autorizar la operación. Revise sesión, contraseña, MFA y vuelva a entrar.');
    }
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || 'Solicitud rechazada.');
    return result.result;
  }
  const labels = { PREPARED: 'Validada; pendiente de aplicar', APPLYING: 'Aplicando; puede interrumpirse la conexión',
    AWAITING_CONFIRMATION: 'Confirme acceso por la nueva URL', CONFIRMED: 'Confirmada', ROLLED_BACK: 'Configuración anterior restaurada',
    FAILED: 'No aplicada', EXPIRED: 'Preparación caducada', CANCELLED: 'Preparación cancelada' };
  function renderJobs(rows) {
    jobs.replaceChildren();
    if (!rows.length) { jobs.textContent = 'No hay solicitudes recientes.'; return; }
    rows.forEach(job => {
      const block = document.createElement('div'); block.className = 'alert';
      const heading = document.createElement('strong'); heading.textContent = labels[job.state] || job.state; block.append(heading);
      const info = document.createElement('p');
      info.textContent = 'Modo: ' + job.preview.mode + ' · Agentes: ' + job.preview.agent_url + ' · Administración: ' + job.preview.admin_cidr.join(', ');
      block.append(info);
      const link = document.createElement('a'); link.textContent = 'Abrir WebAdmin: ' + job.preview.web_url;
      const target = new URL(job.preview.web_url);
      if (target.protocol === 'https:') { link.href = target.origin + '/infrastructure/tls'; link.target = '_blank'; link.rel = 'noopener noreferrer'; }
      block.append(link);
      Object.entries(job.preview.certificates || {}).forEach(([role, cert]) => {
        const detail = document.createElement('p');
        detail.textContent = role + ': vence ' + cert.expires + ' · SHA-256 ' + cert.sha256; detail.className = 'mono'; block.append(detail);
      });
      if (job.preview.acme_pending && job.state === 'PREPARED') {
        const warning = document.createElement('p'); warning.textContent = 'ACME pendiente: el certificado público se solicitará al aplicar.'; block.append(warning);
      }
      if (job.deadline && job.state === 'AWAITING_CONFIRMATION') {
        const deadline = document.createElement('p'); deadline.textContent = 'Confirmar antes de: ' + new Date(job.deadline * 1000).toLocaleString(); block.append(deadline);
      }
      if (job.error) { const error = document.createElement('p'); error.textContent = job.error; block.append(error); }
      if (['PREPARED', 'AWAITING_CONFIRMATION'].includes(job.state)) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'btn'; button.textContent = 'Seleccionar solicitud';
        button.addEventListener('click', () => { actionForm.elements.id.value = job.id; }); block.append(button);
      }
      jobs.append(block);
    });
  }
  async function refresh() {
    clearTimeout(timer);
    try {
      const response = await fetch('/infrastructure/tls/status', { credentials: 'same-origin', cache: 'no-store' });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || 'Estado no disponible.');
      renderJobs(data.result.jobs);
      const current = data.result.current;
      const box = document.getElementById('tls-current'); box.replaceChildren();
      [['WebAdmin', current.web_url], ['Agentes', current.agent_url], ['Modo', current.mode]].forEach(([key, value]) => {
        const row = document.createElement('p'); row.textContent = key + ': ' + (value || 'Pendiente'); box.append(row);
      });
      Object.entries(current.certificates || {}).forEach(([role, cert]) => {
        const row = document.createElement('p'); row.textContent = role + ': ' + (cert.error || ('vence ' + cert.expires + ' · ' + cert.days_left + ' días')); box.append(row);
      });
      const acme = data.result.acme || {};
      const task = acme.renewal_task || {};
      document.getElementById('tls-renewal').textContent = acme.enabled
        ? 'Let’s Encrypt: win-acme instalado · tarea de renovación: ' + (task.status || 'no comprobada') + '. La clave privada permanece local.'
        : 'Let’s Encrypt: no configurado · TLS local de GIDEON activo. Configure el dominio mediante OneClick cuando TCP/80 y DNS estén listos.';
      if (data.result.jobs.some(job => ['APPLYING', 'AWAITING_CONFIRMATION'].includes(job.state))) timer = setTimeout(refresh, 5000);
    } catch (_) { message('No se pudo consultar el estado. Si acaba de aplicar, abra la nueva URL para confirmar; si no puede acceder, espere la restauración automática.', true); }
  }
  document.getElementById('tls-refresh').addEventListener('click', refresh);
  prepare.addEventListener('submit', async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true;
    const fields = new FormData(prepare); const uploads = {};
    try {
      message('Validando certificados y configuración…');
      for (const [name, file] of fields.entries()) {
        if (!(file instanceof File) || !file.size) continue;
        const limit = name === 'ca' ? 2 * 1024 * 1024 : 512 * 1024;
        if (file.size > limit) throw new Error('Archivo demasiado grande: ' + name);
        const bytes = new Uint8Array(await file.arrayBuffer()); let binary = '';
        for (const byte of bytes) binary += String.fromCharCode(byte);
        uploads[name] = btoa(binary);
      }
      const result = await post('prepare', {
        params: {mode: fields.get('mode'), web_host: fields.get('web_host'), agent_host: fields.get('agent_host'),
          web_port: Number(fields.get('web_port')), agent_port: Number(fields.get('agent_port')),
          admin_cidr: String(fields.get('admin_cidr')).split(',').map(value => value.trim()).filter(Boolean), email: fields.get('email') || '',
          agree_acme_tos: fields.has('agree_acme_tos'), accept_agent_reconfiguration: fields.has('accept_agent_reconfiguration')},
        uploads, passwords: {web: fields.get('web_file_password') || '', agent: fields.get('agent_file_password') || ''},
        current_password: fields.get('current_password'), mfa_code: fields.get('mfa_code')
      });
      actionForm.elements.id.value = result.id;
      message('Preparación validada. Revise las nuevas direcciones antes de aplicar.'); await refresh();
    } catch (error) { message(error.message, true); }
    finally { button.disabled = false; prepare.querySelectorAll('input[type=password],input[type=file],input[name=mfa_code]').forEach(input => { input.value = ''; }); }
  });
  actionForm.addEventListener('submit', async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true;
    try {
      const action = button.value;
      const result = await post(action, {id: actionForm.elements.id.value,
        current_password: actionForm.elements.current_password.value, mfa_code: actionForm.elements.mfa_code.value});
      message(action === 'apply' ? 'Cambio en curso. Abra la nueva URL, inicie sesión y confirme antes de 5 minutos.' : (labels[result.state] || result.state));
      await refresh();
    } catch (error) { message(error.message, true); }
    finally { button.disabled = false; actionForm.elements.current_password.value = ''; actionForm.elements.mfa_code.value = ''; }
  });
  refresh();
})();
