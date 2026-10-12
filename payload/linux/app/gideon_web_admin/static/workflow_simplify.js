(() => {
  'use strict';
  const UI = window.GIDEON_UI;
  const path = location.pathname;

  // Security Assets: apply to the main page AND POST response URLs such as
  // /security/assets/ssh-identity/<id>/probe. This was a real source of view-state drift.
  if (path === '/security/assets' || path.startsWith('/security/assets/')) {
    const toggle = document.querySelector('[data-security-advanced-toggle]');
    const advanced = Array.from(document.querySelectorAll('[data-gideon-advanced-section="security"]'));
    if (advanced.length) {
      if (UI) {
        UI.bindAdvancedGroup('security', toggle, advanced, {
          defaultMode: 'simple',
          showLabel: 'Mostrar opciones avanzadas',
          hideLabel: 'Ocultar opciones avanzadas'
        });
      } else {
        advanced.forEach(el => { el.hidden = true; });
      }
    }
  }

  // Execute: when coming from Scripts, preselect the requested approved script.
  if (path === '/execute' || path.startsWith('/execute/')) {
    const scriptId = new URLSearchParams(location.search).get('script_id');
    if (scriptId) {
      const esc = window.CSS?.escape ? CSS.escape(scriptId) : scriptId.replace(/["\\]/g, '\\$&');
      const cb = document.querySelector(`input[name="script_id"][value="${esc}"]`);
      if (cb) {
        cb.checked = true;
        cb.closest('.check-row')?.scrollIntoView({block:'center'});
      }
    }
  }

  // Transfers: remember only non-secret convenience data in this browser.
  if (path === '/transfers' || path.startsWith('/transfers/')) {
    const key = 'gideon.transfer.defaults.v1';
    const transferForm = document.querySelector('form[data-transfer-form]');
    const reuse = document.querySelector('[data-transfer-reuse]');
    const destinationPreview = document.getElementById('transferDestinationPreview');
    const selectionSummary = document.getElementById('transferSelectionSummary');
    const portableDestination = value => String(value || '')
      .trim().replaceAll('\\', '/')
      .replace(/^(?:gideon:\/\/|gideon_root\/|c:\/gideon\/|\/opt\/gideon\/|\/var\/lib\/gideon\/files\/|\/library\/application support\/gideon\/)/i, '')
      .replace(/^\/+|\/+$/g, '');
    const destinationFor = (platform, logical) => {
      const part = logical || 'Distribucion';
      const normalized = String(platform || '').toLowerCase();
      if (normalized === 'windows') return `C:\\GIDEON\\${part.replaceAll('/', '\\')}`;
      if (normalized === 'macos' || normalized === 'darwin') return `/Library/Application Support/GIDEON/${part}`;
      return `/opt/gideon/${part}`;
    };
    const updateTransferPreview = () => {
      const destinationInput = document.getElementById('transferDestination');
      const original = String(destinationInput?.value || '');
      const logical = portableDestination(original) || 'Distribucion';
      if (destinationPreview) {
        const title = document.createElement('strong');
        title.textContent = 'Vista previa de destino';
        const note = document.createElement('span');
        note.className = 'muted';
        note.textContent = original && original.trim() !== logical
          ? `Se normalizará “${original.trim()}” como “${logical}”.`
          : 'La carpeta se crea automáticamente dentro de la raíz GIDEON de cada sistema.';
        const rows = document.createElement('div');
        rows.className = 'transfer-preview-rows';
        [['Windows', destinationFor('windows', logical)], ['Linux / Raspberry Pi', destinationFor('linux', logical)], ['macOS', destinationFor('macos', logical)]].forEach(([name, value]) => {
          const row = document.createElement('span');
          const label = document.createElement('b'); label.textContent = name;
          const code = document.createElement('code'); code.textContent = value;
          row.append(label, code); rows.append(row);
        });
        destinationPreview.replaceChildren(title, note, rows);
      }
      const selected = Array.from(document.querySelectorAll('input[name="agent_id"]:checked'));
      if (selectionSummary) {
        if (!selected.length) selectionSummary.textContent = 'Seleccione uno o más equipos. La carga crea el Job inmediatamente; el análisis y despacho continúan en segundo plano.';
        else {
          const counts = selected.reduce((result, input) => {
            const platform = String(input.dataset.platform || 'otros').toLowerCase();
            result[platform] = (result[platform] || 0) + 1;
            return result;
          }, {});
          const breakdown = Object.entries(counts).map(([platform, count]) => `${count} ${platform}`).join(' · ');
          selectionSummary.textContent = `${selected.length} equipo(s) seleccionado(s) (${breakdown}). Se entregará por HTTPS/PULL a la carpeta lógica “${logical}”.`;
        }
      }
    };
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(key) || 'null'); } catch (_) {}
    if (saved && reuse) reuse.hidden = false;
    reuse?.addEventListener('click', () => {
      if (!saved) return;
      const dest = document.getElementById('transferDestination');
      if (dest && saved.destination) dest.value = portableDestination(saved.destination) || 'Distribucion';
      const wanted = new Set(Array.isArray(saved.agent_ids) ? saved.agent_ids : []);
      document.querySelectorAll('input[name="agent_id"]').forEach(cb => { cb.checked = wanted.has(cb.value); });
      updateTransferPreview();
    });
    document.getElementById('transferDestination')?.addEventListener('input', updateTransferPreview);
    document.querySelectorAll('input[name="agent_id"]').forEach(cb => cb.addEventListener('change', updateTransferPreview));
    updateTransferPreview();
    transferForm?.addEventListener('submit', () => {
      const destinationInput = document.getElementById('transferDestination');
      const destination = portableDestination(destinationInput?.value) || 'Distribucion';
      if (destinationInput) destinationInput.value = destination;
      const agent_ids = Array.from(document.querySelectorAll('input[name="agent_id"]:checked')).map(x => x.value);
      try { localStorage.setItem(key, JSON.stringify({destination, agent_ids})); } catch (_) {}
    });
  }

  // Reapply once after all page-specific transforms have moved/hidden DOM nodes.
  setTimeout(() => UI?.reapply?.(), 0);
})();
