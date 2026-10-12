(() => {
  'use strict';
  const PREFIX = 'gideon.ui.v4';
  const groups = [];

  const storage = {
    get(key) { try { return window.localStorage.getItem(key); } catch (_) { return null; } },
    set(key, value) { try { window.localStorage.setItem(key, value); } catch (_) {} },
    remove(key) { try { window.localStorage.removeItem(key); } catch (_) {} }
  };

  function canonicalScope(pathname) {
    const p = String(pathname || '/');
    const scopes = [
      ['/security/assets', 'security-assets'],
      ['/system/dependencies', 'dependencies'],
      ['/system-updates', 'system-updates'],
      ['/installers', 'installers'],
      ['/execute', 'execute'],
      ['/remote', 'remote'],
      ['/transfers', 'transfers'],
      ['/scripts', 'scripts'],
      ['/updates', 'updates'],
      ['/users', 'users'],
      ['/agents', 'agents'],
      ['/jobs', 'jobs'],
      ['/settings', 'settings'],
      ['/gateway', 'gateway'],
      ['/diagnostics', 'diagnostics'],
      ['/sessions', 'sessions'],
      ['/audit', 'audit']
    ];
    for (const [prefix, name] of scopes) if (p === prefix || p.startsWith(prefix + '/')) return name;
    const first = p.split('/').filter(Boolean)[0];
    return first || 'home';
  }

  function hidden(el, value) {
    if (!el) return;
    const yes = !!value;
    el.hidden = yes;
    el.classList.toggle('gideon-hidden', yes);
    el.setAttribute('aria-hidden', yes ? 'true' : 'false');
  }

  function stableText(value) {
    return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ').replace(/[^a-z0-9áéíóúñü -]/gi, '').slice(0, 80);
  }

  function disclosureIdentity(el, index) {
    if (el.dataset.gideonDisclosureKey) return el.dataset.gideonDisclosureKey;
    if (el.id) return `id:${el.id}`;
    const summary = el.querySelector(':scope > summary');
    const label = stableText(summary?.textContent);
    if (label) return `summary:${label}`;
    return `index:${index}`;
  }

  function disclosureKey(el, index) {
    return `${PREFIX}:details:${canonicalScope(location.pathname)}:${disclosureIdentity(el, index)}`;
  }

  function isAdvancedDisclosure(el) {
    if (el.hasAttribute('data-gideon-advanced-default')) return true;
    if (el.classList.contains('advanced-block')) return true;
    const label = stableText(el.querySelector(':scope > summary')?.textContent);
    return /^(avanzado|opciones avanzadas|detalle técnico|detalle tecnico|más acciones|mas acciones)/i.test(label);
  }

  function applyDetails() {
    document.querySelectorAll('details').forEach((el, index) => {
      const key = disclosureKey(el, index);
      const stored = storage.get(key);
      // Fail closed for advanced disclosures. For all others, closed is the stable default
      // unless the template explicitly opts in with data-gideon-default-open="true".
      const templateOpen = el.dataset.gideonDefaultOpen === 'true';
      const wanted = stored === '1' ? true : stored === '0' ? false : (isAdvancedDisclosure(el) ? false : templateOpen);
      if (el.open !== wanted) el.open = wanted;
      if (!el.dataset.gideonStateBound) {
        el.dataset.gideonStateBound = '1';
        el.addEventListener('toggle', () => storage.set(key, el.open ? '1' : '0'));
      }
    });
  }

  function groupKey(name) {
    return `${PREFIX}:view:${canonicalScope(location.pathname)}:${name}`;
  }

  function bindAdvancedGroup(name, toggle, sections, options = {}) {
    if (!toggle || !sections || !sections.length) return null;
    const key = groupKey(name);
    const defaultMode = options.defaultMode === 'advanced' ? 'advanced' : 'simple';
    const stored = storage.get(key);
    let mode = stored === 'advanced' || stored === 'simple' ? stored : defaultMode;

    const apply = (next, persist = false) => {
      mode = next === 'advanced' ? 'advanced' : 'simple';
      const show = mode === 'advanced';
      sections.forEach(el => hidden(el, !show));
      toggle.textContent = show ? (options.hideLabel || 'Ocultar opciones avanzadas') : (options.showLabel || 'Mostrar opciones avanzadas');
      toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
      toggle.classList.add('gideon-view-toggle');
      if (persist) storage.set(key, mode);
      return mode;
    };

    apply(mode, false);
    if (!toggle.dataset.gideonViewBound) {
      toggle.dataset.gideonViewBound = '1';
      toggle.addEventListener('click', () => apply(mode === 'advanced' ? 'simple' : 'advanced', true));
    }
    const group = {name, toggle, sections, apply: () => apply(mode, false)};
    groups.push(group);
    return group;
  }

  function reapply() {
    applyDetails();
    groups.forEach(g => g.apply());
  }

  window.GIDEON_UI = { bindAdvancedGroup, hidden, reapply, storage, canonicalScope };

  const init = () => applyDetails();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, {once:true});
  else init();
  window.addEventListener('pageshow', () => setTimeout(reapply, 0));
  window.addEventListener('popstate', () => setTimeout(reapply, 0));
})();
