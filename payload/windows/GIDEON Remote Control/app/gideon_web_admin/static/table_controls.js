/* GIDEON RC30.96.5 · Persist table queries only when a page is opened without one. */
(() => {
  'use strict';
  const prefix = 'gideon.ui.v4:table:';
  const parseJson = (value, fallback) => { try { return JSON.parse(value); } catch (_) { return fallback; } };
  const fields = (form) => [...form.elements].filter((field) => field.name && !field.disabled && ['INPUT', 'SELECT', 'TEXTAREA'].includes(field.tagName));
  const read = (form) => Object.fromEntries(fields(form).map((field) => [field.name, field.value]));
  const same = (left, right) => Object.keys(left).every((key) => String(left[key] ?? '') === String(right[key] ?? ''));
  document.querySelectorAll('form[data-gideon-persist-query]').forEach((form) => {
    const key = prefix + form.dataset.gideonPersistQuery;
    const defaults = parseJson(form.dataset.gideonPersistDefaults || '{}', {});
    const save = () => { try { localStorage.setItem(key, JSON.stringify(read(form))); } catch (_) {} };
    form.addEventListener('submit', save);
    form.addEventListener('change', save);
    form.addEventListener('input', () => window.clearTimeout(form._gideonPersistTimer) || (form._gideonPersistTimer = window.setTimeout(save, 180)));
    if (window.location.search || form.dataset.gideonPersistRestored === '1') return;
    const remembered = parseJson((() => { try { return localStorage.getItem(key) || '{}'; } catch (_) { return '{}'; } })(), {});
    if (!remembered || same(remembered, defaults)) return;
    let changed = false;
    fields(form).forEach((field) => { if (Object.prototype.hasOwnProperty.call(remembered, field.name) && String(field.value) !== String(remembered[field.name])) { field.value = remembered[field.name]; changed = true; } });
    if (changed) { form.dataset.gideonPersistRestored = '1'; window.setTimeout(() => form.requestSubmit(), 0); }
  });
  document.querySelectorAll('[data-gideon-clear-persisted-filters]').forEach((control) => control.addEventListener('click', () => { try { localStorage.removeItem(prefix + control.dataset.gideonClearPersistedFilters); } catch (_) {} }));
})();
