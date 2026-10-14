/* GIDEON navigation groups: remember only the visual open/closed preference. */
(() => {
  'use strict';
  const KEY = 'gideon.remote.navigation.groups.v1';
  const read = () => {
    try { return JSON.parse(window.localStorage.getItem(KEY) || '{}'); }
    catch (_) { return {}; }
  };
  const write = (state) => {
    try { window.localStorage.setItem(KEY, JSON.stringify(state)); }
    catch (_) { /* visual preference remains usable for this page */ }
  };
  const init = () => {
    const groups = Array.from(document.querySelectorAll('.nav-group[data-nav-group]'));
    if (!groups.length) return;
    const state = read();
    groups.forEach((group) => {
      const id = group.dataset.navGroup;
      // Always reveal the group containing the current page, regardless of a
      // previous collapsed preference, so active navigation is never hidden.
      if (!group.querySelector('.nav-link.active') && Object.prototype.hasOwnProperty.call(state, id)) {
        group.open = Boolean(state[id]);
      }
      group.addEventListener('toggle', () => {
        state[id] = group.open;
        write(state);
      });
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
