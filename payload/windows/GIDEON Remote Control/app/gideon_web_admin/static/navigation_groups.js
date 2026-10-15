/* GIDEON navigation groups: keep the sidebar contextual and deterministic. */
(() => {
  'use strict';
  const init = () => {
    const groups = Array.from(document.querySelectorAll('.nav-group[data-nav-group]'));
    if (!groups.length) return;
    // The server marks the current section open. Do not restore stale
    // persisted browser state: an old page should not expand unrelated sections
    // when the user navigates to a new screen.
    const activeGroup = groups.find((group) => group.querySelector('.nav-link.active'));
    // Always assign the complete state, including pages without a section.
    // This keeps hard navigation consistent with soft navigation and prevents
    // a previously-open group from flashing during a route transition.
    groups.forEach((group) => {
      group.open = Boolean(activeGroup && group === activeGroup);
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
