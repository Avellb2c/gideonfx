/* GIDEON RC30.95.31.8.2 · persistent compact sidebar + global content reflow */
(() => {
  'use strict';

  const STORAGE_KEY = 'gideon.remote.sidebar.compact.v1';
  const ROOT_CLASS = 'gideon-sidebar-compact';
  const DESKTOP_QUERY = '(min-width: 981px)';
  const root = document.documentElement;

  const readSaved = () => {
    try { return window.localStorage.getItem(STORAGE_KEY) === '1'; }
    catch (_) { return false; }
  };

  const writeSaved = (value) => {
    try { window.localStorage.setItem(STORAGE_KEY, value ? '1' : '0'); }
    catch (_) { /* private mode / storage disabled: visual behavior still works */ }
  };

  const desktopNow = () => {
    try { return window.matchMedia(DESKTOP_QUERY).matches; }
    catch (_) { return window.innerWidth >= 981; }
  };

  // Apply before body painting where possible, avoiding the expanded -> compact flash.
  if (desktopNow() && readSaved()) root.classList.add(ROOT_CLASS);

  const updateButton = (button) => {
    if (!button) return;
    const compact = root.classList.contains(ROOT_CLASS) && desktopNow();
    button.setAttribute('aria-expanded', compact ? 'false' : 'true');
    button.setAttribute('aria-label', compact ? 'Mostrar menú lateral' : 'Ocultar menú lateral');
    button.title = compact ? 'Mostrar menú lateral' : 'Ocultar menú lateral';
    const label = button.querySelector('span');
    if (label) label.textContent = compact ? 'Mostrar menú' : 'Ocultar menú';
  };

  const apply = (compact, persist = true) => {
    const effective = Boolean(compact) && desktopNow();
    root.classList.toggle(ROOT_CLASS, effective);
    if (persist) writeSaved(Boolean(compact));
    updateButton(document.querySelector('[data-sidebar-compact-toggle]'));
    window.dispatchEvent(new CustomEvent('gideon:sidebar-layout', { detail: { compact: effective } }));

    // Global reflow: tables, grids, canvases and any viewport-aware components
    // must recalculate after the sidebar transition releases/claims horizontal space.
    const pulseLayout = () => {
      try { window.dispatchEvent(new Event('resize')); } catch (_) { /* noop */ }
      try { window.dispatchEvent(new CustomEvent('gideon:content-reflow', { detail: { compact: effective } })); } catch (_) { /* noop */ }
    };
    requestAnimationFrame(pulseLayout);
    window.setTimeout(pulseLayout, 80);
    window.setTimeout(pulseLayout, 240);
  };

  const init = () => {
    const button = document.querySelector('[data-sidebar-compact-toggle]');
    if (!button) return;

    // Reconcile early class with the stored preference and the current viewport.
    apply(readSaved(), false);

    button.addEventListener('click', () => {
      const compact = root.classList.contains(ROOT_CLASS) && desktopNow();
      apply(!compact, true);
    });

    let media = null;
    try { media = window.matchMedia(DESKTOP_QUERY); } catch (_) { /* noop */ }
    const onViewport = () => apply(readSaved(), false);
    if (media && typeof media.addEventListener === 'function') media.addEventListener('change', onViewport);
    else window.addEventListener('resize', onViewport, { passive: true });

    // Give icon-only navigation native hover hints even if a future template forgets title.
    document.querySelectorAll('.sidebar .nav-link').forEach((link) => {
      const label = link.querySelector('.gideon-nav-label')?.textContent?.trim();
      if (label && !link.getAttribute('title')) link.setAttribute('title', label);
      if (label && !link.getAttribute('aria-label')) link.setAttribute('aria-label', label);
    });

    updateButton(button);
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
