/* Shared partial refresh for long-running WebAdmin views.
 * The server-rendered page remains the source of truth.  Refreshing a live
 * region must not destroy the operator's visual context: no full navigation,
 * no lost scroll position, and no collapsed disclosure panels.
 */
(() => {
  const normalize = (value) => String(value || '').trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 120);
  const detailKey = (el, index) => {
    const explicit = el.dataset.gideonDisclosureKey || el.id;
    if (explicit) return `explicit:${explicit}`;
    const summary = el.querySelector(':scope > summary');
    return `summary:${normalize(summary?.textContent)}:${index}`;
  };
  const openDetailKeys = (root) => {
    const result = new Set();
    root.querySelectorAll('details').forEach((el, index) => {
      if (el.open) result.add(detailKey(el, index));
    });
    return result;
  };
  const restoreDetailKeys = (root, keys) => {
    root.querySelectorAll('details').forEach((el, index) => {
      if (keys.has(detailKey(el, index))) el.open = true;
    });
  };
  const fetchFragment = async (marker) => {
    if (!marker) return false;
    const currentSelector = marker.dataset.partialTarget || marker.dataset.partialRefreshTarget || ".content";
    const url = marker.dataset.partialRefreshUrl || window.location.href;
    const current = document.querySelector(currentSelector);
    if (!current) return false;
    const active = document.activeElement;
    if (active && current.contains(active) && marker.dataset.partialAllowEditing !== "true") return false;
    const scrollX = window.scrollX;
    const scrollY = window.scrollY;
    const openKeys = openDetailKeys(current);
    const response = await fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "text/html", "X-GIDEON-Partial": "1" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const html = await response.text();
    const documentFragment = new DOMParser().parseFromString(html, "text/html");
    const source = documentFragment.querySelector(currentSelector);
    if (!source) return false;
    current.replaceChildren(...source.childNodes);
    // Partial replacement creates new details elements. Rebind the common UI
    // state first, then restore exactly what the operator had open.
    try { window.GIDEON_UI?.reapply?.(); } catch (_) { /* page remains usable */ }
    restoreDetailKeys(current, openKeys);
    window.scrollTo({ top: scrollY, left: scrollX, behavior: "auto" });
    document.dispatchEvent(new CustomEvent("gideon:partial-updated", { detail: { selector: currentSelector, url } }));
    return true;
  };
  const refreshPartial = async (markerOrSelector) => {
    const marker = typeof markerOrSelector === "string" ? document.querySelector(markerOrSelector) : markerOrSelector;
    try { return await fetchFragment(marker); } catch (error) {
      if (marker) marker.dataset.partialError = String(error && error.message || error);
      return false;
    }
  };
  const active = new WeakMap();
  const currentMarker = (marker) => {
    if (!marker || !marker.isConnected) return false;
    try {
      const target = new URL(marker.dataset.partialRefreshUrl || window.location.href, window.location.href);
      return target.origin === window.location.origin &&
        target.pathname === window.location.pathname &&
        target.search === window.location.search;
    } catch (_) { return false; }
  };
  const stop = (marker) => {
    const state = active.get(marker);
    if (!state) return;
    window.clearTimeout(state.timer);
    document.removeEventListener("visibilitychange", state.onVisibility);
    active.delete(marker);
    delete marker.dataset.partialStarted;
  };
  const start = (marker) => {
    if (!marker || !marker.isConnected || active.has(marker)) return;
    marker.dataset.partialStarted = "1";
    const interval = Math.max(1800, Math.min(15000, Number(marker.dataset.partialRefresh || marker.dataset.autoRefresh || 3500)));
    const state = { timer: 0, onVisibility: null };
    const schedule = (delay = interval) => {
      window.clearTimeout(state.timer);
      state.timer = window.setTimeout(async () => {
        if (!currentMarker(marker)) { stop(marker); return; }
        const changed = await refreshPartial(marker);
        if (currentMarker(marker)) schedule(changed ? interval : Math.min(interval * 2, 15000));
        else stop(marker);
      }, delay);
    };
    state.onVisibility = () => { if (!document.hidden && currentMarker(marker)) schedule(150); };
    active.set(marker, state);
    document.addEventListener("visibilitychange", state.onVisibility);
    schedule(interval);
  };
  window.GIDEONLive = { refreshPartial, start };
  document.addEventListener("DOMContentLoaded", () => document.querySelectorAll("[data-partial-refresh]").forEach(start));
})();
