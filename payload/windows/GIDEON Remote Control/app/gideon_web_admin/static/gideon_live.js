/* Shared partial refresh for long-running WebAdmin views.
 * The server-rendered page remains the source of truth; this helper only
 * replaces the declared region and falls back to a full navigation when the
 * fragment cannot be reconciled.  Forms and scroll outside that region stay
 * untouched.
 */
(() => {
  const fetchFragment = async (marker) => {
    if (!marker) return false;
    const currentSelector = marker.dataset.partialTarget || marker.dataset.partialRefreshTarget || ".content";
    const url = marker.dataset.partialRefreshUrl || window.location.href;
    const current = document.querySelector(currentSelector);
    if (!current) return false;
    const active = document.activeElement;
    if (active && current.contains(active) && marker.dataset.partialAllowEditing !== "true") return false;
    const response = await fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "text/html", "X-GIDEON-Partial": "1" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const html = await response.text();
    const documentFragment = new DOMParser().parseFromString(html, "text/html");
    const source = documentFragment.querySelector(currentSelector);
    if (!source) return false;
    const scrollTop = window.scrollY;
    current.replaceChildren(...source.childNodes);
    window.scrollTo({ top: scrollTop, left: 0, behavior: "auto" });
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
  const start = (marker) => {
    if (!marker || marker.dataset.partialStarted === "1") return;
    marker.dataset.partialStarted = "1";
    const interval = Math.max(1800, Math.min(15000, Number(marker.dataset.partialRefresh || marker.dataset.autoRefresh || 3500)));
    let timer = 0;
    const schedule = (delay = interval) => { window.clearTimeout(timer); timer = window.setTimeout(async () => { const changed = await refreshPartial(marker); schedule(changed ? interval : Math.min(interval * 2, 15000)); }, delay); };
    schedule(interval);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) schedule(150); });
  };
  window.GIDEONLive = { refreshPartial, start };
  document.addEventListener("DOMContentLoaded", () => document.querySelectorAll("[data-partial-refresh]").forEach(start));
})();
