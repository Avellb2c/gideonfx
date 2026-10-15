"""Regression contracts for non-destructive live refreshes."""
from __future__ import annotations

import os
from pathlib import Path
import unittest


ROOT = Path(os.environ.get("GIDEON_TEST_ROOT") or Path(__file__).resolve().parents[2]).resolve()
LINUX = ROOT / "payload/linux/app/gideon_web_admin"
WINDOWS = ROOT / "payload/windows/GIDEON Remote Control/app/gideon_web_admin"


class LiveRefreshStabilityTests(unittest.TestCase):
    def read_mirrored(self, relative: str) -> str:
        linux = LINUX / relative
        windows = WINDOWS / relative
        self.assertTrue(linux.is_file(), linux)
        self.assertTrue(windows.is_file(), windows)
        self.assertEqual(linux.read_bytes(), windows.read_bytes(), f"Mirror differs: {relative}")
        return linux.read_text(encoding="utf-8-sig")

    def test_partial_refresh_preserves_context_and_rebinds_ui(self):
        script = self.read_mirrored("static/gideon_live.js")
        for marker in (
            "openDetailKeys", "restoreDetailKeys", "window.GIDEON_UI?.reapply?.()",
            "const scrollX = window.scrollX", "const scrollY = window.scrollY",
            "window.scrollTo({ top: scrollY, left: scrollX",
            "const currentMarker = (marker)", "marker.isConnected",
            "const active = new WeakMap()", "const stop = (marker)",
        ):
            self.assertIn(marker, script)
        self.assertNotIn("location.reload", script)

    def test_partial_refresh_stops_when_the_operator_changes_page(self):
        script = self.read_mirrored("static/gideon_live.js")
        # A timer from the previous .content must never fetch its old URL into
        # the newly selected tab. Detached markers and changed routes both stop
        # before the next refresh and remove their visibility listener.
        self.assertIn("if (!currentMarker(marker)) { stop(marker); return; }", script)
        self.assertIn("if (currentMarker(marker)) schedule", script)
        self.assertIn("document.removeEventListener(\"visibilitychange\", state.onVisibility)", script)

    def test_job_terminal_refresh_never_forces_full_navigation(self):
        script = self.read_mirrored("static/job_live.js")
        self.assertIn("marker.dataset.terminalRefresh = 'not-needed'", script)
        self.assertNotIn("location.reload", script)

    def test_generic_auto_refresh_does_not_fallback_to_destructive_reload(self):
        script = self.read_mirrored("static/app.js")
        self.assertIn("autoRefresh.dataset.refreshUnavailable='1'", script)
        self.assertNotIn("setTimeout(()=>location.reload()", script)

    def test_safe_pages_use_content_navigation_without_reloading_shell(self):
        script = self.read_mirrored("static/app.js")
        for marker in (
            "const SOFT_NAV_EXCLUDED", "const softNavigate = async",
            "current.replaceChildren(...next.childNodes)",
            "history.pushState({ gideonSoft: true }", "syncSoftNavLinks",
            "document.dispatchEvent(new CustomEvent('gideon:page-updated'",
        ):
            self.assertIn(marker, script)
        self.assertIn("'/jobs/'", script)
        self.assertIn("'/remote'", script)

    def test_spa_navigation_keeps_native_scroll_and_no_entry_animation(self):
        script = self.read_mirrored("static/app.js")
        css = self.read_mirrored("static/app.css")
        self.assertNotIn("addEventListener('wheel'", script)
        self.assertNotIn('addEventListener("wheel"', script)
        self.assertNotIn("premiumScrollMotion", script)
        self.assertNotIn("addEventListener('pointerenter'", script)
        self.assertNotIn("scroll-behavior:smooth", css)
        self.assertNotIn("gideon-enter", css)
        self.assertNotIn("body.ui-ready .content", css)
        self.assertIn("scroll-behavior:auto", css)

    def test_soft_navigation_paints_shell_and_cancels_stale_responses(self):
        script = self.read_mirrored("static/app.js")
        css = self.read_mirrored("static/app.css")
        for marker in (
            "let softNavigationController = null",
            "softNavigationController?.abort()",
            "const createSoftLoadingShell = (label)",
            "current.replaceChildren(createSoftLoadingShell(label || softNavLabel(url)))",
            "signal,",
            "navigationId !== softNavigationSequence",
            "current.classList.remove('is-loading')",
            "current.removeAttribute('aria-busy')",
        ):
            self.assertIn(marker, script)
        for marker in (
            ".page-loading-shell{",
            ".page-loading-grid{",
            ".page-loading-card{",
            ".page-loading-skeleton{",
        ):
            self.assertIn(marker, css)

    def test_media_terminal_state_refreshes_only_the_library_region(self):
        script = self.read_mirrored("static/media_campaigns.js")
        template = self.read_mirrored("templates/media_library.html")
        self.assertIn("data-media-library-partial", template)
        self.assertIn("refreshMediaLibraryPage", script)
        self.assertNotIn("window.location.reload()", script)

    def test_gateway_read_cache_is_stale_while_revalidating(self):
        gateway = self.read_mirrored("gateway.py")
        for marker in (
            "def _cached_read_stale_while_revalidate",
            "self._cached_read_stale_while_revalidate(",
            "Only one background refresh",
            "gideon-gateway-refresh-",
        ):
            self.assertIn(marker, gateway)
        self.assertIn('timeout=4', gateway)


if __name__ == "__main__":
    unittest.main()
