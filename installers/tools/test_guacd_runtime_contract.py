from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HOME_TMPFS = "/home/guacd:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700"


class GuacdRuntimeContractTests(unittest.TestCase):
    def test_all_container_launchers_keep_read_only_root_and_writable_freerdp_home(self) -> None:
        paths = (
            ROOT / "installers/LINUX/install-gideon-master-linux.sh",
            ROOT / "installers/LINUX/docker/compose.guacd.yml",
            ROOT / "installers/WINDOWS/templates/start-guacd.sh.tpl",
            ROOT / "installers/WINDOWS/Provision-GuacdDockerWindows.ps1",
            ROOT / "payload/linux/app/deploy/guacamole/docker-compose.yml",
            ROOT / "payload/windows/GIDEON Remote Control/app/deploy/guacamole/docker-compose.yml",
        )
        for path in paths:
            source = path.read_text(encoding="utf-8-sig")
            self.assertTrue("--read-only" in source or "read_only: true" in source, path)
            self.assertIn(HOME_TMPFS, source, path)
            self.assertTrue("--init" in source or "init: true" in source, path)

    def test_linux_post_install_validation_enforces_freerdp_home(self) -> None:
        source = (ROOT / "installers/tools/validate_linux_installation.py").read_text(encoding="utf-8-sig")
        self.assertIn("FreeRDP HOME is not a writable tmpfs", source)
        self.assertIn("freerdp_home_tmpfs", source)

    def test_websocket_tasks_are_observed_before_server_error_is_raised(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            source = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            gather_at = source.index("await asyncio.gather(*pending, return_exceptions=True)")
            raise_at = source.index("if server_error is not None:", gather_at)
            self.assertLess(gather_at, raise_at)
            self.assertIn("error = task.exception()", source[gather_at:raise_at])

    def test_live_remote_session_is_not_classified_as_a_runtime_failure(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            source = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            template = (app_root / "gideon_web_admin/templates/remote_viewer.html").read_text(encoding="utf-8-sig")
            self.assertIn(
                'runtime_failure is None and not end_reason and server_status in {"ISSUED", "ACTIVE"}',
                source,
            )
            self.assertIn('"REMOTE_SESSION_ACTIVE" if server_status == "ACTIVE"', source)
            self.assertIn("liveWithoutRuntimeError", viewer)
            self.assertIn("REMOTE_SESSION_ACTIVE", viewer)
            self.assertIn("static_url('remote_viewer.js')", template)

    def test_delayed_first_frame_recovers_the_viewer_without_a_false_black_screen(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            self.assertIn("VISUAL_OPCODES", viewer)
            self.assertIn("graphicsConfirmed=true", viewer)
            self.assertIn("if(noImageTimer){clearTimeout(noImageTimer);noImageTimer=null;}", viewer)
            self.assertIn("if(clientState===3&&!terminal) setState('ACTIVO'", viewer)
            self.assertIn("if(!graphicsConfirmed) armNoImageTimer();", viewer)
            self.assertIn("renderedOps()===0&&!terminal&&clientState===3", viewer)
            self.assertIn("},15000);", viewer)
            self.assertNotIn("no se recibió imagen en 8 segundos", viewer)

    def test_rejected_async_image_decode_cannot_strand_guacamole_sync(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn("disableAsyncDecoder('createImageBitmap')", viewer)
            self.assertIn("disableAsyncDecoder('ImageDecoder')", viewer)
            self.assertIn("renderer=html-image-fallback", viewer)
            self.assertIn("originalInstruction.call(tunnel,opcode,parameters)", viewer)
            self.assertIn("GUACD_CLIENT_UNRESPONSIVE", app)
            self.assertIn('str(code) == "776"', app)
            self.assertIn('server_flow["client_syncs"]', app)
            self.assertIn('server_flow["server_syncs"]', app)

    def test_autoscale_is_visual_only_and_cannot_renegotiate_xrdp(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            self.assertIn("autoscale=visual-only", viewer)
            self.assertIn("observer.observe(viewport)", viewer)
            self.assertNotIn("observer.observe(displayRoot)", viewer)
            self.assertNotIn("client.sendSize(", viewer)
            self.assertIn("queueVisualFit('operator-refit',0)", viewer)

    def test_autoscale_does_not_run_at_guacamole_frame_cadence(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            self.assertIn("if(op==='size') queueVisualFit('opcode:size',32)", viewer)
            self.assertNotIn("op==='sync') queueVisualFit", viewer)
            self.assertIn("if(fitTimer) return", viewer)
            self.assertIn("geometry!==lastFitGeometry", viewer)

    def test_remote_canvas_rules_are_isolated_from_global_layout_css(self) -> None:
        """A generic responsive canvas rule must never resize Guacamole layers."""
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            global_css = (app_root / "gideon_web_admin/static/ui_hardening.css").read_text(encoding="utf-8-sig")
            viewer_css = (app_root / "gideon_web_admin/static/remote_viewer.css").read_text(encoding="utf-8-sig")
            viewer_template = (app_root / "gideon_web_admin/templates/remote_viewer.html").read_text(encoding="utf-8-sig")
            window_template = (app_root / "gideon_web_admin/templates/remote_window.html").read_text(encoding="utf-8-sig")
            self.assertNotIn("img,svg,video,canvas", global_css)
            self.assertNotIn(".remote-viewer-shell", global_css)
            self.assertIn(".remote-viewer-shell", viewer_css)
            self.assertIn(".remote-display canvas", viewer_css)
            self.assertIn("static_url('remote_viewer.css')", viewer_template)
            self.assertIn("static_url('remote_viewer.css')", window_template)

    def test_viewport_is_negotiated_before_connect_and_mouse_uses_display_scale(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            viewer = (app_root / "gideon_web_admin/static/remote_viewer.js").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertIn("new URLSearchParams({width:String(initialWidth),height:String(initialHeight),dpi:'96'})", viewer)
            self.assertIn("client.sendMouseState(mouseState,true)", viewer)
            self.assertIn("requestAnimationFrame(flushMouseMotion)", viewer)
            self.assertIn("mouse.onmousedown=mouse.onmouseup", viewer)
            self.assertIn('viewport_width = viewport_dimension("width", 1440, 640, 3840)', app)
            self.assertIn("width=viewport_width", app)
            self.assertIn("height=viewport_height", app)

    def test_rdp_no_resize_uses_parameter_omission_and_has_stall_watchdog(self) -> None:
        for app_root in (
            ROOT / "payload/linux/app",
            ROOT / "payload/windows/GIDEON Remote Control/app",
        ):
            guacamole = (app_root / "gideon_web_admin/guacamole.py").read_text(encoding="utf-8-sig")
            app = (app_root / "gideon_web_admin/app.py").read_text(encoding="utf-8-sig")
            self.assertNotIn('"resize-method": "none"', guacamole)
            self.assertIn("async def rdp_stall_watchdog", app)
            self.assertIn("GUACD_RDP_STALLED", app)
            self.assertIn('pending_inputs >= 3 and meaningful_idle >= 15.0', app)
            self.assertIn('opcode not in {"", "sync", "nop", "ack"}', app)
            self.assertIn("await asyncio.wait_for(writer.wait_closed(), timeout=2.0)", app)


if __name__ == "__main__":
    unittest.main()
