"""
Garudatva v3 — Frida Controller
Manages Frida server deployment, script injection, and artifact collection.
Uses spawn mode (-f) for early hooking before app init code runs.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

FRIDA_SERVER_DEVICE_PATH = "/data/local/tmp/frida-server"
FRIDA_SCRIPTS_DIR = Path(__file__).parent.parent.parent.parent / "frida-scripts"

HOOK_SCRIPTS = [
    "network_intercept.js",
    "crypto_key_extract.js",
    "interceptor_hooks.js",
    "sms_intercept.js",
    "clipboard_intercept.js",
    "accessibility_intercept.js",
]

ARTIFACT_PATHS = {
    "network":      "/data/local/tmp/garudatva_network.json",
    "crypto":       "/data/local/tmp/garudatva_crypto.json",
    "sms":          "/data/local/tmp/garudatva_sms.json",
    "interceptors": "/data/local/tmp/garudatva_interceptors.json",
    "clipboard":    "/data/local/tmp/garudatva_clipboard.json",
    "accessibility":"/data/local/tmp/garudatva_accessibility.json",
}


class FridaController:
    def __init__(self, sandbox):
        self.sandbox = sandbox
        self._frida_proc: Optional[asyncio.subprocess.Process] = None

    async def setup(self) -> None:
        """Push frida-server to AVD and start it."""
        import frida
        server_path = self._find_frida_server()
        if server_path:
            await self.sandbox.push_file(server_path, FRIDA_SERVER_DEVICE_PATH)
            await self.sandbox._adb(f"chmod 755 {FRIDA_SERVER_DEVICE_PATH}")
            await self.sandbox._adb(f"{FRIDA_SERVER_DEVICE_PATH} &")
            await asyncio.sleep(2)
            logger.info("Frida server started on AVD")
        else:
            logger.warning("frida-server binary not found — gadget mode assumed")

    async def inject_all_hooks(self, package_name: str) -> None:
        """
        Inject all 6 hook scripts simultaneously via frida CLI.
        Uses spawn mode to hook before app initialization.
        """
        combined_script = self._build_combined_script()
        script_path = Path("/tmp/garudatva_combined_hooks.js")
        script_path.write_text(combined_script, encoding="utf-8")

        cmd = [
            "frida",
            "-U",                           # USB/emulator device
            "-f", package_name,             # spawn mode
            "--no-pause",
            "-l", str(script_path),
        ]
        try:
            self._frida_proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            logger.info(f"Frida hooks injected into {package_name} (spawn mode)")
        except FileNotFoundError:
            logger.error("frida CLI not found — install: pip install frida-tools")
            raise

    async def collect_artifacts(self, work_dir: Path) -> Dict[str, Any]:
        """Pull all hook output JSON files from AVD after analysis."""
        artifacts: Dict[str, Any] = {}
        work_dir.mkdir(parents=True, exist_ok=True)

        for artifact_name, device_path in ARTIFACT_PATHS.items():
            local_path = work_dir / f"garudatva_{artifact_name}.json"
            ok = await self.sandbox.pull_file(device_path, local_path)
            if ok and local_path.exists():
                try:
                    artifacts[artifact_name] = json.loads(
                        local_path.read_text(encoding="utf-8")
                    )
                    logger.info(f"Artifact pulled: {artifact_name} ({local_path.stat().st_size} bytes)")
                except json.JSONDecodeError:
                    artifacts[artifact_name] = []
                    logger.warning(f"Invalid JSON in {artifact_name} artifact")
            else:
                artifacts[artifact_name] = []

        return artifacts

    async def stop(self) -> None:
        if self._frida_proc:
            try:
                self._frida_proc.kill()
                await self._frida_proc.wait()
            except Exception:
                pass

    def _build_combined_script(self) -> str:
        """Concatenate all 6 hook scripts with error isolation per script."""
        parts = ["'use strict';", ""]
        for script_name in HOOK_SCRIPTS:
            script_path = FRIDA_SCRIPTS_DIR / script_name
            if script_path.exists():
                content = script_path.read_text(encoding="utf-8")
                parts.append(f"// ── {script_name} ──────────────────────────")
                parts.append("try {")
                parts.append(content)
                parts.append("} catch(e) {")
                parts.append(f"  console.error('[garudatva] {script_name} failed:', e.message);")
                parts.append("}")
                parts.append("")
            else:
                logger.warning(f"Hook script not found: {script_path}")
        return "\n".join(parts)

    def _find_frida_server(self) -> Optional[Path]:
        """Find a local frida-server binary matching the installed frida version."""
        import frida
        version = frida.__version__
        candidates = [
            Path(f"/opt/frida/frida-server-{version}-android-x86_64"),
            Path(f"/tmp/frida-server-{version}-android-x86_64"),
            Path(f"./frida-server"),
        ]
        for p in candidates:
            if p.exists():
                return p
        return None
