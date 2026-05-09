from __future__ import annotations

import json
import logging
import os
import subprocess
import time

from tools.safe_util import safe_subprocess_env

logger = logging.getLogger("mordor.tools.frida")


def _frida_available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except ImportError:
        return False


def attach_hooks(binary_path: str, functions: list[str]) -> dict:
    if not functions:
        return {"hooks_attached": 0, "results": [], "status": "no_functions"}

    if not _frida_available():
        logger.warning("frida package not installed")
        return {"hooks_attached": 0, "results": [], "status": "frida_not_installed"}

    script_template = """
    'use strict';
    const hooks = %s;
    const results = [];
    hooks.forEach(function(fn) {
        try {
            const mod = Process.findModuleByName(null);
            const addr = Module.findExportByName(null, fn);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        results.push({
                            function: fn,
                            action: "enter",
                            args: Array.from(args).slice(0, 4).map(function(a) { return a.toString(); }),
                            timestamp: Date.now(),
                        });
                    },
                    onLeave: function(retval) {
                        results.push({
                            function: fn,
                            action: "leave",
                            retval: retval.toString(),
                            timestamp: Date.now(),
                        });
                    }
                });
            }
        } catch(e) {
            results.push({function: fn, error: e.toString()});
        }
    });
    send(JSON.stringify(results));
    recv('stop', function() { /* cleanup */ });
    """

    try:
        import frida
        pid = None
        try:
            pid = int(
                subprocess.check_output(["pgrep", "-x", os.path.basename(binary_path)],
                                        env=safe_subprocess_env())
                .decode().strip()
            )
        except (subprocess.CalledProcessError, ValueError):
            logger.info("Binary not running, spawning via frida...")
            device = frida.get_local_device()
            pid = device.spawn([binary_path])
            device.resume(pid)
            time.sleep(0.5)

        session = frida.attach(pid)
        script = session.create_script(script_template % json.dumps(functions))

        hook_results = []

        def on_message(message, data):
            if message.get("type") == "send":
                try:
                    hook_results.extend(json.loads(message["payload"]))
                except (json.JSONDecodeError, KeyError):
                    hook_results.append({"raw": str(message)})

        script.on("message", on_message)
        script.load()
        script.post({"type": "stop"})
        session.detach()

        return {
            "hooks_attached": len(functions),
            "results": hook_results,
            "status": "ok",
        }
    except Exception as e:
        logger.warning("Frida hooks failed: %s", e)
        return {"hooks_attached": 0, "results": [], "status": f"error: {e}"}
