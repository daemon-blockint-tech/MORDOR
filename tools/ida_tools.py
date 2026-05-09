import json
import logging
import os
import subprocess
import tempfile

from tools.safe_util import sanitize_path, safe_subprocess_env, get_subprocess_timeout

logger = logging.getLogger("mordor.tools.ida")

IDA_PATH = os.environ.get("IDA_PATH", "/Applications/IDA Free 9.3.app/Contents/MacOS/idat64")
ALLOWED_DIR = os.environ.get("MORDOR_CASES_DIR", os.path.realpath("cases"))


def extract_with_ida(binary_path: str) -> dict:
    if not os.path.exists(IDA_PATH):
        logger.error(f"IDA not found at {IDA_PATH}")
        return {"status": "error", "error": "IDA executable not found"}

    try:
        binary_path = sanitize_path(binary_path, ALLOWED_DIR)
    except (ValueError, FileNotFoundError) as e:
        return {"status": "error", "error": str(e)}

    script_content = """import idaapi
import idautils
import idc
import json

def extract():
    idaapi.auto_wait()
    results = {
        "functions": [],
        "strings": [],
        "imports": []
    }
    
    for ea in idautils.Functions():
        results["functions"].append({"name": idc.get_func_name(ea), "address": hex(ea)})
        
    for s in idautils.Strings():
        results["strings"].append({"value": str(s), "address": hex(s.ea)})
        
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        module_name = idaapi.get_import_module_name(i)
        def imp_cb(ea, name, ord):
            if name:
                results["imports"].append({"name": name, "module": module_name})
            return True
        idaapi.enum_import_names(i, imp_cb)
        
    out_path = idc.ARGV[1] if len(idc.ARGV) > 1 else "ida_output.json"
    with open(out_path, "w") as f:
        json.dump(results, f)

try:
    extract()
except Exception as e:
    pass
finally:
    idc.qexit(0)
"""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as sf:
        sf.write(script_content)
        script_path = sf.name
        
    output_json = binary_path + ".ida.json"
    
    cmd = [
        IDA_PATH,
        "-c", "-A",
        f'-S{script_path} {output_json}',
        binary_path
    ]
    
    try:
        logger.info(f"Running IDA: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=get_subprocess_timeout(120),
                                env=safe_subprocess_env())
        
        if "does not support the batch mode" in result.stdout or "does not support the batch mode" in result.stderr:
            logger.error("IDA Free license detected - batch mode is unsupported.")
            return {"status": "error", "error": "IDA Free does not support batch mode (-A / -S). Pro license required."}
            
        if os.path.exists(output_json):
            with open(output_json, "r") as f:
                data = json.load(f)
            os.remove(output_json)
            return {"status": "ok", "results": data}
        else:
            return {"status": "error", "error": "IDA script failed to produce output", "output": result.stdout}
            
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "IDA execution timed out"}
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)
