import idaapi
import idautils
import idc
import json

def extract():
    idaapi.auto_wait()
    funcs = []
    for ea in idautils.Functions():
        funcs.append(idc.get_func_name(ea))
    
    out_path = idc.ARGV[1] if len(idc.ARGV) > 1 else "ida_out.json"
    with open(out_path, "w") as f:
        json.dump(funcs[:10], f)

try:
    extract()
except Exception as e:
    with open("ida_error.txt", "w") as f:
        f.write(str(e))
finally:
    idc.qexit(0)
