import json
import idautils
import idc
funcs = [idc.get_func_name(ea) for ea in idautils.Functions()]
with open("ida_out.json", "w") as f:
    json.dump(funcs, f)
idc.qexit(0)
