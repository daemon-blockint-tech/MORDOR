"""IDA Python: Decompile a single function by name."""
import ida_auto
import ida_funcs
import ida_pro
import sys

ida_auto.auto_wait()

target = sys.argv[-2] if len(sys.argv) > 2 else ""

func = ida_funcs.find_func_byname(target)
if func:
    import ida_hexrays
    ida_hexrays.init_hexrays_plugin()
    try:
        cfunc = ida_hexrays.decompile(func)
        print(f"FUNCTION:{target}")
        print(cfunc)
    except Exception as e:
        print(f"FUNCTION:{target}")
        print(f"// decompile failed: {e}")
else:
    print(f"FUNCTION:{target}")
    print("// function not found")

ida_pro.qexit(0)
