"""IDA Python: Decompile all non-library functions."""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_pro

ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()

count = 0
addr = ida_funcs.get_next_func(0)
while addr:
    func = ida_funcs.get_func(addr)
    if func:
        name = ida_funcs.get_func_name(func.start_ea)
        try:
            cfunc = ida_hexrays.decompile(func)
            print(f"FUNCTION:{name}")
            print(cfunc)
            print("---")
            count += 1
        except Exception:
            pass
    addr = ida_funcs.get_next_func(addr)

print(f"// Decompiled {count} functions total")
ida_pro.qexit(0)
