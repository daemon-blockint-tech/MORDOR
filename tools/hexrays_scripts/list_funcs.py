"""IDA Python: List all function names and addresses."""
import ida_auto
import ida_funcs
import ida_pro

ida_auto.auto_wait()

addr = ida_funcs.get_next_func(0)
while addr:
    func = ida_funcs.get_func(addr)
    if func:
        name = ida_funcs.get_func_name(func.start_ea)
        print(f"FUNC:0x{func.start_ea:x} {name}")
    addr = ida_funcs.get_next_func(addr)

ida_pro.qexit(0)
