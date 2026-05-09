"""IDA Python: Run FLIRT signature scans for known library detection."""
import ida_auto
import ida_pro
import ida_sig

ida_auto.auto_wait()

try:
    ida_sig.sigmgr_apply(None)
except Exception:
    pass

for i in range(ida_sig.get_sig_count()):
    sig_name = ida_sig.get_sig_name(i)
    applied = ida_sig.get_sig_applied(i)
    if applied > 0:
        print(f"SIG:{sig_name} -> {applied} matches")

ida_pro.qexit(0)
