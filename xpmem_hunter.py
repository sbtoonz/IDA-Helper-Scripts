# IDA 7.7+ script
# Cross-process memory hunter v5.4
# - IOCTL recovery (IoStackLocation & IRP-walk)
# - Handler discovery & indirect call resolution
# - Map protections
# - memmove direction with userbuf vs remote-map classification
# - Cross-callee remote map tagging (mapper returns in RAX)
# - Device name/link discovery (IoCreateSymbolicLink/WDF + string harvest)
# - C++ header export with all IOCTLs + device candidates + try_open_any()
#
# Output header: xpmem_user.hpp (change HEADER_OUT_PATH below to customize)

import idaapi, idc, ida_bytes, ida_funcs, ida_nalt, ida_xref, idautils, ida_segment
import os
import datetime

# ============================ Config ============================
HEADER_OUT_PATH = "xpmem_user.hpp"    # change if you want a different location/filename
DEFAULT_DEVICE_SYMLINK = r"\\.\YourDeviceName"  # used only if we can't discover one

# ============================ Targets ============================
TARGET_APIS = {
    "ZwReadVirtualMemory":   "read",
    "ZwWriteVirtualMemory":  "write",
    "MmCopyVirtualMemory":   "rw",
    "KeStackAttachProcess":  "ctx",
    "KeUnstackDetachProcess":"ctx",
    "MmMapViewOfSection":    "map",
    "ZwMapViewOfSection":    "map",
    "MmProbeAndLockPages":           "mdl",
    "MmGetSystemAddressForMdlSafe":  "mdlmap",
    "ProbeForRead":   "read_guard",
    "ProbeForWrite":  "write_guard",
    "RtlCopyMemory":  "copy",
    "RtlMoveMemory":  "copy",
    "memcpy":         "copy",
    "memmove":        "copy",
    "RtlFillMemory":  "write_fill",
    "RtlZeroMemory":  "write_fill",
    "IoGetCurrentIrpStackLocation": "dispatcher",
}

LOCK_OPERATION_NAMES = {0: "IoReadAccess", 1: "IoWriteAccess", 2: "IoModifyAccess"}

PROT_FLAGS = {
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
}

METHOD_NAMES = {0:"METHOD_BUFFERED",1:"METHOD_IN_DIRECT",2:"METHOD_OUT_DIRECT",3:"METHOD_NEITHER"}
ACCESS_NAMES = {0:"FILE_ANY_ACCESS",1:"FILE_READ_ACCESS",2:"FILE_WRITE_ACCESS",3:"FILE_READ|WRITE_ACCESS"}

# ============================ Utils ============================
def is64(): return ida_nalt.inf_is_64bit()
def seg_contains(ea): return ida_segment.getseg(ea) is not None
def fn_name(ea):
    f = ida_funcs.get_func(ea)
    if not f: return "sub_%X" % ea
    nm = ida_funcs.get_func_name(f.start_ea)
    return nm or "sub_%X" % f.start_ea

def _get_switch_info_ex_compat(ea):
    try: return ida_nalt.get_switch_info_ex(ea)
    except Exception: pass
    try: return idaapi.get_switch_info_ex(ea)
    except Exception: pass
    try: return idaapi.get_switch_info(ea)
    except Exception: return None

# ============================ IOCTL helpers ============================
def _is_plausible_ioctl(val):
    if val is None: return False
    val &= 0xFFFFFFFF
    if (val & 0xF0000000) in (0xC0000000, 0x80000000):  # STATUS_* etc
        return False
    if val in (0x001F01FF, 0x000F0003, 0x00100000):    # common masks
        return False
    dev  = (val >> 16) & 0xFFFF
    func = (val >> 2)  & 0xFFF
    meth = val & 0x3
    acc  = (val >> 14) & 0x3
    if func == 0 or meth > 3 or acc > 3: return False
    if dev == 0 or dev == 0xC000: return False
    return True

def decode_ioctl(v):
    dev  = (v >> 16) & 0xFFFF
    acc  = (v >> 14) & 0x3
    func = (v >> 2)  & 0xFFF
    meth = v & 0x3
    return dev, func, meth, acc

def fmt_ioctl(v):
    dev, func, meth, acc = decode_ioctl(v)
    return f"IOCTL=0x{v:08X} DEV=0x{dev:04X} FUNC=0x{func:03X} {METHOD_NAMES.get(meth,str(meth))} {ACCESS_NAMES.get(acc,str(acc))}"

def get_switch_cases_at(ea):
    si = _get_switch_info_ex_compat(ea)
    if not si: return []
    try:
        cv = idaapi.casevec_t(); idaapi.calc_switch_cases(ea, cv, si); vec = cv
    except Exception:
        try:
            cv = ida_xref.casevec_t(); ida_xref.calc_switch_cases(ea, cv, si); vec = cv
        except Exception:
            try:
                vec = ida_xref.calc_switch_cases(ea, si)
            except Exception:
                return []
    out = []
    try:
        for c in vec:
            for v in c.cases:
                out.append(int(v) & 0xFFFFFFFF)
    except Exception:
        for i in range(len(vec)):
            c = vec[i]
            try:
                for j in range(len(c.cases)):
                    out.append(int(c.cases[j]) & 0xFFFFFFFF)
            except Exception:
                pass
    return out

# ============================ Backtracking ============================
def read_unicode_from(addr, max_bytes=0x400):
    if not seg_contains(addr): return None
    raw = ida_bytes.get_bytes(addr, max_bytes)
    if not raw: return None
    try: s = raw.decode("utf-16le", errors="ignore")
    except Exception: return None
    z = s.find("\x00"); return s if z < 0 else s[:z]

def read_unicode_string_struct(us_ptr):
    if not seg_contains(us_ptr): return None
    buf = ida_bytes.get_qword(us_ptr + 8) if is64() else ida_bytes.get_dword(us_ptr + 4)
    if not seg_contains(buf): return None
    return read_unicode_from(buf, 0x800)

def backtrack_reg_value(func, at_ea, reg_name, max_back=160):
    reg = reg_name.lower()
    ea = idc.prev_head(at_ea); steps = 0
    while ea != idaapi.BADADDR and steps < max_back and ea >= func.start_ea:
        m = idc.print_insn_mnem(ea)
        if m in ("mov","lea"):
            dst = idc.print_operand(ea, 0).lower()
            if dst == reg:
                otype = idc.get_operand_type(ea, 1)
                txt   = idc.print_operand(ea, 1)
                if otype in (idc.o_imm, idc.o_mem, idc.o_far, idc.o_near, idc.o_displ):
                    val = idc.get_operand_value(ea, 1)
                    if "[" in txt and any(x in txt.lower() for x in ("rsp","rbp","esp","ebp")):
                        return ("stack", None, ea, txt)
                    return ("imm", val, ea, txt)
                return ("unknown", None, ea, txt)
        ea = idc.prev_head(ea); steps += 1
    return (None, None, None, None)

# ============================ IDA helpers ============================
def find_import_eas_by_name(name):
    hits = set()
    sym_ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if sym_ea != idaapi.BADADDR: hits.add(sym_ea)
    try:
        qty = ida_nalt.get_import_module_qty()
        for i in range(qty):
            def cb(ea, s, ord):
                try: s = s.decode() if isinstance(s, bytes) else s
                except Exception: pass
                if s == name: hits.add(ea)
                return True
            ida_nalt.enum_import_names(i, cb)
    except Exception:
        pass
    return sorted(hits)

def calls_to_import_in_func(name, fn_ea):
    out = []
    iats = find_import_eas_by_name(name)
    if not iats: return out
    f = ida_funcs.get_func(fn_ea)
    if not f: return out
    for iat in iats:
        for xr in idautils.XrefsTo(iat):
            if f.contains(xr.frm) and idc.print_insn_mnem(xr.frm) == "call":
                out.append(xr.frm)
    return sorted(set(out))

def get_callers(func_start_ea, max_depth=2):
    seen, frontier, depth, callers = set(), {func_start_ea}, 0, set()
    while depth < max_depth and frontier:
        new_frontier = set()
        for callee in frontier:
            for x in idautils.CodeRefsTo(callee, True):
                f = ida_funcs.get_func(x)
                if not f: continue
                fea = f.start_ea
                if fea in seen: continue
                seen.add(fea); callers.add(fea); new_frontier.add(fea)
        frontier = new_frontier; depth += 1
    return callers

# ============================ Dynamic resolution ============================
def find_mmgsra_calls():
    iats = find_import_eas_by_name("MmGetSystemRoutineAddress")
    calls = []
    for iat in iats:
        for xr in idautils.XrefsTo(iat):
            if idc.print_insn_mnem(xr.frm) == "call":
                calls.append(xr.frm)
    return sorted(set(calls))

def find_rtlinit_calls_in_func(fn_ea):
    out = []
    iats = find_import_eas_by_name("RtlInitUnicodeString")
    if not iats: return out
    f = ida_funcs.get_func(fn_ea)
    if not f: return out
    for iat in iats:
        for xr in idautils.XrefsTo(iat):
            if f.contains(xr.frm):
                out.append(xr.frm)
    return sorted(set(out))

def recover_name_for_mmgsra_call(call_ea):
    f = ida_funcs.get_func(call_ea)
    if not f: return None, "no-func"
    kind, val, _, _ = backtrack_reg_value(f, call_ea, "rcx", max_back=200)
    if kind == "imm" and val and seg_contains(val):
        s = read_unicode_string_struct(val)
        return s, f"UNICODE_STRING @{val:#x}"
    if kind == "stack":
        cand = [ea for ea in find_rtlinit_calls_in_func(f.start_ea) if ea < call_ea]
        cand.sort(reverse=True)
        for ru in cand:
            k2, v2, _, _ = backtrack_reg_value(f, ru, "rdx", max_back=160)
            if k2 == "imm" and v2 and seg_contains(v2):
                s = read_unicode_from(v2, 0x800)
                if s: return s, f"RtlInitUnicodeString buffer @{v2:#x}"
        return None, "stack-ru-missed"
    return None, "unknown"

def scan_forward_for_saved_fp(call_ea, max_fwd=40):
    slots = []
    ea = idc.next_head(call_ea); steps = 0
    while ea != idaapi.BADADDR and steps < max_fwd:
        m = idc.print_insn_mnem(ea)
        if m == "mov":
            if idc.get_operand_type(ea, 0) in (idc.o_mem, idc.o_displ) and idc.print_operand(ea, 1).lower() == "rax":
                dst_val = idc.get_operand_value(ea, 0)
                if dst_val and seg_contains(dst_val): slots.append(dst_val)
        if m in ("ret","retn","jmp"): break
        ea = idc.next_head(ea); steps += 1
    return sorted(set(slots))

def find_calls_through_slot(slot_ea):
    calls = []
    for xr in idautils.XrefsTo(slot_ea):
        at = xr.frm
        if idc.print_insn_mnem(at) == "call":
            if idc.get_operand_type(at, 0) in (idc.o_mem, idc.o_displ) and idc.get_operand_value(at, 0) == slot_ea:
                calls.append(at)
    return sorted(set(calls))

# ============================ Map protections ============================
def guess_protect_near_call(call_ea, lookback=40):
    ea = call_ea; prot_val = None; steps = 0
    while steps < lookback:
        ea = idc.prev_head(ea)
        if ea == idaapi.BADADDR: break
        m = idc.print_insn_mnem(ea)
        if m == "mov" and idc.get_operand_type(ea, 0) == idc.o_displ and idc.get_operand_type(ea, 1) == idc.o_imm:
            dst = idc.print_operand(ea, 0).lower()
            if dst.startswith("[rsp+") or dst.startswith("[rbp-") or dst.startswith("[rsp-"):
                imm = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                if (imm & 0xFF) in (0x02,0x04,0x08,0x10,0x20,0x40,0x80):
                    prot_val = imm; break
        if m in ("ret","retn"): break
        steps += 1
    if prot_val is None: return None, "unknown"
    parts = [name for bit, name in PROT_FLAGS.items() if prot_val & bit]
    txt = "|".join(parts) if parts else f"0x{prot_val:X}"
    writey = any(flag in parts for flag in ("PAGE_READWRITE","PAGE_WRITECOMBINE","PAGE_WRITECOPY","PAGE_EXECUTE_READWRITE","PAGE_EXECUTE_WRITECOMBINE","PAGE_EXECUTE_WRITECOMBINE","PAGE_EXECUTE_WRITECOPY"))
    return (prot_val, txt, "WRITE" if writey else "READ"), "ok"

# ============================ IOCTL finders ============================
def find_real_ioctls_in_func(fn_ea):
    f = ida_funcs.get_func(fn_ea)
    if not f: return {}
    out = {}
    sites = calls_to_import_in_func("IoGetCurrentIrpStackLocation", fn_ea)
    if not sites: return out
    for call in sites:
        regs_holding = set(["rax"])
        ea = idc.next_head(call); steps = 0
        while ea != idaapi.BADADDR and steps < 120 and f.contains(ea):
            m = idc.print_insn_mnem(ea)
            if m == "mov":
                if idc.get_operand_type(ea, 0) == idc.o_reg and idc.get_operand_type(ea, 1) == idc.o_reg:
                    dst = idc.print_operand(ea, 0).lower()
                    src = idc.print_operand(ea, 1).lower()
                    if src in regs_holding: regs_holding.add(dst)
            if m.startswith("cmp"):
                if idc.get_operand_type(ea, 0) == idc.o_reg and idc.get_operand_type(ea, 1) == idc.o_imm:
                    reg = idc.print_operand(ea, 0).lower()
                    if reg in regs_holding or reg.replace("e","r",1) in regs_holding:
                        val = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                        if _is_plausible_ioctl(val): out.setdefault(val, []).append(ea)
            if _get_switch_info_ex_compat(ea):
                for v in get_switch_cases_at(ea):
                    if _is_plausible_ioctl(v): out.setdefault(v, []).append(ea)
            if m in ("ret","retn","jmp"): break
            ea = idc.next_head(ea); steps += 1
    return out

def find_ioctls_via_irp_walk(fn_ea):
    f = ida_funcs.get_func(fn_ea); 
    if not f: return {}
    out = {}
    irp_ptr_regs = set(["rdx","edx"])
    field_regs   = set()
    for ea in idautils.FuncItems(fn_ea):
        m = idc.print_insn_mnem(ea).lower()
        if m in ("mov","lea"):
            dst = idc.print_operand(ea, 0).lower()
            src = idc.print_operand(ea, 1).lower()
            o1  = idc.get_operand_type(ea, 1)
            if o1 == idc.o_reg:
                if src in irp_ptr_regs: irp_ptr_regs.add(dst)
                if src in field_regs:   field_regs.add(dst)
            elif o1 in (idc.o_displ, idc.o_phrase):
                if any(src.startswith("[" + r) or ("[" + r + "+") in src for r in list(irp_ptr_regs)+list(field_regs)):
                    field_regs.add(dst)
        elif m.startswith("cmp"):
            if idc.get_operand_type(ea, 0) == idc.o_reg and idc.get_operand_type(ea, 1) == idc.o_imm:
                reg = idc.print_operand(ea, 0).lower()
                if reg in field_regs or reg.replace("e","r",1) in field_regs:
                    val = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                    if _is_plausible_ioctl(val): out.setdefault(val, []).append(ea)
        if _get_switch_info_ex_compat(ea):
            look = idc.prev_head(ea); ok = False
            for _ in range(8):
                if look == idaapi.BADADDR or not f.contains(look): break
                txt = idc.GetDisasm(look).lower()
                if any(f"[{r}+" in txt or txt.strip().startswith(f"mov {r},") for r in field_regs):
                    ok = True; break
                look = idc.prev_head(look)
            if ok:
                for v in get_switch_cases_at(ea):
                    if _is_plausible_ioctl(v): out.setdefault(v, []).append(ea)
    return out

# ============================ Indirect calls ============================
def _read_ptr(ptr_ea):
    try:
        if is64(): return ida_bytes.get_qword(ptr_ea)
        else:      return ida_bytes.get_dword(ptr_ea)
    except Exception:
        return None

def resolve_indirect_call(call_ea):
    op_t = idc.get_operand_type(call_ea, 0)
    op_s = idc.print_operand(call_ea, 0).lower()
    f = ida_funcs.get_func(call_ea)
    if not f: return (None, "no-func", None)
    if op_t in (idc.o_mem, idc.o_displ):
        tgt = idc.get_operand_value(call_ea, 0)
        if tgt and seg_contains(tgt):
            ptr = _read_ptr(tgt)
            if ptr and seg_contains(ptr):
                cf = ida_funcs.get_func(ptr)
                return (ptr if cf else None, "mem-indirect", tgt)
        return (None, "mem-indirect", tgt)
    if op_t == idc.o_reg:
        reg = op_s
        kind, val, _, txt = backtrack_reg_value(f, call_ea, reg, max_back=200)
        if kind == "imm" and val and seg_contains(val):
            cf = ida_funcs.get_func(val)
            return (val if cf else None, "reg-imm", val)
        ea = idc.prev_head(call_ea); steps = 0
        while ea != idaapi.BADADDR and steps < 40 and ea >= f.start_ea:
            if idc.print_insn_mnem(ea).lower() == "mov":
                dst = idc.print_operand(ea, 0).lower()
                if dst == reg and idc.get_operand_type(ea, 1) in (idc.o_mem, idc.o_displ):
                    slot = idc.get_operand_value(ea, 1)
                    if slot and seg_contains(slot):
                        ptr = _read_ptr(slot)
                        if ptr and seg_contains(ptr):
                            cf = ida_funcs.get_func(ptr)
                            return (ptr if cf else None, "reg-slot", slot)
            ea = idc.prev_head(ea); steps += 1
        return (None, "reg-indirect", None)
    return (None, "unknown", None)

# ============================ Remote/user tagging ============================
def _normalize_bracket(text): return text.lower().replace(" ", "") if text else ""
def _same_memop(a, b): return _normalize_bracket(a) == _normalize_bracket(b)

MAPPER_FUNCS = None
def build_mapper_funcs():
    global MAPPER_FUNCS
    if MAPPER_FUNCS is not None: return MAPPER_FUNCS
    mappers = set()
    for fea in idautils.Functions():
        if calls_to_import_in_func("ZwMapViewOfSection", fea) or calls_to_import_in_func("MmMapViewOfSection", fea):
            mappers.add(fea)
    MAPPER_FUNCS = mappers
    return MAPPER_FUNCS

def record_remote_map_regs(fn_ea):
    f = ida_funcs.get_func(fn_ea)
    if not f: return set()
    remote_regs = set()

    # (A) local out-slot pattern
    sites = calls_to_import_in_func("ZwMapViewOfSection", fn_ea) + calls_to_import_in_func("MmMapViewOfSection", fn_ea)
    for call in sites:
        kind, val, _, txt = backtrack_reg_value(f, call, "r8", max_back=120)
        slot_txt = txt if kind in ("stack","imm","unknown") and txt else None
        if not slot_txt: continue
        ea = idc.next_head(call); steps = 0
        while ea != idaapi.BADADDR and steps < 120 and f.contains(ea):
            m = idc.print_insn_mnem(ea).lower()
            if m in ("mov","lea"):
                if idc.get_operand_type(ea, 0) == idc.o_reg and idc.get_operand_type(ea, 1) in (idc.o_displ, idc.o_phrase):
                    src_txt = idc.print_operand(ea, 1)
                    if _same_memop(src_txt, slot_txt):
                        remote_regs.add(idc.print_operand(ea, 0).lower())
                if idc.get_operand_type(ea, 0) == idc.o_reg and idc.get_operand_type(ea, 1) == idc.o_reg:
                    dst = idc.print_operand(ea, 0).lower()
                    src = idc.print_operand(ea, 1).lower()
                    if src in remote_regs: remote_regs.add(dst)
            if m in ("ret","retn"): break
            ea = idc.next_head(ea); steps += 1

    # (B) cross-callee mapper return (RAX)
    mappers = build_mapper_funcs()
    for insn in idautils.FuncItems(fn_ea):
        if idc.print_insn_mnem(insn).lower() == "call":
            callee = None
            if idc.get_operand_type(insn, 0) == idc.o_near:
                callee = idc.get_operand_value(insn, 0)
            else:
                tgt, _, _ = resolve_indirect_call(insn)
                callee = tgt
            if callee and ida_funcs.get_func(callee) and ida_funcs.get_func(callee).start_ea in mappers:
                # After call: reg <- rax
                ea2 = idc.next_head(insn); steps = 0
                while ea2 != idaapi.BADADDR and steps < 32 and f.contains(ea2):
                    m = idc.print_insn_mnem(ea2).lower()
                    if m == "mov" and idc.get_operand_type(ea2, 0) == idc.o_reg and idc.print_operand(ea2, 1).lower() == "rax":
                        remote_regs.add(idc.print_operand(ea2, 0).lower()); break
                    if m in ("ret","retn"): break
                    ea2 = idc.next_head(ea2); steps += 1
    return remote_regs

def collect_mdl_map_regs(fn_ea):
    f = ida_funcs.get_func(fn_ea)
    if not f: return set()
    mdl_regs = set()
    for call in calls_to_import_in_func("MmGetSystemAddressForMdlSafe", fn_ea):
        ea = idc.next_head(call); steps = 0
        while ea != idaapi.BADADDR and steps < 32 and f.contains(ea):
            m = idc.print_insn_mnem(ea).lower()
            if m == "mov" and idc.get_operand_type(ea, 0) == idc.o_reg and idc.print_operand(ea, 1).lower() == "rax":
                mdl_regs.add(idc.print_operand(ea, 0).lower()); break
            if m in ("ret","retn"): break
            ea = idc.next_head(ea); steps += 1
    return mdl_regs

def classify_memmoves_with_context(fn_ea):
    f = ida_funcs.get_func(fn_ea)
    if not f: return []
    # IRP-derived (heuristic)
    irp_ptr_regs = set(["rdx","edx"])
    field_regs   = set()
    for ea in idautils.FuncItems(fn_ea):
        m = idc.print_insn_mnem(ea).lower()
        if m in ("mov","lea"):
            dst = idc.print_operand(ea, 0).lower()
            src = idc.print_operand(ea, 1).lower()
            o1  = idc.get_operand_type(ea, 1)
            if o1 == idc.o_reg:
                if src in irp_ptr_regs: irp_ptr_regs.add(dst)
                if src in field_regs:   field_regs.add(dst)
            elif o1 in (idc.o_displ, idc.o_phrase):
                if any(src.startswith("[" + r) or ("[" + r + "+") in src for r in list(irp_ptr_regs)+list(field_regs)):
                    field_regs.add(dst)

    mdl_regs   = collect_mdl_map_regs(fn_ea)
    user_regs  = set(field_regs) | set(mdl_regs)
    remote_regs= record_remote_map_regs(fn_ea)

    results = []
    mem_sites = sorted(set(calls_to_import_in_func("memmove", fn_ea) + calls_to_import_in_func("RtlMoveMemory", fn_ea)))
    for ce in mem_sites:
        kdst, vdst, _, txtdst = backtrack_reg_value(f, ce, "rcx", max_back=120)  # dest
        ksrc, vsrc, _, txtsrc = backtrack_reg_value(f, ce, "rdx", max_back=120)  # src
        dest_reg = "rcx"; src_reg = "rdx"

        dest_is_user   = dest_reg in user_regs
        src_is_user    = src_reg  in user_regs
        dest_is_remote = dest_reg in remote_regs
        src_is_remote  = src_reg  in remote_regs
        dest_is_mdl    = dest_reg in mdl_regs
        src_is_mdl     = src_reg  in mdl_regs

        # textual fallbacks
        if txtdst:
            t = txtdst.lower()
            dest_is_user   |= any((" "+r in t) or ("["+r in t) for r in user_regs)
            dest_is_remote |= any((" "+r in t) or ("["+r in t) for r in remote_regs)
        if txtsrc:
            t = txtsrc.lower()
            src_is_user    |= any((" "+r in t) or ("["+r in t) for r in user_regs)
            src_is_remote  |= any((" "+r in t) or ("["+r in t) for r in remote_regs)

        direction = "unknown"
        if src_is_user and dest_is_remote:
            direction = "WRITE (userbuf -> remote-map)"
        elif src_is_remote and dest_is_user:
            direction = "READ (remote-map -> userbuf)"
        elif src_is_user and not dest_is_user:
            direction = "WRITE (userbuf -> other)"
        elif dest_is_user and not src_is_user:
            direction = "READ (other -> userbuf)"

        results.append({
            "call": ce,
            "direction": direction,
            "src_is_user": src_is_user,
            "dest_is_user": dest_is_user,
            "src_is_remote": src_is_remote,
            "dest_is_remote": dest_is_remote,
            "src_is_mdl": src_is_mdl,
            "dest_is_mdl": dest_is_mdl,
        })
    return results

# ============================ Direction pass per function ============================
def analyze_direction_in_func(fn_ea):
    f = ida_funcs.get_func(fn_ea)
    if not f: return {"read":[], "write":[], "mdl":[], "apis":{}, "map_prot":[]}
    apis = {}; read_hits = []; write_hits = []; mdl_ops = []; map_prot = []
    for nm, tag in TARGET_APIS.items():
        sites = calls_to_import_in_func(nm, fn_ea)
        if sites:
            apis[nm] = sites
            if tag in ("read","read_guard"): read_hits.extend(sites)
            if tag in ("write","write_guard","write_fill"): write_hits.extend(sites)
    for call_ea in apis.get("MmProbeAndLockPages", []):
        k, v, _, _ = backtrack_reg_value(f, call_ea, "r8", max_back=120)
        if k == "imm":
            lo = v & 0xFFFFFFFF
            name = LOCK_OPERATION_NAMES.get(lo, f"Unknown({lo})")
            mdl_ops.append((call_ea, name))
            if lo == 0: read_hits.append(call_ea)
            elif lo in (1,2): write_hits.append(call_ea)
    for call_ea in apis.get("ZwMapViewOfSection", []) + apis.get("MmMapViewOfSection", []):
        info, ok = guess_protect_near_call(call_ea)
        if ok == "ok" and info:
            _, prot_txt, clas = info
            map_prot.append((call_ea, prot_txt))
            (write_hits if clas=="WRITE" else read_hits).append(call_ea)
    return {"read":sorted(set(read_hits)),"write":sorted(set(write_hits)),"mdl":mdl_ops,"apis":apis,"map_prot":map_prot}

# ============================ Direct calls listing ============================
def find_direct_calls_to_targets():
    hits = set()
    for name in TARGET_APIS.keys():
        iats = find_import_eas_by_name(name)
        for iat in iats:
            for xr in idautils.XrefsTo(iat):
                if idc.print_insn_mnem(xr.frm) == "call":
                    hits.add((name, xr.frm))
    return sorted(hits, key=lambda x:(x[0], x[1]))

# ============================ Handler call harvesting ============================
def find_handler_calls_near(f, site_ea, fwd_limit=80):
    calls = []
    ea = idc.next_head(site_ea); steps = 0
    while ea != idaapi.BADADDR and steps < fwd_limit and f.contains(ea):
        m = idc.print_insn_mnem(ea).lower()
        if m.startswith("j"):
            tgt = idc.get_operand_value(ea, 0)
            if seg_contains(tgt):
                c = tgt; inner = 0
                while inner < 24 and c != idaapi.BADADDR and f.contains(c):
                    mm = idc.print_insn_mnem(c).lower()
                    if mm == "call": calls.append(c); break
                    if mm in ("ret","retn"): break
                    if mm.startswith("j") and c != ea: break
                    c = idc.next_head(c); inner += 1
        if m == "call": calls.append(ea)
        if m in ("ret","retn"): break
        ea = idc.next_head(ea); steps += 1
    out = []
    seen = set()
    for ce in calls:
        if ce in seen: continue
        seen.add(ce)
        callee_ea = idc.get_operand_value(ce, 0) if idc.get_operand_type(ce,0)==idc.o_near else None
        out.append((ce, callee_ea, fn_name(callee_ea) if callee_ea else "indirect"))
    return out

# ============================ Device name resolution ============================
def _collect_unicode_literals():
    """Return {ea_of_buffer: decoded_wstring} for embedded UTF-16LE literals that look dev/links."""
    hits = {}
    for s in idautils.Strings():
        try:
            txt = str(s)
        except Exception:
            continue
        if any(p.lower() in txt.lower() for p in ["\\device\\", "\\dosdevices\\", "\\??\\", "global??"]):
            ea = int(s.ea)
            w = read_unicode_from(ea, 0x400)
            if w and any(w.lower().startswith(p) for p in ["\\device\\", "\\dosdevices\\", "\\??\\", "\\global??\\", "\\global??"]):
                hits[ea] = w
            else:
                if txt.startswith("\\"):
                    hits[ea] = txt
    return hits

def _unicode_arg_from_call(call_ea, reg_name):
    """Given a call site & arg reg, chase UNICODE_STRING or PWSTR buffer -> return text."""
    f = ida_funcs.get_func(call_ea)
    if not f: return None
    kind, val, _, _ = backtrack_reg_value(f, call_ea, reg_name, max_back=220)
    if kind == "imm" and val and seg_contains(val):
        us = read_unicode_string_struct(val)
        if us: return us
        lit = read_unicode_from(val, 0x800)
        if lit: return lit
    if kind == "stack":
        for ru in reversed(find_rtlinit_calls_in_func(f.start_ea)):
            if ru < call_ea:
                k2, v2, _, _ = backtrack_reg_value(f, ru, "rdx", max_back=160)
                if k2 == "imm" and v2 and seg_contains(v2):
                    s = read_unicode_from(v2, 0x800)
                    if s: return s
    return None

def _norm_user_doslink(s):
    """
    Map NT-style names to user-mode \\.\ links:
      \DosDevices\Foo  -> \\.\Foo
      \??\Foo          -> \\.\Foo
      GLOBAL??\Foo     -> \\.\Foo
    Return (user_path, nt_path) tuple where user_path may be None.
    """
    if not s: return (None, None)
    sl = s.replace("\\\\", "\\").strip()
    nt = sl
    user = None
    for pref in ["\\DosDevices\\", "\\??\\", "\\GLOBAL??\\", "\\GLOBAL??", "\\DosDevices"]:
        if sl.lower().startswith(pref.lower()):
            tail = sl[len(pref):].lstrip("\\")
            if tail:
                user = r"\\.\{}".format(tail)
            break
    return (user, nt)

def resolve_device_paths():
    """
    Discover user-mode device links and NT device names.
    Returns: {'user_links':[...], 'nt_devices':[...], 'raw': set([...])}
    """
    user_links = set()
    nt_devices = set()
    raw = set()

    # literals
    lit = _collect_unicode_literals()
    for _, s in lit.items():
        u, n = _norm_user_doslink(s)
        if u: user_links.add(u)
        if n and n.lower().startswith("\\device\\"): nt_devices.add(n)
        raw.add(s)

    # IoCreateSymbolicLink
    for api in ("IoCreateSymbolicLink",):
        for iat in find_import_eas_by_name(api):
            for xr in idautils.XrefsTo(iat):
                if idc.print_insn_mnem(xr.frm) != "call": continue
                link = _unicode_arg_from_call(xr.frm, "rcx")
                dev  = _unicode_arg_from_call(xr.frm, "rdx")
                for s in (link, dev):
                    if s: raw.add(s)
                u, _ = _norm_user_doslink(link)
                if u: user_links.add(u)
                if dev and dev.lower().startswith("\\device\\"): nt_devices.add(dev)

    # IoCreateDevice / IoCreateDeviceSecure -> device name in r8
    for api in ("IoCreateDevice", "IoCreateDeviceSecure"):
        for iat in find_import_eas_by_name(api):
            for xr in idautils.XrefsTo(iat):
                if idc.print_insn_mnem(xr.frm) != "call": continue
                dev = _unicode_arg_from_call(xr.frm, "r8")
                if dev:
                    raw.add(dev)
                    if dev.lower().startswith("\\device\\"): nt_devices.add(dev)

    # KMDF symbolic link & names
    for api in ("WdfDeviceCreateSymbolicLink",):
        for iat in find_import_eas_by_name(api):
            for xr in idautils.XrefsTo(iat):
                if idc.print_insn_mnem(xr.frm) != "call": continue
                link = _unicode_arg_from_call(xr.frm, "rdx")
                if link:
                    raw.add(link)
                    u, _ = _norm_user_doslink(link)
                    if u: user_links.add(u)

    for api in ("WdfDeviceInitAssignName",):
        for iat in find_import_eas_by_name(api):
            for xr in idautils.XrefsTo(iat):
                if idc.print_insn_mnem(xr.frm) != "call": continue
                dev = _unicode_arg_from_call(xr.frm, "rdx")
                if dev:
                    raw.add(dev)
                    if dev.lower().startswith("\\device\\"): nt_devices.add(dev)

    # last chance normalize
    for s in list(raw):
        u, n = _norm_user_doslink(s)
        if u: user_links.add(u)
        if n and n.lower().startswith("\\device\\"): nt_devices.add(n)

    def score_user(u): return len(u or "zzzz")
    def score_nt(n):   return len(n or "zzzz")
    return {
        "user_links": sorted(user_links, key=score_user),
        "nt_devices": sorted(nt_devices, key=score_nt),
        "raw": raw
    }

# ============================ Header generation ============================
def make_ioctl_const_name(code):
    dev, func, meth, acc = decode_ioctl(code)
    return f"IOCTL_DEV_{dev:04X}_FUNC_{func:03X}_{METHOD_NAMES.get(meth,'M'+str(meth))}_{ACCESS_NAMES.get(acc,'ACC'+str(acc)).replace('|','_').replace(' ','')}"

def emit_header(ioctls, out_path=HEADER_OUT_PATH, device_candidates=None):
    """
    ioctls: iterable of integers (DWORD) recovered
    device_candidates: dict from resolve_device_paths() or None
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Choose a default device path
    user_paths = (device_candidates or {}).get("user_links", []) if device_candidates else []
    chosen = user_paths[0] if user_paths else DEFAULT_DEVICE_SYMLINK

    lines = []
    lines.append("#pragma once")
    lines.append("#ifndef XPMEM_USER_HPP")
    lines.append("#define XPMEM_USER_HPP")
    lines.append("")
    lines.append("// Auto-generated by xpmem_hunter v5.4 in IDA")
    lines.append(f"// Generated: {ts}")
    if user_paths:
        if len(user_paths) > 1:
            lines.append("// Device path candidates (in discovery order):")
            for u in user_paths:
                lines.append(f"//   {u}")
        else:
            lines.append(f"// Device path candidate: {user_paths[0]}")
    else:
        lines.append("// No device path discovered; edit kDefaultDevicePath manually.")
    lines.append("")
    lines.append("#include <windows.h>")
    lines.append("#include <string>")
    lines.append("#include <stdexcept>")
    lines.append("#include <vector>")
    lines.append("#include <type_traits>")
    lines.append("#include <cstdint>")
    lines.append("#include <array>")
    lines.append("")
    lines.append("#ifndef CTL_CODE")
    lines.append("  #define CTL_CODE(DeviceType, Function, Method, Access) \\")
    lines.append("      (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))")
    lines.append("#endif")
    lines.append("")
    lines.append("namespace xpmem {")
    lines.append("")
    lines.append(f'inline constexpr const wchar_t* kDefaultDevicePath = LR"({chosen})";')
    if user_paths and len(user_paths) > 1:
        lines.append("inline constexpr std::array<const wchar_t*, %d> kAllDevicePaths = {" % (len(user_paths)))
        for i,u in enumerate(user_paths):
            comma = "," if i < len(user_paths)-1 else ""
            lines.append(f'    LR"({u})"{comma}')
        lines.append("};")
    else:
        lines.append("inline constexpr std::array<const wchar_t*, 1> kAllDevicePaths = { kDefaultDevicePath };")
    lines.append("")

    # IOCTL constants
    lines.append("// ================= IOCTLs recovered =================")
    names = []
    for code in sorted(set(ioctls)):
        name = make_ioctl_const_name(code)
        names.append((name, code))
        # Also include decoded info as a comment
        dev, func, meth, acc = decode_ioctl(code)
        lines.append(f"constexpr DWORD {name} = 0x{code:08X}u;  // DEV=0x{dev:04X} FUNC=0x{func:03X} {METHOD_NAMES.get(meth,str(meth))} {ACCESS_NAMES.get(acc,str(acc))}")
    if not names:
        lines.append("// (none found in this run)")
    lines.append("")

    # error + device wrapper
    lines.append("// ================= Error helper =================")
    lines.append("struct win32_error : std::runtime_error {")
    lines.append("    DWORD code;")
    lines.append('    explicit win32_error(const char* where, DWORD ec = ::GetLastError())')
    lines.append('        : std::runtime_error(std::string(where) + " failed, GetLastError=" + std::to_string(ec)), code(ec) {}')
    lines.append("};")
    lines.append("")
    lines.append("// ================= RAII Device wrapper =================")
    lines.append("class Device {")
    lines.append("public:")
    lines.append("    Device() = default;")
    lines.append('    explicit Device(const std::wstring& path, DWORD access = GENERIC_READ | GENERIC_WRITE,')
    lines.append("                    DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE,")
    lines.append("                    DWORD flags = FILE_ATTRIBUTE_NORMAL) { open(path, access, share, flags); }")
    lines.append("    ~Device() { close(); }")
    lines.append("    Device(const Device&) = delete;")
    lines.append("    Device& operator=(const Device&) = delete;")
    lines.append("    Device(Device&& other) noexcept : h_(other.h_) { other.h_ = INVALID_HANDLE_VALUE; }")
    lines.append("    Device& operator=(Device&& other) noexcept { if (this!=&other){ close(); h_=other.h_; other.h_=INVALID_HANDLE_VALUE; } return *this; }")
    lines.append("    void open(const std::wstring& path, DWORD access = GENERIC_READ | GENERIC_WRITE, DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE, DWORD flags = FILE_ATTRIBUTE_NORMAL) {")
    lines.append("        close();")
    lines.append("        h_ = ::CreateFileW(path.c_str(), access, share, nullptr, OPEN_EXISTING, flags, nullptr);")
    lines.append("        if (h_ == INVALID_HANDLE_VALUE) throw win32_error(\"CreateFileW\");")
    lines.append("        path_ = path;")
    lines.append("    }")
    lines.append("    void close() noexcept { if (h_ != INVALID_HANDLE_VALUE) { ::CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; } }")
    lines.append("    bool valid() const noexcept { return h_ != INVALID_HANDLE_VALUE; }")
    lines.append("    HANDLE native() const noexcept { return h_; }")
    lines.append("    const std::wstring& path() const noexcept { return path_; }")
    lines.append("    DWORD ioctl(DWORD code, const void* inBuf, DWORD inSize, void* outBuf, DWORD outSize) const {")
    lines.append("        if (!valid()) throw win32_error(\"Device::ioctl (invalid handle)\", ERROR_INVALID_HANDLE);")
    lines.append("        DWORD bytes=0;")
    lines.append("        BOOL ok = ::DeviceIoControl(h_, code, const_cast<void*>(inBuf), inSize, outBuf, outSize, &bytes, nullptr);")
    lines.append("        if (!ok) throw win32_error(\"DeviceIoControl\");")
    lines.append("        return bytes;")
    lines.append("    }")
    lines.append("    template <typename TIn, typename TOut>")
    lines.append("    DWORD ioctl(DWORD code, const TIn& in, TOut& out) const {")
    lines.append("        static_assert(std::is_trivially_copyable_v<TIn>,  \"TIn must be trivially copyable\");")
    lines.append("        static_assert(std::is_trivially_copyable_v<TOut>, \"TOut must be trivially copyable\");")
    lines.append("        return ioctl(code, &in, sizeof(TIn), &out, sizeof(TOut));")
    lines.append("    }")
    lines.append("    template <typename TIn>")
    lines.append("    std::vector<std::byte> ioctl_outvec(DWORD code, const TIn& in, size_t out_bytes) const {")
    lines.append("        static_assert(std::is_trivially_copyable_v<TIn>, \"TIn must be trivially copyable\");")
    lines.append("        std::vector<std::byte> out(out_bytes);")
    lines.append("        DWORD got = ioctl(code, &in, sizeof(TIn), out.data(), static_cast<DWORD>(out.size()));")
    lines.append("        out.resize(got); return out;")
    lines.append("    }")
    lines.append("    std::vector<std::byte> ioctl_raw(DWORD code, const void* inBuf, size_t inSize, size_t out_bytes) const {")
    lines.append("        std::vector<std::byte> out(out_bytes);")
    lines.append("        DWORD got = ioctl(code, inBuf, static_cast<DWORD>(inSize), out.data(), static_cast<DWORD>(out.size()));")
    lines.append("        out.resize(got); return out;")
    lines.append("    }")
    lines.append("private:")
    lines.append("    HANDLE h_ = INVALID_HANDLE_VALUE;")
    lines.append("    std::wstring path_;")
    lines.append("};")
    lines.append("")
    lines.append("// Try opening any discovered device path; returns a valid Device or throws after last failure.")
    lines.append("inline Device try_open_any(DWORD access = GENERIC_READ | GENERIC_WRITE, DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE, DWORD flags = FILE_ATTRIBUTE_NORMAL) {")
    lines.append("    for (auto wpath : kAllDevicePaths) {")
    lines.append("        try {")
    lines.append("            Device d(std::wstring(wpath), access, share, flags);")
    lines.append("            return d;")
    lines.append("        } catch (const win32_error&) {")
    lines.append("            // try next")
    lines.append("        }")
    lines.append("    }")
    lines.append("    // last resort: default path (even if already in list)")
    lines.append("    Device d(std::wstring(kDefaultDevicePath), access, share, flags);")
    lines.append("    return d;")
    lines.append("}")
    lines.append("")
    lines.append("// ================= Example payload scaffolding =================")
    lines.append("#pragma pack(push, 1)")
    lines.append("struct XpMemGenericIn {")
    lines.append("    std::uint64_t src_pid{0};")
    lines.append("    std::uint64_t dst_pid{0};")
    lines.append("    std::uint64_t src_addr{0};")
    lines.append("    std::uint64_t dst_addr{0};")
    lines.append("    std::uint32_t size{0};")
    lines.append("    std::uint32_t flags{0};")
    lines.append("};")
    lines.append("struct XpMemGenericOut {")
    lines.append("    std::uint32_t status{0};")
    lines.append("    std::uint32_t bytes_transferred{0};")
    lines.append("    std::uint64_t reserved{0};")
    lines.append("};")
    lines.append("#pragma pack(pop)")
    lines.append("")
    lines.append("// ================= Convenience wrappers for recovered IOCTLs =================")
    for name, code in names:
        lines.append(f"inline DWORD ioctl_{name.lower()}(Device& dev, const void* inBuf, DWORD inSize, void* outBuf, DWORD outSize) {{")
        lines.append(f"    return dev.ioctl({name}, inBuf, inSize, outBuf, outSize);")
        lines.append("}")
        lines.append(f"inline DWORD ioctl_{name.lower()}(Device& dev, const XpMemGenericIn& in, XpMemGenericOut& out) {{")
        lines.append(f"    return dev.ioctl({name}, in, out);")
        lines.append("}")
    if not names:
        lines.append("// (no wrappers emitted — no IOCTLs found)")
    lines.append("")
    lines.append("// ================= Discovery table =================")
    lines.append("struct IoctlDesc { DWORD code; const char* name; const char* method; const char* access; };")
    lines.append("inline std::vector<IoctlDesc> known_ioctls() {")
    lines.append("    std::vector<IoctlDesc> v;")
    for name, code in names:
        dev, func, meth, acc = decode_ioctl(code)
        lines.append(f'    v.push_back({{ {name}, "{name}", "{METHOD_NAMES.get(meth,str(meth))}", "{ACCESS_NAMES.get(acc,str(acc))}" }});')
    lines.append("    return v;")
    lines.append("}")
    lines.append("")
    lines.append("} // namespace xpmem")
    lines.append("#endif // XPMEM_USER_HPP")

    txt = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(txt)
    return os.path.abspath(out_path)

# ============================ Main ============================
def main():
    print("[*] Cross-process memory hunter v5.4: IOCTL flow + IRP-walk + handlers + indirect resolution + memmove direction + cross-callee map + protections + device discovery + header export")

    direct = find_direct_calls_to_targets()
    if direct:
        print(f"[+] Direct calls found: {len(direct)}")
        for name, ea in direct:
            f = ida_funcs.get_func(ea)
            print(f"  - {name} call at 0x{ea:X} in {fn_name(f.start_ea) if f else 'n/a'}")
    else:
        print("[i] No direct calls to target APIs found")

    mm_calls = find_mmgsra_calls()
    dyn_map = {nm: {'slots': [], 'calls': [], 'callers': set()} for nm in TARGET_APIS.keys()}
    resolved_any = False
    if mm_calls:
        print(f"[+] Found {len(mm_calls)} MmGetSystemRoutineAddress call site(s)")
    else:
        print("[i] No calls to MmGetSystemRoutineAddress found")

    for call_ea in mm_calls:
        name, how = recover_name_for_mmgsra_call(call_ea)
        f = ida_funcs.get_func(call_ea); fnea = f.start_ea if f else None
        print(f"  - MmGetSystemRoutineAddress at 0x{call_ea:X} in {fn_name(fnea) if fnea else 'n/a'} target={name!r} via {how}")
        if not name: continue
        name = name.strip()
        if name not in TARGET_APIS: continue
        resolved_any = True
        slots = scan_forward_for_saved_fp(call_ea, max_fwd=40)
        if not slots: print("      [i] no global slot store of RAX observed near this site")
        for s in slots:
            print(f"      [slot] [{s:#x}] written here")
            dyn_map[name]['slots'].append((s, fnea))
            for ce in find_calls_through_slot(s):
                dyn_map[name]['calls'].append(ce)
                cfn = ida_funcs.get_func(ce)
                if cfn: dyn_map[name]['callers'].add(cfn.start_ea)

    funcs_of_interest = set()
    for _, ea in direct:
        f = ida_funcs.get_func(ea)
        if f: funcs_of_interest.add(f.start_ea)
    for nm, info in dyn_map.items():
        funcs_of_interest |= info['callers']
    more = set()
    for fea in list(funcs_of_interest):
        more |= get_callers(fea, max_depth=1)
    funcs_of_interest |= more

    dir_summary = {}
    ioctl_sites_by_func = {}
    ioctl_all = set()

    for fea in sorted(funcs_of_interest):
        a = analyze_direction_in_func(fea)
        mp = find_real_ioctls_in_func(fea)
        if not mp: mp = find_ioctls_via_irp_walk(fea)
        if mp:
            ioctl_sites_by_func[fea] = mp
            for k in mp.keys(): ioctl_all.add(k)
        r = len(a["read"]) > 0; w = len(a["write"]) > 0
        cls = "READ+WRITE" if (r and w) else ("WRITE" if w else ("READ" if r else "UNKNOWN"))
        dir_summary[fea] = {"class": cls, "analysis": a}

    print("\n================ RESULTS ================\n")

    if direct:
        print("[Direct target calls]")
        for name, ea in direct:
            f = ida_funcs.get_func(ea)
            print(f"  {name}: call at 0x{ea:X} in {fn_name(f.start_ea) if f else 'n/a'}")
        print("")

    if resolved_any:
        print("[Dynamic target resolution and call-through]")
        for nm, info in dyn_map.items():
            if not info['slots'] and not info['calls']: continue
            print(f"  {nm}:")
            for slot, setter in info['slots']:
                print(f"    slot [{slot:#x}] set in {fn_name(setter)} @ 0x{setter:X}")
                for ce in find_calls_through_slot(slot):
                    cfn = ida_funcs.get_func(ce)
                    print(f"      call via slot at 0x{ce:X} in {fn_name(cfn.start_ea) if cfn else 'n/a'}")
        print("")
    else:
        print("[i] No dynamic resolution of target names recovered")

    if dir_summary:
        print("[Direction indicators per function]")
        for fea, data in sorted(dir_summary.items(), key=lambda x:x[0]):
            a = data["analysis"]
            print(f"  {fn_name(fea)} @ 0x{fea:X}  => {data['class']}")
            if a["apis"]:
                apis = ", ".join(f"{k}({len(v)})" for k,v in a["apis"].items() if v)
                print(f"    apis: {apis}")
            if a["map_prot"]:
                for call_ea, prot in a["map_prot"]:
                    print(f"    Zw/MmMapViewOfSection @ 0x{call_ea:X} -> {prot}")
            if a["mdl"]:
                for call_ea, op in a["mdl"]:
                    print(f"    MmProbeAndLockPages @ 0x{call_ea:X} -> {op}")
            if a["read"]:
                print("    read_hits:");  [print(f"      - 0x{ea:X}") for ea in a["read"]]
            if a["write"]:
                print("    write_hits:"); [print(f"      - 0x{ea:X}") for ea in a["write"]]
        print("")

    if ioctl_sites_by_func:
        print("[IOCTLs -> candidate handlers (with indirect resolution + memmove direction)]")
        for fea, mp in sorted(ioctl_sites_by_func.items(), key=lambda x:x[0]):
            print(f"  {fn_name(fea)} @ 0x{fea:X}")
            f = ida_funcs.get_func(fea)
            moves = classify_memmoves_with_context(fea)
            moves_by_ea = {m["call"]: m for m in moves}
            for v, sites in sorted(mp.items(), key=lambda x:x[0]):
                dev, func, meth, acc = decode_ioctl(v)
                print(f"    {fmt_ioctl(v)}")
                for site in sorted(set(sites)):
                    print(f"      compare/switch @ 0x{site:X}")
                    handlers = find_handler_calls_near(f, site)
                    if handlers:
                        for ce, callee, nm in handlers:
                            if nm == "indirect":
                                tgt, how, aux = resolve_indirect_call(ce)
                                if tgt:
                                    nm2 = fn_name(tgt)
                                    print(f"        call @ 0x{ce:X} -> {nm2} (0x{tgt:X})  [{how}]")
                                else:
                                    if aux and isinstance(aux,int):
                                        print(f"        call @ 0x{ce:X} -> [indirect via {how} @{aux:#x}]")
                                    else:
                                        print(f"        call @ 0x{ce:X} -> [indirect via {how}]")
                            else:
                                print(f"        call @ 0x{ce:X} -> {nm} (0x{callee:X})")
                            mv = moves_by_ea.get(ce)
                            if mv:
                                src_user    = mv.get('src_is_user', False)
                                dest_user   = mv.get('dest_is_user', False)
                                src_remote  = mv.get('src_is_remote', False)
                                dest_remote = mv.get('dest_is_remote', False)
                                src_mdl     = mv.get('src_is_mdl', False)
                                dest_mdl    = mv.get('dest_is_mdl', False)
                                direction   = mv.get('direction', 'unknown')
                                line = f"          memmove dir: {direction}  (src_user={src_user}, dest_user={dest_user}, src_remote={src_remote}, dest_remote={dest_remote}, src_mdl={src_mdl}, dest_mdl={dest_mdl})"
                                if direction == "unknown" and meth == 1:
                                    if dest_mdl and not src_mdl:  line += "  [hint: IN_DIRECT -> likely READ]"
                                    elif src_mdl and not dest_mdl: line += "  [hint: IN_DIRECT -> likely WRITE]"
                                print(line)
                    else:
                        print("        [i] no nearby call found (fallthrough/inline?)")
    else:
        print("[i] No IOCTLs recovered via IoStack/IRP walk")

    # ================= Device discovery + Header export =================
    print("\n=============== SUMMARY ================")
    if ioctl_all:
        for v in sorted(ioctl_all):
            print(f"- {fmt_ioctl(v)}")
    else:
        print("No IOCTLs found via data-flow.")

    devinfo = resolve_device_paths()
    if devinfo["user_links"]:
        print("\n[+] Device link candidates (user-mode):")
        for u in devinfo["user_links"]:
            print(f"    {u}")
    if devinfo["nt_devices"]:
        print("[+] NT device name candidates:")
        for n in devinfo["nt_devices"]:
            print(f"    {n}")

    try:
        outp = emit_header(sorted(ioctl_all), HEADER_OUT_PATH, device_candidates=devinfo)
        print(f"\n[+] C++ header emitted: {outp}")
        chosen = devinfo["user_links"][0] if devinfo["user_links"] else DEFAULT_DEVICE_SYMLINK
        print(f"    -> kDefaultDevicePath set to: {chosen}")
    except Exception as e:
        print(f"[!] Failed to write header: {e}")

    print("")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[error] {e}")
