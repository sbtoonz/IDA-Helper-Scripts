# xpmem_rw_587_fix.py — R/W hunter v5.8.7 (IDA 7.6–8.x)
# - Generic IOCTL dispatcher discovery + R/W-adjacent call co-occurrence
# - Robust strings/segments API usage across IDA 7.6–8.x
# - FIX: define/select default device path in emit_header()
# - Emits <input>_user.hpp (device paths + selected IOCTLs)

import idaapi, idautils, idc
import ida_funcs, ida_name, ida_bytes, ida_ua, ida_search, ida_nalt

OUT_HPP = (ida_nalt.get_input_file_path() or "xpmem").rsplit('.',1)[0] + "_user.hpp"
MAX_CALL_XREFS = 2000
DISPATCH_MIN_IOCTL_IMMS = 6  # threshold to call a function "dispatcher-like"

TARGET_APIS = [
    "memmove", "memcpy", "RtlCopyMemory",
    "ZwMapViewOfSection", "MmMapViewOfSection",
    "ZwUnmapViewOfSection", "MmUnmapViewOfSection",
    "MmCopyVirtualMemory",
    "ProbeForRead", "ProbeForWrite",
    "PsLookupProcessByProcessId",
]

def ea_name(ea):
    return ida_name.get_ea_name(ea) or ida_funcs.get_func_name(ea) or "sub_%X" % ea

# ---- strings ---------------------------------------------------------------

def _all_ida_strings():
    s = idautils.Strings()
    try:
        s.setup(); s.refresh()
    except Exception:
        pass
    for si in s:
        try:
            yield str(si)
        except Exception:
            continue

def _ascii_ok(s):
    try:
        for ch in s:
            o = ord(ch)
            if ch == '\\':
                continue
            if not (32 <= o < 127):
                return False
        return True
    except Exception:
        return False

def discover_device_strings():
    devs = set()
    for s in _all_ida_strings():
        if not s:
            continue
        s2 = s.replace("\x00", " ")
        if "\\\\.\\" in s2:
            for tok in s2.split():
                if tok.startswith("\\\\.\\" ):
                    devs.add(tok)
        if "\\Device\\" in s2:
            for tok in s2.split():
                if tok.startswith("\\Device\\"):
                    devs.add(tok)
    out = []
    for d in sorted(devs):
        if 1 <= len(d) <= 120 and _ascii_ok(d):
            out.append(d)
    return out

def normalize_um_path(p):
    """Return a user-mode CreateFile path if possible."""
    if p.startswith("\\\\.\\" ):
        return p
    if p.startswith("\\Device\\"):
        tail = p.split("\\")[-1]
        if tail:
            return "\\\\.\\%s" % tail
    return p

def choose_default_path(dev_paths):
    # Prefer explicit user-mode paths:
    for p in dev_paths:
        if p.startswith("\\\\.\\" ):
            return p
    # Otherwise convert any NT path:
    for p in dev_paths:
        if p.startswith("\\Device\\"):
            return normalize_um_path(p)
    # Fallback if nothing found:
    return "\\\\.\\EBIoDispatch"

# ---- call/xref helpers -----------------------------------------------------

def _calls_to(ea_target):
    res=[]
    # Try the fast path
    try:
        for frm in idautils.CodeRefsTo(ea_target, 0):
            res.append(frm)
            if len(res) > MAX_CALL_XREFS: break
        if res: return res
    except Exception:
        pass
    # Fallback: generic XrefsTo (older IDA flavors)
    try:
        for xr in idautils.XrefsTo(ea_target, 0):
            try:
                res.append(xr.frm)
                if len(res) > MAX_CALL_XREFS: break
            except Exception:
                continue
    except Exception:
        pass
    return res

def _enum_import_eas_by_name(want_names):
    want = set(want_names)
    hits = []
    # Named thunks / already-resolved symbols
    for name in want:
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea != idaapi.BADADDR:
            hits.append((name, ea))
    # Import tables
    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        def cb(ea, name, ordno):
            if not name:
                return True
            if name in want:
                hits.append((name, ea))
            return True
        ida_nalt.enum_import_names(i, cb)
    # Dedup
    seen=set(); out=[]
    for n,ea in hits:
        k=(n,ea)
        if k in seen: continue
        seen.add(k); out.append((n,ea))
    return out

def heuristic_rw_api_hits():
    hits=[]
    for name, ea_imp in _enum_import_eas_by_name(TARGET_APIS):
        for callsite in _calls_to(ea_imp):
            f = ida_funcs.get_func(callsite)
            if not f: continue
            hits.append((name, callsite, f.start_ea))
    # Also look for local memmove/memcpy by name
    for name in ["memmove", "memcpy", "RtlCopyMemory"]:
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea != idaapi.BADADDR:
            for callsite in _calls_to(ea):
                f = ida_funcs.get_func(callsite)
                if not f: continue
                hits.append((name, callsite, f.start_ea))
    # Dedup
    seen=set(); out=[]
    for n,c,fs in hits:
        k=(n,c,fs)
        if k in seen: continue
        seen.add(k); out.append((n,c,fs))
    return out

# ---- IOCTL helpers ---------------------------------------------------------

def is_ioctl_like(v):
    if v < 0x10000 or v > 0xFFFFFFFF:
        return False
    method = v & 0x3
    access = (v >> 14) & 0x3
    func   = (v >> 2) & 0xFFF
    dev    = (v >> 16) & 0xFFFF
    if method > 3 or access > 3:
        return False
    if func == 0 or dev == 0:
        return False
    return True

def decode_method_access(v):
    method = ["METHOD_BUFFERED","METHOD_IN_DIRECT","METHOD_OUT_DIRECT","METHOD_NEITHER"][v & 3]
    accmap = {0:"FILE_ANY_ACCESS",1:"FILE_READ_ACCESS",2:"FILE_WRITE_ACCESS",3:"FILE_READ_ACCESS|FILE_WRITE_ACCESS"}
    access = accmap.get((v>>14)&3, "FILE_ANY_ACCESS")
    return method, access

def gather_immediates_and_calls(f):
    imms=set(); calls=set()
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            # immediates
            for op in insn.ops:
                if op.type == ida_ua.o_imm:
                    try:
                        v = int(op.value) & 0xFFFFFFFF
                    except Exception:
                        continue
                    if is_ioctl_like(v):
                        imms.add(v)
            # calls (follow code refs)
            if idaapi.is_call_insn(ea):
                try:
                    for to in idautils.CodeRefsFrom(ea, False):
                        calls.add(to)
                except Exception:
                    pass
        ea += idaapi.get_item_size(ea)
    return imms, calls

def find_dispatchers_and_map_rw():
    # 1) R/W-adjacent functions (calls to interesting APIs)
    rw_hits = heuristic_rw_api_hits()
    rw_funcs = { fs for (_n,_c,fs) in rw_hits }
    # 2) Scan all funcs for IOCTL-like immediates + outgoing calls
    candidates=[]
    perfunc = {}  # fstart -> (ioctls, calls)
    for fstart in idautils.Functions():
        f = ida_funcs.get_func(fstart)
        if not f: continue
        ioctls, calls = gather_immediates_and_calls(f)
        if len(ioctls) >= DISPATCH_MIN_IOCTL_IMMS:
            candidates.append(fstart)
        perfunc[fstart] = (ioctls, calls)
    # 3) Keep candidates that call any rw-adjacent func
    dispatchers=[]
    rw_ioctls=set()
    for fstart in candidates:
        ioctls, calls = perfunc.get(fstart, (set(), set()))
        if not ioctls: continue
        if any((ct in rw_funcs) for ct in calls):
            dispatchers.append(fstart)
            rw_ioctls.update(ioctls)
    # Fallback: choose the single func with most IOCTL immediates
    if not dispatchers and candidates:
        best = max(candidates, key=lambda ea: len(perfunc[ea][0]))
        dispatchers = [best]
        rw_ioctls.update(perfunc[best][0])
    return dispatchers, rw_ioctls, rw_hits

# ---- header emit -----------------------------------------------------------

def emit_header(dev_paths, ioctls):
    # Normalize + dedupe paths; ensure default is present
    dev_paths = [p for p in dev_paths if p]  # drop empties
    dev_paths = sorted(set(dev_paths))
    default = choose_default_path(dev_paths)
    if default not in dev_paths:
        dev_paths = [default] + dev_paths
    # Emit
    with open(OUT_HPP, "w", encoding="utf-8") as fp:
        fp.write("// Generated by xpmem_rw_587_fix.py\n#pragma once\n"
                 "#include <cstdint>\n#include <string>\n#include <vector>\n\n"
                 "namespace xpmem {\n")
        fp.write('static const wchar_t* kDefaultDevicePath = LR"(%s)";\n' % default)
        fp.write("static const std::vector<std::wstring> kAllDevicePaths = {\n")
        for p in dev_paths:
            fp.write('  LR"(%s)",\n' % p)
        fp.write("};\n\n")
        fp.write("struct ioctl_desc { uint32_t code; const char* name; const char* method; "
                 "const char* access; const char* tag; };\n")
        if ioctls:
            fp.write("inline std::vector<ioctl_desc> known_ioctls() { return {\n")
            for code in sorted(ioctls):
                method, access = decode_method_access(code)
                fp.write('  { 0x%08X, "IOCTL_%08X", "%s", "%s", "rw-adj" },\n'
                         % (code, code, method, access))
            fp.write("}; }\n")
        else:
            fp.write("inline std::vector<ioctl_desc> known_ioctls() { return {}; }\n")
        fp.write("} // namespace xpmem\n")

# ---- main ------------------------------------------------------------------

def main():
    print("[*] R/W hunter v5.8.7 — generic dispatcher + R/W IOCTL selection")

    devs = discover_device_strings()
    if devs:
        print("[+] Device string candidates (%d):" % len(devs))
        for d in devs: print("    %s" % d)

    dispatchers, rw_codes, rw_hits = find_dispatchers_and_map_rw()

    if rw_hits:
        print("[+] Direct calls found: %d" % len(rw_hits))
        for n,call,fs in rw_hits:
            print("  - %s call at 0x%X in %s" % (n, call, ea_name(fs)))
    else:
        print("[i] No direct memmove/ZwMapView/MmCopyVirtualMemory calls recovered.")

    if dispatchers:
        print("[i] Dispatcher candidate(s):")
        for ea in dispatchers:
            print("   - %s @ 0x%X" % (ea_name(ea), ea))
    else:
        print("[!] No dispatcher with IOCTL mapping found.")

    # Opportunistic add: if the 0x426F6541 code bytes exist anywhere, include it
    ACPI_CODE = 0x426F6541
    sig = "%02X %02X %02X %02X" % (ACPI_CODE & 0xFF, (ACPI_CODE>>8)&0xFF, (ACPI_CODE>>16)&0xFF, (ACPI_CODE>>24)&0xFF)
    found_acpi = False
    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        ea = ida_search.find_binary(seg_start, seg_end, sig, 16, ida_search.SEARCH_DOWN)
        if ea != idaapi.BADADDR:
            found_acpi = True
            break
    if found_acpi:
        rw_codes.add(ACPI_CODE)

    emit_header(devs, rw_codes)

    print("\n=== SUMMARY ===")
    print("[*] %d direct R/W-adjacent calls" % len(rw_hits))
    if dispatchers:
        print("[*] %d dispatcher(s) and %d R/W-relevant IOCTL code(s) selected" % (len(dispatchers), len(rw_codes)))
    else:
        print("[i] No dispatcher found; header contains device paths%s." % (" + ACPI" if found_acpi else ""))

if __name__ == "__main__":
    main()
