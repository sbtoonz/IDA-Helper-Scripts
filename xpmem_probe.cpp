// xpmem_probe.cpp v1.4.2 — fixed duplicate struct definition
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <memory>
#include <cstring>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

#if __has_include("xpmem_rw.hpp")
  #include "xpmem_rw.hpp"
  namespace xh = xpmem;
#elif __has_include("xpmem_user.hpp")
  #include "xpmem_user.hpp"
  namespace xh = xpmem;
#else
  namespace xh {
    struct ioctl_desc { DWORD code; const char* name; const char* method; const char* access; const char* tag; };
    inline std::vector<ioctl_desc> known_ioctls() { return {}; }
    static const wchar_t* kDefaultDevicePath = L"\\\\.\\EBIoDispatch";
    static const std::vector<std::wstring> kAllDevicePaths = { std::wstring(L"\\\\.\\EBIoDispatch") };
  }
#endif

static std::string hex32(DWORD v){ std::ostringstream o; o<<"0x"<<std::hex<<std::uppercase<<std::setw(8)<<std::setfill('0')<<v; return o.str(); }
static void hexdump(const void* p, size_t n, size_t w=16){
    auto* b = static_cast<const unsigned char*>(p);
    for(size_t i=0;i<n;i+=w){
        std::cout<<"  "<<std::setw(6)<<std::setfill(' ')<<std::dec<<i<<"  ";
        size_t j=0;
        for(; j<w && i+j<n; ++j) std::cout<<std::hex<<std::uppercase<<std::setw(2)<<std::setfill('0')<<unsigned(b[i+j])<<' ';
        for(; j<w; ++j) std::cout<<"   ";
        std::cout<<" ";
        for(j=0; j<w && i+j<n; ++j){ unsigned char c=b[i+j]; std::cout<<(std::isprint(c)?char(c):'.'); }
        std::cout<<"\n";
    }
}
static bool parse_size(const std::string& s, size_t& out){
    char* e=nullptr; unsigned long long v=0;
    if(s.size()>2 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) v=strtoull(s.c_str(), &e, 16);
    else v=strtoull(s.c_str(), &e, 10);
    if(!e||*e) return false; out=size_t(v); return true;
}
static bool parse_hex_bytes(const std::string& sIn, std::vector<uint8_t>& out){
    out.clear(); std::string s; s.reserve(sIn.size());
    for(char c: sIn) if(!std::isspace((unsigned char)c)) s.push_back(c);
    if(s.size()%2) return false;
    auto hx=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    for(size_t i=0;i<s.size();i+=2){ int a=hx(s[i]),b=hx(s[i+1]); if(a<0||b<0) return false; out.push_back(uint8_t((a<<4)|b)); }
    return true;
}
static void append_wstr_null(const std::wstring& ws, std::vector<uint8_t>& out){
    out.reserve(out.size()+(ws.size()+1)*2);
    for(wchar_t ch: ws){ out.push_back(uint8_t(ch&0xFF)); out.push_back(uint8_t((ch>>8)&0xFF)); }
    out.push_back(0); out.push_back(0);
}

static void enable_priv(LPCWSTR name){
    HANDLE tok{};
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) return;
    LUID luid{};
    if(!LookupPrivilegeValueW(nullptr, name, &luid)){ CloseHandle(tok); return; }
    TOKEN_PRIVILEGES tp{1, {{luid, SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(tok);
}

// ---- OM scanning
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
typedef struct _UNICODE_STRING2 { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING2, *PUNICODE_STRING2;
typedef struct _OBJECT_ATTRIBUTES2 { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING2 ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES2, *POBJECT_ATTRIBUTES2;
typedef struct _OBJECT_DIRECTORY_INFORMATION { UNICODE_STRING2 Name; UNICODE_STRING2 TypeName; } OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES  ((NTSTATUS)0x8000001AL)
#endif
static void RtlInitUnicodeString2(PUNICODE_STRING2 u, PCWSTR s){ if(!s){ u->Length=0; u->MaximumLength=0; u->Buffer=nullptr; return;} size_t n=wcslen(s); if(n>0x7FFF) n=0x7FFF; u->Length=USHORT(n*2); u->MaximumLength=USHORT((n+1)*2); u->Buffer=(PWSTR)s; }
static void InitializeObjectAttributes2(POBJECT_ATTRIBUTES2 p, PUNICODE_STRING2 n, ULONG a, HANDLE r, PVOID sd){ p->Length=sizeof(*p); p->RootDirectory=r; p->ObjectName=n; p->Attributes=a; p->SecurityDescriptor=sd; p->SecurityQualityOfService=nullptr; }
typedef NTSTATUS (NTAPI *NtOpenDirectoryObject_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES2);
typedef NTSTATUS (NTAPI *NtQueryDirectoryObject_t)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

struct OmEntry { std::wstring name; std::wstring type; };
static bool om_list_device(std::vector<OmEntry>& out, std::wstring* err=nullptr){
    out.clear();
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if(!ntdll){ if(err)*err=L"GetModuleHandle(ntdll) failed"; return false; }
    auto pOpen  = reinterpret_cast<NtOpenDirectoryObject_t>(GetProcAddress(ntdll, "NtOpenDirectoryObject"));
    auto pQuery = reinterpret_cast<NtQueryDirectoryObject_t>(GetProcAddress(ntdll, "NtQueryDirectoryObject"));
    if(!pOpen || !pQuery){ if(err)*err=L"Nt*DirectoryObject missing"; return false; }
    UNICODE_STRING2 us; RtlInitUnicodeString2(&us, L"\\Device");
    OBJECT_ATTRIBUTES2 oa; InitializeObjectAttributes2(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE hDir = nullptr; NTSTATUS st = pOpen(&hDir, DIRECTORY_QUERY, &oa);
    if(!NT_SUCCESS(st)){ if(err)*err=L"NtOpenDirectoryObject failed"; return false; }
    std::vector<char> buf(16*1024);
    ULONG ctx = 0, retLen = 0; bool first = TRUE;
    for(;;){
        st = pQuery(hDir, buf.data(), (ULONG)buf.size(), TRUE, first, &ctx, &retLen);
        first = FALSE;
        if(st == STATUS_NO_MORE_ENTRIES){ CloseHandle(hDir); return true; }
        if(!NT_SUCCESS(st)){ if(err)*err=L"NtQueryDirectoryObject failed"; CloseHandle(hDir); return false; }
        auto* odi = reinterpret_cast<OBJECT_DIRECTORY_INFORMATION*>(buf.data());
        std::wstring n, t;
        if(odi->Name.Buffer && odi->Name.Length)     n.assign(odi->Name.Buffer, odi->Name.Length/2);
        if(odi->TypeName.Buffer && odi->TypeName.Length) t.assign(odi->TypeName.Buffer, odi->TypeName.Length/2);
        out.push_back({n,t});
    }
}

// ---- 0x22E090 pack (0x204 path + 0x104 ACPI block) — single definition here
#pragma pack(push,1)
struct ACPI_EVAL_INPUT_MIN { ULONG Signature; ULONG MethodName; };
#pragma pack(pop)

static ULONG fourcc4(const std::string& s4){
    char a=' ',b=' ',c=' ',d=' '; if(s4.size()>0)a=s4[0]; if(s4.size()>1)b=s4[1]; if(s4.size()>2)c=s4[2]; if(s4.size()>3)d=s4[3];
    return ULONG(uint8_t(a) | (uint32_t(uint8_t(b))<<8) | (uint32_t(uint8_t(c))<<16) | (uint32_t(uint8_t(d))<<24));
}
static std::vector<uint8_t> make_22090_input(const std::wstring& devPath, const std::string& method4){
    const size_t STR_REGION=0x204, ACPI_IN_SZ=0x104;
    std::vector<uint8_t> buf(STR_REGION+ACPI_IN_SZ, 0);
    std::vector<uint8_t> s; append_wstr_null(devPath, s);
    if(s.size()>STR_REGION) std::copy(s.begin(), s.begin()+STR_REGION, buf.begin());
    else std::copy(s.begin(), s.end(), buf.begin());
    ACPI_EVAL_INPUT_MIN in{}; in.Signature=0x41435049; in.MethodName=fourcc4(method4);
    std::memcpy(buf.data()+STR_REGION, &in, sizeof(in));
    return buf;
}

// ---- header bridge
struct MyIoctl { DWORD code{}; std::string name, method, access, tag; };
template<typename T>
auto cvt_desc_impl(const T& d, int) -> decltype((void)d.tag, MyIoctl{}) { return MyIoctl{ d.code, d.name?d.name:"", d.method?d.method:"", d.access?d.access:"", d.tag?d.tag:"" }; }
template<typename T> MyIoctl cvt_desc_impl(const T& d, long) { return MyIoctl{ d.code, d.name?d.name:"", d.method?d.method:"", d.access?d.access:"", "" }; }
template<typename T> MyIoctl to_my(const T& d){ return cvt_desc_impl(d,0); }
static std::vector<MyIoctl> load_known_ioctls(){ auto raw=xh::known_ioctls(); std::vector<MyIoctl> out; out.reserve(raw.size()); for(auto& e: raw) out.push_back(to_my(e)); return out; }
static std::vector<std::wstring> load_device_paths(){
    std::vector<std::wstring> v;
#if __has_include("xpmem_rw.hpp") || __has_include("xpmem_user.hpp")
    if(!xh::kAllDevicePaths.empty()) v.assign(xh::kAllDevicePaths.begin(), xh::kAllDevicePaths.end());
    else if(xh::kDefaultDevicePath && *xh::kDefaultDevicePath) v.emplace_back(xh::kDefaultDevicePath);
#else
    v.emplace_back(L"\\\\.\\EBIoDispatch");
#endif
    if(v.empty()) v.emplace_back(L"\\\\.\\EBIoDispatch");
    return v;
}

// ---- CLI
struct Args{
    bool show_list=false, open_dev=false, do_poke=false, dump_out=false, dry_run=false;
    bool do_scan=false, do_hunt22090=false;
    std::wstring scan_filter, hunt_filter, deviceW;
    std::vector<DWORD> codes;
    size_t in_sz=0, out_sz=0; bool has_in=false, has_out=false;
    std::vector<uint8_t> in_seed;
    std::wstring wstr_seed;
    std::string acpi_method;

    bool parse(int argc, char** argv){
        for(int i=1;i<argc;++i){
            std::string t=argv[i];
            if(t=="--list") show_list=true;
            else if(t=="--open") open_dev=true;
            else if(t=="--poke") do_poke=true;
            else if(t=="--dump-out") dump_out=true;
            else if(t=="--dry-run") dry_run=true;
            else if(t=="--device" && i+1<argc){ std::string s=argv[++i]; deviceW.assign(s.begin(), s.end()); }
            else if(t=="--code" && i+1<argc){ size_t tmp=0; std::string v=argv[++i]; if(!parse_size(v,tmp)) return false; codes.push_back(DWORD(tmp)); }
            else if(t=="--in" && i+1<argc){ size_t tmp=0; if(!parse_size(argv[++i],tmp)) return false; in_sz=tmp; has_in=true; }
            else if(t=="--out" && i+1<argc){ size_t tmp=0; if(!parse_size(argv[++i],tmp)) return false; out_sz=tmp; has_out=true; }
            else if(t=="--in-hex" && i+1<argc){ std::vector<uint8_t> v; if(!parse_hex_bytes(argv[++i],v)) return false; in_seed=std::move(v); }
            else if(t=="--wstr" && i+1<argc){ std::string s=argv[++i]; wstr_seed.assign(s.begin(), s.end()); }
            else if(t=="--preset" && i+1<argc){ std::string w=argv[++i]; std::transform(w.begin(), w.end(), w.begin(), [](unsigned char c){return (char)std::tolower(c);});
                if(w=="acpi") wstr_seed=L"\\Device\\ACPI"; else if(w=="ksecdd") wstr_seed=L"\\Device\\KsecDD"; else if(w=="null") wstr_seed=L"\\Device\\Null"; else return false; }
            else if(t=="--acpi-method" && i+1<argc){ acpi_method=argv[++i]; if(acpi_method.size()>4) acpi_method.resize(4); while(acpi_method.size()<4) acpi_method.push_back(' '); }
            else if(t=="--scan-obj"){ do_scan=true; if(i+1<argc && argv[i+1][0] != '-') { std::string s=argv[++i]; scan_filter.assign(s.begin(), s.end()); } }
            else if(t=="--hunt-22090"){ do_hunt22090=true; if(i+1<argc && argv[i+1][0] != '-') { std::string s=argv[++i]; hunt_filter.assign(s.begin(), s.end()); } }
            else { std::cerr<<"[?] Unknown or incomplete arg: "<<t<<"\n"; return false; }
        }
        return true;
    }
};

static void usage(){
    std::cout <<
R"(xpmem_probe.exe [--list] [--open] [--device "\\.\EBIoDispatch"]
                 [--poke --code 0x22E090
                        [--in N] [--in-hex "..."]
                        [--wstr "\Device\X"] [--preset acpi|ksecdd|null]
                        [--acpi-method _STA]
                        [--out N] [--dump-out] [--dry-run]]
                 [--scan-obj [filter]]
                 [--hunt-22090 [filter] --acpi-method _STA  [--out N] [--dump-out]]
)";
}

struct DevHandle{ HANDLE h=INVALID_HANDLE_VALUE; std::wstring path; ~DevHandle(){ if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);} };
static bool open_device(const std::wstring& p, DevHandle& out){
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(h==INVALID_HANDLE_VALUE){ std::wcerr<<L"[ERR] CreateFile "<<p<<L" -> GLE="<<GetLastError()<<L"\n"; return false; }
    out.h=h; out.path=p; std::wcout<<L"[+] Opened "<<p<<L"\n"; return true;
}
static bool devctl(HANDLE h, DWORD code, std::vector<uint8_t>& inout, std::vector<uint8_t>& outbuf, DWORD& br){
    LPVOID inP = inout.empty()? nullptr : inout.data();
    DWORD inL  = (DWORD)inout.size();
    LPVOID outP= outbuf.empty()? nullptr : outbuf.data();
    DWORD outL = (DWORD)outbuf.size();
    BOOL ok = DeviceIoControl(h, code, inP, inL, outP, outL, &br, nullptr);
    return ok!=FALSE;
}

int main(int argc, char** argv){
    enable_priv(L"SeDebugPrivilege");

    Args a; if(!a.parse(argc, argv) || argc==1){ usage(); return (argc==1)?0:2; }

    auto devpaths = load_device_paths();
    auto ioctls   = load_known_ioctls();

    if(a.show_list){
        std::cout<<"[i] Device path candidates ("<<devpaths.size()<<"):\n";
        for(auto& p: devpaths) std::wcout<<L"    "<<p<<L"\n";
        std::cout<<"[i] Known IOCTLs ("<<ioctls.size()<<"):\n";
        for(auto& d: ioctls){
            std::cout<<"  "<<hex32(d.code)<<"  "<<(d.name.empty()?"(unnamed)":d.name)<<"  "<<(d.method.empty()?"?":d.method)<<"  "<<(d.access.empty()?"":d.access);
            if(!d.tag.empty()) std::cout<<"  ["<<d.tag<<"]";
            std::cout<<"\n";
        }
        if(!a.open_dev && !a.do_poke && !a.do_scan && !a.do_hunt22090) return 0;
    }

    if(a.do_scan){
        std::vector<OmEntry> ents; std::wstring err;
        if(!om_list_device(ents, &err)) std::wcerr<<L"[ERR] OM scan failed: "<<err<<L"\n";
        std::wcout<<L"[i] \\Device entries ("<<ents.size()<<L")";
        if(!a.scan_filter.empty()) std::wcout<<L" filtered by '"<<a.scan_filter<<L"'";
        std::wcout<<L":\n";
        size_t shown=0;
        for(auto& e: ents){
            if(!a.scan_filter.empty()){
                std::wstring f=a.scan_filter, n=e.name, t=e.type;
                std::transform(f.begin(),f.end(),f.begin(),::towlower);
                std::transform(n.begin(),n.end(),n.begin(),::towlower);
                std::transform(t.begin(),t.end(),t.begin(),::towlower);
                if(n.find(f)==std::wstring::npos && t.find(f)==std::wstring::npos) continue;
            }
            std::wcout<<L"  ["<<e.type<<L"] \\Device\\"<<e.name<<L"\n"; ++shown;
        }
        if(shown==0) std::wcout<<L"  (no matches)\n";
        if(!a.open_dev && !a.do_poke && !a.do_hunt22090) return 0;
    }

    std::wstring chosen = !a.deviceW.empty()? a.deviceW : (!devpaths.empty()? devpaths.front() : std::wstring(L"\\\\.\\EBIoDispatch"));
    DevHandle dev;
    if(a.open_dev || a.do_poke || a.do_hunt22090){
        if(!open_device(chosen, dev)) return 1;
    }

    if(a.do_hunt22090){
        if(a.acpi_method.empty()){ std::cerr<<"[!] --hunt-22090 requires --acpi-method <FOUR>\n"; return 2; }

        std::vector<OmEntry> ents; om_list_device(ents, nullptr);
        std::vector<std::wstring> cand;
        std::wstring want = a.hunt_filter.empty()? L"acpi" : a.hunt_filter;
        std::wstring wantL = want; std::transform(wantL.begin(), wantL.end(), wantL.begin(), ::towlower);

        for(auto& e: ents){
            if(_wcsicmp(e.type.c_str(), L"Device")!=0) continue;
            std::wstring nL=e.name; std::transform(nL.begin(),nL.end(),nL.begin(),::towlower);
            if(wantL.empty() || nL.find(wantL)!=std::wstring::npos) cand.push_back(L"\\Device\\"+e.name);
        }
        std::sort(cand.begin(), cand.end()); cand.erase(std::unique(cand.begin(), cand.end()), cand.end());
        if(cand.empty()){ std::wcout<<L"[i] No \\Device candidates matched '"<<want<<L"'\n"; return 0; }

        std::wcout<<L"[i] Trying "<<cand.size()<<L" candidate(s) for 0x22E090 / "<<std::wstring(a.acpi_method.begin(), a.acpi_method.end())<<L"\n";
        for(auto& path : cand){
            auto in = make_22090_input(path, a.acpi_method);
            std::vector<uint8_t> out(a.has_out? a.out_sz : 0x4000, 0);
            DWORD br=0;
            std::wcout<<L"  -> "<<path<<L"  in="<<in.size()<<L" out="<<out.size()<<L"\n";
            BOOL ok = devctl(dev.h, 0x0022E090, in, out, br);
            if(!ok){
                DWORD gle=GetLastError();
                std::cout<<"     [ERR] "<<hex32(0x0022E090)<<" -> GLE="<<gle<<"\n";
                if(gle != ERROR_FILE_NOT_FOUND) { if(a.dump_out && !out.empty()){ std::cout<<"     -- OUTBUF --\n"; hexdump(out.data(), out.size()); } break; }
            }else{
                std::cout<<"     [OK ] "<<hex32(0x0022E090)<<" returned bytes="<<br<<"\n";
                if(a.dump_out) { std::cout<<"     -- OUTBUF --\n"; hexdump(out.data(), out.size()); }
                break;
            }
        }
        return 0;
    }

    if(a.do_poke){
        if(a.codes.empty()){ std::cerr<<"[!] --poke requires at least one --code <value>\n"; return 2; }
        std::wcout<<L"\n=== Probing on "<<(chosen.empty()?L"(unknown)":chosen)<<L" ===\n";
        for(DWORD code : a.codes){
            std::vector<uint8_t> inbuf;
            size_t required_in = 0;

            if(code == 0x0022E090 && !a.acpi_method.empty()){
                std::wstring pathW = a.wstr_seed.empty()? L"\\Device\\ACPI" : a.wstr_seed;
                if(!pathW.empty() && pathW[0]!=L'\\') pathW = L"\\" + pathW;
                inbuf = make_22090_input(pathW, a.acpi_method);
                required_in = inbuf.size(); // 0x308
            } else {
                if(!a.wstr_seed.empty()){
                    std::wstring p=a.wstr_seed; if(!p.empty() && p[0]!=L'\\') p=L"\\"+p;
                    append_wstr_null(p, inbuf);
                    if(inbuf.size() < 0x204) inbuf.resize(0x204, 0);
                }
                if(!a.in_seed.empty()) inbuf.insert(inbuf.end(), a.in_seed.begin(), a.in_seed.end());
                required_in = inbuf.size();
            }
            size_t final_in = a.has_in ? a.in_sz : required_in;
            if(final_in < required_in){
                std::cerr<<"[!] --in ("<<final_in<<") smaller than required seed ("<<required_in<<") for this code\n";
                return 2;
            }
            inbuf.resize(final_in, 0);

            std::vector<uint8_t> outbuf(a.has_out ? a.out_sz : 0);
            DWORD bytes=0;

            std::cout<<" IOCTL "<<hex32(code);
            for(auto& d : load_known_ioctls()){
                if(d.code == code){
                    std::cout<<" ("<<(d.name.empty()?"?":d.name)<<")";
                    if(!d.method.empty()) std::cout<<"  ["<<d.method<<"]";
                    if(!d.tag.empty())    std::cout<<"  <"<<d.tag<<">";
                    break;
                }
            }
            std::cout<<"\n";
            std::cout<<"   -> in="<<inbuf.size()<<" out="<<outbuf.size()<<"\n";
            if(a.dry_run) continue;

            BOOL ok = devctl(dev.h, code, inbuf, outbuf, bytes);
            if(!ok){ std::cout<<"  [ERR] "<<hex32(code)<<"  -> GLE="<<GetLastError()<<"\n"; continue; }
            std::cout<<"  [OK ] "<<hex32(code)<<"  returned bytes="<<bytes<<"\n";
            if(a.dump_out){
                if(!outbuf.empty()){ std::cout<<"  -- OUTBUF --\n"; hexdump(outbuf.data(), outbuf.size()); }
                else if(!inbuf.empty()){ std::cout<<"  -- SYSTEMBUFFER (METHOD_BUFFERED) --\n"; hexdump(inbuf.data(), inbuf.size()); }
            }
        }
    }
    return 0;
}
