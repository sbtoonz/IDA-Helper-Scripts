// xpmem_probe.cpp — targeted IOCTL probe with ACPI packer for 0x22E090
// Build: cl /std:c++17 /EHsc /O2 xpmem_probe.cpp /link user32.lib

#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>

// ---------- Header autodetect ----------
#if __has_include("xpmem_rw.hpp")
  #include "xpmem_rw.hpp"
  namespace xh = xpmem;
#elif __has_include("xpmem_user.hpp")
  #include "xpmem_user.hpp"
  namespace xh = xpmem;
#else
  #warning "No xpmem_rw.hpp or xpmem_user.hpp found. Using empty stubs."
  namespace xh {
    struct ioctl_desc { DWORD code; const char* name; const char* method; const char* access; };
    inline std::vector<ioctl_desc> known_ioctls() { return {}; }
    static const wchar_t* kDefaultDevicePath = L"\\\\.\\EBIoDispatch";
    static const std::vector<std::wstring> kAllDevicePaths = { std::wstring(L"\\\\.\\EBIoDispatch") };
  }
#endif

// unify descriptor shape (with/without .tag)
struct MyIoctl { DWORD code{}; std::string name, method, access, tag; };

template<typename T>
auto convert_desc_impl(const T& d, int) -> decltype((void)d.tag, MyIoctl{}) {
    return MyIoctl{ d.code, d.name ? d.name : "", d.method ? d.method : "", d.access ? d.access : "", d.tag ? d.tag : "" };
}
template<typename T>
MyIoctl convert_desc_impl(const T& d, long) {
    return MyIoctl{ d.code, d.name ? d.name : "", d.method ? d.method : "", d.access ? d.access : "", "" };
}
template<typename T>
MyIoctl convert_desc(const T& d) { return convert_desc_impl(d, 0); }

static std::vector<MyIoctl> load_known_ioctls() {
    auto raw = xh::known_ioctls();
    std::vector<MyIoctl> out;
    out.reserve(raw.size());
    for (auto& e : raw) out.push_back(convert_desc(e));
    return out;
}

static std::vector<std::wstring> load_device_paths() {
    std::vector<std::wstring> v;
#if __has_include("xpmem_rw.hpp") || __has_include("xpmem_user.hpp")
    if (!xh::kAllDevicePaths.empty()) {
        v.assign(xh::kAllDevicePaths.begin(), xh::kAllDevicePaths.end());
    } else if (xh::kDefaultDevicePath && *xh::kDefaultDevicePath) {
        v.emplace_back(xh::kDefaultDevicePath);
    }
#else
    v.emplace_back(L"\\\\.\\EBIoDispatch");
#endif
    if (v.empty()) v.emplace_back(L"\\\\.\\EBIoDispatch");
    return v;
}

// ---------- pretty helpers ----------
static std::string to_hex32(DWORD v) {
    std::ostringstream oss; oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return oss.str();
}

static void hexdump(const void* data, size_t len, size_t width = 16) {
    auto* p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < len; i += width) {
        std::cout << "  " << std::setw(6) << std::setfill(' ') << std::dec << i << "  ";
        size_t j = 0;
        for (; j < width && i + j < len; ++j) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(p[i + j]) << ' ';
        }
        for (; j < width; ++j) std::cout << "   ";
        std::cout << " ";
        for (j = 0; j < width && i + j < len; ++j) {
            unsigned char c = p[i + j];
            std::cout << (std::isprint(c) ? static_cast<char>(c) : '.');
        }
        std::cout << "\n";
    }
}

// parse "AA BB CC" or "AABBCC"
static bool parse_hex_bytes(const std::string& src, std::vector<uint8_t>& out) {
    out.clear();
    std::string s;
    s.reserve(src.size());
    for (char c : src) if (!std::isspace(static_cast<unsigned char>(c))) s.push_back(c);
    if (s.size() % 2) return false;
    auto hex = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); i += 2) {
        int a = hex(s[i]), b = hex(s[i+1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<uint8_t>((a << 4) | b));
    }
    return true;
}

static bool parse_size(const std::string& s, size_t& out) {
    char* end = nullptr;
    unsigned long long v = 0;
    if (s.size() > 2 && s[0]=='0' && (s[1]=='x' || s[1]=='X')) v = std::strtoull(s.c_str(), &end, 16);
    else v = std::strtoull(s.c_str(), &end, 10);
    if (!end || *end) return false;
    out = static_cast<size_t>(v);
    return true;
}

// UTF-16LE append + NUL
static void append_wstr_null(const std::wstring& ws, std::vector<uint8_t>& out) {
    out.reserve(out.size() + (ws.size()+1)*2);
    for (wchar_t ch : ws) {
        out.push_back(static_cast<uint8_t>(ch & 0xFF));
        out.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
    }
    out.push_back(0); out.push_back(0);
}

// ---------- ACPI packers (minimal) ----------
#pragma pack(push, 1)
struct ACPI_EVAL_INPUT_BUFFER_MIN {
    ULONG Signature;   // 'ACPI' = 0x41435049
    ULONG MethodName;  // e.g., '_STA' -> 0x4154535F (LE)
    // buffer is 0x104 total; we zero the rest
};
#pragma pack(pop)

static ULONG make_fourcc_4(const std::string& s4) {
    char a=' ', b=' ', c=' ', d=' ';
    if (s4.size() > 0) a = s4[0];
    if (s4.size() > 1) b = s4[1];
    if (s4.size() > 2) c = s4[2];
    if (s4.size() > 3) d = s4[3];
    return static_cast<ULONG>( static_cast<uint8_t>(a)
         | (static_cast<ULONG>(static_cast<uint8_t>(b)) << 8)
         | (static_cast<ULONG>(static_cast<uint8_t>(c)) << 16)
         | (static_cast<ULONG>(static_cast<uint8_t>(d)) << 24) );
}

// Build: [0x204 UTF-16 path + NUL + pad] + [0x104 ACPI input (signature + method + zeros)]
static std::vector<uint8_t> build_acpi_0x22E090_input(const std::wstring& devPath, const std::string& method4) {
    const size_t STR_REGION = 0x204;
    const size_t ACPI_IN_SZ = 0x104;
    std::vector<uint8_t> buf;
    buf.resize(STR_REGION + ACPI_IN_SZ, 0);

    // Write UTF-16 path at offset 0
    std::vector<uint8_t> tmp;
    append_wstr_null(devPath, tmp);
    if (tmp.size() > STR_REGION) {
        // truncate safely
        std::copy(tmp.begin(), tmp.begin() + STR_REGION, buf.begin());
    } else {
        std::copy(tmp.begin(), tmp.end(), buf.begin());
        // rest already zero
    }

    // Write ACPI input at offset STR_REGION
    ACPI_EVAL_INPUT_BUFFER_MIN in{};
    in.Signature  = 0x41435049;                // 'ACPI'
    in.MethodName = make_fourcc_4(method4);    // e.g. "_STA"
    std::memcpy(buf.data() + STR_REGION, &in, sizeof(in));
    // remaining bytes in the 0x104 block are already zeroed

    return buf;
}

// ---------- args ----------
struct Args {
    bool show_list = false;
    bool open_dev  = false;
    bool do_poke   = false;
    bool dump_out  = false;
    bool dry_run   = false;

    std::wstring device;
    std::vector<DWORD> codes;

    size_t in_size  = 0;
    size_t out_size = 0;
    bool has_in_size  = false;
    bool has_out_size = false;

    std::vector<uint8_t> in_seed;      // raw bytes
    std::wstring         wstr_seed;    // device path (UTF-16)
    std::string          acpi_method;  // if set, pack 0x22E090 layout

    bool parse(int argc, char** argv) {
        for (int i=1; i<argc; ++i) {
            std::string t = argv[i];
            if (t == "--list") show_list = true;
            else if (t == "--open") open_dev = true;
            else if (t == "--poke") do_poke = true;
            else if (t == "--dump-out") dump_out = true;
            else if (t == "--dry-run") dry_run = true;

            else if (t == "--device" && i+1 < argc) {
                std::string s = argv[++i];
                device.assign(s.begin(), s.end());
            }
            else if (t == "--code" && i+1 < argc) {
                size_t tmp=0; std::string val = argv[++i];
                if (!parse_size(val, tmp)) {
                    std::cerr << "[!] Invalid --code value: '" << val << "'. Use decimal or hex like 0x22E090.\n";
                    return false;
                }
                codes.push_back(static_cast<DWORD>(tmp));
            }
            else if (t == "--in" && i+1 < argc) {
                size_t tmp=0; if (!parse_size(argv[++i], tmp)) return false;
                in_size = tmp; has_in_size = true;
            }
            else if (t == "--out" && i+1 < argc) {
                size_t tmp=0; if (!parse_size(argv[++i], tmp)) return false;
                out_size = tmp; has_out_size = true;
            }
            else if (t == "--in-hex" && i+1 < argc) {
                std::vector<uint8_t> v;
                if (!parse_hex_bytes(argv[++i], v)) return false;
                in_seed = std::move(v);
            }
            else if (t == "--wstr" && i+1 < argc) {
                std::string s = argv[++i];
                wstr_seed.assign(s.begin(), s.end()); // ASCII -> wide
            }
            else if (t == "--preset" && i+1 < argc) {
                std::string which = argv[++i];
                std::transform(which.begin(), which.end(), which.begin(), [](unsigned char c){ return (char)std::tolower(c); });
                if (which == "acpi")      wstr_seed = L"\\Device\\ACPI";
                else if (which == "ksecdd") wstr_seed = L"\\Device\\KsecDD";
                else if (which == "null")   wstr_seed = L"\\Device\\Null";
                else {
                    std::cerr << "[!] Unknown preset: " << which << " (try: acpi, ksecdd, null)\n";
                    return false;
                }
            }
            else if (t == "--acpi-method" && i+1 < argc) {
                acpi_method = argv[++i]; // e.g. "_STA"
                if (acpi_method.size() > 4) acpi_method.resize(4);
                while (acpi_method.size() < 4) acpi_method.push_back(' ');
            }
            else {
                std::cerr << "[?] Unknown or incomplete arg: " << t << "\n";
                return false;
            }
        }
        return true;
    }
};

static void usage() {
    std::cout <<
R"(xpmem_probe.exe [--list] [--open] [--device "\\.\EBIoDispatch"]
                 [--poke --code 0x22E090
                        [--in N] [--in-hex "..."]
                        [--wstr "\Device\ACPI"] [--preset acpi|ksecdd|null]
                        [--acpi-method _STA]
                        [--out N] [--dump-out] [--dry-run]]

  --acpi-method NAME      When used with 0x22E090, packs the second 0x104 block for ACPI
                          (minimal ACPI_EVAL_INPUT_BUFFER: Signature='ACPI', Method=NAME)
  NOTE: With --acpi-method and no --in, input is auto-sized to 0x308 (0x204 + 0x104).
)";
}

// ---------- device helpers ----------
struct DevHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    std::wstring path;
    ~DevHandle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

static bool open_device(const std::wstring& path, DevHandle& out) {
    HANDLE h = CreateFileW(path.c_str(),
                           GENERIC_READ|GENERIC_WRITE,
                           FILE_SHARE_READ|FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[ERR] CreateFile " << path << L" -> GLE=" << GetLastError() << L"\n";
        return false;
    }
    out.h = h;
    out.path = path;
    std::wcout << L"[+] Opened " << path << L"\n";
    return true;
}

static bool device_control(HANDLE h, DWORD code,
                           std::vector<uint8_t>& inout,
                           std::vector<uint8_t>& outbuf,
                           DWORD& bytes_ret)
{
    LPVOID in_ptr  = inout.empty() ? nullptr : inout.data();
    DWORD  in_len  = static_cast<DWORD>(inout.size());
    LPVOID out_ptr = outbuf.empty() ? nullptr : outbuf.data();
    DWORD  out_len = static_cast<DWORD>(outbuf.size());

    BOOL ok = DeviceIoControl(h, code, in_ptr, in_len, out_ptr, out_len, &bytes_ret, nullptr);
    if (!ok) return false;
    return true;
}

static void print_ioctl_row(const MyIoctl& d) {
    std::cout << "  " << to_hex32(d.code) << "  "
              << (d.name.empty() ? "(unnamed)" : d.name)
              << "  " << (d.method.empty() ? "?" : d.method)
              << "  " << (d.access.empty() ? "" : d.access);
    if (!d.tag.empty()) std::cout << "  [" << d.tag << "]";
    std::cout << "\n";
}

// ---------- main ----------
int main(int argc, char** argv) {
    Args a;
    if (!a.parse(argc, argv) || argc == 1) {
        usage();
        return (argc == 1) ? 0 : 2;
    }

    auto devpaths = load_device_paths();
    auto ioctls   = load_known_ioctls();

    if (a.show_list) {
        std::cout << "[i] Device path candidates (" << devpaths.size() << "):\n";
        for (auto& p : devpaths) std::wcout << L"    " << p << L"\n";
        std::cout << "[i] Known IOCTLs (" << ioctls.size() << "):\n";
        for (auto& d : ioctls) print_ioctl_row(d);
        if (!a.open_dev && !a.do_poke) return 0;
    }

    // Choose device
    std::wstring chosen =
        !a.device.empty() ? a.device :
        (!devpaths.empty() ? devpaths.front() : std::wstring(L"\\\\.\\EBIoDispatch"));

    DevHandle dev;
    if (a.open_dev || a.do_poke) {
        if (!open_device(chosen, dev)) return 1;
    }

    if (a.do_poke) {
        if (a.codes.empty()) {
            std::cerr << "[!] --poke requires at least one --code <value>\n";
            return 2;
        }

        // Build seed
        std::vector<uint8_t> in_template;

        // If 0x22E090 + --acpi-method: build composite input (0x204 path + 0x104 ACPI block)
        const bool wants_acpi = std::find(a.codes.begin(), a.codes.end(), (DWORD)0x0022E090) != a.codes.end()
                                && !a.acpi_method.empty();

        if (wants_acpi) {
            std::wstring pathW = a.wstr_seed.empty() ? L"\\Device\\ACPI" : a.wstr_seed;
            if (!pathW.empty() && pathW[0] != L'\\') pathW = L"\\" + pathW;
            in_template = build_acpi_0x22E090_input(pathW, a.acpi_method);
        } else {
            // Otherwise: just pack device string if given
            if (!a.wstr_seed.empty()) {
                std::wstring pathW = a.wstr_seed;
                if (!pathW.empty() && pathW[0] != L'\\') pathW = L"\\" + pathW;
                append_wstr_null(pathW, in_template);
                if (in_template.size() < 0x204) in_template.resize(0x204, 0); // match driver's copy size
            }
            // and/or raw bytes
            if (!a.in_seed.empty()) {
                in_template.insert(in_template.end(), a.in_seed.begin(), a.in_seed.end());
            }
        }

        // Decide sizes
        size_t final_in  = 0;
        size_t final_out = a.has_out_size ? a.out_size : 0;
        if (a.has_in_size) {
            final_in = a.in_size;
            if (final_in < in_template.size()) {
                std::cerr << "[!] --in size smaller than seed (" << in_template.size() << "), refusing.\n";
                return 2;
            }
        } else {
            final_in = in_template.size();
            // For the ACPI case, ensure exactly 0x308 unless user overrides
            if (wants_acpi && final_in < 0x308) final_in = 0x308;
        }

        std::wcout << L"\n=== Probing on " << (chosen.empty() ? L"(unknown)" : chosen) << L" ===\n";

        for (DWORD code : a.codes) {
            std::cout << " IOCTL " << to_hex32(code);
            auto it = std::find_if(ioctls.begin(), ioctls.end(),
                                   [&](const MyIoctl& d){ return d.code == code; });
            if (it != ioctls.end()) {
                std::cout << " (" << (it->name.empty()? "?" : it->name) << ")";
                if (!it->method.empty()) std::cout << "  [" << it->method << "]";
                if (!it->tag.empty())    std::cout << "  <" << it->tag << ">";
            }
            std::cout << "\n";

            std::vector<uint8_t> inbuf(final_in, 0);
            if (!in_template.empty()) std::copy(in_template.begin(), in_template.end(), inbuf.begin());

            std::vector<uint8_t> outbuf(final_out, 0);
            DWORD bytes = 0;

            std::cout << "   -> in=" << inbuf.size() << " out=" << outbuf.size() << "\n";
            if (a.dry_run) continue;

            BOOL ok = device_control(dev.h, code, inbuf, outbuf, bytes);
            if (!ok) {
                DWORD gle = GetLastError();
                std::cout << "  [ERR] " << to_hex32(code) << "  -> GLE=" << gle << "\n";
                continue;
            }

            std::cout << "  [OK ] " << to_hex32(code) << "  returned bytes=" << bytes << "\n";
            if (a.dump_out) {
                if (!outbuf.empty()) {
                    std::cout << "  -- OUTBUF --\n";
                    hexdump(outbuf.data(), outbuf.size());
                } else if (!inbuf.empty()) {
                    std::cout << "  -- SYSTEMBUFFER (METHOD_BUFFERED) --\n";
                    hexdump(inbuf.data(), inbuf.size());
                }
            }
        }
    }

    return 0;
}
