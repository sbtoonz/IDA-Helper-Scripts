#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

// Include the auto-generated header from the IDA script v5.4
#include "xpmem_user.hpp"

using std::wcout;
using std::cout;
using std::wcerr;
using std::cerr;
using std::endl;

static void print_usage(const char* argv0) {
    std::cout <<
R"(xpmem_probe — smoke-test CLI for your generated xpmem_user.hpp

Usage:
  )" << argv0 << R"( [--list] [--open] [--poke | --poke-all] [--in N] [--out N] [--path \\.\DeviceName]

Options:
  --list          Print device paths and known IOCTLs (default if no flags)
  --open          Attempt to open each discovered device path
  --poke          Probe each IOCTL once against the first openable device
  --poke-all      Probe each IOCTL against every openable device
  --in N          Input buffer size in bytes (default 0)
  --out N         Output buffer size in bytes (default 0)
  --path P        Override: only try this device path
  --help          Show this help

Exit codes:
  0 = at least one device opened
  1 = no device opened
  2 = bad arguments
)";
}

static inline uint32_t IOCTL_DeviceType(uint32_t code) { return (code >> 16) & 0xFFFFu; }
static inline uint32_t IOCTL_Function  (uint32_t code) { return (code >>  2) & 0x0FFFu; }
static inline uint32_t IOCTL_Method    (uint32_t code) { return  code        & 0x0003u; }
static inline uint32_t IOCTL_Access    (uint32_t code) { return (code >> 14) & 0x0003u; }

static const char* MethodName(uint32_t m) {
    switch (m) {
        case 0: return "METHOD_BUFFERED";
        case 1: return "METHOD_IN_DIRECT";
        case 2: return "METHOD_OUT_DIRECT";
        case 3: return "METHOD_NEITHER";
        default: return "?";
    }
}
static const char* AccessName(uint32_t a) {
    switch (a) {
        case 0: return "FILE_ANY_ACCESS";
        case 1: return "FILE_READ_ACCESS";
        case 2: return "FILE_WRITE_ACCESS";
        case 3: return "FILE_READ|WRITE_ACCESS";
        default: return "?";
    }
}

struct Args {
    bool do_list   = false;
    bool do_open   = false;
    bool do_poke   = false;
    bool poke_all  = false;
    size_t in_sz   = 0;
    size_t out_sz  = 0;
    std::wstring override_path; // optional
};

static bool parse_size(const char* s, size_t& out) {
    // accept decimal or 0xHEX
    char* end = nullptr;
    unsigned long long v = 0ULL;
    if (std::strlen(s) > 2 && s[0]=='0' && (s[1]=='x' || s[1]=='X')) {
        v = std::strtoull(s, &end, 16);
    } else {
        v = std::strtoull(s, &end, 10);
    }
    if (!end || *end) return false;
    out = static_cast<size_t>(v);
    return true;
}

static bool parse_args(int argc, char** argv, Args& a) {
    if (argc == 1) { a.do_list = true; return true; }

    for (int i=1; i<argc; ++i) {
        std::string t = argv[i];
        if (t == "--help" || t == "-h" || t == "/?") { print_usage(argv[0]); std::exit(0); }
        else if (t == "--list") a.do_list = true;
        else if (t == "--open") a.do_open = true;
        else if (t == "--poke") a.do_poke = true;
        else if (t == "--poke-all") { a.do_poke = true; a.poke_all = true; }
        else if (t == "--in" && i+1 < argc) {
            if (!parse_size(argv[++i], a.in_sz)) return false;
        }
        else if (t == "--out" && i+1 < argc) {
            if (!parse_size(argv[++i], a.out_sz)) return false;
        }
        else if (t == "--path" && i+1 < argc) {
            std::string p = argv[++i];
            // convert to wide
            a.override_path.assign(p.begin(), p.end());
        }
        else {
            return false;
        }
    }

    if (!a.do_list && !a.do_open && !a.do_poke) a.do_list = true; // default behavior
    return true;
}

static void list_devices_and_ioctls() {
    std::wcout << L"[i] Device path candidates (" << xpmem::kAllDevicePaths.size() << L"):\n";
    for (auto p : xpmem::kAllDevicePaths) {
        std::wcout << L"    " << p << L"\n";
    }
    auto ioctls = xpmem::known_ioctls();
    std::cout << "[i] Known IOCTLs (" << ioctls.size() << "):\n";
    for (auto& d : ioctls) {
        std::cout << "    0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << d.code << std::dec << "  "
                  << d.name << "  "
                  << "DEV=0x"   << std::hex << std::setw(4) << std::setfill('0') << IOCTL_DeviceType(d.code)
                  << " FUNC=0x" << std::setw(3) << (IOCTL_Function(d.code))
                  << std::dec
                  << "  " << d.method
                  << "  " << d.access
                  << "\n";
    }
}

static std::vector<std::wstring> enumerate_paths(const Args& a) {
    std::vector<std::wstring> paths;
    if (!a.override_path.empty()) {
        paths.push_back(a.override_path);
        return paths;
    }
    for (auto p : xpmem::kAllDevicePaths) paths.emplace_back(p);
    // ensure default present at least once
    if (paths.empty()) paths.emplace_back(xpmem::kDefaultDevicePath);
    return paths;
}

static bool try_open_paths(const std::vector<std::wstring>& paths,
                           std::vector<xpmem::Device>& opened,
                           DWORD access = GENERIC_READ | GENERIC_WRITE) {
    bool any = false;
    for (auto& p : paths) {
        try {
            xpmem::Device dev(p, access, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL);
            std::wcout << L"[+] Opened " << p << L"\n";
            opened.emplace_back(std::move(dev));
            any = true;
        } catch (const xpmem::win32_error& e) {
            std::wcout << L"[-] Open failed " << p << L" (GLE=" << e.code << L")\n";
        }
    }
    return any;
}

static void poke_all(const std::vector<xpmem::Device>& devs, size_t in_sz, size_t out_sz) {
    auto ioctls = xpmem::known_ioctls();
    if (ioctls.empty()) {
        std::cout << "[i] No IOCTLs to probe.\n";
        return;
    }

    std::vector<std::byte> in(in_sz ? in_sz : 1, std::byte{0});
    std::vector<std::byte> out(out_sz ? out_sz : 1);

    for (const auto& dev : devs) {
        std::wcout << L"\n=== Probing on " << dev.path() << L" ===\n";
        for (auto& d : ioctls) {
            DWORD got = 0;
            try {
                got = dev.ioctl(d.code,
                                in_sz ? in.data() : nullptr, static_cast<DWORD>(in_sz),
                                out_sz ? out.data() : nullptr, static_cast<DWORD>(out_sz));
                std::cout << "  [OK] 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                          << d.code << std::dec << "  " << d.name
                          << "  -> bytes=" << got << "\n";
            } catch (const xpmem::win32_error& e) {
                std::cout << "  [ERR] 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                          << d.code << std::dec << "  " << d.name
                          << "  -> GLE=" << e.code << "\n";
            }
        }
    }
}

int main(int argc, char** argv) try {
    Args a;
    if (!parse_args(argc, argv, a)) {
        print_usage(argv[0]);
        return 2;
    }

    if (a.do_list) {
        list_devices_and_ioctls();
    }

    std::vector<std::wstring> paths = enumerate_paths(a);
    std::vector<xpmem::Device> opened;

    bool an
