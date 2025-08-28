# xpmem_probe

`xpmem_probe` is a small companion CLI that pairs with the auto-generated
[`xpmem_user.hpp`](./xpmem_user.hpp) header your IDA analysis script produces.
It provides a quick way to **smoke-test driver access** from user-mode:

- Lists device paths (`\\.\Foo`) discovered by the script
- Attempts to open handles to those devices
- Enumerates known IOCTLs and shows DEV/FUNC/Method/Access
- Optionally sends **zeroed test buffers** to each IOCTL to see which routes succeed

It’s meant for **diagnostic probing only**

---

## Build

### MSVC (Developer Command Prompt)

```bat
cl /std:c++17 /O2 xpmem_probe.cpp /link user32.lib
