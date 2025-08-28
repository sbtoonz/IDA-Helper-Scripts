xpmem_probe.exe [--list] [--open] [--poke | --poke-all] [--in N] [--out N] [--path \\.\DeviceName]

  --list          Print device paths and known IOCTLs (default if no flags)
  --open          Attempt to open each discovered device path
  --poke          Probe each IOCTL once against the first openable device
  --poke-all      Probe each IOCTL against every openable device
  --in N          Input buffer size in bytes (default 0)
  --out N         Output buffer size in bytes (default 0)
  --path P        Override: only try this device path
  --help          Show help
Exit codes: 0 = at least one device opened; 1 = none opened; 2 = bad args
