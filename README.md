GLib based IP flow manager

Manage IP flows using GLib constructs

## Build
```
make
make install
```

# Demo
```
Usage:
  demo [OPTION...] - Demonstration of libginetflow

Help Options:
  -h, --help        Show help options

Application Options:
  -p, --pcap        Pcap file to use
  -w, --workers     Number of worker threads
  -d, --dpi         Analyse frames using DPI
  -v, --verbose     Be verbose
```

```
LD_LIBRARY_PATH=. ./demo -p test.pcap -d -w 8
```
