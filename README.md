# rz-frida

Frida integration plugin for Rizin and Cutter.

The Rizin plugin provides the backend and command interface. The Cutter plugin provides a native frontend over the Rizin backend.

The plugin provides:

- Rizin core plugin build support
- Cutter native plugin build support
- `frida://` URI validation
- session ownership, timeout, and cancellation primitives
- structured status and error replies
- structured device, process, and application enumeration across local, USB, and remote devices when `frida-core` is enabled
- session control across local, USB, and remote devices when `frida-core` is enabled
- script execution inside the target through an injected agent when `frida-core` is enabled
- target memory r/w through the agent when `frida-core` is enabled
- target memory range and thread listing through the agent when `frida-core` is enabled
- target module, export, import, and sym listing through the agent when `frida-core` is enabled

# Rizin Plugin

## Build

```
meson setup build
ninja -C build
meson test -C build
```

## Build with Frida

The Frida library and compiler toolchain must be ABI-compatible. Configuration fails
early when `frida-core` is found but cannot be linked by the active compiler.

```
meson setup build \
  -Dfrida_core=enabled \
  -Dfrida_include_dir=/path/to/frida-core-devkit \
  -Dfrida_library=/path/to/frida-core-library
ninja -C build
meson test -C build
```

## Commands

```
fridas
fridasj
fridau frida://attach/local//1234
fridauj frida://attach/local//1234
fridadj
fridapj
fridapj frida://list/usb/device-1/
fridaaj
fridaaj frida://apps/usb/device-1/
fridaoj frida://attach/local//1234
fridaoj frida://spawn/local///bin/ls
fridaoj frida://attach/usb//com.example.app
fridaoj frida://spawn/usb//com.example.app
fridaoj frida://attach/remote/127.0.0.1:27042/1234
fridarj
fridacj
fridaij
fridaej Process.arch
fridalj hook.js
fridamj
fridaxj 0x1000 64
fridawj 0x1000 deadbeef
fridaRj
fridatj
fridaMj
fridaEj libc.so
fridaIj libc.so
fridaSj libc.so
```

`fridadj`, `fridapj`, `fridaaj`, and `fridaoj` return a structured `frida_unavailable`
error when the plugin is built without `frida-core`. `fridapj` and `fridaaj` list the
local device by default, or take a `frida://` URI to select a USB or remote device.
`fridaoj` opens a session on the device named by the URI (attach, spawn, or launch on
local, USB, or remote), `fridarj` resumes a target that was spawned suspended, and
`fridacj` closes it. Closing kills a target that was spawned but never resumed and
leaves an attached or launched target running. Open, resume, and close honor the
session timeout and can be cancelled.

## Targets and transports

The `device` field of a `frida://` URI selects where the session runs. An empty device
on the `local` transport uses the host system. On the `usb` transport a device id picks
that device, and an empty device id picks the single connected device. On the `remote`
transport the device is the `host:port` of a frida-server.

`attach` accepts a numeric pid or a process name. A name is matched against the running
processes and resolved to a pid, and an unknown name returns an `invalid_target` error.
`spawn` and `launch` accept an executable path on local and remote targets or a package
identifier on USB targets. `spawn` starts the target suspended for `fridarj`, `launch`
resumes it immediately.

### Android over USB

Start `frida-server` on the device, then enumerate and open over USB:

```
fridadj
fridaaj frida://apps/usb//
fridapj frida://list/usb//
fridaoj frida://spawn/usb//com.example.app
fridarj
fridacj
```

A device that is not reachable, because `frida-server` is not running or the cable is
unplugged, surfaces as a `timeout` or `internal_error` carrying the message from
`frida-core`. An unknown package or process name surfaces as an `invalid_target` error.

### Remote frida-server

Start `frida-server -l 0.0.0.0:27042` on the host, then dial it from the listing or
session commands:

```
fridapj frida://list/remote/127.0.0.1:27042/
fridaoj frida://attach/remote/127.0.0.1:27042/1234
```

The remote transport connects to a plain frida-server. TLS and token authenticated
portals are not wired up.

## Script execution

Once a session is open, the plugin injects a small agent into the target and talks to it
over a request/response channel. The agent is loaded on first use, so the script cmds
work directly after `fridaoj` w/o a separate load step.

```
fridaij
fridaej Process.arch
fridalj /path/to/hook.js
fridamj
```

`fridaij` pings the agent and returns its ver and the target platform, arch, and
ptr size, a quick check that the host-agent channel is alive. `fridaej` evals a
JS expression inside the target and returns its val and type. `fridalj` reads a
script from a file and evals it same way, for instrumentation too large for the
cmd line. Each request respects the session timeout and can be interrupted with Ctrl-C.

Not every msg from the agent is a reply. Console o/p, uncaught script errors, and
unsolicited `send()` notifs are buffered per session in a bounded queue that drops the
oldest entry when full and counts how many it dropped. `fridamj` drains that buffer as a JSON
array and clears it. Binary data attached to a `send()` is carried through as base64 with its
byte length.

## Memory

`fridaxj` reads a block of target memory and returns the bytes as a hex string. `fridawj`
writes a hex byte string into target memory and returns the number of bytes written. Both
load the agent on first use, take an addr that rizin evals (so expressions and symbols
work), and are bounded by the `frida.mem.max` config.

```
fridaxj 0x1000 64
fridawj 0x1000 deadbeef
```

The first reads 64 bytes at `0x1000`, the second writes the four bytes `de ad be ef` at
`0x1000`. The agent validates the address against the mapped ranges first, so a r/w
of unmapped mem comes back as an `internal_error`, and both cmds report `invalid_target`
when no session is open.

## Runtime info

`fridaRj` lists the target memory ranges, each with its base, size, protection, and backing
file when mapped. `fridatj` lists target threads, each with its id, state, register
context, and entrypoint. `fridaMj` lists loaded modules with their name, base, size, and
path. `fridaEj <module>`, `fridaIj <module>`, and `fridaSj <module>` list a module's exports,
imports, and symbols. All load the agent on first use.

```
fridaRj
fridatj
fridaMj
fridaEj libc.so
fridaIj libc.so
fridaSj libc.so
```

The agent caches the range and module lists and re-enumerates after code runs in the target
(`fridaej` or `fridalj`), so listing stays current w/o re-scanning on every call. The reply's
`cached` flag says whether it came from the cache, and passing any arg to `fridaRj` or
`fridaMj` forces a fresh enumeration.

## Configuration

Two `e` config variables tune the runtime behaviour:

```
e frida.mem.max=0x100000   # max bytes per fridaxj/fridawj transfer, 0 for no limit
e frida.timeout=5000       # session and agent request timeout in milliseconds
```

`frida.timeout` is applied when a session is opened with `fridaoj`.

## Install

```
ninja -C build install
```

or on a custom prefix:

```
meson setup build --prefix=/usr
ninja -C build
ninja -C build install
```

## Build ASAN

```
meson setup build-asan -Dbuildtype=debugoptimized -Db_sanitize=address,undefined
ninja -C build-asan
```

# Cutter Plugin

Requires Cutter headers and CMake package files to build the native plugin.

```
cmake -S plugin/cutter -B build-cutter -DCMAKE_PREFIX_PATH=/path/to/cutter/install
cmake --build build-cutter
cmake --install build-cutter
```

# References

- [r2frida](https://github.com/nowsecure/r2frida), Frida integration plugin for radare2.
