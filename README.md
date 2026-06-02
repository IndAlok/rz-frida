# rz-frida

Frida integration plugin for Rizin and Cutter.

The Rizin plugin provides the backend and command interface. The Cutter plugin provides a native frontend over the Rizin backend.

The plugin provides:

- Rizin core plugin build support
- Cutter native plugin build support
- `frida://` URI validation
- session ownership, timeout, and cancellation primitives
- structured status and error replies
- structured device and local process enumeration when `frida-core` is enabled
- local session control (attach, spawn, launch, and resume) when `frida-core` is enabled

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
fridaoj frida://attach/local//1234
fridaoj frida://spawn/local///bin/ls
fridarj
```

`fridadj`, `fridapj`, and `fridaoj` return a structured `frida_unavailable` error
when the plugin is built without `frida-core`. `fridaoj` opens a session on the
local device (attach, spawn, or launch) and `fridarj` resumes a target that was
spawned suspended.

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
