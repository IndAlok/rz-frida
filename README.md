# rz-frida

Frida integration plugin for Rizin and Cutter.

The Rizin plugin provides the backend and command interface. The Cutter plugin provides a native frontend over the Rizin backend.

Current functionality includes:

- Rizin core plugin build support
- Cutter native plugin skeleton build support
- `frida://` URI validation
- session ownership, timeout, and cancellation primitives
- structured status and error replies
- structured device-listing entry point when `frida-core` is enabled

# Rizin Plugin

## Build

```
meson setup build
ninja -C build
```

## Build with Frida devkit

The devkit and compiler toolchain must be ABI-compatible. Configuration fails early when
`frida-core` is found but cannot be linked by the active compiler.

```
meson setup build \
  -Dfrida_core=enabled \
  -Dfrida_include_dir=/path/to/frida-core-devkit \
  -Dfrida_library=/path/to/frida-core-library
ninja -C build
```

## Commands

```
frida status
frida statusj
frida uri frida://attach/local//1234
frida urij frida://attach/local//1234
frida devicesj
```

`frida devicesj` returns a structured `frida_unavailable` error when the plugin is built
without `frida-core`.

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
