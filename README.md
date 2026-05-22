# Rizin/Cutter Frida plugin

Frida integration plugin for Rizin and Cutter.

The Rizin plugin provides the Frida backend, command interface, target lifecycle handling, script execution, runtime inspection, and Android Java/Kotlin metadata recovery. The Cutter plugin provides a native frontend over the same Rizin command interface.

# Rizin Plugin

## Build

```
meson setup build
ninja -C build
```

## Build with Frida devkit

```
meson setup build \
  -Dfrida_core=enabled \
  -Dfrida_include_dir=/path/to/frida-core-devkit \
  -Dfrida_library=/path/to/frida-core-library
ninja -C build
```

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

