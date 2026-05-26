cc = meson.get_compiler('c')

rz_core_dep = dependency('rz_core')
frida_core_opt = get_option('frida_core')
frida_core_dep = dependency('frida-core-1.0', required: false)

frida_include_dir = get_option('frida_include_dir')
frida_library = get_option('frida_library')
if not frida_core_dep.found() and frida_include_dir != '' and frida_library != ''
  frida_core_dep = declare_dependency(
    compile_args: ['-I' + frida_include_dir],
    link_args: [frida_library],
  )
endif
if frida_core_opt.enabled() and not frida_core_dep.found()
  error('frida-core was requested but not found through pkg-config or manual devkit options')
endif

rz_frida_c_args = []
rz_frida_deps = [rz_core_dep]
rz_frida_include_args = []

rizin_include_dir = get_option('rizin_include_dir')
if rizin_include_dir != ''
  rz_frida_include_args += ['-I' + rizin_include_dir]
endif
rizin_build_dir = get_option('rizin_build_dir')
if rizin_build_dir != ''
  rz_frida_include_args += ['-I' + rizin_build_dir]
endif
rizin_sdb_include_dir = get_option('rizin_sdb_include_dir')
if rizin_sdb_include_dir != ''
  rz_frida_include_args += ['-I' + rizin_sdb_include_dir]
endif

if frida_core_dep.found()
  rz_frida_deps += frida_core_dep
  rz_frida_c_args += ['-DRZ_FRIDA_HAVE_FRIDA_CORE=1']
else
  rz_frida_c_args += ['-DRZ_FRIDA_HAVE_FRIDA_CORE=0']
endif

rz_frida_incs = include_directories('include')

rz_frida_src = [
  'src/rz_frida_plugin.c',
  'src/rz_frida_protocol.c',
  'src/rz_frida_session.c',
  'src/rz_frida_uri.c',
]

rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
  rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
endif

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

rz_frida_lib = shared_library('rz_frida',
  rz_frida_src,
  c_args: rz_frida_c_args + rz_frida_include_args,
  dependencies: rz_frida_deps,
  include_directories: rz_frida_incs,
  implicit_include_directories: false,
  install: true,
  install_dir: rizin_plugdir,
)

test_uri = executable('test_uri',
  ['tests/test_uri.c', 'src/rz_frida_uri.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_incs,
)

test('uri parser', test_uri)

test_session = executable('test_session',
  ['tests/test_session.c', 'src/rz_frida_session.c', 'src/rz_frida_uri.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_incs,
)

test('session lifecycle', test_session)

test_protocol = executable('test_protocol',
  ['tests/test_protocol.c', 'src/rz_frida_protocol.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_incs,
)

test('protocol helpers', test_protocol)
