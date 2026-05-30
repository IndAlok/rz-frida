cc = meson.get_compiler('c')

rz_core_dep = dependency('rz_core')
frida_core_opt = get_option('frida_core')
frida_core_dep = []
frida_core_enabled = false
frida_core_manual = false
frida_core_compile_args = []
frida_core_link_args = []

if not frida_core_opt.disabled()
  frida_include_dir = get_option('frida_include_dir')
  frida_library = get_option('frida_library')
  if frida_include_dir != '' and frida_library != ''
    frida_core_manual = true
    if host_machine.system() == 'windows' and cc.get_id() == 'gcc' and frida_library.to_lower().endswith('.lib')
      error('frida-core was found but cannot be linked with this compiler and toolchain')
    endif
    frida_core_compile_args = ['-I' + frida_include_dir]
    frida_core_link_args = [frida_library]
    frida_core_dep = declare_dependency(
      compile_args: frida_core_compile_args,
      link_args: frida_core_link_args,
    )
  else
    frida_core_dep = dependency('frida-core-1.0', required: false)
  endif

  if frida_core_dep.found()
    frida_core_link_check = '''
    #include <frida-core.h>
    int main(void) {
      frida_init();
      frida_deinit();
      return 0;
    }
    '''
    if frida_core_manual
      frida_core_enabled = cc.links(
        frida_core_link_check,
        args: frida_core_compile_args + frida_core_link_args,
        name: 'frida-core link check',
      )
    else
      frida_core_enabled = cc.links(
        frida_core_link_check,
        dependencies: frida_core_dep,
        name: 'frida-core link check',
      )
    endif
    if not frida_core_enabled and frida_core_opt.enabled()
      error('frida-core was found but cannot be linked with this compiler and toolchain')
    endif
  elif frida_core_opt.enabled()
    error('frida-core was requested but not found through pkg-config or manual devkit options')
  endif
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

if frida_core_enabled
  rz_frida_deps += frida_core_dep
  rz_frida_backend_src = 'src/rz_frida_backend.c'
else
  rz_frida_backend_src = 'src/rz_frida_backend_null.c'
endif

rz_frida_incs = include_directories('include', 'src/cmd_descs')
rz_frida_test_incs = include_directories('include', 'src/cmd_descs', 'tests')

rz_frida_src = [
  rz_frida_backend_src,
  'src/cmd_descs/cmd_descs.c',
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
  include_directories: rz_frida_test_incs,
)

test('uri parser', test_uri)

test_session = executable('test_session',
  ['tests/test_session.c', 'src/rz_frida_session.c', 'src/rz_frida_uri.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('session lifecycle', test_session)

test_protocol = executable('test_protocol',
  ['tests/test_protocol.c', 'src/rz_frida_protocol.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('protocol helpers', test_protocol)

test_backend = executable('test_backend',
  ['tests/test_backend.c', 'src/rz_frida_backend_null.c', 'src/rz_frida_protocol.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('backend unavailable response', test_backend)

test_plugin = executable('test_plugin',
  [
    'tests/test_plugin.c',
    rz_frida_backend_src,
    'src/cmd_descs/cmd_descs.c',
    'src/rz_frida_plugin.c',
    'src/rz_frida_protocol.c',
    'src/rz_frida_session.c',
    'src/rz_frida_uri.c',
  ],
  c_args: rz_frida_c_args + rz_frida_include_args,
  dependencies: rz_frida_deps,
  include_directories: rz_frida_test_incs,
)

test('plugin command registration', test_plugin)
