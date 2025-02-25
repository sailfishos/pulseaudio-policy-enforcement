project('pulseaudio-policy-enforcement', 'c',
        version : run_command(find_program('git-version-gen'), join_paths(meson.current_source_dir(), '.tarball-version'), check: true).stdout().strip(),
        meson_version : '>= 0.50.0',
        default_options : [ 'c_std=gnu11' ]
        )

cc = meson.get_compiler('c')

configinc = include_directories('.')
libdir = join_paths(get_option('prefix'), get_option('libdir'))

# dependencies
dbus_dep = dependency('dbus-1', version : '>= 1.2', required : true)
meego_common_dep = dependency('libmeego-common', version : '>= 24', required : true)
pulsecore_dep = dependency('pulsecore', version : '>= 14.2', required : true)

pa_version_str = pulsecore_dep.version()
# For tarballs, the first split will do nothing, but for builds in git, we
# split out suffixes when there are commits since the last tag
# (e.g.: v11.99.1-3-gad14bdb24 -> v11.99.1)
version_split = pa_version_str.split('-')[0].split('.')
pa_version_major = version_split[0].split('v')[0]
pa_version_minor = version_split[1]
pa_version_major_minor = pa_version_major + '.' + pa_version_minor

pa_c_args = ['-DHAVE_CONFIG_H', '-DPULSEAUDIO_VERSION=' + pa_version_major]

libdir = join_paths(get_option('prefix'), get_option('libdir'))
modlibexecdir = get_option('modlibexecdir')
if modlibexecdir == ''
  modlibexecdir = join_paths(libdir, 'pulse-' + pa_version_major_minor, 'modules')
endif

cdata = configuration_data()
cdata.set_quoted('PACKAGE', meson.project_name())
cdata.set_quoted('PACKAGE_NAME', meson.project_name())
cdata.set_quoted('PACKAGE_VERSION', pa_version_str)
cdata.set_quoted('VERSION', pa_version_str)

# Headers
check_headers = [
  'valgrind/memcheck.h',
]

foreach h : check_headers
  if cc.has_header(h)
    define = 'HAVE_' + h.underscorify().to_upper()
    cdata.set(define, 1)
  endif
endforeach

subdir('src')

# Now generate config.h from everything above
configure_file(output : 'config.h', configuration : cdata)

