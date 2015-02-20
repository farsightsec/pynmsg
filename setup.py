#!/usr/bin/env python

NAME = 'pynmsg'
VERSION = '0.3.1'

from distutils.core import setup
from distutils.extension import Extension

def pkgconfig(*packages, **kw):
    import subprocess
    flag_map = {
            '-I': 'include_dirs',
            '-L': 'library_dirs',
            '-l': 'libraries'
    }
    pkg_config_cmd = (
        'pkg-config',
        '--cflags',
        '--libs',
        ' '.join(packages),
    )
    pkg_config_output = subprocess.check_output(pkg_config_cmd, universal_newlines=True)
    for token in pkg_config_output.split():
        flag = token[:2]
        arg = token[2:]
        if flag in flag_map:
            kw.setdefault(flag_map[flag], []).append(arg)
    return kw

try:
    from Cython.Distutils import build_ext
    setup(
        name = NAME,
        version = VERSION,
        ext_modules = [
            Extension('_nmsg', ['_nmsg.pyx'],
                depends = [
                    'nmsg.pxi',
                    'nmsg_input.pyx',
                    'nmsg_io.pyx',
                    'nmsg_message.pyx',
                    'nmsg_msgmod.pyx',
                    'nmsg_msgtype.pyx',
                    'nmsg_output.pyx',
                    'nmsg_util.pyx',
                ],
                **pkgconfig('libnmsg')
            )
        ],
        cmdclass = {'build_ext': build_ext},
        py_modules = ['nmsg'],
    )
except ImportError:
    import os
    if os.path.isfile('_nmsg.c'):
        setup(
            name = NAME,
            version = VERSION,
            ext_modules = [ Extension('_nmsg', ['_nmsg.c'], **pkgconfig('libnmsg')) ],
            py_modules = ['nmsg'],
        )
    else:
        raise
