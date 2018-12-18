#!/usr/bin/env python

# Copyright (c) 2009-2015 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import print_function

from distutils.core import setup
from distutils.extension import Extension

NAME = 'pynmsg'
VERSION = '0.4.0'


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

    pkg_config_output = subprocess.check_output(pkg_config_cmd,
                                                universal_newlines=True)

    for token in pkg_config_output.split():
        flag = token[:2]
        arg = token[2:]
        if flag in flag_map:
            kw.setdefault(flag_map[flag], []).append(arg)
    return kw

try:
    from Cython.Build import build_ext, cythonize
    from distutils.extension import Extension
    extensions = [Extension("_nmsg", ['_nmsg.pyx'],
                            depends=[
                                'nmsg.pxi',
                                'nmsg_input.pyx',
                                'nmsg_io.pyx',
                                'nmsg_message.pyx',
                                'nmsg_msgmod.pyx',
                                'nmsg_msgtype.pyx',
                                'nmsg_output.pyx',
                                'nmsg_util.pyx',
                            ],
                            **pkgconfig('libnmsg >= 0.10.0')
                            )]

    setup(ext_modules=cythonize(extensions),
          name=NAME,
          version=VERSION,
          py_modules=['nmsg']
          )
except ImportError:
    import os
    if os.path.isfile('_nmsg.c'):
        setup(
            name=NAME,
            version=VERSION,
            ext_modules=[Extension('_nmsg', ['_nmsg.c'],
                                   **pkgconfig('libnmsg >= 0.10.0'))],
            py_modules=['nmsg'],
        )
    else:
        raise
