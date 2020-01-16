#!/usr/bin/env python

# Copyright (c) 2009-2019 by Farsight Security, Inc.
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

from setuptools import setup, Command
from distutils.extension import Extension
from distutils.command.clean import clean
import unittest
import os
import shutil

NAME = 'pynmsg'
VERSION = '0.5.0'


class Cleaner(clean):
    def run(self):
        clean.run(self)
        for i in ["_nmsg.c",
                  "_nmsg.h",
                  "build",
                  "__pycache__",
                  "pynmsg.egg-info",
                  "dist"]:
            print("Cleaning ", i)
            if os.path.isfile(i):
                os.unlink(i)
            elif os.path.isdir(i):
                shutil.rmtree(i)


class Test(Command):
    user_options = []
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        unittest.TextTestRunner(verbosity=1).run(
            unittest.TestLoader().discover('tests'))


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
    extensions = [Extension("_nmsg", ['_nmsg.pyx', 'sig_manager.c'],
                            extra_compile_args=["-Wno-unused-variable"],
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

    for f in ["_nmsg.c", "_nmsg.h"]:
        try:
            os.remove(f)
        except OSError:
            pass
    setup(ext_modules=cythonize(extensions),
          name=NAME,
          version=VERSION,
          py_modules=['nmsg'],
          cmdclass={'test': Test, 'clean': Cleaner},
          zip_safe=True
          )
except ImportError as e:
    import sys
    print("Cython is required. You are building with Python {}".format(sys.version_info.major))
    print(e)
