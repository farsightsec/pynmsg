#!/usr/bin/env python

NAME = 'pynmsg'
VERSION = '0.3.0'

from distutils.core import setup
from distutils.extension import Extension
import os

try:
    from Cython.Distutils import build_ext
    setup(
        name = NAME,
        version = VERSION,
        ext_modules = [ Extension('_nmsg', ['_nmsg.pyx'], libraries = ['nmsg'],
            depends = [ 'nmsg_input.pyx', 'nmsg_io.pyx', 'nmsg_message.pyx', 
                        'nmsg_msgmod.pyx', 'nmsg_msgtype.pyx',
                        'nmsg_output.pyx', 'nmsg_util.pyx', 'nmsg.pxi' ],
                ) ],
        cmdclass = {'build_ext': build_ext},
        py_modules = ['nmsg'],
    )
except ImportError:
    if os.path.isfile('_nmsg.c'):
        setup(
            name = NAME,
            version = VERSION,
            ext_modules = [ Extension('_nmsg', ['_nmsg.c'], libraries = ['nmsg']) ],
            py_modules = ['nmsg'],
        )
    else:
        raise
