#cython: embedsignature=True

# Copyright (c) 2009-2014 by Farsight Security, Inc.
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

import os
import socket
import time

include "nmsg.pxi"

PyEval_InitThreads()

chalias_fnames = (
    '/etc/nmsgtool.chalias',
    '/etc/nmsg.chalias',
    '/usr/local/etc/nmsg.chalias',
    '/usr/local/etc/nmsgtool.chalias'
)

nmsg_set_autoclose(False)
res = nmsg_init()
if res != nmsg_res_success:
    raise Exception, 'unable to initialize libnmsg'

include "nmsg_msgmod.pyx"
include "nmsg_message.pyx"
include "nmsg_output.pyx"
include "nmsg_msgtype.pyx"
msgtype = _msgtype()
include "nmsg_input.pyx"
include "nmsg_io.pyx"
include "nmsg_util.pyx"
