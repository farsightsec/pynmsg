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
