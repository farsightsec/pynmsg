#cython: embedsignature=True

# Copyright (c) 2023 DomainTools LLC
# Copyright (c) 2009-2015, 2018-2021 by Farsight Security, Inc.
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
import threading

def _cstr2str(x):
    t = x.decode('ascii')
    return t

def input_open_file(obj):
    if type(obj) == str:
        obj = open(obj)
    i = input()
    i._open_file(obj)
    return i

def input_open_json(obj):
    if type(obj) == str:
        obj = open(obj)
    i = input()
    i._open_json(obj)
    return i

def input_open_sock(addr, port):
    obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    obj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        obj.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1048576)
    except socket.error:
        pass
    obj.bind((addr, int(port)))
    i = input()
    i._open_sock(obj)
    return i

cdef class nullinput(object):
    cdef nmsg_input_t _instance
    cdef object lock

    def __cinit__(self):
        self._instance = nmsg_input_open_null()

    def __init__(self):
        self.lock = threading.Lock()

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_input_close(&self._instance)

    def __repr__(self):
        return 'nmsg nullinput object _instance=0x%x' % <uint64_t> self._instance

    def read(self, bytes buf, tv=None):
        cdef nmsg_res res
        cdef nmsg_message_t *_msgarray
        cdef size_t n_msg
        cdef _recv_message msg
        cdef timespec ts
        cdef timespec *tsp
        msg_list = []

        if self._instance == NULL:
            raise Exception, 'object not initialized'

        cdef uint8_t * buf_ptr = <uint8_t *> buf
        cdef size_t buf_len = len(buf)

        if tv is not None:
            if not isinstance(tv, numbers.Real):
                raise ValueError('tv must be a real number')
            ts.tv_sec = int(tv)
            ts.tv_nsec = tv - int(tv)
            tsp = &ts
        else:
            tsp = NULL

        with self.lock:
            with nogil:
                res = nmsg_input_read_null(self._instance, buf_ptr, buf_len, tsp, &_msgarray, &n_msg)

        if res == nmsg_res_success:
            for i in range(n_msg):
                msg = _recv_message()
                msg.set_instance(_msgarray[i])
                msg_list.append(msg)
            free(_msgarray)
        else:
            raise Exception, 'nmsg_input_null() failed: %s' % _cstr2str(nmsg_res_lookup(res))

        return msg_list

cdef class input(object):
    cdef nmsg_input_t _instance
    cdef object fileobj
    cdef str input_type
    cdef bool blocking_io
    cdef object lock

    open_file = staticmethod(input_open_file)
    open_json = staticmethod(input_open_json)
    open_sock = staticmethod(input_open_sock)

    def __cinit__(self):
        self._instance = NULL
        self.lock = threading.Lock()

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_input_close(&self._instance)

    def __init__(self):
        self.blocking_io = True

    def __repr__(self):
        return 'nmsg input object type=%s _instance=0x%x' % (self.input_type, <uint64_t> self._instance)

    cpdef _open_file(self, fileobj):
        self.fileobj = fileobj
        self._instance = nmsg_input_open_file(fileobj.fileno())
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_file() failed'
        self.input_type = 'file'

    cpdef _open_json(self, fileobj):
        cdef int fileno = fileobj.fileno()
        self.fileobj = fileobj
        with nogil:
            self._instance = nmsg_input_open_json(fileno)
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_json() failed'
        self.input_type = 'json'

    cpdef _open_sock(self, fileobj):
        self.fileobj = fileobj
        self._instance = nmsg_input_open_sock(fileobj.fileno())
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_file() failed'
        self.input_type = 'socket'

    def fileno(self):
        return self.fileobj.fileno()

    def close(self):
        nmsg_input_close(&self._instance)
        self._instance = NULL

    def read(self):
        cdef int err
        cdef nmsg_res res
        cdef nmsg_message_t _msg
        cdef _recv_message msg

        if self._instance == NULL:
            raise Exception, 'object not initialized'

        res = nmsg_res_failure

        while res != nmsg_res_success:
            with self.lock:
                with nogil:
                    res = nmsg_input_read(self._instance, &_msg)
            if res == nmsg_res_success:
                msg = _recv_message()
                msg.set_instance(_msg)
                return msg
            elif res == nmsg_res_eof:
                return None
            elif res == nmsg_res_again:
                err = PyErr_CheckSignals()
                if err != 0:
                    if PyErr_ExceptionMatches(KeyboardInterrupt):
                        raise KeyboardInterrupt
                elif self.blocking_io is False:
                    return None
                continue
            else:
                raise Exception, 'nmsg_input_read() xfailed: %s' % _cstr2str(nmsg_res_lookup(res))
        
    def set_filter_msgtype(self, vid, msgtype):
        if self._instance == NULL:
            raise Exception, 'object not initialized'
        if type(vid) == str:
            vid = msgmod_vname_to_vid(vid)
        if type(msgtype) == str:
            msgtype = msgmod_mname_to_msgtype(vid, msgtype)
        nmsg_input_set_filter_msgtype(self._instance, vid, msgtype)

    def set_filter_source(self, unsigned source):
        if self._instance == NULL:
            raise Exception, 'object not initialized'
        nmsg_input_set_filter_source(self._instance, source)

    def set_filter_operator(self, str s_operator):
        cdef unsigned operator

        if self._instance == NULL:
            raise Exception, 'object not initialized'
        # oname_to_oid will raise an exception if s_operator is not in the nmsg.opalias file
        operator = msgmod.oname_to_oid(s_operator)
        nmsg_input_set_filter_operator(self._instance, operator)

    def set_filter_group(self, str s_group):
        cdef unsigned group

        if self._instance == NULL:
            raise Exception, 'object not initialized'
        # Get the the group id from the nmsg.gralias file, raise Exception if the group name is not in the file
        group = msgmod.grname_to_grid(s_group)
        nmsg_input_set_filter_group(self._instance, group)

    def set_blocking_io(self, bool flag):
        cdef nmsg_res res

        res = nmsg_input_set_blocking_io(self._instance, flag)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_input_set_blocking_io() failed'
        self.blocking_io = flag
