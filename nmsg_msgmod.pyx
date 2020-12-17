#cython: embedsignature=True

# Copyright (c) 2009-2015, 2018-2019 by Farsight Security, Inc.
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

def msgmod_oname_to_oid(str oname):
    cdef unsigned oid
    cdef char *oname2
    t = oname.encode('ascii')
    oname2 = t
    oid = nmsg_alias_by_value(nmsg_alias_operator, oname2)
    if oid == 0:
        raise Exception, 'unknown operator name: %s' % oname
    return oid

def msgmod_grname_to_grid(str grname):
    cdef unsigned oid
    cdef char *grname2
    t = grname.encode('ascii')
    grname2 = t
    grid = nmsg_alias_by_value(nmsg_alias_group, grname2)
    if grid == 0:
        raise Exception, 'unknown group name: %s' % grname
    return grid

def msgmod_get_max_msgtype(unsigned vid):
    cdef const char *vname
    vname = nmsg_msgmod_vid_to_vname(vid)
    if vname == NULL:
        raise Exception, 'unknown vendor ID'
    else:
        return nmsg_msgmod_get_max_msgtype(vid)

def msgmod_vid_to_vname(unsigned vid):
    cdef const char *vname
    vname = nmsg_msgmod_vid_to_vname(vid)
    if vname == NULL:
        raise Exception, 'unknown vendor ID'
    else:
        return vname.decode('utf-8')

def msgmod_vname_to_vid(str vname):
    cdef unsigned vid
    cdef char *vname2
    t = vname.encode('ascii')
    vname2 = t
    vid = nmsg_msgmod_vname_to_vid(vname2)
    if vid == 0:
        raise Exception, 'unknown vendor name'
    return vid

def msgmod_msgtype_to_mname(unsigned vid, unsigned msgtype):
    cdef const char *mname
    mname = nmsg_msgmod_msgtype_to_mname(vid, msgtype)
    if mname == NULL:
        raise Exception, 'unknown message type'
    else:
        return mname.decode('utf-8')

def msgmod_mname_to_msgtype(unsigned vid, mname):
    cdef unsigned msgtype
    cdef char *mname2
    t = mname.encode('ascii')
    mname2 = t
    msgtype = nmsg_msgmod_mname_to_msgtype(vid, mname2)
    if msgtype == 0:
        raise Exception, 'unknown vendor ID or message type name'
    return msgtype

cdef class msgmod(object):
    cdef unsigned _vid
    cdef unsigned _msgtype
    cdef void *_clos
    cdef nmsg_msgmod_t _instance

    get_max_msgtype = staticmethod(msgmod_get_max_msgtype)
    vid_to_vname = staticmethod(msgmod_vid_to_vname)
    vname_to_vid = staticmethod(msgmod_vname_to_vid)
    msgtype_to_mname = staticmethod(msgmod_msgtype_to_mname)
    mname_to_msgtype = staticmethod(msgmod_mname_to_msgtype)
    msgmod_oname_to_oid = staticmethod(msgmod_oname_to_oid)
    msgmod_grname_to_grid = staticmethod(msgmod_grname_to_grid)

    def __cinit__(self, unsigned vid, unsigned msgtype):
        cdef nmsg_res res

        self._instance = nmsg_msgmod_lookup(vid, msgtype)
        if self._instance != NULL:
            res = nmsg_msgmod_init(self._instance, &self._clos)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_msgmod_init() failed'
        else:
            raise Exception, 'nmsg_msgmod_lookup() failed'

        self._vid = vid
        self._msgtype = msgtype

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_msgmod_fini(self._instance, &self._clos)

    def __str__(self):
        return '[%d:%d %s %s] message module' % (
            self._vid,
            self._msgtype,
            msgmod_vid_to_vname(self._vid),
            msgmod_msgtype_to_mname(self._vid, self._msgtype)
        )
