#cython: embedsignature=True

# Copyright (c) 2023 DomainTools LLC
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

class _msgtype(object):
    def __init__(self):
        cdef const char *vname_str
        cdef const char *mname_str

        for vid in range(1, nmsg_msgmod_get_max_vid() + 1):
            vname_str = nmsg_msgmod_vid_to_vname(vid)

            if vname_str:
                vname = vname_str.decode('utf-8').lower()
                v_dict = {}

                for msgtype in range(1, nmsg_msgmod_get_max_msgtype(vid) + 1):
                    mname_str = nmsg_msgmod_msgtype_to_mname(vid, msgtype)
                    if mname_str:
                        mname = mname_str.decode('utf-8').lower()
                        mod = msgmod(vid, msgtype)
                        m_dict = {
                            '_vid': vid,
                            '_msgtype': msgtype,
                        }
                        v_dict[mname] = type(str('%s_%s' % (vname, mname)), (_meta_message,), m_dict)
                v_dict['_vname'] = vname
                v_dict['_vid'] = vid

                setattr(self, vname, type(str(vname), (object,), v_dict))

                # map 'isc' to 'base' vendor to avoid breaking code
                # upon upgrade from libnmsg 0.7 to libnmsg 0.8
                if vname == 'base' and not getattr(self, 'isc', None):
                    setattr(self, 'isc', type(str(vname), (object,), v_dict))
