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

def ip_pton(ip):
    try:
        return socket.inet_pton(socket.AF_INET, ip)
    except:
        return socket.inet_pton(socket.AF_INET6, ip)

def print_nmsg_header(m, out):
    tm = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(m.time_sec))
    out.write('[%s.%d] ' % (tm, m.time_nsec))
    out.write('[%d:%d %s %s] ' % (m.vid, m.msgtype,
        msgmod.vid_to_vname(m.vid),
        msgmod.msgtype_to_mname(m.vid, m.msgtype)))

    if m.has_source:
        out.write('[%.8x] ' % m.source)
    else:
        out.write('[] ')

    if m.has_operator:
        out.write('[%s] ' % m.operator)
    else:
        out.write('[] ')

    if m.has_group:
        out.write('[%s] ' % m.group)
    else:
        out.write('[] ')

    out.write('\n')
