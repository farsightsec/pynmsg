#!/usr/bin/env python

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

import nmsg
import socket
import sys
import time

def main(addr, port, out):
    i = nmsg.input.open_sock(addr, port)

    while True:
        m = i.read()
        if not m:
            break

        nmsg.print_nmsg_header(m, out)

        for key in m.keys():
            val = m[key]
            if type(val) == list:
                for v in val:
                    out.write('%s: %s\n' % (key, repr(v)))
            else:
                out.write('%s: %s\n' % (key, repr(val)))
        out.write('\n')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.stdout)
