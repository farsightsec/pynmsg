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

import select
import sys

import nmsg

def main(ip, port):
    ni = nmsg.input.open_sock(ip, port)
    fd = ni.fileno()

    p = select.poll()
    p.register(fd, select.POLLIN)

    while True:
        events = p.poll(1000)
        if events:
            m = ni.read()
            while m:
                print 'got a message'
                m = ni.read()
        else:
            print 'no messages!'

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
