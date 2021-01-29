#!/usr/bin/env python

# Copyright (c) 2009-2014, 2018-2019 by Farsight Security, Inc.
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
import nmsg
import sys

n = nmsg.input.open_sock('127.0.0.1', 8430)
o = nmsg.output.open_sock('127.0.0.1', 9430)

print('starting...')
c = 0
try:
    while True:
        if (c % 1000) == 0:
            sys.stderr.write('.')
        if (c % 10000) == 0:
            sys.stderr.write('%s' % c)

        m = n.read()
        o.write(m)
        c += 1
except Exception as e:
    print(e)

print("Processed {} messages.".format(c))

