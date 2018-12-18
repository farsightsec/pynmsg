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

import sys
import time

import nmsg

if len(sys.argv) == 1:
    o = nmsg.output.open_sock('127.0.0.1', 9430)
elif len(sys.argv) == 3:
    o = nmsg.output.open_sock(sys.argv[1], int(sys.argv[2]))
else:
    sys.stderr.write('Usage: %s [<ADDR> <PORT>]\n' % sys.argv[0])
    sys.exit(1)

m = nmsg.msgtype.isc.encode()

iterations = 3

def send(e_type, e_payload):
    t = time.time()
    m.time_sec = int(t)
    m.time_nsec = int((t - int(t)) * 1E9)

    m['type'] = e_type
    m['payload'] = e_payload
    o.write(m)

# TEXT
for i in range(0, iterations):
    hello = 'hello world %s' % i
    send('TEXT', hello)
print 'sent TEXT-encoded payloads'

# JSON
try:
    import json
    hello = { 'hello': 'world', 'foo': 'bar' }
    for i in range(0, iterations):
        hello['id'] = i
        send('JSON', json.dumps(hello))
    print 'sent JSON-encoded payloads'
except ImportError:
    print 'no JSON support'

# YAML
try:
    import yaml
    hello = { 'hello': 'world', 'foo': 'baz' }
    for i in range(0, iterations):
        hello['id'] = i
        send('YAML', yaml.dump(hello))
    print 'sent YAML-encoded payloads'
except ImportError:
    print 'no YAML support'

# MSGPACK
try:
    import msgpack
    hello = { 'hello': 'world', 'foo': 'q\x00\x00x' }
    for i in range(0, iterations):
        hello['id'] = i
        send('MSGPACK', msgpack.dumps(hello))
    print 'sent MSGPACK-encoded payloads'
except ImportError:
    print 'no MSGPACK support'

# XML - dummy
for i in range(0, iterations):
    send('XML', '<xml/>')
print 'sent dummy XML-encoded payloads'
