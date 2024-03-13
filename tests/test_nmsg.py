# Copyright (c) 2023 DomainTools LLC
# Copyright (c) 2019-2021 by Farsight Security, Inc.
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
import signal
import unittest
import nmsg
import json
import time
import os
import warnings
import multiprocessing as mp
import socket
import tempfile

try:
    # This is needed because 'spawn' is the start method in macos by default since 3.8.
    mp.set_start_method("fork")
except AttributeError:
    # Running in Python2, fork is already the start method
    pass

data = b'NMSG\x00\x02\x00\x00\x02\x1c\n.\x08\x01\x10\x0b\x18\xe2\xaa\xe5\xe0\x05%\x92\xa0\x93%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe3\xaa\xe5\xe0\x05%\xcd\x8c\xd0\x07*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe3\xaa\xe5\xe0\x05%T\xc3\xa6%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe4\xaa\xe5\xe0\x05%\xa2v\xe2\x07*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe4\xaa\xe5\xe0\x05%\xb8\xc0\xb8%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe5\xaa\xe5\xe0\x05%\x0b$\xf5\x07*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe5\xaa\xe5\xe0\x05%\x04\x14\xcd%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe6\xaa\xe5\xe0\x05%\xd4\x92\x05\x08*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe6\xaa\xe5\xe0\x05%\xe9\xdc\xdb%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe7\xaa\xe5\xe0\x05%\xc7\xa3\x17\x08*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08'

expected = {"val": '"FSI SIE heartbeat"', "b64": "IkZTSSBTSUUgaGVhcnRiZWF0Ig=="}

try:
    warnings.simplefilter("ignore", ResourceWarning)
except NameError:

    class ResourceWarning:
        pass


try:
    raise TimeoutError()
except NameError:

    class TimeoutError:
        pass

except:
    pass


class timeout:
    def __init__(self, seconds=1, error_message="Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


def ignore_warnings(test_func):
    # multiprocessing+unittest seems to have issues with tracking open/close fd's
    # so we suppress those using this decorator
    # https://stackoverflow.com/questions/26563711/disabling-python-3-2-resourcewarning
    def do_test(self, *args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            test_func(self, *args, **kwargs)

    return do_test


class fileobj(object):
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd


class TestNMSG(unittest.TestCase):
    def test_nullinput(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)

        assert len(mlist) == 10
        j = json.loads(mlist[0].to_json())
        self.assertEqual(j["message"]["type"], "TEXT")
        self.assertEqual(j["message"]["payload"], expected)

    @ignore_warnings
    def test_send_recv_filter_match(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)

        def reader():
            r = nmsg.input.open_sock("127.0.0.1", 19191)
            r.set_filter_msgtype("base", "encode")
            j = json.loads(r.read().to_json())
            r.close()
            self.assertEqual(j["message"]["type"], "TEXT")
            self.assertEqual(j["message"]["payload"], expected)

        p = mp.Process(target=reader)
        p.start()
        time.sleep(1)
        s = nmsg.output.open_sock("127.0.0.1", 19191)
        s.write(mlist[0])
        s.flush()
        s.close()
        p.join()

    @ignore_warnings
    def test_send_recv_filter_nomatch(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)
        r = nmsg.input.open_sock("127.0.0.1", 19192)
        r.set_filter_msgtype("base", "email")
        s = nmsg.output.open_sock("127.0.0.1", 19192)

        def reader():
            # this should hang and process will stay alive
            # cant use signals to timeout bc cython
            with self.assertRaises(TimeoutError):
                j = json.loads(r.read().to_json())
                self.assertEqual(j["message"]["type"], "TEXT")
                self.assertEqual(j["message"]["payload"], expected)

        p = mp.Process(target=reader)
        p.start()
        s.write(mlist[0])
        s.flush()
        time.sleep(2)
        self.assertEqual(p.is_alive(), True)
        p.terminate()
        r.close()
        s.close()

    @unittest.skip("signals still tricky with cython")
    def test_send_recv(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)
        r = nmsg.input.open_sock("127.0.0.1", 19193)
        r.set_filter_msgtype("base", "email")
        s = nmsg.output.open_sock("127.0.0.1", 19193)

        def reader():
            try:
                with timeout(seconds=3):
                    j = json.loads(r.read().to_json())
                    r.close()
                    self.assertEqual(j["message"]["type"], "TEXT")
                    self.assertEqual(j["message"]["payload"], expected)
            except TimeoutError:
                r.close()
                assert False, "timeout occurred but should not have"

        p = Process(target=reader).start()
        s.write(mlist[0])
        s.flush()
        s.close()
        p.join()

    @ignore_warnings
    def test_write_read(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)

        _r, _w = os.pipe()
        _rfo = fileobj(_r)
        _wfo = fileobj(_w)

        def reader(num):
            r = nmsg.input.open_file(_rfo)
            num.value = 1
            j = json.loads(r.read().to_json())
            r.close()
            self.assertEqual(j["message"]["type"], "TEXT")
            self.assertEqual(j["message"]["payload"], expected)

        num = mp.Value("d", 0)
        p = mp.Process(target=reader, args=(num,))
        p.start()
        s = nmsg.output.open_file(_wfo)
        while num.value == 0:
            s.write(mlist[0])
        s.flush()
        p.join()
        s.close()

    @ignore_warnings
    def test_send_recv_nonblocking(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)
        r = nmsg.input.open_sock("127.0.0.1", 19194)
        r.set_filter_msgtype("base", "email")
        r.set_blocking_io(False)
        j = r.read()
        self.assertEqual(j, None)
        r.close()

    @ignore_warnings
    def test_message_http(self):
        # See https://github.com/farsightsec/nmsg/blob/master/nmsg/base/http.proto
        data = {
            "type": 1,
            "srcip": "0.0.0.0",
            "dstip": "255.255.255.255",
            "request": "there is no cow level",
            "srcport": 0,
            "dstport": 65534,
        }

        m = nmsg.msgtype.isc.http()
        m["type"] = data["type"]  # sinkhole
        m["srcip"] = data["srcip"]
        m["dstip"] = data["dstip"]
        m["request"] = data["request"]
        m["srcport"] = data["srcport"]
        m["dstport"] = data["dstport"]

        def reader():
            r = nmsg.input.open_sock("127.0.0.1", 19191)
            j = json.loads(r.read().to_json())
            r.close()
            self.assertEqual(j["message"]["type"], "sinkhole")
            self.assertEqual(j["message"]["srcip"], data["srcip"])
            self.assertEqual(j["message"]["dstip"], data["dstip"])
            self.assertEqual(j["message"]["request"], data["request"])
            self.assertEqual(j["message"]["srcport"], data["srcport"])
            self.assertEqual(j["message"]["dstport"], data["dstport"])

        p = mp.Process(target=reader)
        p.start()
        time.sleep(1)

        s = nmsg.output.open_sock("127.0.0.1", 19191)
        s.write(m)
        s.flush()
        s.close()
        p.join()

    @ignore_warnings
    def test_message_dnsqr(self):
        # See https://github.com/farsightsec/nmsg/blob/master/nmsg/base/dnsqr.proto
        data = {
            "type": "TCP",
            "query_ip": "0000::0000",
            "response_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "proto": 42,
            "query_port": 1,
            "response_port": 65534,
            "id": 12,
            "response_packet": b"\xde\xad\xbe\xef",
            "udp_checksum": "CORRECT",
            "response_time_sec": [123],
            "response_time_nsec": [256],
            "resolver_address_zeroed": False,
        }

        m = nmsg.msgtype.base.dnsqr()
        m["type"] = data["type"]
        m["query_ip"] = data["query_ip"]
        m["response_ip"] = data["response_ip"]
        m["proto"] = data["proto"]
        m["query_port"] = data["query_port"]
        m["response_port"] = data["response_port"]
        m["id"] = data["id"]
        m["response_packet"] = data["response_packet"]
        m["udp_checksum"] = data["udp_checksum"]
        m["response_time_sec"] = data["response_time_sec"]
        m["response_time_nsec"] = data["response_time_nsec"]
        m["resolver_address_zeroed"] = data["resolver_address_zeroed"]

        def reader():
            r = nmsg.input.open_sock("127.0.0.1", 19191)
            j = json.loads(r.read().to_json())
            r.close()
            self.assertEqual(j["message"]["type"], data["type"])

            actual_ip = socket.inet_pton(socket.AF_INET6, j["message"]["query_ip"])
            expected_ip = socket.inet_pton(socket.AF_INET6, data["query_ip"])
            self.assertEqual(actual_ip, expected_ip)

            actual_ip = socket.inet_pton(socket.AF_INET6, j["message"]["response_ip"])
            expected_ip = socket.inet_pton(socket.AF_INET6, data["response_ip"])
            self.assertEqual(actual_ip, expected_ip)

            self.assertEqual(j["message"]["proto"], str(data["proto"]))
            self.assertEqual(j["message"]["query_port"], data["query_port"])
            self.assertEqual(j["message"]["response_port"], data["response_port"])
            self.assertEqual(j["message"]["id"], data["id"])
            self.assertEqual(j["message"]["response_packet"], ["3q2+7w=="])
            self.assertEqual(j["message"]["udp_checksum"], data["udp_checksum"])
            self.assertEqual(
                j["message"]["response_time_sec"], data["response_time_sec"]
            )
            self.assertEqual(
                j["message"]["response_time_nsec"], data["response_time_nsec"]
            )
            self.assertEqual(
                j["message"]["resolver_address_zeroed"], data["resolver_address_zeroed"]
            )

        p = mp.Process(target=reader)
        p.start()
        time.sleep(1)

        s = nmsg.output.open_sock("127.0.0.1", 19191)
        s.write(m)
        s.flush()
        s.close()
        p.join()

    @ignore_warnings
    def test_input_repr_should_not_raise(self):
        with tempfile.NamedTemporaryFile(
            prefix="test-data-", dir="/tmp", delete=True
        ) as f:
            f.write(data)
            f.flush()
            nif = nmsg.input_open_file(f.name)
            try:
                nif.__repr__()
            except Exception:
                self.fail("input_open_file then __repr__() failed")
            nif.close()


if __name__ == "__main__":
    unittest.main()
