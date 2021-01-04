# Copyright (c) 2019 by Farsight Security, Inc.
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

try:
    # This is needed because 'spawn' is the start method in macos by default since 3.8.
    mp.set_start_method('fork')
except AttributeError:
    # Running in Python2, fork is already the start method
    pass

data = b'NMSG\x00\x02\x00\x00\x02\x1c\n.\x08\x01\x10\x0b\x18\xe2\xaa\xe5\xe0\x05%\x92\xa0\x93%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe3\xaa\xe5\xe0\x05%\xcd\x8c\xd0\x07*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe3\xaa\xe5\xe0\x05%T\xc3\xa6%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe4\xaa\xe5\xe0\x05%\xa2v\xe2\x07*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe4\xaa\xe5\xe0\x05%\xb8\xc0\xb8%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe5\xaa\xe5\xe0\x05%\x0b$\xf5\x07*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe5\xaa\xe5\xe0\x05%\x04\x14\xcd%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe6\xaa\xe5\xe0\x05%\xd4\x92\x05\x08*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe6\xaa\xe5\xe0\x05%\xe9\xdc\xdb%*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\n.\x08\x01\x10\x0b\x18\xe7\xaa\xe5\xe0\x05%\xc7\xa3\x17\x08*\x17\x08\x00\x12\x13"FSI SIE heartbeat"8\xfd\xd9\x80\xdd\x01\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08\x10\xac\x8c\xd8\xff\x08'


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
    def __init__(self, seconds=1, error_message='Timeout'):
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
        self.assertEqual(j['message']['type'], "TEXT")
        self.assertEqual(j['message']['payload'], "IkZTSSBTSUUgaGVhcnRiZWF0Ig==")

    @ignore_warnings
    def test_send_recv_filter_match(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)

        def reader():
            r = nmsg.input.open_sock('127.0.0.1', 19191)
            r.set_filter_msgtype('base', 'encode')
            j = json.loads(r.read().to_json())
            r.close()
            self.assertEqual(j['message']['type'], "TEXT")
            self.assertEqual(j['message']['payload'], "IkZTSSBTSUUgaGVhcnRiZWF0Ig==")

        p = mp.Process(target=reader)
        p.start()
        time.sleep(1)
        s = nmsg.output.open_sock('127.0.0.1', 19191)
        s.write(mlist[0])
        s.flush()
        s.close()
        p.join()

    @ignore_warnings
    def test_send_recv_filter_nomatch(self):
        ni = nmsg.nullinput()
        mlist = ni.read(data)
        r = nmsg.input.open_sock('127.0.0.1', 19192)
        r.set_filter_msgtype('base', 'email')
        s = nmsg.output.open_sock('127.0.0.1', 19192)

        def reader():
            # this should hang and process will stay alive
            # cant use signals to timeout bc cython
            with self.assertRaises(TimeoutError):
                j = json.loads(r.read().to_json())
                self.assertEqual(j['message']['type'], "TEXT")
                self.assertEqual(j['message']['payload'], "IkZTSSBTSUUgaGVhcnRiZWF0Ig==")

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
        r = nmsg.input.open_sock('127.0.0.1', 19193)
        r.set_filter_msgtype('base', 'email')
        s = nmsg.output.open_sock('127.0.0.1', 19193)

        def reader():
            try:
                with timeout(seconds=3):
                    j = json.loads(r.read().to_json())
                    r.close()
                    self.assertEqual(j['message']['type'], "TEXT")
                    self.assertEqual(j['message']['payload'], "IkZTSSBTSUUgaGVhcnRiZWF0Ig==")
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
            self.assertEqual(j['message']['type'], "TEXT")
            self.assertEqual(j['message']['payload'], "IkZTSSBTSUUgaGVhcnRiZWF0Ig==")

        num = mp.Value('d', 0)
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
        r = nmsg.input.open_sock('127.0.0.1', 19194)
        r.set_filter_msgtype('base', 'email')
        r.set_blocking_io(False)
        j = r.read()
        self.assertEqual(j, None)
        r.close()


if __name__ == "__main__":
    unittest.main()
