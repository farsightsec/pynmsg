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

def message_from_json(s):
    return _json_message(s)

cdef class message(object):
    cdef msgmod _mod
    cdef nmsg_message_t _instance
    cdef bool changed
    cdef readonly int vid
    cdef readonly int msgtype
    cdef public long time_sec
    cdef public int time_nsec
    cdef public long source
    cdef public bytes operator
    cdef public bytes group
    cdef public bool has_source
    cdef public bool has_operator
    cdef public bool has_group

    cdef readonly object fields
    cdef readonly object field_types
    cdef readonly object field_names

    def __cinit__(self):
        self._instance = NULL
        self._mod = None
        self.vid = 0
        self.msgtype = 0
        self.has_source = False
        self.has_operator = False
        self.has_group = False
        self.changed = False

    def __init__(self, unsigned vid, unsigned msgtype):
        self.vid = vid
        self.msgtype = msgtype
        self._mod = msgmod(self.vid, self.msgtype)
        self._instance = nmsg_message_init(self._mod._instance)
        if self._instance == NULL:
            raise Exception, 'nmsg_message_init() failed'

        self.load_message()

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_message_destroy(&self._instance)

    cdef reinit(self):
        if self._mod == None:
            self._mod = msgmod(self.vid, self.msgtype)
        if self._instance == NULL:
            self._instance = nmsg_message_init(self._mod._instance)
            if self._instance == NULL:
                raise Exception, 'nmsg_message_init() failed'
            self.changed = True

    cdef set_instance(self, nmsg_message_t instance):
        cdef const char *a
        cdef timespec ts
        cdef uint32_t u

        if self._instance != NULL:
            nmsg_message_destroy(&self._instance)
        self._instance = instance

        self.vid = nmsg_message_get_vid(instance)
        self.msgtype = nmsg_message_get_msgtype(instance)

        nmsg_message_get_time(instance, &ts)
        self.time_sec = ts.tv_sec
        self.time_nsec = ts.tv_nsec

        u = nmsg_message_get_source(instance)
        if u != 0:
            self.has_source = True
            self.source = u

        u = nmsg_message_get_operator(instance)
        if u != 0:
            self.has_operator = True
            a = nmsg_alias_by_key(nmsg_alias_operator, u)
            if a != NULL:
                self.operator = a
            else:
                self.operator = b'<UNKNOWN>'
        else:
            self.operator = None

        u = nmsg_message_get_group(instance)
        if u != 0:
            self.has_group = True
            a = nmsg_alias_by_key(nmsg_alias_group, u)
            if a != NULL:
                self.group = a
            else:
                self.group = b'<UNKNOWN>'
        else:
            self.group = None

        self.load_message()

    cdef sync_fields(self):
        cdef timespec ts
        cdef unsigned u

        if self._instance == NULL:
            raise Exception, 'message not initialized'

        ts.tv_sec = self.time_sec
        ts.tv_nsec = self.time_nsec
        nmsg_message_set_time(self._instance, &ts)

        if self.has_source:
            nmsg_message_set_source(self._instance, self.source)
        else:
            nmsg_message_set_source(self._instance, 0)

        if self.has_operator:
            u = nmsg_alias_by_value(nmsg_alias_operator, self.operator)
            nmsg_message_set_operator(self._instance, u)
        else:
            nmsg_message_set_operator(self._instance, 0)

        if self.has_group:
            u = nmsg_alias_by_value(nmsg_alias_group, self.group)
            nmsg_message_set_group(self._instance, u)
        else:
            nmsg_message_set_group(self._instance, 0)

    cdef load_message(self):
        cdef nmsg_res res
        cdef size_t n_fields
        cdef const char *field_name
        cdef nmsg_msgmod_field_type field_type
        cdef unsigned field_flags

        cdef unsigned val_enum
        cdef const char *str_enum
        cdef int val_bool
        cdef uint32_t val_uint32
        cdef uint64_t val_uint64
        cdef int32_t val_int32
        cdef int64_t val_int64
        cdef double val_double
        cdef uint8_t *data
        cdef size_t data_len

        self.fields = {}
        self.field_types = {}
        self.field_names = set()

        res = nmsg_message_get_num_fields(self._instance, &n_fields)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_message_get_num_fields() failed'

        for field_idx from 0 <= field_idx < n_fields:
            res = nmsg_message_get_field_name(self._instance, field_idx, &field_name)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_field_name() failed'

            field_name_dec = field_name.decode('utf-8')
            self.field_names.add(field_name_dec)

            res = nmsg_message_get_field_type_by_idx(self._instance, field_idx, &field_type)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_field_type_by_idx() failed'

            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_num_field_values_by_idx() failed'

            val_list = []
            val_idx = 0

            while True:
                res = nmsg_message_get_field_by_idx(self._instance, field_idx, val_idx, <void **> &data, &data_len)
                if res != nmsg_res_success:
                    break
                val_idx += 1
                if field_type == nmsg_msgmod_ft_enum:
                    val_enum = (<unsigned *> data)[0]
                    res = nmsg_message_enum_value_to_name_by_idx(self._instance, field_idx, val_enum, &str_enum)
                    if res == nmsg_res_success:
                        val_list.append(str_enum.decode('utf-8'))

                    else:
                        val_list.append(val_enum)

                elif field_type == nmsg_msgmod_ft_bytes:
                    val_list.append(data[:data_len])

                elif field_type == nmsg_msgmod_ft_string or field_type == nmsg_msgmod_ft_mlstring:
                    if data_len > 0 and data[data_len - 1] == '\x00':
                        data_len -= 1
                    val_list.append(data[:data_len])

                elif field_type == nmsg_msgmod_ft_ip:
                    ip = data[:data_len]
                    if data_len == 4:
                        val_list.append(socket.inet_ntop(socket.AF_INET, ip))
                    elif data_len == 16:
                        val_list.append(socket.inet_ntop(socket.AF_INET6, ip))

                elif field_type == nmsg_msgmod_ft_uint16 or field_type == nmsg_msgmod_ft_uint32:
                    val_uint32 = (<uint32_t *> data)[0]
                    val_list.append(val_uint32)

                elif field_type == nmsg_msgmod_ft_uint64:
                    val_uint64 = (<uint64_t *> data)[0]
                    val_list.append(val_uint64)

                elif field_type == nmsg_msgmod_ft_int16 or field_type == nmsg_msgmod_ft_int32:
                    val_int32 = (<int32_t *> data)[0]
                    val_list.append(val_int32)

                elif field_type == nmsg_msgmod_ft_int64:
                    val_int64 = (<int64_t *> data)[0]
                    val_list.append(val_int64)

                elif field_type == nmsg_msgmod_ft_double:
                    val_double = (<double *> data)[0]
                    val_list.append(val_double)

                elif field_type == nmsg_msgmod_ft_bool:
                    val_bool = (<int *> data)[0]
                    val_list.append(val_bool)

            res = nmsg_message_get_field_flags_by_idx(self._instance, field_idx, &field_flags)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_field_flags_by_idx() failed'
            if len(val_list) > 0:
                if field_flags & NMSG_MSGMOD_FIELD_REPEATED:
                    self.fields[field_name_dec] = val_list
                else:
                    self.fields[field_name_dec] = val_list[0]
            self.field_types[field_name_dec] = field_type

    cdef sync_message(self):
        cdef nmsg_res res

        cdef nmsg_msgmod_field_type field_type

        cdef unsigned val_enum
        cdef char *str_enum
        cdef int val_bool
        cdef uint16_t val_uint16
        cdef uint32_t val_uint32
        cdef uint64_t val_uint64
        cdef int16_t val_int16
        cdef int32_t val_int32
        cdef int64_t val_int64
        cdef double val_double
        cdef char *val_buf
        cdef Py_ssize_t val_buf_len
        cdef uint8_t *data
        cdef size_t data_len

        if self._instance == NULL:
            self.reinit()

        for field_name in self.fields:
            field_type = self.field_types[field_name]

            if type(self.fields[field_name]) == list:
                fields = self.fields[field_name]
            else:
                fields = [ self.fields[field_name] ]

            for i in range(0, len(fields)):
                if type(fields[i]) == bytes:
                    fields_enc = fields[i]
                else:
                    fields_enc = fields[i].encode('utf-8')
                if field_type == nmsg_msgmod_ft_enum:
                    if type(fields[i]) == int:
                        val_enum = fields_enc
                        data = <uint8_t *> &val_enum
                        data_len = sizeof(val_enum)
                    elif type(fields[i]) == str or type(fields[i]) == unicode:
                        tmp = field_name.encode('utf-8')
                        res = nmsg_message_enum_name_to_value(self._instance, tmp,
                                                              fields_enc, &val_enum)
                        if res != nmsg_res_success:
                            raise Exception, 'unknown enum value for field_name=%s: %s' % (field_name, fields[i])
                        data = <uint8_t *> &val_enum
                        data_len = sizeof(val_enum)
                    else:
                        raise Exception, 'unhandled python enum type: %s' % type(fields[i])

                elif field_type == nmsg_msgmod_ft_bytes:
                    data = fields_enc
                    data_len = len(data)

                elif field_type == nmsg_msgmod_ft_string or field_type == nmsg_msgmod_ft_mlstring:
                    tmp_py_string = fields_enc + '\x00'

                    data = tmp_py_string
                    data_len = len(data)

                elif field_type == nmsg_msgmod_ft_ip:
                    try:
                        ip = socket.inet_pton(socket.AF_INET, fields[i])
                    except:
                        ip = socket.inet_pton(socket.AF_INET6, fields[i])
                    data = ip
                    data_len = len(data)


                elif field_type == nmsg_msgmod_ft_uint16:
                    val_uint16 = fields_enc
                    data = <uint8_t *> &val_uint16
                    data_len = sizeof(val_uint16)

                elif field_type == nmsg_msgmod_ft_int16:
                    val_int16 = fields_enc
                    data = <uint8_t *> &val_int16
                    data_len = sizeof(val_int16)

                elif field_type == nmsg_msgmod_ft_uint32:
                    val_uint32 = fields_enc
                    data = <uint8_t *> &val_uint32
                    data_len = sizeof(val_uint32)

                elif field_type == nmsg_msgmod_ft_int32:
                    val_int32 = fields_enc
                    data = <uint8_t *> &val_int32
                    data_len = sizeof(val_int32)

                elif field_type == nmsg_msgmod_ft_uint64:
                    val_uint64 = fields_enc
                    data = <uint8_t *> &val_uint64
                    data_len = sizeof(val_uint64)

                elif field_type == nmsg_msgmod_ft_int64:
                    val_int64 = fields_enc
                    data = <uint8_t *> &val_int64
                    data_len = sizeof(val_int64)

                elif field_type == nmsg_msgmod_ft_double:
                    val_double = fields_enc
                    data = <uint8_t *> &val_double
                    data_len = sizeof(val_double)

                elif field_type == nmsg_msgmod_ft_bool:
                    val_bool = fields_enc
                    data = <uint8_t *> &val_bool
                    data_len = sizeof(int)

                else:
                    raise Exception, 'unknown field_type'

                tmp = field_name.encode('utf-8')
                res = nmsg_message_set_field(self._instance, tmp, i, data, data_len)
                if res != nmsg_res_success:
                    raise Exception, 'nmsg_message_set_field() failed'

        self.changed = False

    def __contains__(self, key):
        return key in self.fields

    def __getitem__(self, key):
        return self.fields[key]

    def __setitem__(self, key, value):
        if key in self.field_names:
            self.fields[key] = value
            self.changed = True
        else:
            raise KeyError(key)

    def __repr__(self):
        return repr(self.fields)

    def keys(self):
        return self.fields.keys()

    from_json = staticmethod(message_from_json)

    def to_json(self):
        cdef nmsg_res res
        cdef char *s

        self.sync_message()
        res = nmsg_message_to_json(self._instance, &s)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_message_to_json() failed: %s' % nmsg_res_lookup(res)

        rval = s
        free(s)
        return rval

cdef class _recv_message(message):
    def __init__(self):
        pass

cdef class _meta_message(message):
    def __init__(self):
        message.__init__(self, self.__vid, self.__msgtype)

cdef class _json_message(message):
    def __init__(self, bytes json):
        cdef nmsg_res res
        cdef char *s

        s = json
        with nogil:
            res = nmsg_message_from_json(s, &self._instance)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_message_from_json() failed: %s' % nmsg_res_lookup(res)

        self._mod = msgmod(nmsg_message_get_vid(self._instance),
                nmsg_message_get_msgtype(self._instance))
        self.load_message()
