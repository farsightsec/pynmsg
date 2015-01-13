class _msgtype(object):
    def __init__(self):
        cdef const char *vname_str
        cdef const char *mname_str

        for vid from 1 <= vid <= nmsg_msgmod_get_max_vid():
            vname_str = nmsg_msgmod_vid_to_vname(vid)

            if vname_str:
                vname = str(vname_str).lower()
                v_dict = {}

                for msgtype from 1 <= msgtype <= nmsg_msgmod_get_max_msgtype(vid):
                    mname_str = nmsg_msgmod_msgtype_to_mname(vid, msgtype)

                    if mname_str:
                        mname = str(mname_str).lower()
                        mod = msgmod(vid, msgtype)
                        m_dict = {
                            '__vid':     vid,
                            '__msgtype': msgtype,
                        }
                        v_dict[mname] = type('%s_%s' % (vname, mname), (_meta_message,), m_dict)
                v_dict['_vname'] = vname
                v_dict['_vid'] = vid

                setattr(self, vname, type(vname, (object,), v_dict))

                # map 'isc' to 'base' vendor to avoid breaking code
                # upon upgrade from libnmsg 0.7 to libnmsg 0.8
                if vname == 'base' and not getattr(self, 'isc', None):
                    setattr(self, 'isc', type(vname, (object,), v_dict))
