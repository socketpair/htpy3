from libc.stdio cimport printf, puts
from libc.stdint cimport uint64_t, int64_t, uint16_t
from posix.time cimport timeval, suseconds_t, time_t
from cpython cimport Py_INCREF, Py_DECREF

# TODO: move definitions to .pxd file

cdef extern from "htp/htp.h":
    ctypedef struct htp_connp_t
    ctypedef struct htp_cfg_t
    ctypedef timeval htp_time_t

    enum htp_stream_state_t:
        HTP_STREAM_NEW,
        HTP_STREAM_OPEN,
        HTP_STREAM_CLOSED,
        HTP_STREAM_ERROR,
        HTP_STREAM_TUNNEL,
        HTP_STREAM_DATA_OTHER,
        HTP_STREAM_STOP,
        HTP_STREAM_DATA

    enum htp_log_level_t:
        HTP_LOG_NONE,
        HTP_LOG_ERROR,
        HTP_LOG_WARNING,
        HTP_LOG_NOTICE,
        HTP_LOG_INFO,
        HTP_LOG_DEBUG,
        HTP_LOG_DEBUG2

    enum htp_file_source_t:
        HTP_FILE_MULTIPART,
        HTP_FILE_PUT

    ctypedef struct htp_log_t:
        htp_connp_t *connp
        htp_tx_t *tx
        const char *msg
        htp_log_level_t level;
        int code;
        const char *file;
        unsigned int line;

    ctypedef htp_file_data_t

    ctypedef struct bstr
    size_t bstr_len(bstr* s)
    unsigned char* bstr_ptr(bstr* s)

    ctypedef struct htp_uri_t:
        bstr *scheme
        bstr *username
        bstr *password
        bstr *hostname
        bstr *port
        # /**
        #  * Port, as number. This field will contain HTP_PORT_NONE if there was
        #  * no port information in the URI and HTP_PORT_INVALID if the port information
        #  * was invalid (e.g., it's not a number or it falls out of range.
        #  */
        int port_number
        bstr *path
        bstr *query
        bstr *fragment

    ctypedef struct htp_tx_t:
        htp_connp_t *connp
        bstr *request_method # raw
        bstr *request_uri # raw
        bstr *request_protocol # raw
        htp_uri_t *parsed_uri
        htp_uri_t *parsed_uri_raw

    ctypedef struct htp_tx_data_t:
        htp_tx_t *tx
        const unsigned char *data
        size_t len
        int is_last


    #
    # ctypedef struct htp_file_t:
    #     htp_file_source_t source
    #     bstr *filename
    #     int64_t len
    #     char *tmpname
    #     int fd
    #
    # ctypedef struct htp_file_data_t:
    #     htp_file_t *file
    #     const unsigned char *data
    #     size_t len

    htp_connp_t* htp_connp_create(htp_cfg_t *cfg)
    void htp_connp_destroy_all(htp_connp_t *connp)

    void htp_connp_open(htp_connp_t *connp, const char *client_addr, int client_port, const char *server_addr,  int server_port, htp_time_t *timestamp) nogil
    void htp_connp_close(htp_connp_t *connp, const htp_time_t *timestamp) nogil
    int htp_connp_req_data(htp_connp_t *connp, const htp_time_t *timestamp, const void *data, size_t len) nogil
    int htp_connp_res_data(htp_connp_t *connp, const htp_time_t *timestamp, const void *data, size_t len) nogil

    void htp_connp_set_user_data(htp_connp_t *connp, const void *user_data)
    void* htp_connp_get_user_data(const htp_connp_t *connp) nogil
    size_t htp_connp_req_data_consumed(htp_connp_t *connp) nogil
    size_t htp_connp_res_data_consumed(htp_connp_t *connp) nogil

    htp_cfg_t* htp_config_create()

    void htp_config_register_log(htp_cfg_t *cfg, int (*callback_fn)(htp_log_t *))
    void htp_config_set_log_level(htp_cfg_t *cfg, htp_log_level_t log_level)

    # void htp_config_register_request_file_data(htp_cfg_t *cfg, int (*callback_fn)(htp_file_data_t *))
    void htp_config_register_request_start(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_request_line(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_request_uri_normalize(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_request_header_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *))
    void htp_config_register_request_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_request_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *))
    void htp_config_register_request_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_request_trailer_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *d))
    void htp_config_register_request_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))


    void htp_config_register_response_start(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_response_line(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_response_header_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *))
    void htp_config_register_response_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_response_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *))
    void htp_config_register_response_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))
    void htp_config_register_response_trailer_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *d))
    void htp_config_register_response_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))

    void htp_config_register_transaction_complete(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_t *))

    void htp_config_set_tx_auto_destroy(htp_cfg_t *cfg, int tx_auto_destroy)
    void htp_config_destroy(htp_cfg_t *cfg)

    void *htp_tx_get_user_data(const htp_tx_t *tx) nogil
    void htp_tx_set_user_data(htp_tx_t *tx, void *user_data) nogil

    enum: HTP_OK
    enum: HTP_DECLINED

cdef int log_cb(htp_log_t *l) nogil:
    printf("HTP log: where:%s:%u code=%d msg=%s\n", l.file, l.line, l.code, l.msg)
    return HTP_OK

#########################
cdef bstr2bytes(bstr* s):
    cdef size_t l = bstr_len(s)
    cdef const char* p = <char*>bstr_ptr(s)
    return p[:l]



#########################
cdef int request_start_cb(htp_tx_t *tx) nogil:
    with gil:
        connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
        try:
            trans = connp.on_request_start()
            if trans is not None:
                Py_INCREF(trans)
                htp_tx_set_user_data(tx, <void*>trans)
                # trans.on_request_start()
            return HTP_OK
        except BaseException as e:
            connp._cbexc  = e
            return HTP_DECLINED

# TODO: will this fire when transaction aborted (i.e. connection closed) ?
cdef int transaction_complete_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_transaction_complete()
            return HTP_OK
        except BaseException as e:
            trans._cbexc = e
            return HTP_DECLINED
        finally:
            htp_tx_set_user_data(tx, NULL)
            Py_DECREF(trans)

cdef int request_line_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_request_line(bstr2bytes(tx.request_method), bstr2bytes(tx.request_uri), bstr2bytes(tx.request_protocol))
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int request_trailer_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: pass req trailer here
            trans.on_request_trailer()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED



cdef int request_uri_normalize_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: pass normalized uri here
            trans.on_request_uri_normalize()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED


cdef int request_headers_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_request_headers()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int request_body_data_cb(htp_tx_data_t *tx_data) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx_data.tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: create buffer! but.... user may store references....
            # so, just copy data :(
            trans.on_request_body_data(tx_data.data[:tx_data.len])
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx_data.tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int request_trailer_data_cb(htp_tx_data_t *tx_data) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx_data.tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: create buffer! but.... user may store references....
            # so, just copy data :(
            trans.on_request_trailer_data(tx_data.data[:tx_data.len])
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx_data.tx.connp)
            connp._cbexc = e
            return HTP_DECLINED


cdef int request_header_data_cb(htp_tx_data_t *tx_data) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx_data.tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: create buffer! but.... user may store references....
            # so, just copy data :(
            trans.on_request_header_data(tx_data.data[:tx_data.len])
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx_data.tx.connp)
            connp._cbexc = e
            return HTP_DECLINED


cdef int request_complete_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_request_complete()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

##########################################################

cdef int response_line_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: pass resp line here
            trans.on_response_line()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int response_trailer_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: pass resp trailer here
            trans.on_response_trailer()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int response_headers_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_response_headers()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int response_body_data_cb(htp_tx_data_t *tx_data) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx_data.tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: create buffer! but.... user may store references....
            # so, just copy data :(
            trans.on_response_body_data(tx_data.data[:tx_data.len])
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx_data.tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int response_trailer_data_cb(htp_tx_data_t *tx_data) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx_data.tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: create buffer! but.... user may store references....
            # so, just copy data :(
            trans.on_response_trailer_data(tx_data.data[:tx_data.len])
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx_data.tx.connp)
            connp._cbexc = e
            return HTP_DECLINED


cdef int response_header_data_cb(htp_tx_data_t *tx_data) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx_data.tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            # TODO: create buffer! but.... user may store references....
            # so, just copy data :(
            trans.on_response_header_data(tx_data.data[:tx_data.len])
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx_data.tx.connp)
            connp._cbexc = e
            return HTP_DECLINED


cdef int response_complete_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_response_complete()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED

cdef int response_start_cb(htp_tx_t *tx) nogil:
    cdef void*transdata = htp_tx_get_user_data(tx)
    if transdata is NULL:
        return HTP_OK
    with gil:
        trans = <HTPTrans>transdata
        try:
            trans.on_response_start()
            return HTP_OK
        except BaseException as e:
            connp = <HTPConnp>htp_connp_get_user_data(tx.connp)
            connp._cbexc = e
            return HTP_DECLINED


############
cdef class HTPConfig:
    cdef htp_cfg_t *cfg
    def __cinit__(self):
        self.cfg = NULL

    def __init__(self):
        cdef htp_cfg_t *cfg = htp_config_create()
        if cfg is NULL:
            raise RuntimeError("Cannot create config")
        self.cfg = cfg

        htp_config_set_tx_auto_destroy(cfg, 1)

        # TODO: не ргеать каллбэки если в коннекшене нет хэндлера.
        # Есть вариант не вызывать их из коннп в сишных коллбэках. имхо лучшее решениие
        # TODO: if (self.on_request_headers.__code__ is not HTPConn.on_request_headers.__code__):
        htp_config_set_log_level(cfg, HTP_LOG_DEBUG2)
        htp_config_register_log(cfg, log_cb)

        htp_config_register_request_start(cfg, request_start_cb)
        htp_config_register_request_line(cfg, request_line_cb)
        htp_config_register_request_uri_normalize(cfg, request_uri_normalize_cb)
        htp_config_register_request_header_data(cfg, request_header_data_cb)
        htp_config_register_request_headers(cfg, request_headers_cb)
        htp_config_register_request_body_data(cfg, request_body_data_cb)
        htp_config_register_request_trailer(cfg, request_trailer_cb)
        htp_config_register_request_trailer_data(cfg, request_trailer_data_cb)
        htp_config_register_request_complete(cfg, request_complete_cb)

        htp_config_register_response_start(cfg, response_start_cb)
        htp_config_register_response_line(cfg, response_line_cb)
        htp_config_register_response_header_data(cfg, response_header_data_cb)
        htp_config_register_response_headers(cfg, response_headers_cb)
        htp_config_register_response_body_data(cfg, response_body_data_cb)
        htp_config_register_response_trailer(cfg, response_trailer_cb)
        htp_config_register_response_trailer_data(cfg, response_trailer_data_cb)
        htp_config_register_response_complete(cfg, response_complete_cb)

        htp_config_register_transaction_complete(cfg, transaction_complete_cb)


    def __dealloc__(self):
        if self.cfg is not NULL:
            htp_config_destroy(self.cfg)
            self.cfg = NULL

# TODO: move it to __init__ to pure python!
cdef class HTPTrans:
    def __init__(self, connp):
        self.connp = connp

    def on_request_body_data(self, qwe):
        print('request_body_data DUMMY')

    def on_request_header_data(self, qwe):
        print('request_header_data DUMMY')

    def on_request_headers(self):
        print('request_headers DUMMY')

    def on_request_complete(self):
        print('request_complete DUMMY')

    def on_request_line(self, method, uri, protocol):
        print('request_line DUMMY', method, uri, protocol)

    def on_request_uri_normalize(self):
        print('request_uri_normalize DUMMY')

    def on_request_trailer_data(self, qwe):
        print('request_header_data DUMMY')

    def on_request_trailer(self):
        print('request_uri_normalize DUMMY')

    def on_response_body_data(self, qwe):
        print('response_body_data DUMMY')

    def on_response_header_data(self, qwe):
        print('response_header_data DUMMY')

    def on_response_headers(self):
        print('response_headers DUMMY')

    def on_response_complete(self):
        print('response_complete DUMMY')

    def on_response_start(self):
        print('response_start DUMMY')

    def on_response_line(self):
        print('response_line DUMMY')

    def on_response_trailer_data(self, qwe):
        print('response_header_data DUMMY')

    def on_response_trailer(self):
        print('response_uri_normalize DUMMY')

    def on_transaction_complete(self):
        print('transaction_complete DUMMY')


cdef class HTPConnp:
    cdef htp_connp_t *connp
    cdef int in_callback

    def __cinit__(self):
        self.connp = NULL
        self.in_callback = 0

    def __dealloc__(self):
        if self.connp is not NULL:
            htp_connp_destroy_all(self.connp)
            self.connp = NULL

    def __init__(self, cfg):
        cdef HTPConfig _cfg
        # htp_connp_get_last_error ?
        # htp_connp_clear_error

        if not isinstance(cfg, HTPConfig):
            raise ValueError('Only HTPConfig classes are supported')

        self._cbexc = None
        self.cfg = cfg # grab reference!

        _cfg = <HTPConfig>cfg


        cdef htp_connp_t *connp = htp_connp_create(_cfg.cfg)

        if connp is NULL:
            raise RuntimeError("Cannot create HTP connection")

        htp_connp_set_user_data(connp, <void*>self)

        self.connp = connp


    def handle_connect(self, remote_ip, remote_port, local_ip, local_port, ts=None):
        if self.in_callback:
            raise RuntimeError('It is not allowed to call this function from handle_XXX')

        cdef:
            htp_time_t tv
            htp_time_t* tvp
            int res
            double _ts
            const char*lip
            const char*rip
            uint16_t lport,rport

        if isinstance(remote_ip, unicode):
            remote_ip = remote_ip.encode('ascii') # TODO: regex check!

        if isinstance(local_ip, unicode):
            local_ip = local_ip.encode('ascii')

        if ts is None:
            tvp = NULL
        else:
            _ts = ts
            tv.tv_sec = <time_t>_ts
            tv.tv_usec = <suseconds_t>((_ts - tv.tv_sec) * 1000000)
            tvp = &tv

        lip = local_ip
        rip = remote_ip
        lport = local_port
        rport = remote_port

        self._cbexc = None
        with nogil:
            self.in_callback = 1
            htp_connp_open(self.connp, rip, rport, lip, lport, tvp)
            self.in_callback = 0
        if self._cbexc is not None:
            exc = self._cbexc
            self._cbexc = None
            raise exc

    # def push_in(self, unsigned char[:] data, ts):
    #     cdef:
    #         htp_time_t tv
    #         int res
    #     tv.tv_sec = ts // 1000000000
    #     tv.tv_usec = (ts % 1000000000) // 1000
    #     res = htp_connp_req_data(self.connp, &tv, &data[0], data.shape[0])
    #     return res
    def push_in(self, data, ts=None):
        if self.in_callback:
            raise RuntimeError('It is not allowed to call this function from handle_XXX')

        cdef:
            htp_time_t tv
            htp_time_t* tvp
            int res
            double _ts;
            const char* data_ = <const char*>data
            size_t datalen = len(data)
            size_t consumed

        if ts is None:
            tvp = NULL
        else:
            _ts = ts
            tv.tv_sec = <time_t>_ts
            tv.tv_usec = <suseconds_t>((_ts - tv.tv_sec) * 1000000)
            tvp = &tv

        self._cbexc = None
        with nogil:
            self.in_callback = 1
            res = htp_connp_req_data(self.connp, tvp, data_, datalen)
            self.in_callback = 0

        if self._cbexc is not None:
            exc = self._cbexc
            self._cbexc = None
            raise exc

        consumed = htp_connp_req_data_consumed(self.connp)
        if consumed != datalen:
            raise RuntimeError('Consumed partial data. dont know how to handle!')

        # TODO: getlasterror ?
        if res is HTP_STREAM_ERROR:
            raise RuntimeError('HTP stream error')

        if res is HTP_STREAM_DATA:
            return

        if res is HTP_STREAM_DATA_OTHER:
            raise NotImplementedError('STREAM_STATE_DATA_OTHER handling is not implemented')

        # TODO: tunnel = websocket ? sstp ?
        raise NotImplementedError('Dont know how to handle stream state {}'.format(res))


    def push_out(self, data, ts=None):
        if self.in_callback:
            raise RuntimeError('It is not allowed to call this function from handle_XXX')

        cdef:
            htp_time_t tv
            htp_time_t* tvp
            int res
            double _ts;
            const char* data_ = <const char*>data
            size_t datalen = len(data)

        if ts is None:
            tvp = NULL
        else:
            _ts = ts
            tv.tv_sec = <time_t>_ts
            tv.tv_usec = <suseconds_t>((_ts - tv.tv_sec) * 1000000)
            tvp = &tv

        self._cbexc = None
        with nogil:
            self.in_callback = 1
            res = htp_connp_res_data(self.connp, tvp, data_, datalen)
            self.in_callback = 0

        if self._cbexc is not None:
            exc = self._cbexc
            self._cbexc = None
            raise exc

        consumed = htp_connp_res_data_consumed(self.connp)
        if consumed != datalen:
            raise RuntimeError('Consumed partial data. dont know how to handle!')

        # TODO: getlasterror ?
        if res is HTP_STREAM_ERROR:
            raise RuntimeError('HTP stream error')

        if res is HTP_STREAM_DATA:
            return

        if res is HTP_STREAM_DATA_OTHER:
            raise NotImplementedError('STREAM_STATE_DATA_OTHER handling is not implemented')

        # TODO: tunnel = websocket ? sstp ?
        raise NotImplementedError('Dont know how to handle stream state {}'.format(res))

    def handle_close(self, ts=None):
        if self.in_callback:
            raise RuntimeError('It is not allowed to call this function from handle_XXX')

        cdef:
            htp_time_t tv
            htp_time_t* tvp
            double _ts;

        if ts is None:
            tvp = NULL
        else:
            _ts = ts
            tv.tv_sec = <time_t>_ts
            tv.tv_usec = <suseconds_t>((_ts - tv.tv_sec) * 1000000)
            tvp = &tv


        self._cbexc = None
        with nogil:
            self.in_callback = 1
            htp_connp_close(self.connp, tvp)
            self.in_callback = 0

        if self._cbexc is not None:
            exc = self._cbexc
            self._cbexc = None
            raise exc

    def on_request_start(self):
        print('request_start DUMMY')
        return None
