import asyncio
import shutil
import tempfile
import time

from htpy3 import HTPConnp, HTPConfig, HTPTrans

cfg = HTPConfig()


@asyncio.coroutine
def conn_handler(localreader: asyncio.StreamReader, localwriter: asyncio.StreamWriter):
    (remote_reader, remote_writer) = yield from asyncio.open_connection('www.yandex.ru', 80)
    MyHTTPSrv(localreader, localwriter, remote_reader, remote_writer)


# TODO: timeouts!
class MyHTTPSrv(HTPConnp):
    def __init__(self, localreader: asyncio.StreamReader, localwriter: asyncio.StreamWriter,
                 remotereader: asyncio.StreamReader, remotewriter: asyncio.StreamWriter):
        super().__init__(cfg)
        self.localreader = localreader
        self.localwriter = localwriter
        self.remotereader = remotereader
        self.remotewriter = remotewriter
        self.responses = asyncio.Queue()
        # https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.BaseEventLoop.create_task
        # asyncio callback
        print("connection_made")
        (rip, rport) = localwriter.transport.get_extra_info('peername')
        (lip, lport) = localwriter.transport.get_extra_info('sockname')
        self.handle_connect(rip, rport, lip, lport, time.monotonic())


        # TODO: make racy megatask
        asyncio.get_event_loop().create_task(self.local_writer_loop())  # TODO: returns task?...
        asyncio.get_event_loop().create_task(self.local_reader_loop())  # TODO: returns task?...
        asyncio.get_event_loop().create_task(self.remote_reader_loop())  # TODO: returns task?...

    @asyncio.coroutine
    def local_writer_loop(self):
        try:
            while True:
                trans = yield from self.responses.get()
                if trans is None:
                    break
                yield from trans.get_result()

        finally:
            # TODO: check libhtp state
            # TODO: properly abort  waiting tasks on that connection and abrupt it!
            self.handle_close(time.monotonic())
            self.localwriter.close()
            self.remotewriter.close()

    @asyncio.coroutine
    def local_reader_loop(self):
        try:
            while True:
                data = yield from self.localreader.read(65536)
                if not data:
                    break
                self.push_request_data(data, time.monotonic())
                try:
                    yield from self.remotewriter.drain()
                except ConnectionResetError:
                    print('Remote has reset connection')
                    break
        finally:
            # TODO: check libhtp state
            # TODO: properly abort  waiting tasks on that connection and abrupt it!
            self.responses.put_nowait(None)
            self.handle_close(time.monotonic())
            self.localwriter.close()

    @asyncio.coroutine
    def remote_reader_loop(self):
        try:
            while True:
                data = yield from self.remotereader.read(65536)
                if not data:
                    break
                self.push_response_data(data, time.monotonic())
                try:
                    yield from self.localwriter.drain()
                except ConnectionResetError:
                    print('Remote has reset connection')
                    break
        finally:
            # TODO: check libhtp state
            # TODO: properly abort  waiting tasks on that connection and abrupt it!
            self.responses.put_nowait(None)
            self.handle_close(time.monotonic())
            self.localwriter.close()

    def on_request_start(self):
        print('on_request_start')
        trans = MyTransaction(self)
        self.responses.put_nowait(trans)
        return trans


class MyTransaction(HTPTrans):
    def __init__(self, connp: MyHTTPSrv):
        super().__init__()
        self.request_splice = False
        self.response_splice_mode = False
        self.orig_response_chunks = []
        self.connp = connp
        self.may_start_responding = asyncio.Future()
        self.response_complete = asyncio.Future()
        self.banpage = None
        self.transaction_complete = False
        self.reqbodytmpfile = tempfile.SpooledTemporaryFile()
        self.responsetmpfile = tempfile.SpooledTemporaryFile()
        self.last_req_unsent_byte = None

    def write_banpage(self):
        response = self.banpage
        d = response.encode('utf-8')
        # simulate data from remoteserver
        self.connp.localwriter.write(b'\r\n'.join([
            b'HTTP/1.1 403 Forbidden',
            'Content-Length: {}'.format(len(d)).encode('ascii'),
            # required, since we also close remote connection. closing because only partial req is sent
            b'Connection: close',
            b'',
            d,
        ]))
        self.connp.remotewriter.close()
        self.connp.localwriter.close()
        self.response_complete.set_result(None)

    @asyncio.coroutine
    def get_result(self):
        yield from self.may_start_responding
        self.reqbodytmpfile.close()
        if self.banpage is not None:
            self.write_banpage()
            return
        print('response should be written. waiting')
        yield from self.response_complete
        self.responsetmpfile.close()

    def on_response_line(self, line, statusnum):
        # TODO: on invalid line there will not be \r\n actually.
        if not line:
            return
        self.responsetmpfile.write(line)
        self.responsetmpfile.write(b'\r\n')
        # there is nothing to scan in response line...

    def on_response_header_data(self, data):
        if not data:
            return
        self.responsetmpfile.write(data)

    def on_response_headers(self):
        if True is False:
            # if banned by content-type of response
            self.banpage = 'banned by response headers'
            self.write_banpage()
            return

        if True is False:
            # if allowed by some content-type
            self.response_splice_mode = True
            self.responsetmpfile.seek(0)
            shutil.copyfileobj(self.responsetmpfile, self.connp.localwriter, 65536)
            self.responsetmpfile.truncate(0)
            return

    def on_response_body_data(self, data):
        if not data:
            return

        if self.banpage is not None:
            # may happen if response and bad headers are send in one big chunk
            return

        if self.response_splice_mode:
            self.connp.localwriter.write(data)
            return

        if True is False:
            self.response_splice_mode = True
            self.responsetmpfile.seek(0)
            shutil.copyfileobj(self.responsetmpfile, self.connp.localwriter, 65536)
            self.responsetmpfile.truncate(0)
            self.connp.localwriter.write(data)
            return

        if True is False:
            self.banpage = 'Banned in streaming mode'
            self.write_banpage()
            return

        self.responsetmpfile.write(data)

    def on_response_trailer_data(self, data):
        if not data:
            return

        if self.banpage is not None:
            # may happen if response and bad headers are send in one big chunk
            return

        if self.response_splice_mode:
            self.connp.localwriter.write(data)
            return

        self.responsetmpfile.write(data)

    def on_response_complete(self):
        if self.banpage is not None:
            return
        if self.response_splice_mode:
            return

        if True is False:
            self.banpage = 'Banned based on full request data'
            self.write_banpage()
            return

        self.responsetmpfile.seek(0)
        shutil.copyfileobj(self.responsetmpfile, self.connp.localwriter, 65536)
        self.responsetmpfile.truncate(0)

    def on_transaction_complete(self):
        if self.banpage is not None:
            # may happen if response and bad headers are send in one big chunk
            return

        if self.response_splice_mode:
            self.response_complete.set_result(None)
            return

        print('Transaction complete')
        self.response_complete.set_result(None)

    # TODO: connp->in_chunked_length - data left in current chunk
    def on_request_line(self, raw_req_line, method, path, version):
        # TODO: on invalid line there will not be \r\n actually.
        if True is False:
            self.banpage = 'Blocked by url'
            return
        if True is False:
            # request can be fully spliced
            self.request_splice = True
            self.connp.remotewriter.writelines([raw_req_line, b'\r\n'])
            return
        self.connp.remotewriter.writelines([raw_req_line, b'\r\n'])

    def on_request_header_data(self, data):
        data = data.replace(b'localhost:8888', b'www.yandex.ru')
        if not data:
            return
        if self.banpage is not None:
            return
        if self.request_splice:
            self.connp.remotewriter.write(data)
            return
        buf = []
        if self.last_req_unsent_byte:
            buf.append(self.last_req_unsent_byte)
            self.last_req_unsent_byte = None

        self.last_req_unsent_byte = data[-1:]
        data = data[:-1]
        if data:
            buf.append(data)
        if buf:
            self.connp.remotewriter.writelines(buf)

    def on_request_headers(self):
        if self.banpage is not None:
            return
        if self.request_splice:
            return
        # TODO: analyze headers from HTP-collected data!!!
        if True is False:
            self.banpage = 'Blocked by HTTP headers'
            return
        if True is False:
            self.request_splice = True
            if self.last_req_unsent_byte:
                self.connp.remotewriter.write(self.last_req_unsent_byte)
                self.last_req_unsent_byte = None

    # de-chunked and de-compressed data....
    def on_request_body_data(self, data):
        if not data:
            return
        if self.banpage is not None:
            return
        if self.request_splice:
            self.connp.remotewriter.write(data)
            return

        buf = []
        if self.last_req_unsent_byte:
            buf.append(self.last_req_unsent_byte)
            self.last_req_unsent_byte = None

        if True is False:
            self.banpage = 'Blocked by req body contents in streaming mode!'
            self.reqbodytmpfile.truncate(0)
            return

        if True is False:
            self.request_splice = True
            self.reqbodytmpfile.truncate(0)
            buf.append(data)
            self.connp.remotewriter.writelines(buf)
            return

        self.reqbodytmpfile.write(data)
        self.last_req_unsent_byte = data[-1:]
        data = data[:-1]
        if data:
            buf.append(data)
        if buf:
            self.connp.remotewriter.writelines(buf)

    def on_request_trailer_data(self, data):
        if not data:
            return
        if self.banpage is not None:
            return
        if self.request_splice:
            self.connp.remotewriter.write(data)
            return
        buf = []
        if self.last_req_unsent_byte:
            buf.append(self.last_req_unsent_byte)
            self.last_req_unsent_byte = None
        buf.append(data)
        self.connp.remotewriter.writelines(data)

    def on_request_complete(self):
        if self.banpage is not None:
            self.may_start_responding.set_result(None)
            return
        if self.request_splice:
            self.may_start_responding.set_result(None)
            return

        #self.reqbodytmpfile.seek(0)
        #if b'asdasdsdfsdf22asd' in self.reqbodytmpfile.read():
        if True is False:
            self.banpage = 'Blocked by req body contents in non-streaming mode!'
            self.may_start_responding.set_result(None)
            return

        if self.last_req_unsent_byte:
            self.connp.remotewriter.writelines([self.last_req_unsent_byte])
            self.last_req_unsent_byte = None

        self.may_start_responding.set_result(None)


def main():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(conn_handler, '127.0.0.1', 8888)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

if __name__ == '__main__':
    main()
