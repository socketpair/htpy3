import asyncio
import time

from htpy3 import HTPConnp, HTPConfig, HTPTrans

cfg = HTPConfig()


class RequestHandler:
    def __init__(self, httpsrv):
        super().__init__()
        self.httpsrv = httpsrv

    def handle(self):
        pass


class MyTransaction(HTPTrans):
    def __init__(self, connp):
        print('creating trans')
        super().__init__(connp)
        self.may_start_responding = asyncio.Future()
        self.banpage = None
        self.chunks = []

    @asyncio.coroutine
    def get_result(self):
        print('Okay waiting for req to complete')
        yield from self.may_start_responding
        print('Req complete. generating response')
        if self.banpage is not None:
            response = self.banpage
            d = response.encode('utf-8')
            self.connp.do_writelines([b'\r\n'.join([
                b'HTTP/1.1 403 OK',
                b'Content-Length: ' + str(len(d)).encode('ascii'),
                b'',
                d,
            ])])
            # self.write_end_complete = True
        else:
            response = 'Hello world!\n'
            d = response.encode('utf-8')
            self.connp.do_writelines([b'\r\n'.join([
                b'HTTP/1.1 200 OK',
                b'Content-Length: ' + str(len(d)).encode('ascii'),
                b'',
                d,
            ])])
            # self.write_end_complete = True

    def on_request_line(self, method, path, version):
        print('req line', method, path, version)
        if b'test' in path:
            self.banpage = 'Blocked by url'
            return
        # TODO: parse URL and potentially switch to blockpage generatorrespond with blockpage based on URL
        # TODO: also hack URL if required.
        # TODO: it may be deirable to hack hostname also
        # TODO: method as integer constant!
        # TODO: parsed uri can be get in another hook
        pass

    # def on_request_headers(self):
    #     # TODO: analyze request content-type (if any) and potentially switch to
    #     pass

    def on_request_complete(self):
        print('req complete')
        self.may_start_responding.set_result(None)


class MyHTTPSrv(asyncio.Protocol, HTPConnp):
    def __init__(self):
        super().__init__(cfg)
        self.responses = asyncio.Queue()
        # https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.BaseEventLoop.create_task
        asyncio.get_event_loop().create_task(self.writerloop()) # TODO: returns task?...

    @asyncio.coroutine
    def writerloop(self):
        try:
            while True:
                trans = yield from self.responses.get()
                if trans is None:
                    break
                yield from trans.get_result()

        except Exception as e:
            print('writerloop exceoption:', repr(e))

        # TODO: properly abort  waiting tasks on that connection and abrupt it!
        self.handle_close(time.monotonic())
        self.transport.close()

    def connection_made(self, transport):
        # asyncio callback
        print("connection_made")
        (rip, rport) = transport.get_extra_info('peername')
        (lip, lport) = transport.get_extra_info('sockname')
        self.transport = transport
        self.handle_connect(rip, rport, lip, lport, time.monotonic())

    def connection_lost(self, exc):
        # asyncio callback
        if exc is not None:
            print("connection_lost", exc)
        self.responses.put_nowait(None)

    def eof_received(self):
        # asyncio callback
        print("eof received")
        self.responses.put_nowait(None)

    def data_received(self, data):
        # asyncio callback
        self.push_in(data, time.monotonic())

    def do_writelines(self, chunks):
        for i in chunks:
            if i:
                self.push_out(i, time.monotonic())
        self.transport.writelines(chunks)

    def on_request_start(self):
        print('on_request_start')
        trans = MyTransaction(self)
        self.responses.put_nowait(trans)
        return trans

def main():
    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance
    coro = loop.create_server(MyHTTPSrv, '127.0.0.1', 8888)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()

    # asyncio.start_server!!!!!!!!!!!!!!!!!!!!!!!

    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()
