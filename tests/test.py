from htpy3 import HTPConnp, HTPConfig, HTPTrans
from pprint import pprint

cfg = HTPConfig()

class MyTransaction(HTPTrans):
    def __init__(self, connp, counter):
        super().__init__(connp)
        self.counter = counter

    def on_request_body_data(self, qwe):
        print('req({}) data:'.format(self.counter), qwe)

    def on_response_body_data(self, qwe):
        print('resp({}) data:'.format(self.counter), qwe)

class MyHTTPConnp(HTPConnp):
    def __init__(self):
        super(MyHTTPConnp, self).__init__(cfg)
        self.counter = 0

    def on_request_start(self):
        self.counter+=1
        return MyTransaction(self, self.counter)


# error check! GET -requests cannot contain body!
def test_weird_pipeline():
    qwe = MyHTTPConnp()
    qwe.handle_connect('1.2.3.4', 80, '127.0.0.1', 12345)
    qwe.push_in(b'\r\n'.join([
        b'POST / HTTP/1.1',
        b'host: yandex.ru',
        b'content-length: 2',
        b'',
        b'12',
    ]))
    qwe.push_out(b'\r\n'.join([
        b'HTTP/1.1 200 OK',
        b'Content-Length: 3',
        b'',
        b'',
    ]))
    qwe.push_in(b'\r\n'.join([
        b'GET / HTTP/1.1',
        b'host: yandex.ru',
        b'content-length: 2',
        b'',
        b'34',
    ])) # pipelinig
    qwe.push_out(b'abc')
    qwe.push_out(b'\r\n'.join([
        b'HTTP/1.1 200 OK',
        b'content-length: 3',
        b'',
        b'def',
    ]))
    qwe.handle_close()

def test_pipeline():
    qwe = MyHTTPConnp()
    qwe.handle_connect('1.2.3.4', 80, '127.0.0.1', 12345)
    qwe.push_in(b'\r\n'.join([
        b'POST / HTTP/1.1',
        b'host: yandex.ru',
        b'content-length: 2', 
        b'',
        b'12',
    ]))
    qwe.push_in(b'\r\n'.join([
        b'PUT / HTTP/1.1',
        b'host: yandex.ru',
        b'content-length: 3', 
        b'',
        b'456',
    ]))
    qwe.push_out(b'\r\n'.join([
        b'HTTP/1.1 200 OK',
        b'Content-Length: 2',
        b'',
        b'ab',
    ]))
    qwe.push_out(b'\r\n'.join([
        b'HTTP/1.1 200 OK',
        b'Content-Length: 3',
        b'',
        b'def',
    ]))
    qwe.handle_close()

test_pipeline()
test_weird_pipeline()

