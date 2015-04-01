from SocketServer import ThreadingTCPServer
import socket
import signal
import sys

import XSE.server

HOST = '0.0.0.0'
PORT = 9769
serv = None

def reload_code(signum, frame):
    print 'Reloading Code...'
    for module in sys.modules.keys():
        if module.startswith('XSE.'):
            del(sys.modules[module])

    import XSE
    import XSE.server
    reload(XSE)
    reload(XSE.server)
    if serv:
        serv.RequestHandlerClass = XSE.server.XSERequestHandler
    print 'Code Reloaded'

def serve_forever():
    global serv
    retry = 0
    signal.signal(signal.SIGUSR1, reload_code)
    while retry < 50:
        try:
            serv = ThreadingTCPServer((HOST, PORT), XSE.server.XSERequestHandler)
            break
        except socket.error as ex:
            if ex.errno != errno.EADDRINUSE:
                raise
            print 'Retrying bind...'
            time.sleep(10)
            retry += 1
    print 'Bound...'
    serv.serve_forever()
    serv.shutdown()


def shutdown():
    if serv:
        serv.shutdown()
