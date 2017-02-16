#! /usr/bin/env python



import os
import sys
import time
import socket
import threading
import SocketServer



class TCPConnection(SocketServer.BaseRequestHandler):
    
    def write_data(self, port, data):
        if port in self.log_files:
            self.log_files[port].write(data)
        else:
            self.log_files[port] = open(self.logdir + "/log-%d.dat" % port, "wb")
            self.log_files[port].write(data)
            self.log_cb("<< Flash trace data")
     
    def handle(self):
        #self.log_cb("<< New flash log connection")
        trace = False
        while True:
            try:
                self.data = self.request.recv(1024)
                if self.data:
                    if self.data == '<policy-file-request/>\x00':
                        #self.log_cb("<< Flash policy file request")
                        self.request.sendall("<?xml version=\"1.0\"?><cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>" + "\0")
                    else:
                        if self.data == "Trace":
                            #self.log_cb("<< Flash trace data")
                            trace = True
                        #else:
                        elif trace == True:
                            self.write_data(self.client_address[1], self.data)

                        self.request.sendall("ok\0")
                else:
                    break
            except:
                self.request.close()
                return

class LogServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

    def handle_timeout(self):
        self.timed_out = True

def Sleeper(t, server):
    time.sleep(t)
    server.timed_out = True
    server.shutdown()

def log_cb(string):
    print string
    sys.stdout.flush()

def main(argv):
    
    if len(argv) != 3:
        print "Usage: logserver <dir> <port> <timeout>"
        sys.exit(1)
    
    ldir = argv[0]
    lport = argv[1]
    timeout = argv[2]
    
    print "Logserver listening on port " + lport
    sys.stdout.flush()
    
    # Run logserver until timeout (or ctrl+c)
    server = LogServer(('', int(lport)), TCPConnection)
    t = threading.Thread(target=Sleeper, args=(int(timeout), server))
    t.daemon = True
    t.start()
    TCPConnection.log_files = {}
    TCPConnection.logdir = ldir
    TCPConnection.log_cb = staticmethod(log_cb)
    server.timed_out = False
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print "Stopped by KeyboardInterrupt"
        sys.stdout.flush()
    
    if server.timed_out == True:
        print "Stopped by timeout"
        sys.stdout.flush()
    
    for v in TCPConnection.log_files.itervalues():
        v.close()
    
    server.server_close()

if __name__ == "__main__":
     main(sys.argv[1:])

