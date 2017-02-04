import socket
import select

class UDPServer(object):
    def __init__(self, engine, bind=None):
        self.engine = engine
        self.bind = bind
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.recv_size = 2048
        if bind != None:
            self.sock.bind(bind)
        self.engine.register(self)

    def fileno(self):
        return self.sock.fileno()

    def handle_event(self, evt):
        if evt & select.EPOLLIN:
            data, addr = self.sock.recvfrom(self.recv_size)
            #print "%r -> %r" % (addr, data)
            try:
                self.handle_packet(data, addr)
            except:
                self.handle_error(data, addr)

    def handle_error(self, data, addr):
        print "-"*40
        print "Error handing packet from %s:%d" % (addr[0], addr[1])
        import traceback
        traceback.print_exc() # XXX But this goes to stderr!
        print "-"*40

    def handle_packet(self, data, addr):
        pass

    def send_packet(self, data, addr):
        #print "%r <- %r" % (addr, data)
        try:
            self.sock.sendto(data, addr)
        except socket.error:
            print "Sendto failed", addr, `data`


class TestServer(UDPServer):
    def handle_packet(self, data, addr):
        print "Got \"%s\" from %s:%d" % (data.strip(), addr[0], addr[1])
        self.send_packet(data.upper(), addr)


if __name__ == "__main__":
    import engine
    eng = engine.Engine()
    serv = TestServer(eng, bind=("0.0.0.0", 0))
    eng.start()
