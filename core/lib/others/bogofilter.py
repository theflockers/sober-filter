import socket, os
from subprocess import Popen, PIPE

class BogofilterClientException(Exception): pass


class BogofilterForkClient:

    def __init__(self, bogofilter_path, filedata, homedir, config):

        self.config   = config
        self.homedir  = homedir
        self.filedata = filedata
        self.bogofilter_path = bogofilter_path

    def check(self):
        try:
            if not os.path.exists(self.homedir):
                print 'unexistent wordlist in %s' % (self.homedir)
                return 
            sh = Popen([self.bogofilter_path, '-c', self.config, '-t','-l','-d', self.homedir], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            output =  sh.communicate(input=self.filedata)
            return output[0].split(' ')
        # exception se nao ha treinamento
        except OSError:
            print 'unexistent wordlist in %s' % (self.homedir)


class BogofilterClient:

    filedata = None

    def __init__(self, address, filedata):
        if filedata == None:
            raise BogofilterClientException('missing filedata')

        self.filedata = filedata
        self.inet_addr = address[0]
        self.inet_port = address[1]

        self.connect()

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect( (self.inet_addr, self.inet_port) )

    def send_data(self, msg):
        self.sock.send("%s\r\n" % (msg))

    def check(self):
        self.send_data('SCAN')
        self.sock.recv(32)
        self.send_data('DATA')
        self.sock.recv(32)
        self.send_data(self.filedata)
        self.send_data('\r\n.\r\n')
        self.response = self.sock.recv(32)

    def get_response(self):
        return self.response.split(' ')
