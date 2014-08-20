import socket
import string
import sober.exception

class clamav:
    sock = None

    def __init__(self, path):
        if type(path).__name__ == 'str':
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)
        
    def scan(self, filepath):
        self.sock.send('CONTSCAN %s\r' % (filepath.strip()))
        response = self.sock.recv(1024)
        
        if string.find(response, 'ERROR') > 0:
            raise sober.exception.ErrorException(response.strip())
        if string.find(response, 'FOUND') >0:
            raise sober.exception.VirusFoundException(response.strip())

        return response
