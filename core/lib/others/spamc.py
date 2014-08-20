import socket, os

class SpamdClientException(Exception):
    pass

class SpamdClient():

    def __init__(self, user, sockpath, filepath=None, filedata=None):

        if filepath == None and filedata == None:
            raise SpamdClientException('missing filedata and filepath')

        self.sockpath = sockpath
        self.filepath = filepath
        self.filedata = filedata
        self.user     = user 
        
        self.prepare()
        self.connect()
        
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if not os.path.exists(self.sockpath):
            raise SpamdClientException('could not connect do spamd')
        
        s.connect(self.sockpath)        
        self.sock = s        
        
    def prepare(self):
        if self.filepath != None:
            f = open(self.filepath)
            self.message = f.read()
        else:
            self.message = self.filedata

        self.content_len = len(self.message) + 2

    def send_data(self, msg):
        self.sock.send("%s\r\n" % (msg))

    def check(self): 
        self.send_data("CHECK SPAMC/1.4")
        self.send_data("Content-length: %i" % (int(self.content_len)))
        self.send_data("User: %s" % (self.user))
        self.send_data("\r\n%s\r\n" % (self.message))
        
        data = self.sock.recv(1024)
        while 1:
            line = self.sock.recv(1024)
            if len(line) == 0: break
            
            data += line
        
        self.response = data.strip()
        
    def get_response(self):
        response = self.response.split('\r\n')[1].split(';')
        score = response[1].split('/')[0].strip()
        return score 

    def close(self):
        self.sock.close()
