# -*- coding: utf-8 -*-

import sys
import socket
import asyncore
import exceptions
import socket
import setproctitle

import sober.config
import sober.settings

settings = sober.settings.Settings()

__SENDING_QUOTA_EXCEEDED__ = 'sua quota de envio de mensagens foi excedida / you have exceeded your sending quota'

config = sober.config.Config().get_config()

class PolicyServerRequestHandler(asyncore.dispatcher_with_send):

    sender_access_granted = True
    client_access_granted = True
    sender_whitelisted    = False 
    message_is_bounce     = False
    critical_error        = False
    empty_sender          = False
    userprefs             = None

    __DIRECTION_IN  = 0
    __DIRECTION_OUT = 1

    sender = None
    logger = sober.logger.Logger(__name__)

    def handle_read(self):
        try:
            setproctitle.setproctitle('sober (%s: processing)' % (__name__))
            self.__DIRECTION        = 0
            self.sender_whitelisted = False
            self.domprefs           = None
            self.userprefs          = None
            self.client_address     = None
            self.message_is_bounce  = False
            self.critical_error     = False
            self.empty_sender       = False

            while True:
                self.data = self.recv(4096)
                lines = self.data.split('\n')
                for line in lines:
                    if len(line) != 0:
                        #print line
                        name, value = line.strip().split('=', 1)
                        settings.set_obj(value)
                        request = 'self.do_%s("%s")' % (name.upper().strip(), str(value))
                        try:
                            eval(request)
                        except AttributeError: pass
                        except NameError: pass

        except socket.error:
            try:
                if self.sender_whitelisted:
                    self.grant_access_whitelisted()
                elif self.message_is_bounce:
                    self.grant_access()
                elif self.critical_error:
                    self.grant_access()
                elif self.sender_access_granted:
                    self.filter()

                else:
                    self.defer_client(__SENDING_QUOTA_EXCEEDED__)
            except:
                pass
            finally:
                setproctitle.setproctitle('sober (%s: idle)' % (__name__))
   
    def grant_access(self):
	#self.logger.log('mail', 'id=NOQUEUE, (grant_access)' )
        self.send('action=dunno\n\n\r\n')
        setproctitle.setproctitle('sober (%s: idle)' % (__name__))

    def grant_access_whitelisted(self):
	#self.logger.log('mail', 'id=NOQUEUE, (access_whitelisted)' )
        self.send('action=dunno\n\n\r\n')
        setproctitle.setproctitle('sober (%s: idle)' % (__name__))

    def defer_client(self, message):
	#self.logger.log('mail', 'id=NOQUEUE, (defer_client)' )
        self.send('action=defer_if_permit %s\n\n\r\n' % (message) )
        setproctitle.setproctitle('sober (%s: idle)' % (__name__))

    def filter(self):

        if self.domprefs != None:
            mailhost = self.domprefs.get_mailHost()[0]
            self.do_CLIENT_ADDRESS(self.client_address, mailhost)

        if self.__DIRECTION == self.__DIRECTION_IN:
	    #self.logger.log('mail', 'id=NOQUEUE, (filter - enqueue-in)' )
            self.send('action=filter smtp:%s:%s\n\n\r\n' % \
                    (config.get('enqueuer-in', 'listen_address'), 
                    config.get('enqueuer-in','listen_port')) )
        else:
	    #self.logger.log('mail', 'id=NOQUEUE, (filter - enqueue-out)' )
            self.send('action=filter smtp:%s:%s\n\n\r\n' % \
                    (config.get('enqueuer-out', 'listen_address'), 
                        config.get('enqueuer-out','listen_port')) )
       
    def do_RECIPIENT(self, recipient):
        domprefs = None

        try:
            self.userprefs = sober.settings.Settings().get('user', recipient.strip())
        except Exception, e:
            self.critical_error = True

        try:
            domain = recipient.split('@')[1]
            domprefs = sober.settings.Settings().get('domain', domain)
        except IndexError: 
            pass

        if type(self.userprefs).__name__ == 'NoneType' and type(domprefs).__name__ != 'instance' and self.empty_sender == True:
            self.message_is_bounce = True

        bypass = config.get('core', 'bypass_addrlist')
        for addr in bypass.split(' '):
            if recipient.strip().lower() == addr.strip():
                self.sender_whitelisted = True


    def do_SENDER(self, sender):

        setproctitle.setproctitle('sober (%s: checking %s)' % (__name__, sender))
        try:
            domain = sender.split('@')[1]
            self.domprefs = sober.settings.Settings().get('domain', domain)
        except IndexError: 
            self.empty_sender = True

        bypass = config.get('core', 'bypass_addrlist')
        for addr in bypass.split(' '), mailhost:
            if sender.strip().lower() == addr.strip():
                self.sender_whitelisted = True

        '''
        limits = settings.get()['limits']
        if limits['sending_total'] >= limits['sending']:
            self.sender_access_granted = False

        if limits['recipient'] > 0:
            if limits['recipient_total'] >= limits['recipient']:
                self.sender_access_granted = False
        '''

    def do_SASL_METHOD(self, method):
        self.__method = method

    def do_CLIENT_ADDRESS(self, address, netaddr=None):
        import ipcalc

        self.client_address = address

        internal_networks = config.get('core', 'internal_networks')
        if netaddr != None:
            internal_networks += ' '+ netaddr
      
        for network in internal_networks.split(' '):
            if address in ipcalc.Network(network.strip()):
                self.__DIRECTION = self.__DIRECTION_OUT

    def do_SASL_USERNAME(self, username):
        if len(username) > 0:
            self.logger.log('mail', 'id=NOQUEUE, sasl_user=<%s>, method=%s, direction=OUT' % (username, self.__method) )
            self.__DIRECTION = self.__DIRECTION_OUT

'''
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=127.0.0.1
client_name=localhost
reverse_client_name=localhost
helo_name=localhost
sender=leandro@mp13.com.br
recipient=ciclano@local.com.br
recipient_count=0
queue_id=
instance=6799.4d4c6ee6.489b4.0
size=0
etrn_domain=
stress=
sasl_method=
sasl_username=
sasl_sender=
ccert_subject=
ccert_issuer=
ccert_fingerprint=
encryption_protocol=
encryption_cipher=
encryption_keysize=0
'''

class PolicyServer(asyncore.dispatcher):
    def __init__(self, address):

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(address)
        self.listen(50)

    def handle_accept(self):
        remote = self.accept()
        if remote is None:
            pass
        else:
            sock, addr = remote
            handler = PolicyServerRequestHandler(sock)

if __name__ == 'policyd':

    ip, port = config.get(__name__, 'listen_address'), int(config.get(__name__, 'listen_port'))
    try:
        setproctitle.setproctitle('sober (%s: idle)' % (__name__))
        server = PolicyServer((ip, port))
        asyncore.loop()
    except KeyboardInterrupt:
        sys.exit(0)

