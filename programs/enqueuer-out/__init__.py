#/usr/bin/env python2.6
'''
    @name Observi enqueuer 
    @author Leandro Mendes<leandro@wish4web.com.br>
    @copyright Sober

    @brief This helper module is a Postfix content-filter for Sober Observi.
           written by wish4 web.
           The copy and distribution of this software is protected by law.
'''

import os
import sys
import pwd
import smtpd
import email
import smtplib
import string
import random
import asyncore
import asynchat
import socket
import setproctitle

import sober.config
import sober.exception
import sober.logger
import sober.enqueuer

smtpd.__version__ = 'Observi (%s) ready!' % (__name__)

logger = sober.logger.Logger(__name__)

__direction__ = 'out'

class ObserviSMTP(smtpd.SMTPServer):

    hchy        = None
    settings    = None
    cfg         = None
    logger      = None

    def __init__(self, localaddr, remoteaddr, cfg):

        smtpd.SMTPServer.__init__(self, localaddr, remoteaddr)
        self.enqueuer = sober.enqueuer.Enqueuer()
        self.cfg = cfg

    '''
       @name process_message
       @description Overloads the base method. Only used to enqueue messages.
    '''
    def process_message(self, peer, mailfrom, rcpttos, data):

        message = None
        discard = False

        try:
            queue_id = self.enqueuer.enqueue(__direction__, mailfrom, rcpttos, data)
            setproctitle.setproctitle('sober (%s: enqueued %s)' % (__name__, queue_id))
            message = email.message_from_string(data)

            try:
                logger.log('mail', 'host=%s, from=<%s>, to=<%s>, (message queued as %s)' % (peer[0], mailfrom, rcpttos[0], queue_id))
            except:
                 logger.log('mail', 'host=%s, from=<%s>, (message queued as %s)' % (peer[0], mailfrom, queue_id))
                 pass

            setproctitle.setproctitle('sober (%s: idle)' % (__name__))
            return '250 %s queued as %s' % (__name__, queue_id)

        except Exception, e:
            return '421 %s' % (str(e))


if __name__ == 'enqueuer-out':
    config = sober.config.Config()
    cfg = config.get_config()

    if os.getuid() != 0:
        raise sober.exception.NonRootException('this program must to be started as root')

    user_info = pwd.getpwnam(cfg.get('core','user'))
    uid = user_info[2]
    os.setuid(uid)

    localaddr = (cfg.get(__name__, 'listen_address'), int(cfg.get(__name__, 'listen_port')) )
    
    try:
        setproctitle.setproctitle('sober (%s: idle)' % (__name__))
        sober = ObserviSMTP(localaddr, None, cfg)
        asyncore.loop()
    except KeyboardInterrupt:
        sys.exit(0)
