#!/usr/bin/env python2.6
'''
    @name Sober scanner 
    @author Leandro Mendes<theflockers@gmail.com>
    @copyright Sober

    @brief This helper module is a Postfix content-filter for Sober Sober.
           written by wish4 web.
           The copy and distribution of this software is protected by law.
'''

import os
import sys
import smtplib
import time
import email
import string
import socket
import setproctitle
from optparse import OptionParser
from email.MIMEText import MIMEText

import sober.config
import sober.logger
import sober.enqueuer
import sober.exception
import sober.mime

from content_filter import *

logger   = sober.logger.Logger(__name__)
enqueuer = sober.enqueuer.Enqueuer()

config   = sober.config.Config()
cfg = config.get_config()

def process(filepath):
    msg_buffer = bufferize(filepath)

    filepath = msg_buffer[0]
    preamble = msg_buffer[1]
    data     = msg_buffer[2] 
    result   = None

    if os.path.exists(filepath) == False:
        return

    queue_data = enqueuer.parse_preamble(preamble)

    setproctitle.setproctitle('sober (%s: processing %s)' % (__name__, queue_data['queue_id']))
    for to in queue_data['to']:
        try:
            filter = Inspector(queue_data['queue_id'], queue_data['direction'], queue_data['from'], to, filepath, data)
            result = filter.run()

        except sober.exception.ErrorException, e:
            return 75

        except Exception, e:
            return 75

        #force cleanup
        del filter
      
        if result != None:
            try:
                if type(result).__name__ == 'dict':
                    send_back(queue_data['queue_id'], queue_data['from'], result['to'], result['data'])
                    try:
                        # if there is a notification to send
                        for notification in result['notify']:
                           send_back(queue_data['queue_id'],  notification[0], notification[1], notification[2], notification[3])
                    except AttributeError: pass
                else:
                    for notification in result:
                        send_back(queue_data['queue_id'],  notification[0], notification[1], notification[2], notification[3])
            except AttributeError:
                setproctitle.setproctitle('sober (%s: idle)' % (__name__))
                return 0
                
    setproctitle.setproctitle('sober (%s: idle)' % (__name__))
    logger.log('mail', 'id=%s (message dequeued)' % (queue_data['queue_id']) )
    os.unlink(filepath)
    return 0

def send_back(queue_id, mailfrom, to, data, subject = None):

    if subject:
        msg = MIMEText(data, 'plain', 'utf8')
        msg['Subject']  = subject
        msg['From']   = mailfrom
        data = msg.as_string()

    lock = True
    try:
        smtp = smtplib.SMTP(cfg.get('scanner', 'submit_address'), cfg.get('scanner', 'submit_port'))
        smtp.sendmail(mailfrom, to, data)
        lock = False

    except Exception, e:
        lock = False
        logger.log('mail', 'id=%s, status=error, (%s while trying to reinject into postfix)' % (queue_id, str(e)) )
        raise e



def bufferize(filepath):
    read_data = False
    buff = ''
    preamble = ''

    for data in open(filepath).readlines():
        if read_data == True:
            buff += data
        else:
            preamble += data
        if len(data.strip()) == 0:
            read_data = True
    return (filepath, preamble, buff)


if __name__ == 'filter':
    # path pro arquivo na fila
    filepath = sys.argv[3]
    ret = process(filepath)
    sys.exit(ret)
