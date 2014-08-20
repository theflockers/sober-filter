#/usr/bin/env python2.6
'''
    @name Observi scanner 
    @author Leandro Mendes<leandro@wish4web.com.br>
    @copyright Sober

    @brief This helper module is a Postfix content-filter for Sober Observi.
           written by wish4 web.
           The copy and distribution of this software is protected by law.
'''

import os
import sys
import pwd
import smtplib
import time
import email
import string
import socket
import setproctitle
from subprocess import *

import sober.config
import sober.logger
import sober.enqueuer
import sober.exception
import sober.mime

from content_filter import *

enqueuer = sober.enqueuer.Enqueuer()
config   = sober.config.Config()
logger   = sober.logger.Logger(__name__)
queue    = [] 

cfg = config.get_config()
queue_directory = cfg.get('core','queue_directory')
sober_path    = cfg.get('core','sober_path')

# remove delay
remove_time     = time.time()
remove_delay    = int(cfg.get('scanner', 'remove_delay'))
MAX_PROCESS     = int(cfg.get('scanner', 'max_procs'))

f = {}
r = {}
i = 0

def remove(path, files):
    global i, r, f, queue, remove_time

    remove_time = time.time()

    for queued_file in files:
        filepath = "%s/%s" % (path, queued_file)
        for x in range(0, MAX_PROCESS):
            try:
                ret = f[x].wait()
                if ret == 0:
                    queue.remove(r[x]['filepath'])
                    #os.unlink(r[x]['filepath'])
                else:
                    queue.remove(r[x]['filepath'])
                    os.kill(r[x]['pid'])
            except ValueError, e: pass
            except KeyError, e: pass
            except Exception, e:
                print str(e)

            if i == MAX_PROCESS:
                i = 0

            continue
  
def pickup(path, files):
    global i, r, f, queue
    setproctitle.setproctitle('sober (%s: pickup)' % (__name__))
    for queued_file in files:
        filepath = "%s/%s" % (path, queued_file)
        if i < MAX_PROCESS:
            filepath = "%s/%s" % (path, queued_file)
            # asyncronous scan
            try:
                queue.index(filepath)
            except ValueError, e:
                if os.path.exists(filepath):
                    queue.append(filepath)
                    f[i] = Popen(['/usr/bin/env', 'python2.6', sober_path, '-p', 'filter', filepath])
                    r[i] = {'pid': f[i].pid, 'filepath': filepath}
                    i = i + 1

def lookup(directory):
    global remove_time, remove_delay
    base_dirs = os.listdir(directory)
    for first_level in base_dirs:
        first_level_dirs = os.listdir( '%s/%s' % (directory, first_level) )
        for second_level in first_level_dirs:
            files_path = '%s/%s/%s' % (directory, first_level, second_level) 
            files =  os.listdir(files_path)
            if len(files) > 0:
                pickup(files_path, files)
                if i == MAX_PROCESS:
                    remove(files_path, files)
                elif time.time() - remove_time > remove_delay and len(files) > 0:
                    remove(files_path, files)

def run():
    global lock
    # ts = time.time()
    while True:
        lookup(queue_directory)
        time.sleep(.5)

if __name__ == 'scanner':

    if os.getuid() != 0:
        raise sober.exception.NonRootException('this program must to be started as root')

    user_info = pwd.getpwnam(cfg.get('core','user'))
    uid = user_info[2]
    os.setuid(uid)

    try:
        setproctitle.setproctitle('sober (%s: idle)' % (__name__))
        run()
    except KeyboardInterrupt:
        sys.exit(0)
