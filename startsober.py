#!/usr/bin/env python2.6

import os
import sys
import pwd
import time
import signal
import subprocess
import setproctitle

sys.path.append( "%s/core/lib" % (os.getcwd()) )
sys.path.append( "%s/programs" % (os.getcwd()) )
sys.path.append( "%s/modules" % (os.getcwd()) )

import sober.exception
import sober.config

programs     = ['enqueuer-in', 'enqueuer-out', 'scanner','policyd','webservice']
procs        = []

config       = sober.config.Config()
cfg          = config.get_config()
sober_path = cfg.get('core', 'sober_path')

try:
    if os.getuid() != 0:
        raise sober.exception.NonRootException('this program must to be started as root')

    setproctitle.setproctitle('sober')
    
    for prog in programs:
        procs.append(subprocess.Popen(['python2.6', sober_path, '-p', prog]))

    while True:
        time.sleep(10)

except KeyboardInterrupt:
    for proc in procs:
        print 'exiting.. ', proc.pid
        proc.kill()

    sys.exit(0)
