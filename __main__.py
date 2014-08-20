#!/usr/bin/env python2.6
import sys, os
from optparse import OptionParser

sys.path.append( "%s/core/lib" % (os.getcwd()) )
sys.path.append( "%s/programs" % (os.getcwd()) )
sys.path.append( "%s/modules" % (os.getcwd()) )

import sober.exception
try:
    from sober import *
except sober.exception.FatalException, e:
    print 'Fatal Error. Please restart the program (', str(e), ')'

    sys.exit(0)

if __name__ == '__main__':
    # parsing the command line options
    parser = OptionParser()
    parser.add_option("-p", "--program", dest="program", help="the program instance to run, ex. content-filter, policy-server")

    (options, args) = parser.parse_args()

    loop = mainloop.initialize()
    loop.set_args(options)
    loop.start()
