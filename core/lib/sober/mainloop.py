#!/usr/bin/env python2.6

from multiprocessing import Process, Pool
from optparse import OptionParser
import sys

class initialize(Process):
    args = ''
    def set_args(self, args):
        self.args = args

    def run(self):
        mod = self.args.program
        __import__(mod)
