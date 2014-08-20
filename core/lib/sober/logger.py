import syslog

class Logger:

    prios = {'mail': syslog.LOG_INFO}

    def __init__(self, ident):
        syslog.openlog('sober/%s' % (ident), syslog.LOG_PID, syslog.LOG_MAIL)
    
    def log(self, prio, message):
        syslog.syslog(self.prios[prio], message);

    def close(self):
        syslog.closelog()

