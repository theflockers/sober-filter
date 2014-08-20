__all__ = ['Scanner']

import hashlib

import others.clamav as clamav

import sober.config
import sober.logger
import sober.exception
import sober.datasource


class Scanner:

    ST_OK = 0
    ST_FOUND = 1
    ST_ERROR = -1
    VIRUS_NAME = None

    handler = None

    def __init__(self, filepath):

        config        = sober.config.Config()
        self.logger   = sober.logger.Logger(__name__.split('.')[0])
        self.ds       = sober.datasource.ds
        cfg           = config.get_config()
        self.handler  = clamav.clamav(cfg.get('content_filter', 'clamd_socket'))
        self.filepath = filepath
        self.uid      = hashlib.md5(filepath).hexdigest()

    def scan(self):
        res = None
        try:
            res = self.ds.redis_get('cache:%s:antivirus' % (self.uid))
            if res == None:
                res = self.handler.scan(self.filepath)
                self.ds.redis_set('cache:%s:antivirus' % (self.uid), res)

            self.logger.log('mail', 'module=(%s) (%s)' % (__name__, res.strip()))
        except sober.exception.ErrorException, e:
            self.logger.log('mail', 'status=error (%s)' % (str(e)))
            return self.ST_ERROR
        except sober.exception.VirusFoundException, e:
            self.logger.log('mail', 'module=(%s) (%s)' % (__name__, str(e)))
            self.VIRUS_NAME = str(e)
            return self.ST_FOUND


