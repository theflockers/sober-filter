__all__ = ['Scanner']

import others.clamav

import sober.config
import sober.logger
import sober.exception


class Scanner:

    ST_OK = 0
    ST_FOUND = 1
    ST_ERROR = -1

    handler = None

    def __init__(self, filepath):

        config      = sober.config.Config()
        self.logger = sober.logger.Logger(__name__.split('.')[0])

        cfg = config.get_config()
        self.handler  = clamav.clamav(cfg.get('content_filter', 'clamd_socket'))
        self.filepath = filepath

    def scan(self):
        try:
            res = self.handler.scan(self.filepath)
            self.logger.log('mail', 'action=virus_scan (%s)' % (res.strip()))
        except sober.exception.ErrorException, e:
            self.logger.log('mail', 'status=error (%s)' % (str(e)))
            return self.ST_ERROR
        except sober.exception.VirusFoundException, e:
            self.logger.log('mail', 'status=virus (%s)' % (str(e)))
            return self.ST_FOUND


