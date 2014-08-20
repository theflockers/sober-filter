import socket
import hashlib
import email

import sober.config
import sober.datasource
import others.spamc as spamc
import others.bogofilter as bogofilter
import sober.definitions as defines

class Scanner:

    ST_OK = 0
    ST_FOUND = 1
    ST_ERROR = -1
    ST_SCORE = 0
    AGENT = ''

    handler   = None
    ds        = None
    checktype = None
    home      = None

    def __init__(self, uid=None, filedata=None, filepath=None, checktype=None, home=None):

        config      = sober.config.Config()
        self.logger = sober.logger.Logger(__name__.split('.')[0])

        cfg = config.get_config()

        if filedata:
            self.uid = email.message_from_string(filedata)['Message-ID']
        else:
            self.uid = uid

        if checktype != None and home != None:
            self.checktype = checktype
            self.home = home

        self.ds       = sober.datasource.ds

        try:
            self.user            = cfg.get('antispam', 'run_user')
            self.sockpath        = cfg.get('antispam', 'socket_path')
            self.bogofilter_path = cfg.get('antispam', 'bogofilter_path')
            self.bogofilter_cf   = cfg.get('antispam', 'bogofilter_cf')
        except Exception, e:
            self.logger.log('mail', 'module=(%s), ERROR=(%s)'  % \
                    (__name__, str(e)))

        self.filepath = filepath
        self.filedata = filedata

        
    def scan(self, taglevel, tag2level, kill_level):
        try:
            # se ja passou alguma vez no antispam, o score fica gravado.
            # sendo assim, nao ha necessidade de passar de novo, so checar
            # o score.
            try:
                score = self.ds.redis_get('cache:%s:spamlevel' % (self.uid)).split(':')
                self.ST_SCORE = round(float(score[0]),2)
                self.AGENT    = score[1] + ':cache'
            except AttributeError: 
                self.ST_SCORE = None

            if self.ST_SCORE != None and self.checktype != defines.__BOGOFILTER_LOCAL__:
                # se score da mensagem for maior que soberMailSpamKillLevel 
                if self.ST_SCORE >= float(kill_level.strip()):
                    raise sober.exception.SpamFoundKillException
                # se score da mensagem for maior que soberMailSpamTag2Level
                if self.ST_SCORE >= float(tag2level.strip()):
                    raise sober.exception.SpamFoundTag2Exception
                # se score da mensagem for maior que soberMailSpamTagLevel
                if self.ST_SCORE >= float(taglevel.strip()):
                    raise sober.exception.SpamFoundTagException

                #self.logger.log('mail', 'module=(%s), agent=%s, status=CLEAN (%s says this message is HAM)' % \
                #    (__name__, self.AGENT, self.AGENT))

            try:
                if self.checktype == defines.__BOGOFILTER_LOCAL__:
                    self.bogofilter = bogofilter.BogofilterForkClient(self.bogofilter_path,
                            self.filedata, self.home, self.bogofilter_cf)
                    res = self.bogofilter.check()
                    if res == None:
                        # tem que ser string aqui, senao vai precisar converter no content_filter
                        if self.ST_SCORE == None:
                            self.ST_SCORE = '0'
                        return
                    self.AGENT = 'user-bogofilter'

                else:
                    # check bogofilter
                    self.AGENT = 'bogofilter'
                    self.bogofilter = bogofilter.BogofilterClient(('localhost', 4321),
                        self.filedata)
                    self.bogofilter.check()
                    res = self.bogofilter.get_response()

                if res[0].strip() == 'H':
                    self.logger.log('mail', 'module=(%s), agent=%s, status=CLEAN (%s says this message is HAM)' % \
                        (__name__, self.AGENT, self.AGENT))
                    self.ST_SCORE = round(float(res[1].strip()),2)
                    raise sober.exception.HamFound
                if res[0].strip() == 'S':
                    self.ST_SCORE = round(float(res[1].strip()),2)
                    raise sober.exception.SpamFoundKillException

                if self.checktype == defines.__BOGOFILTER_LOCAL__: 
                    if self.ST_SCORE != None:
                        self.AGENT = score[1] + ':cache'
                    return
        
            except socket.error, e:
                print str(e), "Could not connect do antispam %s" % (self.AGENT)


            # check spamassassin
            if self.checktype == None:
                try:
                    self.AGENT = 'spamassassin'
                    self.spamc = spamc.SpamdClient(self.user, self.sockpath, 
                        filepath=self.filepath, filedata=self.filedata)
                    self.spamc.check()
                    res = round(float(self.spamc.get_response()),2)
                    self.ST_SCORE = res
                except Exception, e:
                    print str(e)
   
            score = str(self.ST_SCORE) + ':' + self.AGENT
            self.ds.redis_set('cache:%s:spamlevel' % (self.uid), score)

            # se score da mensagem for maior que soberMailSpamKillLevel 
            if res >= float(kill_level.strip()):
                raise sober.exception.SpamFoundKillException

            # se score da mensagem for maior que soberMailSpamTag2Level
            if res >= float(tag2level.strip()):
                raise sober.exception.SpamFoundTag2Exception

            # se score da mensagem for maior que soberMailSpamTagLevel
            if res >= float(taglevel.strip()):
                raise sober.exception.SpamFoundTagException

            self.ds.redis_set('cache:%s:spamlevel' % (self.uid), score)
            return

        # analise das exceptions 
        except sober.exception.HamFound, e:
            self.logger.log('mail', 'module=(%s), agent=%s, status=CLEAN (%s says this message is HAM)' % \
                    (__name__, self.AGENT, self.AGENT))
            raise e
        except sober.exception.ErrorException, e:
            self.logger.log('mail', 'module=(%s), status=ERROR (%s)' % \
                    (__name__, str(e)))
            raise e
        except sober.exception.SpamFoundKillException, e:
            self.logger.log('mail', 'module=(%s), agent=%s, status=SPAM (%s says this message is certally SPAM, discarded)' % \
                (__name__, self.AGENT, self.AGENT))
            raise e
        except sober.exception.SpamFoundTag2Exception, e:
            self.logger.log('mail', 'module=(%s), agent=%s, status=SPAM (%s says this message is potentially SPAM, adding tag)' % \
                (__name__, self.AGENT, self.AGENT))
            raise e
        except sober.exception.SpamFoundTagException, e:
            self.logger.log('mail', 'module=(%s), agent=%s, status=SPAM (%s says this message is a possible SPAM, adding header )' % \
                (__name__, self.AGENT, self.AGENT))
            raise e
        except socket.error, e:
            print str(e), "Could not connect do antispam %s" % (self.AGENT)

