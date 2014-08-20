# -*- coding: utf-8 -*-
__all__ = ['antispam','antivirus','Inspector','message_templates']

import re
import email
import email.header
import traceback

import sober.settings
import sober.exception
import sober.quarantine
import sober.mime
import sober.mailtrace
import sober.datasource
import sober.config
import sober.definitions as defines

class Inspector:

    recipient  = ''
    filepath   = ''
    quarantine = ''
    ds         = None
    homedir    = None
    prefs      = {}
    result     = {}

    def __init__(self, queue_id, direction, sender, recipient, filepath, data):

        #self.ds = sober.datasource.ds

        # checks        
        self.__ANTIVIRUS_CHECKED   = False
        self.__ANTISPAM_CHECKED    = False
        self.__ATTACHLIST_CHECKED  = False
        self.__FORGEDLIST_CHECKED  = False
        self.__ATTACHMENTS_LOGGED  = False
        self.__LOOPED_GROUPS       = False 
        self.__HEADER_CHECKED      = False
        self.__SIZE_CHECKED        = False
        self.__BODY_CHECKED        = False
        self.__WHITELIST_CHECKED   = False
        self.__BLACKLIST_CHECKED   = False
        self.__BLACKLIST_CN        = None 
        self.__EXPLODE_ARCHIVE     = False 

        self.__MESSAGE_CONTENT_RAISED = False

        self.__CONDITIONS_LENGTH = 0
        self.__CONDITIONS_COUNT  = 0

        # operators 
        self.__OR_OPERATOR   = 0
        self.__AND_OPERATOR  = 1
        self.__OPERATOR_NAME = {0: 'OR', 1: 'AND'}

        # actions
        self.__DISCARD      = False
        self.__COPYTO       = []
        self.__NOTIFY       = False
        self.__FINAL_ACTION = 1

        # rules
        self.__running_rule = {0: 'USUARIO', 1: 'GRUPO', 2: 'DOMINIO'}
        self.__RUNNING      = 0 

        self.__RUNNING_CONDITION       = 0 
        self.__LAST_RUNNING_CONDITION  = 0 
        self.__LAST_RUNNING_ATTACHLIST = 2
        self.__BLOCKED_RULE_NAME  = ''
        self.__BLOCKED_RULE_TYPE  = ''
        self.__BLOCKED_ATTACHMENT = ''
        self.__BLOCKED_CN = ''
        self.__INITIAL_DIRECTION = direction
        self.__DIRECTION = ''

        # outros
        self.sender      = sender.lower()
        self.recipient   = recipient.lower()
        self.filepath    = filepath
        self.data        = data
        self.queue_id    = queue_id
        self.quarantine  = sober.quarantine.Quarantine(queue_id, filepath)
        self.grouprefs   = []
        self.message     = email.message_from_string(self.data)
        self.message_size = len(data)
        self.patterns    = ['TO','SUBJECT','ACTION_TEXT','FROM_TO_TEXT','FROM_TO_EMAIL','ATTACHMENT','SIZE']
        self.attachlist  = None
        self.text_body   = None
        self.whitelist   = []
        self.cfg         = sober.config.Config().get_config()
        self.spamtagscore    = ''

        self.result['notify'] = []
        self.result['to'] = self.recipient

        decoded_utf8_subject = sober.mime.Tools().utf8_encode(self.message['Subject'])
        self.tracer = sober.mailtrace.Trace(queue_id, self.sender, self.recipient, decoded_utf8_subject, self.message_size)

        # busca configs do usuario
        self.userprefs = []
        for prefuser in self.sender, self.recipient:
            prefs = sober.settings.Settings().get('user', prefuser)
            if prefs != None:
                self.userprefs.append(({prefuser: prefs}, direction) )
                self.__DIRECTION = direction

            if direction == 'out':
                direction = 'in'
        self.logger = sober.logger.Logger(__name__)

    # reseta o valor inicial dos checks para False, dessa forma
    # poderao ser feitos os checks nos outros niveis.
    def reset_checks(self):
        self.__ANTIVIRUS_CHECKED   = False
        self.__ANTISPAM_CHECKED    = False
        self.__ATTACHLIST_CHECKED  = False
        self.__ATTACHMENTS_LOGGED  = False

    def process_actions(self, actions):
        # loga a regra que chamou a acao
        self.tracer.logRule(self.__BLOCKED_RULE_NAME)
        for action in actions:
            if type(action).__name__ == 'dict':
                for name, val in action.iteritems():
                    try:
                        eval('self.action%s(%s)' %(name, [val,]))
                    except: pass
            elif type(action).__name__ == 'str':
                try:
                    eval('self.action%s()' %(action))
                except: pass


    def notify(self, accounts_to_notify, patterns):
        import sober.tools as tools
  
        notify            = []
        __SUBJECT__       = 'Mensagem bloqueada'
        __ATTACHMENT__    = 'Nenhum'
        __SIZE__          = tools.humanize_bytes(self.message_size)
        sender_notify_message_t = False

        __TO__ = self.recipient if self.__DIRECTION == 'in' else self.sender

        # Se ha anexos bloqueados
        if self.__BLOCKED_ATTACHMENT:
            __ATTACHMENT__    = self.__BLOCKED_ATTACHMENT

        sober_admin = self.domprefs.get_soberMailAdmin()[0]
        # passa todas as contas q precisa notificar
        if accounts_to_notify != None:
            try:
                if self.__BLOCKED_RULE_NAME.find('Bloqueioanexo') == 0:
                    sender_notify_message_t = self.domprefs.get_soberMailBlockedExtNotifyMessage()[0]
                if self.__BLOCKED_RULE_NAME.find('BloqueioHeader') == 0:
                    sender_notify_message_t = self.domprefs.get_soberMailBlockedHeaderNotifyMessage()[0]
                if self.__BLOCKED_RULE_NAME.find('BloqueioTamanho') == 0:
                    sender_notify_message_t = self.domprefs.get_soberMailBlockedSizeNotifyMessage()[0]
            except Exception, e:
                print 'debug:%s:%s: id=%s erro na coleta da template da notificacao (%s)' % (__name__,self.__class__.__name__,self.queue_id,e)

            sender_notify_message_t = sender_notify_message_t.replace('\\n','\n').replace('Subject: {SUBJECT}','') if sender_notify_message_t else "A mensagem {ACTION_TEXT} {FROM_TO_TEXT} {FROM_TO_EMAIL}\nfoi bloqueada pela Politica de Seguranca da Informacao.\n\nO anexo bloqueado foi: {ATTACHMENT}. Para maiores informacoes, favor entrar em contato com o administrador."

            for sent_to, direction in accounts_to_notify:
                sender_notify_message = sender_notify_message_t
                if direction == 'in':
                    __ACTION_TEXT__   = 'recebida'
                    __FROM_TO_TEXT__  = 'de'
                    __FROM_TO_EMAIL__ = self.sender
                    __TYPE__          = 'RECIPIENT'
                else:
                    __ACTION_TEXT__   = 'enviada'
                    __FROM_TO_TEXT__  = 'para'
                    __FROM_TO_EMAIL__ = self.recipient
                    __TYPE__          = 'SENDER'

                for pattern in self.patterns:
                    sender_notify_message = sender_notify_message.replace('{'+ pattern +'}', eval('__'+ pattern.upper() +'__'))

                self.logger.log('mail', 'id=%s, to=<%s> (sending notification to %s %s)' % (self.queue_id, __TO__, __TYPE__, sent_to) )
                notify.append( (sober_admin, sent_to, sender_notify_message, __SUBJECT__) )

        # notifica o admin
        if self.domprefs.get_soberMailBlockedExtNotifyAdmin()[0] == 'TRUE':
            self.logger.log('mail', 'id=%s, to=<%s> (sending notification to ADMIN)' % (self.queue_id, __TO__) )
            notify.append( (sober_admin, sober_admin, message_templates.__notify_admin_message__ % (self.sender, self.recipient,
                self.__BLOCKED_RULE_NAME, self.__BLOCKED_RULE_TYPE, self.__BLOCKED_CN, __ATTACHMENT__, __SIZE__,self.queue_id), __SUBJECT__) )
        return notify



    # funcao de retorno para o scanner.
    # se retornar None, a mensagem é descartada.
    def run(self):
        # se nao for um email de dominio valido, despacha
        # (em caso de alias)
        if len(self.userprefs) == 0:
            # ajusta a final action
            self.tracer.logRule(False, self.__FINAL_ACTION)
            self.result['data'] = self.message.as_string()
            self.result['notify'] = []
            return self.result

        # pega a lista de usuarios que vai avisar em caso de bloqueio (se ambos for interno)
        accounts_to_notify = []
        # iterator para checar cada configuracao, user, group e domain
        for prefs, direction in (self.userprefs):
            if type(prefs).__name__ == 'dict':
                for user, userprefs in prefs.iteritems():
                    accounts_to_notify.append((user,direction))
                    # pega o dominio
                    domain = user.split('@')[1]
                    domprefs = sober.settings.Settings().get('domain', domain)
                    if type(domprefs).__name__ == 'instance':
                        self.domprefs = domprefs
                    else:
                        raise sober.exception.ErrorException
                    # busca configs para cada grupo que o usuario participa

                    self.__EXPLODE_ARCHIVE = domprefs.get_soberMailExplodeArchive()[0]
                    try:
                        groups = userprefs.get_soberMailGroups()
                        grouprefs = []
                        for group in groups:
                            grouprefs.append(sober.settings.Settings().get('group', group))
                    except AttributeError, e:
                        grouprefs = None
                        # se cair aqui, nao eh membro de nenhum grupo
                        pass
                    # agora sim, roda user, group e dom
                    self.__RUNNING = 0
                    for runprefs in userprefs, grouprefs, domprefs:
                        if runprefs != None:
                           #self.__RUNNING = 0
                            try:
                                if type(runprefs).__name__ == 'list':
                                    for gprefs in runprefs:
                                        #print gprefs.get_cn()[0]
                                        self.filter(gprefs, direction)
                                else:
                                    #print runprefs.get_cn()[0]
                                    self.filter(runprefs, direction)

                                self.__RUNNING = self.__RUNNING +1
                            except BaseException, e:
                                raise sober.exception.ErrorException(e)
        # salva mensagem na quarentena
        self.quarantine.save()
    
        if self.__DISCARD and self.__NOTIFY and self.__FINAL_ACTION != defines.__SPAMKILL__:
            if self.domprefs.get_soberMailBlockedNotifyUser()[0] == 'FALSE':
                accounts_to_notify = None
            try:
                self.result['notify'] = self.notify(accounts_to_notify, self.patterns)
            except Exception, e:
                print 'debug:%s:%s: id=%s erro na geracao de envio de alertas (%s)' % (__name__,self.__class__.__name__,self.queue_id,e)

        # ajusta a final action
        self.tracer.logRule(False, self.__FINAL_ACTION)

        # copia spam para uma conta definida e descarta
        if self.__FINAL_ACTION == defines.__SPAMTAG2__ or \
            self.__FINAL_ACTION == defines.__SPAMTAG1__:

            self.message.add_header('X-Spam-Score', self.spamtagscore)
            if self.__FINAL_ACTION == defines.__SPAMTAG2__:
                self.message.add_header('X-Spam-Flag', 'YES')
            self.message.add_header('X-Spam-Level', '*' * int(float(self.spamtagscore)))
            spamtag = self.domprefs.get_soberMailSpamTag()[0]

            if self.message['Subject'] == None:
                self.message.add_header('Subject', "%s" % (spamtag) )
            else:
                self.message.replace_header('Subject', "%s %s" % (spamtag, self.message.get('Subject') ) )

            try:
                spamlover = self.domprefs.get_soberMailSpamCarbonCopyAccount()[0]
                if spamlover != None:
                    self.__DISCARD = True
                    if self.__COPYTO:
                        self.__COPYTO.append(spamlover)
                    else:
                        self.__COPYTO = spamlover
            except: pass

        # redirect to
        if self.__COPYTO and self.__DISCARD:
            self.result['to'] = self.__COPYTO

        # only copy
        elif self.__COPYTO:
            self.__COPYTO.append(self.result['to'])
            self.result['to'] = self.__COPYTO

        # discard
        elif self.__DISCARD:
            if len(self.result['notify']) > 0:
                return self.result['notify']
            return

        self.result['data'] = self.message.as_string()
        return self.result

    def filter(self, prefs, direction):
        try:
            rules   = prefs.get_soberMailRule()
            for rule in rules:
                #print rule[1]['cn'][0]
                #print 'inside loop rules', rule[1]['cn']
                conditions  = rule[1]['soberMailRuleCondition']
                actions = eval(rule[1]['soberMailRuleAction'][0])
                try:
                    eval(rule[1]['soberMailRuleDirection'][0]).index(direction)
                    # Processing rules
                    # contando quantas regras processar
                    self.__RULE_CONDITIONS_LENGTH = len(conditions)
                    self.__RULE_CONDITIONS_COUNT = 0

                    for condition in conditions:
                        
                        self.__CONDITIONS_LENGTH = 0 
                        self.__CONDITION_TYPE    = 0 

                        #print 'inside conditions', condition#
                        condition = eval(condition)
                        self.__CONDITIONS_LENGTH  = len(condition)
                        
                        #print 'length', self.__CONDITIONS_LENGTH
                        if self.__CONDITIONS_LENGTH > 1:
                            self.__CONDITION_TYPE = self.__AND_OPERATOR

                        #print type(condition)
                        if type(condition).__name__ == 'tuple':
                            # se é tupla, condição é AND
                            for cond in condition:
                                #print 'looping conditions', cond
                                for name, val in cond.iteritems():
                                    try:
                                        eval('self.check%s(%s)' %(name, (val,))) 

                                    except sober.exception.BlockedExtensionFoundException, e:
                                        self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                        self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                        self.__BLOCKED_CN        = prefs.get_cn()[0]
                                        self.__NOTIFY            = True
                                        self.__ATTACHLIST_CHECKED = True
                                        self.process_actions(actions)

                                    except sober.exception.SenderEmailFoundException, address:

                                        if re.match('.*whitelist.*', rule[1]['cn'][0], re.IGNORECASE):
                                            if self.__WHITELIST_CHECKED == False and self.__DISCARD == False:
                                                for item in val:
                                                    self.whitelist.append(item)

                                                self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                                self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                                self.__BLOCKED_CN        = prefs.get_cn()[0]
                                                self.logger.log('mail', 'id=%s, to=<%s> (sender email %s FOUND in %s)' % \
                                                    (self.queue_id,  self.recipient, address, self.__BLOCKED_RULE_NAME) )
                                                self.__WHITELIST_CHECKED = True
                                                self.process_actions(actions)
                                        else:
                                            if self.__BLACKLIST_CHECKED == False and self.__DISCARD == False:
                                                if self.__WHITELIST_CHECKED:
                                                    if str(address) in self.whitelist:
                                                        return

                                                self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                                self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                                self.__BLOCKED_CN        = prefs.get_cn()[0]
                                                self.logger.log('mail', 'id=%s, to=<%s> (sender email %s FOUND in %s)' % \
                                                    (self.queue_id,  self.recipient, address, self.__BLOCKED_RULE_NAME) )
                                                self.__BLACKLIST_CHECKED = True
                                                self.process_actions(actions)

                                    except sober.exception.SenderDomainFoundException, domain:

                                        if re.match('.*whitelist.*', rule[1]['cn'][0], re.IGNORECASE):
                                            if self.__WHITELIST_CHECKED == False and self.__DISCARD == False:
                                                for item in val:
                                                    self.whitelist.append(item)

                                                self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                                self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                                self.__BLOCKED_CN        = prefs.get_cn()[0]
                                                self.logger.log('mail', 'id=%s, to=<%s> (sender domain %s FOUND in %s)' % \
                                                    (self.queue_id,  self.recipient, domain, self.__BLOCKED_RULE_NAME) )
                                                self.__WHITELIST_CHECKED = True
                                                self.process_actions(actions)
                                        else:
                                            if self.__BLACKLIST_CHECKED == False:
                                                if self.__WHITELIST_CHECKED:
                                                    if str(domain) in self.whitelist:
                                                        return
                                                    
                                                self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                                self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                                self.__BLOCKED_CN        = prefs.get_cn()[0]
                                                self.logger.log('mail', 'id=%s, to=<%s> (sender domain %s FOUND in %s)' % \
                                                    (self.queue_id,  self.recipient, domain, self.__BLOCKED_RULE_NAME) )
                                                self.__BLACKLIST_CHECKED = True
                                                self.process_actions(actions)

                                    except sober.exception.MessageContentFoundException, e:
                                        self.__MESSAGE_CONTENT_RAISED = True
                                        self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                        self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                        self.__BLOCKED_CN        = prefs.get_cn()[0]
                                        self.__NOTIFY            = True
                                        self.process_actions(actions)

                                    except sober.exception.MessageTooLargeException, e:
                                        self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                        self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                        self.__BLOCKED_CN        = prefs.get_cn()[0]
                                        self.__NOTIFY            = True
                                        self.process_actions(actions)

                                    except sober.exception.MessageTooSmallException, e:
                                        self.__BLOCKED_RULE_NAME = rule[1]['cn'][0]
                                        self.__BLOCKED_RULE_TYPE = self.__running_rule[self.__RUNNING]
                                        self.__BLOCKED_CN        = prefs.get_cn()[0]
                                        self.__NOTIFY            = True
                                        self.process_actions(actions)

                        self.__RULE_CONDITIONS_COUNT = self.__RULE_CONDITIONS_COUNT + 1
                #except Exception, e:
                except ValueError: pass
                    #print '%s line: 346' % (__name__), str(e)

        except AttributeError, e:
            print 'no rules do sue', str(e)
        except TypeError, e:
            print 'TypeError:'. str(e) 
            pass

        ########################
        # ANTIVIRUS            #
        ########################
        try:
            if self.message_size >= int(self.domprefs.get_soberMailVirusMaxSize()[0]):
                self.__ANTIVIRUS_CHECKED = True

            elif prefs.get_soberMailVirusCheck()[0] == 'FALSE':
                self.__ANTIVIRUS_CHECKED = True

            elif prefs.get_soberMailVirusCheck()[0] == 'TRUE' and  \
                    self.__ANTIVIRUS_CHECKED == False and \
                    self.__DISCARD == False:
                scanner = antivirus.Scanner(self.filepath)
                result = scanner.scan()
                self.__ANTIVIRUS_CHECKED = True

                if result == antivirus.Scanner.ST_FOUND:
                    if prefs.get_soberMailVirusAction()[0] == 'discard':
                        self.__DISCARD = True
                        self.__BLOCKED_RULE_NAME = 'antivirus'
                        self.__FINAL_ACTION = defines.__VIRUS__
                        self.logger.log('mail', 'id=%s, to=<%s> (%s has discarded the message)' % (self.queue_id,  self.recipient, __name__) )
                        self.tracer.logVscanStatus(scanner.VIRUS_NAME)

                        return
        except TypeError: pass

        except AttributeError: pass

        #########################
        # ANTISPAM              #
        #########################
        try:

            if self.message_size >= int(self.domprefs.get_soberMailSpamMaxSize()[0]):
                self.__ANTISPAM_CHECKED = True
                return

            elif self.__INITIAL_DIRECTION == 'out' and self.domprefs.get_soberMailSpamOutCheck()[0] != 'TRUE':
                self.__ANTISPAM_CHECKED = True
                return

            elif prefs.get_soberMailSpamCheck()[0] == 'FALSE':
                self.__ANTISPAM_CHECKED = True
                return

            elif prefs.get_soberMailSpamCheck()[0] == 'TRUE' and \
                self.__ANTISPAM_CHECKED == False and \
                self.__DISCARD == False:

                import sober.tools as tools
                if self.cfg.get('antispam', 'homedirs_hash_type') == 'md5':
                    self.homedir = '%s/%s' % (self.cfg.get('antispam', 'homedirs_path'), tools.gen_hash_md5(self.recipient))
                else:
                    self.homedir = '%s/%s' % (self.cfg.get('antispam', 'homedirs_path'), tools.gen_hash_alpha(self.recipient))

                tagLevel, tag2Level, killLevel = (prefs.get_soberMailSpamTagLevel()[0],
                    prefs.get_soberMailSpamTag2Level()[0],
                    prefs.get_soberMailSpamKillLevel()[0])

                # se nao tiver algum dos niveis, vai checar no "de cima"
                for level in tagLevel, tag2Level, killLevel:
                    if level == None:
                        return

                # antispam global
                try:
                    scanner = None
                    scanner = antispam.Scanner(filedata=self.data)
                    scanner.scan(tagLevel, tag2Level, killLevel)
                except sober.exception.SpamFoundTag2Exception, e:
                    # converte score para string, para utilizar nas outras funcoes de log
                    tag2score = str(scanner.ST_SCORE)
                    tag2agent = scanner.AGENT
                    scanner = None
                    scanner = antispam.Scanner(filedata=self.data, checktype=defines.__BOGOFILTER_LOCAL__,
                        home=self.homedir)
                    scanner.scan(tagLevel, tag2Level, killLevel)
                    raise e

                except sober.exception.SpamFoundTagException, e:
                    # converte score para string, para utilizar nas outras funcoes de log
                    tagscore = str(scanner.ST_SCORE)
                    tagagent = scanner.AGENT
                    scanner = None
                    scanner = antispam.Scanner(filedata=self.data, checktype=defines.__BOGOFILTER_LOCAL__,
                        home=self.homedir)
                    scanner.scan(tagLevel, tag2Level, killLevel)
                    raise e

                # antispam local (por usuario)
                scanner = None
                scanner = antispam.Scanner(filedata=self.data, checktype=defines.__BOGOFILTER_LOCAL__,
                    home=self.homedir)
                scanner.scan(tagLevel, tag2Level, killLevel)

                # Nenhum mecanismo identificou como spam
                # Sera inserido os ultimos dados do spamassassin
                self.__ANTISPAM_CHECKED = True
                self.tracer.logSpamScore(scanner.AGENT, scanner.ST_SCORE)

        except sober.exception.HamFound, e:
            # add headers 
	        # Removido adicao de Headers quando a msg for HAM, pois sistemas com pouco recurso a fila demora pra liberar (alterar o cabecalho de tdas as msg)
            #self.message.add_header('X-Spam-Score', scanner.ST_SCORE)
            #self.message.add_header('X-Spam-Flag', 'NO')
            # Mensagem limpa, seta antispam_checked True
            self.__ANTISPAM_CHECKED = True

            self.tracer.logSpamScore(scanner.AGENT, scanner.ST_SCORE)

        except sober.exception.SpamFoundKillException, e:
            self.__DISCARD = True
            self.__FINAL_ACTION = defines.__SPAMKILL__
            self.__BLOCKED_RULE_NAME = 'antispam' 
            self.logger.log('mail', 'id=%s, to=<%s> (%s has discarded the message)' % (self.queue_id,  self.recipient, __name__) )

            self.tracer.logSpamScore(scanner.AGENT, scanner.ST_SCORE)

        except sober.exception.SpamFoundTag2Exception, e:
            self.__ANTISPAM_CHECKED = True
            self.__FINAL_ACTION = defines.__SPAMTAG2__
            self.__BLOCKED_RULE_NAME = 'antispam' 
            self.spamtagscore = tag2score

            self.tracer.logSpamScore(tag2agent, tag2score)

        except sober.exception.SpamFoundTagException, e:
            self.__ANTISPAM_CHECKED = True
            self.__FINAL_ACTION = defines.__SPAMTAG1__
            self.__BLOCKED_RULE_NAME = 'antispam' 
            self.spamtagscore = tagscore

            self.tracer.logSpamScore(tagagent, tagscore)

        except TypeError: pass


    #######################################
    # CHECK CONDITIONS                    #
    #######################################
    def checkLogAttachments(self, extensions = False):
        if self.__ATTACHMENTS_LOGGED == False:
            if self.attachlist is None:
                self.attachlist = sober.mime.Message(self.data, False).get_attachments(explode = self.__EXPLODE_ARCHIVE)
            for attach in self.attachlist:
                if type(attach).__name__ != 'dict':
                    continue
                pos = attach['filename'].rfind('.')+1
                ext = attach['filename'][pos: len(attach['filename'])].lower()
                self.tracer.logAttachment(attach, ext, attach['content_type'], attach['size'])

            self.__ATTACHMENTS_LOGGED = True

    def checkBlockedExtensions(self, extensions):
        mt = sober.mime.Types()
        if len(extensions) > 0 and self.__ATTACHLIST_CHECKED == False:
            if self.__RUNNING > self.__LAST_RUNNING_ATTACHLIST:
                return
            self.__LAST_RUNNING_ATTACHLIST = self.__RUNNING
                
            if self.attachlist is None:
                self.attachlist = sober.mime.Message(self.data, False).get_attachments(explode = self.__EXPLODE_ARCHIVE)
            for ext in extensions[0]:
                for attach in self.attachlist:
                    if type(attach).__name__ != 'dict':
                        continue
                    # getting content mime-type
                    m = re.compile('.*\.'+ ext + '$')
                    if m.match(attach['filename'].lower()):
                        self.logger.log('mail', 'id=%s, file="%s", content_type="%s" (extension ".%s" FOUND)' % (self.queue_id, attach['filepath'] +'/'+ attach['filename'].encode('utf8'), attach['content_type'], ext) )
                        self.__BLOCKED_ATTACHMENT = attach['filename'].encode('utf8')
                        raise sober.exception.BlockedExtensionFoundException

    def checkMailSize(self, conditions):
        if self.__SIZE_CHECKED == False:
            self.__SIZE_CHECKED = True
            for condition in conditions:
                operator = condition[0]
                value    = int(condition[1][0])
                if operator == 'gt':
                    if len(self.data) >= value:
                        raise sober.exception.MessageTooLargeException
                elif operator == 'lt':
                    if len(self.data) <= value:
                        raise sober.exception.MessageTooSmallException


    def checkForgedExtensions(self, extensions):
        om = sober.mime
        ot = om.Types()
        if len(extensions) > 0 and self.__FORGEDLIST_CHECKED == False:
            self.__FORGEDLIST_CHECKED = True

            if self.attachlist is None:
                self.attachlist = om.Message(self.data, False).get_attachments(explode = self.__EXPLODE_ARCHIVE)
            for attach in self.attachlist:
                # getting content mime-type
                ctype = attach['content_type']
                pos = attach['filename'].rfind('.')
                ext = attach['filename'][pos+1: len(attach['filename'])].lower()
                m = re.compile('.*\.'+ ext + '$')
                if m.match(attach['filename'].lower()):
                    if ot.belongs(ext, ctype) == False:
                        self.logger.log('mail', 'id=%s, file="%s", content_type="%s" (FORGED extension ".%s" FOUND)' % \
                                (self.queue_id, attach['filename'].encode('utf8'), attach['content_type'], ext) )
                        self.__BLOCKED_ATTACHMENT = attach['filename'].encode('utf8')
                        raise sober.exception.BlockedExtensionFoundException

    def checkFrom(self, sender):
        for addr in sender[0]:
            if self.sender.strip() == addr.strip():
                raise sober.exception.SenderEmailFoundException(addr.strip())

            try:
                if self.sender.split('@')[1] == addr.strip():
                    raise sober.exception.SenderDomainFoundException(addr.strip())
            except IndexError: pass

    def checkHeader(self, conditions):
        if self.__DISCARD:
            return

        if self.__HEADER_CHECKED == False and \
                self.__MESSAGE_CONTENT_RAISED == False:

            if self.__RULE_CONDITIONS_COUNT >= self.__RULE_CONDITIONS_LENGTH:
                self.__HEADER_CHECKED = True
                self.__BODY_CHECKED = True

            # total de condicoes para subir exception
            match_conditions_total = len(conditions[0])
            conditions_matched     = 0 
            # looping...
            for header, cond in conditions[0].iteritems():
                for one in cond[1]:
                    #print header, one
                    m = re.compile('.*'+ one +'.*', re.IGNORECASE)

                    message_header_value = sober.mime.Tools().utf8_encode(self.message[header])
                    if m.match(message_header_value):
                        self.logger.log('mail', 'id=%s, to=<%s>, type=HEADER, operator=(%s) (regex "%s.*%s.*" MATCH)' % \
                                (self.queue_id, self.recipient, self.__OPERATOR_NAME[self.__CONDITION_TYPE], header, one) )
                        conditions_matched = conditions_matched +1

            if conditions_matched >= match_conditions_total:
                if self.__CONDITIONS_COUNT <= self.__CONDITIONS_LENGTH and \
                        self.__CONDITION_TYPE == self.__AND_OPERATOR:
                    self.logger.log('mail', 'id=%s, to=<%s>, type=HEADER, operator=(%s) (more matches expected from another conditions)' % (self.queue_id, self.recipient, self.__OPERATOR_NAME[self.__CONDITION_TYPE]) )

                # se condicao for OR, pode dar raise.
                if self.__CONDITION_TYPE == self.__OR_OPERATOR:
                    self.__HEADER_CHECKED = True
                    self.__MESSAGE_CONTENT_RAISED = True
                    raise sober.exception.MessageContentFoundException
                # se for AND, incrementa o contador.
                self.__CONDITIONS_COUNT = self.__CONDITIONS_COUNT + 1

            # sendo AND e todas as condicoes forem satisfeitas, da raise.
            if self.__CONDITION_TYPE == self.__AND_OPERATOR:
                if self.__CONDITIONS_COUNT == self.__CONDITIONS_LENGTH:
                    self.__HEADER_CHECKED = True
                    self.__MESSAGE_CONTENT_RAISED = True
                    raise sober.exception.MessageContentFoundException

    def checkBody(self, conditions):
        if self.__DISCARD:
            return

        if self.__BODY_CHECKED == False and \
                self.__MESSAGE_CONTENT_RAISED == False:

            # nao eh pra passar se ja correu todas as condicoes
            if self.__RULE_CONDITIONS_COUNT >= self.__RULE_CONDITIONS_LENGTH -1:
                self.__BODY_CHECKED = True
                self.__HEADER_CHECKED = True

            condition_matched = False
            content = self.message.get_payload()
            mtype = type(content).__name__
            for cond in conditions:
                eq    = cond[0]
                words = cond[1]
                if eq == 'in':
                    for word in words:
                        if mtype == 'list':
                            for part in content:
                                ctype = part.get_content_type()

                                # se o mime de algum anexo for do tipo text/html (multipart), retira o texto do corpo
                                if self.text_body is None:
                                    try:
                                        if re.match(r'multipart/alternative', ctype):
                                            for m_part in part.get_payload():
                                                m_ctype = m_part.get_content_type()
                                                if re.match(r'text/plain', m_ctype):
                                                    self.text_body = unicode(m_part.get_payload(decode=True),encoding=m_part.get_charsets()[0], errors='replace').encode('utf-8')
                                        # ou verifica se o mime eh text sem nome de aenxo
                                        elif re.match(r'text/plain', ctype) and part.get_filename() == None:
                                            self.text_body = unicode(part.get_payload(decode=True),encoding=part.get_charsets()[0], errors='replace').encode('utf-8')
                                    except: pass

                                if self.text_body != None:
                                    for line in self.text_body.split('\n'):
                                        if re.match(r'.*' + word +'.*', line, re.IGNORECASE ):
                                            self.logger.log('mail', 'id=%s, to=<%s>, type=BODY, operator=(%s) (regex ".*%s.*" MATCH)' % \
                                                    (self.queue_id, self.recipient,self.__OPERATOR_NAME[self.__CONDITION_TYPE], word) )
                                            condition_matched = True
                                            self.__CONDITIONS_COUNT = self.__CONDITIONS_COUNT + 1
                                            break
                                
                        elif mtype == 'str':
                            for line in content.split('\n'):
                                if re.match(r'.*' + word +'.*', line, re.IGNORECASE):
                                    self.logger.log('mail', 'id=%s, to=<%s>, type=BODY, operator=(%s) (regex ".*%s.*" MATCH)' % \
                                           (self.queue_id, self.recipient,self.__OPERATOR_NAME[self.__CONDITION_TYPE], word) )
                                    condition_matched = True
                                    self.__CONDITIONS_COUNT = self.__CONDITIONS_COUNT + 1
                                    break
                        if condition_matched:
                            break

            if self.__CONDITION_TYPE == self.__AND_OPERATOR:
                if self.__CONDITIONS_COUNT == self.__CONDITIONS_LENGTH:
                    raise sober.exception.MessageContentFoundException
            else:
                if condition_matched:
                    raise sober.exception.MessageContentFoundException

            self.logger.log('mail', 'id=%s, to=<%s>, type=BODY, operator=(%s) (not matched)' % (self.queue_id, self.recipient,self.__OPERATOR_NAME[self.__CONDITION_TYPE]) )

    ###################################
    # ACTIONS                         #
    ###################################
    def actionCopyTo(self, recipients):
        if self.__FINAL_ACTION == defines.__DISCARD__:
            self.__FINAL_ACTION = defines.__COPYTODS__
        else:
            self.__FINAL_ACTION = defines.__COPYTO__
        for recipient in recipients[0]:
            self.__COPYTO.append(recipient)
            self.logger.log('mail', 'id=%s, to=<%s>, action=copy, (message copied to %s by %s rule)' % (self.queue_id, self.recipient, recipient, self.__running_rule[self.__RUNNING]))

    def actionDiscard(self):
        self.__DISCARD = True
        if self.__FINAL_ACTION == defines.__COPYTO__:
            self.__FINAL_ACTION = defines.__COPYTODS__
        else:
            self.__FINAL_ACTION = defines.__DISCARD__
        self.logger.log('mail', 'id=%s, to=<%s>, action=discard (message discarded by %s rule)' % (self.queue_id, self.recipient, self.__running_rule[self.__RUNNING]))

    def actionBypassSpam(self):
        self.__ANTISPAM_CHECKED = True
        self.__FINAL_ACTION = defines.__DELIVERED__

