import sober.datasource as ds

class Trace:
    
    __log_mail_seq = 'log_mail_idmail_seq';

    def __init__(self, queue_id, sender, recipient, subject, size):
        self.queue_id  = queue_id
        self.sender    = sender
        self.recipient = recipient
        self.subject   = subject

        self.ds = ds.ds

        query = "INSERT INTO %s (idmessage, sender, recipient, subject, \
            timestamp, size) VALUES \
            ('%s', '%s', '%s', '%s', now(), %s) RETURNING idmail" %  \
            ('log_mail', self.queue_id, self.sender, self.recipient, self.subject.replace('\'','\'\''), int(size))
        try:
            self.id_mail = self.query(query)
        except ds.pg.IntegrityError, e:
            query = "SELECT idmail FROM %s WHERE idmessage = '%s' AND recipient = '%s'" % \
                ('log_mail', self.queue_id, self.recipient)
            self.id_mail = self.query(query)

    def query(self, query):
        try:
            try:
                cursor = self.ds.pg.cursor()
                cursor.execute(query)
                self.ds.pg.commit()

            except ds.pg.IntegrityError, e:
                # entrada duplicada. Precisa pegar o id existente
                raise e
            except Exception, e:
                self.ds.reconnect()
                cursor = self.ds.pg.cursor()
                cursor.execute(query)
                self.ds.pg.commit()

            res = cursor.fetchall()
        # sobe IntegriryError
        except ds.pg.IntegrityError, e:
            raise e
        except Exception:
            return
        
        return res[0][0]

    def logRule(self, rulename=False, action=False):
        if rulename != False:
            query = "INSERT INTO %s (idmail, rule) VALUES \
                (%s, '%s')" %  \
                ('log_mailrules', self.id_mail, rulename)
            self.query(query)
        if action != False:
            query = "UPDATE %s SET status = %s WHERE idmail = %s" % \
                    ('log_mail', action, self.id_mail)
            self.query(query)

    def logSpamScore(self, agent, score):
        query = "UPDATE %s SET spamscore='%s',spamfilter='%s' WHERE idmail = %s" % \
                ('log_mail', score, agent[0], self.id_mail)
        self.query(query)

    def logVscanStatus(self, virusname):
        query = "INSERT INTO %s (idmail, virusname) VALUES \
                (%s, '%s')" % ('log_mailvirus', self.id_mail, virusname.split(' ')[1])
        self.query(query)

    def logAttachment(self, attachment, extension, mimetype, size):
        query = "INSERT INTO %s (idmail, attachname, extension, mimetype, size) VALUES \
                (%s, '%s', '%s', '%s', %s)" % \
                ('log_mailattachments', self.id_mail, attachment, extension, mimetype, size)
        self.query(query)
