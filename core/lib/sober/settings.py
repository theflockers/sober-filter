# -*- coding: utf-8 -*-
import sober.datasource
import sober.model.mailobject as mailobject

class Settings:

    settings = None

    def set_obj(self, obj):
        self.obj = obj

    def get(self, obj_type, obj=False):
        if obj == False:
            obj = self.obj

        try:
            if obj_type == 'user':
                self.settings = mailobject.mailObject().user(obj)
            if obj_type == 'group':
                self.settings = mailobject.mailObject().group(obj)
            if obj_type == 'domain':
                self.settings = mailobject.mailObject().domain(obj)

            return self.settings

        except Exception, e:
            print 'settings', str(e)
            return None

        # stub
        '''
        self.settings = {'soberMailSettings': 
            {
                'soberMailObjectName': self.obj, 
                'soberMailObjectType': 'account', 
                'soberMailGroups': ('diretoria','supervisao','todos'),
                'soberMailSpamCheck': 'True',
                'soberMailSpamAction': 'tag',
                'soberMailSpamTag': '[SPAM]',
                'soberMailVirusCheck': 'True',
                'soberMailVirusAction': 'discard',
                'soberMailConditions': asldglaskjdgçlasd,alsdkjgçasldmasdgkajs
                sending limit, sending_total, recipients_limit, recipients_total, abuse_limit, abuse_total
                'soberMailLimits': (100,0,0,100,1,0),
                'soberMailRule': ({
                    'soberMailRuleName': 'regra0001',
                    # and
                    'soberMailRuleCondition': ( {'Subject': 'teste'}, {'Body': 'testando'},{'BlockedExtension': ('exe','pif','bat')}),
                    'soberMailRuleCondition': {'Subject': 'teste'}, 
                    'soberMailRuleContition': {'Body': 'testando'},
                    # action
                    'soberMailRuleAction': ({'CopyTo': 'teste@teste.com.br'},'Discard','Quarentine',{'Header': (Subject, 'teste')}),
                }, ),
            }
        }
        '''

    def get_blacklist(self):
        self.blacklist = {
            'item': ('theflockers@gmail.com',)
        }

        return self.blacklist

    def get_blockedext(self):
        self.blockedext = {'mail': ('pif','bat','exe', 'jpg','docx')}
        return self.blockedext
