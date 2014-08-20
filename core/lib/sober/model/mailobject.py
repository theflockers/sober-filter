import sober.datasource

class mailObject:

    ds = None

    def __init__(self):
        self.ds = sober.datasource.ds

    def __getattr__(self, name):
        self.__attribute = '_' + name[4: len(name)]
        return getattr(self, '__methodmissing__')

    def __methodmissing__(self, *args, **kwargs):
        attr = self.__attribute[1: len(self.__attribute)]
        if attr in self.__attributes:
            return self.__attributes[attr]
    	# Verifica se nao existe CN e for dominio (CN -> mailDomain)
        elif attr == 'cn':
            if 'mailDomain' in self.__attributes:
                return self.__attributes['mailDomain']
	# Retorna null se nao existir atributo
        return [(None),]

    def user(self, obj):
        redisResponse = self.ds.redis_get('settings:%s' % (obj))
        if redisResponse == None:
            res   = self.ds.ldap_search('(&(objectClass=soberMailObject)(mail=%s))' % (obj))

            if len(res) == 0:
                return None

            dn    = res[0][0]
            setts = res[0][1]

            setts['soberMailRule'] = []
            try:
                for conditions in setts['soberMailConditions']:
                    setts['soberMailRule'].append(self.ds.ldap_search('(objectClass=soberMailRule)', conditions)[0])
            except: pass

            setts['soberMailGroups'] = []
            groups = self.ds.ldap_search('(&(objectClass=soberMailObject)(objectClass=groupOfUniqueNames)(uniqueMember=%s))' % (dn) )
            for group in groups:
                setts['soberMailGroups'].append(group[1]['cn'][0])

            self.ds.redis_set('settings:%s' % (obj), setts)
        else:
           setts = eval(redisResponse)
        self.__set_attribute_settings(setts)
        return self

    def group(self, obj):
        redisResponse = self.ds.redis_get('settings:%s' % (obj))
        if redisResponse == None:
            res   = self.ds.ldap_search('(&(objectClass=soberMailObject)(cn=%s)(objectClass=groupOfUniqueNames))' % (obj))
            if len(res) == 0:
                return None
            dn    = res[0][0]
            setts = res[0][1]
            setts['soberMailRule'] = []

            # pode nao ter regras.
            try:
                for conditions in setts['soberMailConditions']:
                    setts['soberMailRule'].append(self.ds.ldap_search('(objectClass=soberMailRule)', conditions)[0])
            except: pass

            self.ds.redis_set('settings:%s' % (obj), setts)
        else:
           setts = eval(redisResponse)

        self.__set_attribute_settings(setts)

        return self

    def domain(self, obj):
        domain = obj.strip()
        redisResponse = self.ds.redis_get('settings:%s' % (domain))
        if redisResponse == None:
            search = '(&(objectClass=soberMailObject)(dc=%s))' % (domain)
            res   = self.ds.ldap_search(search)
            if len(res) == 0:
                return None
            dn    = res[0][0]
            setts = res[0][1]
            setts['soberMailRule'] = []
            # pode nao ter regras.
            try:
                for conditions in setts['soberMailConditions']:
                    setts['soberMailRule'].append(self.ds.ldap_search('(objectClass=soberMailRule)', conditions)[0])
            except KeyError, e: 
                pass

            self.ds.redis_set('settings:%s' % (obj), setts)
        else:
            setts = eval(redisResponse)

        self.__set_attribute_settings(setts)

        return self



    def __set_attribute_settings(self, setts):
        self.__attributes = {}
        if type(setts).__name__ == 'dict':
            for attr, val in setts.iteritems():
                #setattr(self, '_'+ attr, val)
                self.__attributes[attr] = val
