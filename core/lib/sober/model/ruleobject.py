import sober.datasource

class ruleObject:

    ds       = None
    rulename = None

    def __init__(self, rulename):
        self.rulename = rulename
        self.ds = sober.datasource.ds

    def __getattr__(self, name):
        self.__attribute = '_' + name[4: len(name)]
        return getattr(self, '__methodmissing__')

    def __methodmissing__(self, *args, **kwargs):
        attr = self.__attribute[1: len(self.__attribute)]
        if attr in self.__attributes:
            return self.__attributes[attr]
 	# Retorna null se nao existir atributo
        return [(None),]

    def get(self):
        redisResponse = self.ds.redis_get('rule:%s' % (self.rulename))
        if redisResponse == None:
            res   = self.ds.ldap_search('(&(objectClass=soberMailRule)(cn=%s))' % (self.rulename))
            if len(res) == 0:
                return None

            dn    = res[0][0]
            rule = res[0][1]
            self.ds.redis_set('rule:%s' % (self.rulename), rule)
        else:
            rule= eval(redisResponse)
        self.__set_attribute_settings(rule)
        return self

    def __set_attribute_settings(self, setts):
        self.__attributes = {}
        if type(setts).__name__ == 'dict':
            for attr, val in setts.iteritems():
                #setattr(self, '_'+ attr, val)
                self.__attributes[attr] = val
