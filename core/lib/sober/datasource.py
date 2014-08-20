import redis
import psycopg2 as pg
import ldap
import base64
import zlib
import sys

import sober.config

__name__ = __name__.split('.')[1]

class DataSource:

    __USE_REDIS    = False
    __DS_TIMEOUT   = 20
    __CACHE_TTL = 0

    ldap        = None
    redis       = None
    pg          = None
    config      = None
    data        = None
    __instance  = None

    def __init__(self):
        self.config = sober.config.Config().get_config()
        self.__CACHE_TTL = self.config.get(__name__, 'redis_ttl')
        self.redis = redis.Redis(self.config.get(__name__, 'redis_server'))
        try:
            self.redis.set('connected','true')
            self.__USE_REDIS = True
        except redis.ConnectionError, e: 
            print str(e), 'redis is down.'
	    #raise sober.exception.NoRedisConnection()
	    pass
            #print str(e), 'redis is down.'
        
        try:
            db_host = self.config.get('mailtrace', 'db_host')
            db_name = self.config.get('mailtrace', 'db_name')
            db_user = self.config.get('mailtrace', 'db_user')
            db_pass = self.config.get('mailtrace', 'db_pass')
            self.pg = pg.connect('host=%s dbname=%s user=%s password=%s' %
                    (db_host, db_name, db_user, db_pass))
        except Exception, e:
            print str(e)


    def ldap_connect(self):
        try:
            self.ldap = ldap.initialize(self.config.get(__name__, 'ldap_uri'))
            self.ldap.set_option(ldap.OPT_TIMEOUT, self.__DS_TIMEOUT)
            self.ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, self.__DS_TIMEOUT)
            self.ldap.bind_s(self.config.get(__name__, 'ldap_bind_dn'), 
            self.config.get(__name__, 'ldap_bind_pw'), ldap.AUTH_SIMPLE)
        except ldap.SERVER_DOWN, e:
            raise sober.exception.FatalException(e[0]['desc'])


    def reconnect(self):
        db_host = self.config.get('mailtrace', 'db_host')
        db_name = self.config.get('mailtrace', 'db_name')
        db_user = self.config.get('mailtrace', 'db_user')
        db_pass = self.config.get('mailtrace', 'db_pass')
        self.pg = pg.connect('host=%s dbname=%s user=%s password=%s' %
                    (db_host, db_name, db_user, db_pass))

    def ldap_search(self, _filter, dn = False):
        self.ldap_connect()
        if not dn:
            dn = self.config.get(__name__, 'ldap_base_dn')

        entry = self.ldap.search_st(dn, ldap.SCOPE_SUBTREE, _filter, timeout=self.__DS_TIMEOUT) 
        self.data = entry
        
        return self.data

    def redis_get(self, obj):
       res = self.redis_command('get', obj)
       if res != None:
           try:
               decoded = zlib.decompress(base64.b64decode(res))
               return decoded
           except Exception, e:
               return None 

    def redis_del(self, obj):
        return self.redis.delete(obj)

    def redis_set(self, obj, val, expire = True):
        return self.redis_command('set', obj, base64.b64encode(zlib.compress(str(val))), expire)

    def redis_sadd(self, obj, val, expire = True):
        return self.redis_command('sadd', obj, val, expire)

    def redis_sismember(self, obj, val):
        return self.redis_command('sismember', obj, val)

    def redis_command(self, cmd, param, val = False, expire = True):
        try:
            if cmd == 'get':
                res = self.redis.get(param)
            elif cmd == 'sismember':
                res = self.redis.sismember(param, val)
            else:
                if cmd == 'sadd':
                    for m in val:
                        res = self.redis.sadd(param, m)
                else:
                    res = self.redis.set(param, val)

                if expire:
                    self.redis.expire(param, self.__CACHE_TTL)
                else:
                    self.redis.persist(param)

            return res
        except redis.ConnectionError, e:
            print str(e), 'redis is down'
	    raise sober.exception.NoRedisConnection('sober.exception.NoRedisConnection')
        except Exception, e: pass

# para pegar a instancia conectada
try:
   ds
except NameError: 
    try:
        ds = DataSource()
    except sober.exception.FatalException, e:
        raise e
