from ConfigParser import ConfigParser

class Config:
    config = False
    def __init__(self):
        self.config = ConfigParser()
        self.config.readfp(open('/etc/sober/sober.cfg'))
    def get_config(self):
        return self.config

try:
    config
except NameError:
    config = Config()
