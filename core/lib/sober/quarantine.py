import os
import re
import shutil
import sober.datasource
import sober.config

class Quarantine:
    def __init__(self, queue_id, filepath, message=None):

        self.ds       = sober.datasource.ds
        self.config   = sober.config.Config().get_config()
        self.queue_id = queue_id
        self.message  = message
        self.filepath = filepath
        self.logger = sober.logger.Logger(__name__)
    
    def save(self):
        path = self.config.get('core', 'quarantine_directory')

        message_path = "%s/%s/%s" % (path, self.queue_id[0], self.queue_id[1])

        if os.path.exists(message_path) == False:
            os.makedirs(message_path)
    
        try:
            message_path = "%s/%s" % (message_path, self.queue_id)
            if not os.path.exists(message_path):
                queue_file      = open(self.filepath)
                quarantine_file = open(message_path, 'w')
                copy = False
                for line in queue_file.readlines():
                    if re.match(r'^$', line.strip()) and copy == False:
                        copy = True
                        continue

                    if copy == True:
                        quarantine_file.write(line)
                
                queue_file.close()
                quarantine_file.close()
                #shutil.copy(self.filepath,  "%s" % (message_path))
                #self.ds.redis_set('queue:%s' % (self.queue_id), message_path, expire = False)
        except Exception, e:
            print str(e)
