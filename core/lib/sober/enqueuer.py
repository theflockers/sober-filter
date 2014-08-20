import os
import string
import random
from datetime import datetime
import sober.config

class Enqueuer:

    cfg   = None
    queue_id = ''

    def __init__(self):
        config = sober.config.Config()
        self.cfg = config.get_config()

    def enqueue(self, direction, mailfrom, tos, data):

        enqueued_file_path = self.get_message_path()
        f = open(enqueued_file_path, "wt")
        preamble = "From: %s\nTo: %s\nQueueId: %s\nDirection: %s\nDate: %s\n\n" %  (mailfrom, tos, self.queue_id, direction, datetime.today())

        f.write(preamble)
        f.write(data)
        f.close()

        return self.queue_id

    def get_message_path(self):
        self.queue_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in xrange(10))
        path = self.cfg.get('core', 'queue_directory')
        message_path = "%s/%s/%s" % (path, self.queue_id[0], self.queue_id[1])

        if os.path.exists(message_path) == False:
            os.makedirs(message_path)
        
        return "%s/%s" % (message_path, self.queue_id)

    def parse_preamble(self, data):
        preamble = {}
        for piece in data.split("\n"):
            parts = piece.split(':')
            if parts[0] == 'From':
                preamble['from'] = parts[1].strip()
            if parts[0] == 'To':
                preamble['to'] = eval(parts[1])
            if parts[0] == 'QueueId':
                preamble['queue_id'] = parts[1].strip()
            if parts[0] == 'Direction':
                preamble['direction'] = parts[1].strip()
            if parts[0] == 'Date':
                preamble['date'] = parts[1] 

        return preamble

    
class Queue:
    def add(self, msgid):
        self.queue.append(msgid)

    def remove(self, msgid):
        self.queue.remove(msgid)

    def exists(self, msgid):
        self.queue.index(msgid)

    def get_queue(self):
        return self.queue
        return self.get_count()

    def get_count(self):
        return len(self.queue)
