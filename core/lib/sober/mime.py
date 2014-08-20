import re
import email
import base64
import magic

class Types:
    def __init__(self):
        import sober.datasource
        self.ds = sober.datasource.ds

        if self.ds.redis_get('mimes:loaded') == None:
            f = open('others/mime.types')
            mtypes = {}
            for line in f.readlines():
                m = line.strip().split(' ')
                if m[0] in mtypes:
                    try:
                        mtypes[m[0]].append(m[1])
                    except Exception, e:
                        print str(e)
                else:
                    mtypes[m[0]] = [m[1],]
            f.close()
            for key, val in mtypes.iteritems():
                self.ds.redis_sadd('mimes:%s' % (key.strip()), val, False)

            self.ds.redis_set('mimes:loaded', True, False)

    def belongs(self, ext, mime):
        return self.ds.redis_sismember('mimes:%s' % (ext), mime)

class Message:
    message     = None
    magic       = None
    attachments = []

    def __init__(self, data, filepath = False):

        if filepath:
            self.message = email.message_from_string(open(filepath).read())
        else:
            self.message = email.message_from_string(data)

        # loading magic
        try:
            self.magic = magic.open(magic.MIME_TYPE)
        except:
            self.magic = magic.open(magic.MAGIC_MIME)

        self.magic.load()

    def get_attachments(self, parts = None, explode = False):
    # Zera o list de anexos (bug que esta empilhando a lista de anexos verificadas pelos grupos/dominios ...)
        #attachments[:]
        attachments = []
        filedata = None

        if self.message.is_multipart():
            if parts == None:
                parts = self.message.get_payload()
            else:
                parts = parts.get_payload()

            for part in parts:
                mpart = part.get_payload()
                if type(mpart).__name__ == 'str':
                    filename = Tools().utf8_encode(part.get_filename())
                    filedata = part.get_payload()
                    try:
                        rawfile = base64.b64decode(filedata)
                    except Exception, e:
                        rawfile = filedata

                    size = len(rawfile)
                    ctype = self.magic.buffer(rawfile)
                    if filename != 'None':
                        if explode:
                            import os
                            #exploded = Tools().unarchive(rawfile, ctype)
                            exploded = Tools().unarchive(rawfile, ctype, os.path.basename(filename))
                            if exploded != None:
                                for attach in exploded:
                                    attachments.append(attach)
                        attachments.append({'filename': filename, 'filepath': '', 'content_type': ctype, 'size': size})

                elif type(mpart).__name__ == 'list':
                    attach = self.get_attachments(part)
                    if len(attach) != 0:
                        attachments = attach
                    # base64: Incorrect padding (arquivo somente texto de poucos bytes)
        return attachments


class Tools:

    files = []
    path  = []
    def utf8_encode(self, header_value):
        try:
            mime_decoded_header = email.header.decode_header(header_value)
            dencoded_header_value = []
            try:
                for part in mime_decoded_header:
                    if part[1] == None:
                        dencoded_header_value.append(unicode(part[0], encoding='latin1', errors='replace'))
                    else:
                        dencoded_header_value.append(unicode(part[0], encoding=part[1], errors='replace'))
                encoded_header_value = ''
                for part in dencoded_header_value:
                    try:
                        encoded_header_value += ' ' + part.encode('utf-8')
                    except ValueError: pass
                return encoded_header_value.strip()
            except:
                return mime_decoded_header[0][0]
        except:
            return header_value

    def unarchive(self, content, ctype, filename = False):
        pattern = re.compile(r'.*.(zip|rar|7z).*')
        m = pattern.match(ctype)
        if m == None:
            return

        tmpfile = Tools().save_file(content)
        if filename:
            self.path.append(filename)

        from subprocess import Popen, STDOUT, PIPE
        import os, shutil
        import sober.config
        import random, string, os

        config = sober.config.Config().get_config()
        tmpdir = os.path.dirname(tmpfile)
        if m.group(1) == 'zip':
            cmd = [config.get('core','unzip_path'), '-u', '-q', '-d', tmpdir, tmpfile]
        if m.group(1) == 'rar':
            cmd = [config.get('core','unrar_path'), 'x', '-y', tmpfile, tmpdir]
        if m.group(1) == '7z':
            cmd = [config.get('core','7z_path'), 'x', '-y', '-o', tmpdir, tmpfile]

        #print cmd
        p = Popen(cmd)
        p.wait()

        # read dir
        os.unlink(tmpfile)
        self.scandirs(tmpdir)
        shutil.rmtree(tmpdir)
        return self.files


    def save_file(self, content):
        try:
            import sober.config
            import random, string, os
            config = sober.config.Config().get_config()
            path = config.get('core', 'temp_dir')
            tmpnam = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in xrange(10))
            message_path = "%s/%s/%s" % (path, tmpnam[0], tmpnam[1])
            if os.path.exists(message_path) == False:
                os.makedirs(message_path)

            tmpnam_path = '%s/%s' % (message_path, tmpnam)
            f = open(tmpnam_path, "wt")
            f.write(content)
            f.close()

            return tmpnam_path

        except Exception, e:
            print 'ex: %s' % e

    def scandirs(self, path):
        import os, glob

        exploded = None
        filepath = "/".join(self.path)

        for filename in glob.glob( os.path.join(path, '*') ):
            try:
                m = magic.open(magic.MIME_TYPE)
            except:
                m = magic.open(magic.MAGIC_MIME)

            m.load()

            if os.path.isdir(filename):
                self.scandirs(filename)

            if os.path.isfile(filename):
                f = file(filename, "r")
                content = f.read()
                ctype = m.buffer(content)
                size = os.path.getsize(filename)
                pattern = re.compile(r'.*.(zip|rar|7z).*')
                m = pattern.match(ctype)
                if m != None:
                    exploded = Tools().unarchive(content, ctype, os.path.basename(filename))[0]
                    self.files.extend(exploded)
                    self.path.append(os.path.basename(filename))

                fname = os.path.basename(filename)
                if fname != None:
                    self.files.append({'filename': fname, 'filepath': filepath ,'content_type': ctype, 'size': size})

                f.close()
