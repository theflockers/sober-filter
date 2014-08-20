from __future__ import division
import hashlib

def gen_hash_alpha(str_orig):
    return '%s/%s/%s' % (str_orig[0], str_orig[1], str_orig)

def gen_hash_md5(str_orig):
    md5 = hashlib.md5(str_orig).hexdigest()
    return '%s/%s/%s' % (md5[0], md5[1], str_orig)

def humanize_bytes(size, precision=1):
    bytes = int(size)
    abbrevs = (
        (1<<50L, 'PB'),
        (1<<40L, 'TB'),
        (1<<30L, 'GB'),
        (1<<20L, 'MB'),
        (1<<10L, 'kB'),
        (1, 'bytes')
    )
    if bytes == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if bytes >= factor:
            break
    return '%.*f %s' % (precision, bytes / factor, suffix)
