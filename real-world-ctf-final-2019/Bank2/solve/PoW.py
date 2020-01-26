from itertools import product
import string
import hashlib

def do_pow(s):
    prefix = s.split()[-1]
    for x in product(string.ascii_letters, repeat=5):
        what = ''.join(x)
        m = hashlib.sha1()
        m.update(prefix + what)
        if m.hexdigest()[-4:] == '0000':
            return prefix + what
