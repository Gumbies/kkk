import hmac
import sha
import random
import hashlib
from Crypto.Cipher.ARC4 import ARC4Cipher


secret_1BL = 'dd88ad0c9ed669e7b56794fb68563efa'.decode('hex')


def load_hvex_from_file(filename):
    data = open(filename, 'r').read()

#    return data

    header = data[:0x10]
    random_seed = str(random.getrandbits(16 * 8))
    key = hashlib.sha1(random_seed).hexdigest()[:16]
    hmac_key = hmac.new(secret_1BL, key, sha).digest()[0:0x10]
    hvex_data = data[0x20:]

    hvex_data = ARC4Cipher(hmac_key).encrypt(hvex_data)

    return header + key + hvex_data
