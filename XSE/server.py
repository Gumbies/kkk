from datetime import datetime, timedelta
import errno
import time
import sha
import hmac
import hashlib
import SocketServer
import socket
import struct
import random
from Crypto.Cipher.ARC4 import ARC4Cipher

from XSE import database as db
from XSE.chalcalc import calc_chal_resp, calc_xosc_resp
from XSE.chunks import ChunkBuilder, ChunkReader
from XSE.config import get_config
from XSE.hvex import load_hvex_from_file
from XSE import token


socket.setdefaulttimeout(4.0)

engine = db.open_database('xse.db')
Session = db.create_session_factory(engine)

HOST = '0.0.0.0'
PORT = 9768
ARC4KEY = hashlib.sha1('XBLSTEALTH').digest()[:16]


COMMAND_CODES = {
    0x00: 'GET_TIME',
    0x01: 'GET_SALT',
    0x02: 'GET_STATUS',
    0x03: 'GET_CHAL_RESP',
    0x04: 'GET_UPDATE_PRES',
    0x05: 'GET_XOSC',
    0x06: 'GET_TOKEN',
    # disable these for now
    #0x06: 'GET_CHUNKS',
    #0x07: 'SET_CHUNKS'
}

STATUS_CODES = {
    'SUCCESS': 0x40000000,
    'UPDATE':  0x80000000,
    'EXPIRED': 0x90000000,
    'ERROR':   0xC0000000,
    'BYPASS':  0xE0000000,
    'STEALTH': 0xF0000000
}


def ts():
    return str(datetime.now()).split('.')[0]


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class XSERequestHandler(SocketServer.StreamRequestHandler):
    """
    Packets are as follows

    +---+---+---+---+---+---+---+---+---------+
    | command code  | data length   | payload |
    +---+---+---+---+---+---+---+---+---------+
    """

    def setup(self):
        SocketServer.StreamRequestHandler.setup(self)
        self.db = Session()

    def handle(self):
        #self.log('{0}: connected'.format(self.client_address[0]))

        try:
            header = self.request.recv(8)
            if len(header) == 8:
                self.handle_COMMAND(header)
            elif len(header) == 0:
                pass
            else:
                self.die('invalid header length: {0}. {1}'.format(len(header), header.encode('hex')))
        except socket.error as ex:
            self.die('socket error: {0}'.format(ex))

        #self.log('{0}: disconnected'.format(self.client_address[0]))

    def handle_COMMAND(self, header):
        try:
            (command_code, payload_length) = struct.unpack('!LL', header)
        except struct.error as ex:
            return self.die('invalid header: {0}'.format(ex.message))

        if not command_code in COMMAND_CODES:
            return self.die('invalid command: {0}'.format(command_code))

        if payload_length >= 0x8000:
            return self.die('excessively large payload: {0}'.format(payload_length))

        encrypted_payload = self.rfile.read(payload_length)

        if len(encrypted_payload) != payload_length:
            return self.die('payload length mismatch')

        decrypted_payload = ARC4Cipher(ARC4KEY).decrypt(encrypted_payload)

        handler_name = COMMAND_CODES[command_code]
        handler = getattr(self, 'handle_' + handler_name, self.handle_INVALID)

        self.log('{1}: command {0}'.format(handler_name, self.client_address[0]))

        return handler(decrypted_payload)

    def handle_INVALID(self, data):
        return self.die('invalid command handler')

    def handle_GET_TOKEN(self, data):
        try:
            (cpu_key, tokenIn, redeem) = struct.unpack('!16s 12s L', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_TOKEN: {0}'.format(ex.message))

        days = token.check(tokenIn)
        user = self.try_find_user(no_auth=True, cpu_key=cpu_key.encode('hex'))

        self.log('{0}: cpukey {1}: {2} token {3}: {4} days'.format(self.client_address[0], cpu_key.encode('hex'), 'redeemed' if redeem else 'checked', tokenIn, days))

        if user and not user.enabled:
            days = 0
            self.log('{0}: cpukey {1}: user disabled: token {2}'.format(self.client_address[0], cpu_key.encode('hex'), tokenIn))
        elif user and days and redeem:
            days = token.use(tokenIn)
            user.days += days
            self.db.commit()
        elif not user and days and redeem:
            user = db.Console(cpu_key.encode('hex').lower())
            user.enabled = True
            user.days = token.use(tokenIn)
            user.day_expires = datetime.now()
            user.name = 'tokenuser'
            user.payment = 'token {0} from {1}'.format(tokenIn, self.client_address[0])
            user.bypass = False
            self.db.add(user)
            commit = 1
            self.log('{0}: added cpukey {1} using token {2}'.format(self.client_address[0], cpu_key.encode('hex'), tokenIn))
            self.db.commit()

        self.respond_status('SUCCESS')
        self.respond(struct.pack('!L', days))
        return True

    def handle_GET_TIME(self, data):
        try:
            (cpu_key,) = struct.unpack('!16s', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_TIME: {0}'.format(ex.message))

        user = self.try_find_user(no_consume=True, no_auth=True, cpu_key=cpu_key.encode('hex'))
        if not user:
            return False

        days = user.days
        time_left = (user.day_expires - datetime.now()).total_seconds()
        if time_left < 0: time_left = 0

        if time_left <= 0 and days <= 0:
            self.respond_status('SUCCESS')
        elif time_left <= 0:
            self.respond_status('SUCCESS')
        else:
            self.respond_status('STEALTH')

        resp = struct.pack('!LL', days, time_left)
        self.respond(resp)
        return True

    def handle_GET_SALT(self, data):
        try:
            (version, console_type, cpu_key, kv) = struct.unpack('!2L 16s 16384s', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_SALT: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(no_consume=True, cpu_key=cpu_key.encode('hex'))
        if not user:
            return False

        kvhash = kv[:16].encode('hex')
        self.log('{1}: cpukey {2}: kvhashnew {0}: console_type: {3}'.format(kvhash, self.client_address[0], cpu_key.encode('hex'), console_type))

        random_seed = str(random.getrandbits(16 * 8))
        key = hashlib.sha1(random_seed).hexdigest()[:16]

        # update user values
        user.key_vault = kv
        user.session_key = key.encode('hex')
        user.last_ip = self.client_address[0]
        user.last_connect = datetime.now()

        # store in DB
        self.db.commit()

        # check version
        config = get_config()
        if version < config['version']:
            f = open('update.xex', 'r').read()
            response = struct.pack('!L', len(f))
            #self.respond_status('ERROR')
            #return self.die('old version')
            self.respond_status('UPDATE')
            self.respond(response)
            self.respond(f)
            return True

        if user.bypass:
            self.respond_status('BYPASS')
            self.respond(key)
            sp = open('bo2sp.patch', 'rb').read()
            mp = open('bo2mp.patch', 'rb').read()
			
            rspSzSp = struct.pack('!L', len(sp))
            rspSzMp = struct.pack('!L', len(mp))
            respData = rspSzSp + sp + rspSzMp + mp;
            totalSize = struct.pack('!L ', len(respData));
		
            self.respond(totalSize)
            self.respond(respData)
        else:
            self.respond_status('STEALTH')
            self.respond(key)

        return True

    def handle_GET_STATUS(self, data):
        try:
            (cpu_key, exe_hash) = struct.unpack('!16s 20s', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_STATUS: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(no_consume=True, cpu_key=cpu_key.encode('hex'))
        if not user:
            return False

        #TODO: hash exe here
        config = get_config()

        if config.get('check_hash', None):
            good_hash = hmac.new(user.session_key.decode('hex'), open('update.xex', 'r').read(), sha).digest()

            if good_hash != exe_hash and not cpu_key.encode('hex') in config['exempt']:
                msg = '{4}: cpukey {0}: session key {3} : hash failure: {1} : good hash {2}'.format(cpu_key.encode('hex'), exe_hash.encode('hex'), good_hash.encode('hex'), user.session_key, self.client_address[0])
                if config.get('fatal_hash', None): return self.die(msg)
                else: self.log(msg)

        self.respond_status('SUCCESS')
        return True

    def handle_GET_CHAL_RESP(self, data):
        try:
            (session_key, salt, crl, fcrt, kv_type_1, ecc_salt) = struct.unpack('!16s 16s 3L 2s 2x', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_CHAL_RESP: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(session_key=session_key.encode('hex'))
        if not user:
            return False

        chal_resp = calc_chal_resp(salt, crl, fcrt, kv_type_1, ecc_salt, user.hash_data)
        response = struct.pack('!L 28x 224s', STATUS_CODES['STEALTH'], chal_resp)
        self.respond(response)
        return True

    def handle_GET_UPDATE_PRES(self, data):
        try:
            (session_key, title_id, gamer_tag, version, console_type) = struct.unpack('!16s L 16s 2L', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_UPDATE_PRES: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(session_key=session_key.encode('hex'))
        if not user:
            return False

        # update user values
        user.last_connect = datetime.now()
        user.last_title = title_id

        # store in DB
        self.db.commit()

        update_available = version < get_config()['version']

        if user.bypass:
            status = STATUS_CODES['BYPASS']
        else:
            status = STATUS_CODES['STEALTH']

        resp = struct.pack('!2L', status, update_available)
        self.respond(resp)
        return True

    def handle_GET_XOSC(self, data):
        try:
            (session_key, res, exe_id, hv_protected_flags, crl, fcrt, kv_type_1) = struct.unpack('!16s L 24s Q 3L', data)
            (media_id, version, base_version, title_id, platform,
             exe_type, disc_num, discs_in_set, save_game_id) = struct.unpack('!4L 4B L', exe_id)
        except struct.error as ex:
            return self.die('invalid payload for GET_XOSC: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(session_key=session_key.encode('hex'))
        if not user:
            return False

        response = calc_xosc_resp(user.key_vault, res, exe_id, hv_protected_flags, crl, fcrt, kv_type_1)
        self.respond(response)
        return True

    def handle_GET_CHUNKS(self, data):
        try:
            (session_key, ) = struct.unpack('!16s', data)
        except struct.error as ex:
            return self.die('invalid payload for GET_CHUNKS: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(session_key=session_key.encode('hex'))
        if not user:
            return False

        # read all the files
        hv_data = open('HV.bin', 'r').read()
        garbage_data = open('Garbage.bin', 'r').read()
        hvex_data = load_hvex_from_file('chalGetECC.S.rglp')
        salt_hvex_data = load_hvex_from_file('chalGetECCSALT.S.rglp')

        # build the chunks
        cb = ChunkBuilder(hv_data, garbage_data)
        num_chunks, chunk_data = cb()

        # build the response data
        data = hvex_data + salt_hvex_data + chunk_data

        # build header data
        hvex_len = len(hvex_data)
        salt_hvex_len = len(salt_hvex_data)
        data_len = len(data)

        header = struct.pack('!L 3H 2x', data_len, hvex_len, salt_hvex_len, num_chunks)

        # respond
        self.respond_status('SUCCESS')
        self.respond(header)
        self.respond(data)
        return True

    def handle_SET_CHUNKS(self, data):
        try:
            session_key, data_length, chunk_count = struct.unpack('!16s L H 2x', data)
        except struct.error as ex:
            return self.die('invalid payload for SET_CHUNKS: {0}'.format(ex.message))

        # try to find the console
        user = self.try_find_user(session_key=session_key.encode('hex'))
        if not user:
            return False

        # read the additional chunk data
        chunk_data = self.read(data_length)

        # parse the chunks
        try:
            ChunkReader.read(chunk_data)
        except ValueError as ex:
            return self.die('invalid chunks: {0}'.format(ex))

        user.hash_data = chunk_data

        # store in DB
        self.db.commit()

        # respond
        self.respond_status('SUCCESS')
        return True

    def log(self, message):
        print '{0}: {1}'.format(ts(), message)

    def die(self, reason):
        self.log('{0}: {1}'.format(self.client_address[0], reason))

        return False

    def respond(self, data, encrypt=True):
        if encrypt:
            encrypted_response = ARC4Cipher(ARC4KEY).encrypt(data)
        else:
            encrypted_response = data
        self.wfile.write(encrypted_response)

    def read(self, length):
        encrypted_data = self.rfile.read(length)
        return ARC4Cipher(ARC4KEY).decrypt(encrypted_data)

    def respond_status(self, status):
        self.respond(struct.pack('!L', STATUS_CODES[status]))

    def check_user_auth(self, user, no_consume=False):
        if not user or not user.enabled:
            return False

        if user.day_expires < datetime.now():
            if user.days < 1:
                return False

            # do not consume a day
            if no_consume:
                return True

            # consume a day
            user.days -= 1
            user.day_expires = datetime.now() + timedelta(days=1)
            self.db.commit()

        return True

    def try_find_user(self, no_consume=False, no_auth=False, **kwargs):
        user = self.db.query(db.Console).filter_by(**kwargs).first()

        # dont check for days
        if no_auth: return user

        # user not found
        if not user:
            self.respond_status('ERROR')
            return self.die('user not found {0}'.format(kwargs))

        if not self.check_user_auth(user, no_consume):
            # not authed
            self.respond_status('EXPIRED')
            return self.die('user expired: {0}'.format(user.cpu_key))

        return user


serv = None


def serve_forever():
    global serv
    retry = 0
    while retry < 50:
        try:
            serv = ThreadedTCPServer((HOST, PORT), XSERequestHandler)
            break
        except socket.error as ex:
            if ex.errno != errno.EADDRINUSE:
                raise
            print 'Retrying bind...'
            time.sleep(10)
            retry += 1
    print 'Bound...'
    serv.serve_forever()
    serv.shutdown()


def shutdown():
    if serv:
        serv.shutdown()
