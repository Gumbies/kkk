import hashlib
import struct
import random

from XSE.chunks import ChunkReader


# constants
HV_MAGIC            = 0x4E4E
HV_VERSION          = 0x416B
HV_QFE              = 0x0000
HVEX_ADDR           = 0x01B5
BASE_KERNEL_VERSION = 0x07600000
UPDATE_SEQUENCE     = 0x00000007
RTOC                = 0x0000000200000000
HRMOR               = 0x0000010000000000

# variables
HV_KEYS_STATUS_FLAGS      = 0x023289D3
HV_KEYS_STATUS_FLAGS_CRL  = 0x10000
HV_KEYS_STATUS_FLAGS_FCRT = 0x1000000
BLDR_FLAGS                = 0xD83E
BLDR_FLAGS_KV1            = (~0x20)
CTYPE_SEQ_ALLOW_KV1       = 0x010B0400
CTYPE_SEQ_ALLOW_KV2       = 0x0304000D


HV_PROTECTED_FLAGS_NONE            = 0
HV_PROTECTED_FLAGS_NO_EJECT_REBOOT = 1
HV_PROTECTED_FLAGS_DISC_AUTH       = 2
HV_PROTECTED_FLAGS_AUTH_EX_CAP     = 4
XOSC_FLAG_BASE = 0x00000000000002BF
XOSC_FOOTER    = 0x5F534750


def calc_hv_hash(salt):
    hv = open('HV.bin').read()
    hvhash = hashlib.sha1()

    hvhash.update(salt[:16])
    hvhash.update(read_count(hv, 0x34, 0x40))
    hvhash.update(read_count(hv, 0x78, 0xF88))
    hvhash.update(read_count(hv, 0x100C0, 0x40))
    hvhash.update(read_count(hv, 0x10350, 0xDF0))
    hvhash.update(read_count(hv, 0x16D20, 0x2E0))
    hvhash.update(read_count(hv, 0x20000, 0xFFC))
    hvhash.update(read_count(hv, 0x30000, 0xFFC))

    return hvhash.digest()[14:20]


def calc_ecc_hash(ecc_salt, hash_data):
    cr = ChunkReader()
    hv = open('HV.bin').read()
    ecchash = hashlib.sha1()

    # parse the chunks
    cr(hash_data)

    # build the hash
    ecchash.update(ecc_salt[:2])
    ecchash.update(read_count(hv, 0x34, 0xC))
    ecchash.update(read_count(cr, 0x40, 0x30))
    ecchash.update(read_count(hv, 0x70, 0x4))
    ecchash.update(read_count(hv, 0x78, 0x8))
    ecchash.update(read_count(cr, 0x80, 0x3FE))
    ecchash.update(read_count(cr, 0x100C0, 0x40))
    ecchash.update(read_count(cr, 0x10350, 0x30))
    ecchash.update(read_count(cr, 0x10380, 0x176))
    ecchash.update(read_count(cr, 0x16100, 0x40))
    ecchash.update(read_count(cr, 0x16D20, 0x60))
    ecchash.update(read_count(cr, 0x16D80, 0x24A))
    ecchash.update(read_count(cr, 0x20000, 0x400))
    ecchash.update(read_count(cr, 0x30000, 0x400))

    return ecchash.digest()[:20]


def read_count(buffer, offset, count):
    return buffer[offset:offset + count]


def calc_chal_resp(salt, crl, fcrt, kv_type_1, ecc_salt, hash_data):
    hvhash = calc_hv_hash(salt)
    #ecchash = calc_ecc_hash(ecc_salt, hash_data)
    random_seed = str(random.getrandbits(16 * 8))
    ecchash = hashlib.sha1(random_seed).hexdigest()[:20]
    hv_keys_status_flags = HV_KEYS_STATUS_FLAGS
    bldr_flags = BLDR_FLAGS
    ctype = CTYPE_SEQ_ALLOW_KV2

    if crl:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_CRL
    if fcrt:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_FCRT
    if kv_type_1:
        bldr_flags &= BLDR_FLAGS_KV1
        ctype = CTYPE_SEQ_ALLOW_KV1

    return struct.pack('!8x 4H 4L 2Q 20s 20x 128x H 6s', HV_MAGIC, HV_VERSION, HV_QFE, bldr_flags, BASE_KERNEL_VERSION,
                       UPDATE_SEQUENCE, hv_keys_status_flags, ctype, RTOC, HRMOR, ecchash, HVEX_ADDR, hvhash)


def calc_xosc_resp(kv_data, res, exe_id, hv_protected_flags, crl, fcrt, kv_type_1):
    hv_keys_status_flags = HV_KEYS_STATUS_FLAGS
    bldr_flags = BLDR_FLAGS
    flag_base = XOSC_FLAG_BASE
    xam_odd_media_stuff = '\x00' * 0x8

    if crl:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_CRL
    if fcrt:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_FCRT
    if kv_type_1:
        bldr_flags &= BLDR_FLAGS_KV1
    hv_protected_flags = HV_PROTECTED_FLAGS_AUTH_EX_CAP | (hv_protected_flags & HV_PROTECTED_FLAGS_NO_EJECT_REBOOT)
    if res != 0:
        exe_id = '\xAA' * 0x18
        xam_odd_media_stuff = '\xAA' * 0x8
        flag_base &= 0x4

    # read data from user KV
    drive_phase_level = read_count(kv_data, 0xC89, 0x1)
    drive_data = read_count(kv_data, 0xC8A, 0x24)
    console_id = read_count(kv_data, 0x9CA, 0x5)
    console_serial = read_count(kv_data, 0xB0, 0xC)
    xam_region = read_count(kv_data, 0xC8, 0x2)
    xam_odd = read_count(kv_data, 0x1C, 0x2)

    # pack fields
    result = 0
    stuff1 = '\x00\x09\x00\x02'
    cpu_key_hash = '\x21' * 0x10
    hv_hash = '\x21' * 0x10
    unknown9 = 0xAAAAAAAA

    stuff2 = struct.pack(
        '!8sL28s24s',
        '\x00' * 8,
        res,
        '00000000C8003003AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA00000000'.decode('hex'),
        exe_id
    )

    stuff3 = struct.pack(
        '!19s s 8s 100s 36s 36s 12s 2s H 2s 2s 12s L 4s 12s 4s 8s 32s Q 5s 43s 4s 72s 140s 17s s 13s s 16s',
        '527A5A4BD8F505BB94305A1779729F3B000000'.decode('hex'),
        drive_phase_level,
        xam_odd_media_stuff,
        '\xAA' * 100,
        drive_data,
        drive_data,  # yes, twice
        console_serial,
        '\x00\xAA',
        bldr_flags,
        xam_region,
        xam_odd,
        '000000000000000000070000'.decode('hex'),
        hv_keys_status_flags,
        '\xAA' * 4,
        '\x00' * 12,
        '\xAA' * 4,
        '000D000800000008'.decode('hex'),
        '\x00' * 32,
        hv_protected_flags,
        console_id,
        '\x00' * 43,
        '40000207'.decode('hex'),
        '\x00' * 72,
        '\xAA' * 140,
        '\x00' * 17,
        '\x20',
        '\x00' * 13,
        '\x06',
        '\xAA' * 16
    )

    # pack final result
    return struct.pack('!L 4s Q 64s 16s 16s 616s 2L', result, stuff1, flag_base, stuff2,
                       cpu_key_hash, hv_hash, stuff3, XOSC_FOOTER, unknown9)
