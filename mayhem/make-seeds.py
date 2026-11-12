#!/usr/bin/env python3
"""Regenerates the starter seeds under mayhem/<target>/testsuite/ (deterministic, stdlib only).

Seed layout for two-buffer targets: [selector:1][split:2 LE][A: split bytes][B: the rest] (see fuzz_common.h).
fuzz_fls's A is a list of element records (see fuzz_fls_frame.h).
"""
import os
import plistlib
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))


def emit(target, name, data):
    d = os.path.join(ROOT, target, 'testsuite')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), 'wb') as f:
        f.write(data)


def framed(sel, a, b):
    return struct.pack('<BH', sel, len(a)) + a + b


# ---- ftab -----------------------------------------------------------------------------------------------
def ftab(entries, tag=b'rkos'):
    hdr = struct.pack('<II', 1, 0xFFFFFFFF) + b'\0' * 24 + tag + b'ftab' + struct.pack('<II', len(entries), 0)
    off = 48 + 16 * len(entries)
    tbl, body = b'', b''
    for t, payload in entries:
        tbl += t + struct.pack('<III', off + len(body), len(payload), 0)
        body += payload
    return hdr + tbl + body


emit('fuzz_ftab', 'two_entries', ftab([(b'rkos', bytes(range(32))), (b'rkas', b'A' * 20)]))
emit('fuzz_ftab', 'one_entry', ftab([(b'bbfw', b'baseband-firmware-blob')], tag=b'bbfw'))
emit('fuzz_ftab', 'empty', ftab([]))


# ---- fls ------------------------------------------------------------------------------------------------
def fls_rec(kind, elem):  # fuzz_fls record: [kind][payload length][payload]; the harness rebuilds type and size
    return bytes([kind, len(elem) - 8]) + elem[8:]


def fls_elems():
    hdr_0c = 40
    data0c = bytearray(64)
    data0c[0x10:0x14] = struct.pack('<I', 64)  # must equal data_size
    data0c[0x14:0x18] = struct.pack('<I', 48)  # signature offset -> 16 byte signature
    e0c = struct.pack('<10I', 0x0c, hdr_0c + 64, 0, 0, 0, 0, 0, 64, 0, hdr_0c) + bytes(data0c)
    e10 = struct.pack('<6I', 0x10, 24 + 8, 0, 8, 0, 0) + b'\x10' * 8
    e14 = struct.pack('<6I', 0x14, 24 + 4, 0, 4, 0, 0) + b'\x14' * 4
    e01 = struct.pack('<3I', 0x01, 16, 0) + b'\x01\x02\x03\x04'
    return fls_rec(1, e10) + fls_rec(0, e0c) + fls_rec(2, e14) + fls_rec(3, e01)


blob = bytes(range(0x40, 0x40 + 20))  # 20 bytes: not a multiple of 4, so insert_ticket pads
emit('fuzz_fls', 'update_sig_blob', framed(1, fls_elems(), blob))
emit('fuzz_fls', 'insert_ticket', framed(0, fls_elems(), blob))

# ---- mbn ------------------------------------------------------------------------------------------------
v1 = struct.pack('<10I', 0xA, 0, 0, 0, 24, 0, 0, 0, 0, 0) + b'\xEE' * 24
v2 = bytes.fromhex('D1DC4B843410D773') + struct.pack('<18I', 0, 0xFFFFFFFF, 0xFFFFFFFF, 80, 0, 16, 0, 0, 0, 0, 0, 1, 1,
                                                     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) + b'\xDD' * 16
binimg = b'\x00' + bytes.fromhex('0400EA6C694855') + struct.pack('<4I', 0, 1, 40, 0) + b'\xBB' * 16
mbn_blob16 = bytes(range(16))
mbn_sig = bytes(range(0x90, 0xA0)) * 4

e32 = bytearray(b'\x7fELF' + bytes([1, 1, 1]) + bytes(9) + struct.pack('<HHIIIIIHHHHHH', 2, 40, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0))
e32 += struct.pack('<8I', 1, 84, 0, 0, 64, 64, 5, 4) + b'\xAA' * 64
e64 = bytearray(b'\x7fELF' + bytes([2, 1, 1]) + bytes(9) + struct.pack('<HHIQQQIHHHHHH', 2, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0))
v7_dest = struct.pack('<10I', 0, 7, 0, 0, 0, 0, 0, 0, 0, 0) + bytes(0x100 - 40)
e64 += struct.pack('<IIQQQQQQ', 1, 5, 128, 0, 0, len(v7_dest), len(v7_dest), 4) + bytes(128 - 120) + v7_dest
v7_src = struct.pack('<10I', 0, 7, 0x10, 0, 0, 0x20, 0, 0, 0x68, 0) + bytes(0x10 + 0x20 + 0x68)

emit('fuzz_mbn', 'v1_image', framed(0, v1, mbn_blob16))
emit('fuzz_mbn', 'v2_image', framed(0, v2, mbn_blob16))
emit('fuzz_mbn', 'bin_image', framed(0, binimg, mbn_blob16))
emit('fuzz_mbn', 'elf32_image', framed(0, bytes(e32), mbn_blob16))
emit('fuzz_mbn', 'elf64_image', framed(0, bytes(e64), mbn_blob16))
emit('fuzz_mbn', 'mav25_elf64', framed(1, bytes(e64), v7_src))
e32m = bytearray(b'\x7fELF' + bytes([1, 1, 1]) + bytes(9) + struct.pack('<HHIIIIIHHHHHH', 2, 40, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0))
e32m += struct.pack('<8I', 1, 84, 0, 0, len(v7_dest), len(v7_dest), 4, 4) + v7_dest
emit('fuzz_mbn', 'mav25_elf32', framed(1, bytes(e32m), v7_src))
emit('fuzz_mbn', 'unknown_format', framed(0, b'not-a-known-baseband-image' * 4, mbn_blob16))


# ---- img3 -----------------------------------------------------------------------------------------------
def img3_elem(sig, payload):  # 12 byte element header: signature, full_size, data_size
    return sig[::-1] + struct.pack('<II', 12 + len(payload), len(payload)) + payload


def img3_file(elements, image_type=b'ibss'):
    body = b''.join(elements)
    return b'Img3'[::-1] + struct.pack('<III', 20 + len(body), len(body), 0) + image_type[::-1] + body


comp = img3_file([img3_elem(b'TYPE', b'ibss'), img3_elem(b'DATA', bytes(range(32))), img3_elem(b'VERS', b'1.0\0'),
                  img3_elem(b'KBAG', bytes(0x30)), img3_elem(b'SHSH', bytes(128)), img3_elem(b'CERT', bytes(64))])
sigblob = img3_elem(b'ECID', bytes(8)) + img3_elem(b'SHSH', bytes(128)) + img3_elem(b'CERT', bytes(64))
comp_all = img3_file([img3_elem(b'TYPE', b'ibss'), img3_elem(b'DATA', bytes(range(32))), img3_elem(b'VERS', b'1.0\0'),
                      img3_elem(b'SEPO', bytes(4)), img3_elem(b'BORD', bytes(4)), img3_elem(b'CHIP', bytes(4)),
                      img3_elem(b'ECID', bytes(8)), img3_elem(b'KBAG', bytes(0x30)), img3_elem(b'SHSH', bytes(128)),
                      img3_elem(b'CERT', bytes(64)), img3_elem(b'SALT', bytes(32))])
emit('fuzz_img3', 'component_all_elements', framed(0, comp_all, sigblob))
emit('fuzz_img3', 'component_blob_size_mismatch', framed(0, comp, sigblob))
# the real caller's shape: the blob buffer holds ECID+SHSH+CERT, blob_size is the ECID element's full_size
sigblob_ok = bytearray(sigblob)
assert struct.unpack('<I', sigblob_ok[4:8])[0] == 20
emit('fuzz_img3', 'component_replace_signature', framed(0, comp, bytes(sigblob_ok)))
emit('fuzz_img3', 'component_insert_signature', framed(0, img3_file([img3_elem(b'TYPE', b'ibss'), img3_elem(b'DATA', bytes(range(32))),
                                                                     img3_elem(b'VERS', b'1.0\0'), img3_elem(b'KBAG', bytes(0x30))]), bytes(sigblob_ok)))
emit('fuzz_img3', 'component_short_blob', framed(0, comp, sigblob[:19]))

# ---- img4 -----------------------------------------------------------------------------------------------
def der(tag, payload):
    n = len(payload)
    if n < 0x80:
        return bytes([tag, n]) + payload
    if n < 0x100:
        return bytes([tag, 0x81, n]) + payload
    return bytes([tag, 0x82, n >> 8, n & 0xFF]) + payload


def im4p(kind, payload):
    return der(0x30, der(0x16, b'IM4P') + der(0x16, kind) + der(0x16, b'desc') + der(0x04, payload))


tss_plain = plistlib.dumps({'ApImg4Ticket': b'\x30\x82\x01\x00' + bytes(range(64))}, fmt=plistlib.FMT_XML)
tss_tbm = plistlib.dumps({'ApImg4Ticket': bytes(range(48)), 'SEP-TBM': {'ucon': b'U' * 20, 'ucer': b'C' * 24}},
                         fmt=plistlib.FMT_XML)
emit('fuzz_img4', 'ibss_ticket', framed(0, im4p(b'ibss', bytes(range(64))), tss_plain))
emit('fuzz_img4', 'kernelcache_rename', framed(1, im4p(b'krnl', b'K' * 48), tss_plain))
emit('fuzz_img4', 'sep_nonce_slot_tbm', framed(0x40 | 7, im4p(b'sepi', b'S' * 40), tss_tbm))

# Selector bit 7: img4_create_local_manifest(request, build identity). The identity maps iBSS to a payload type
# and leaves 'Unlisted' to the built-in tag table; SEP/RestoreSEP carry TBMDigests.
local_request = {
    'ApBoardID': 12, 'ApChipID': 0x8120, 'ApProductionMode': True, 'ApSecurityDomain': 1,
    'iBSS': {'Digest': bytes(range(20)), 'Trusted': True, 'EPRO': True, 'ESEC': False},
    'SEP': {'Digest': bytes(range(20, 40)), 'TBMDigests': b'T' * 20, 'Trusted': True},
    'RestoreSEP': {'Digest': bytes(range(40, 60)), 'TBMDigests': b'R' * 20},
    'Unlisted': {'Digest': b'U' * 20},
}
local_identity = {'Manifest': {'iBSS': {'Info': {'Img4PayloadType': 'ibss'}}, 'Unlisted': {'Info': {'Img4PayloadType': 'unls'}}}}
emit('fuzz_img4', 'local_manifest_identity', framed(
    0x80, plistlib.dumps(local_request, fmt=plistlib.FMT_XML), plistlib.dumps(local_identity, fmt=plistlib.FMT_XML)))
emit('fuzz_img4', 'local_manifest_no_identity', framed(0x80, plistlib.dumps(local_request, fmt=plistlib.FMT_XML), b''))


# ---- ace3 -----------------------------------------------------------------------------------------------
class Archive:
    def __init__(self):
        self.objs = ['$null']

    def add(self, v):
        self.objs.append(None)
        idx = len(self.objs) - 1
        if isinstance(v, dict):
            keys = [self.add(k) for k in v]
            vals = [self.add(x) for x in v.values()]
            self.objs[idx] = {'NS.keys': [plistlib.UID(k) for k in keys], 'NS.objects': [plistlib.UID(x) for x in vals],
                              '$class': plistlib.UID(self.cls('NSDictionary'))}
        elif isinstance(v, list):
            vals = [self.add(x) for x in v]
            self.objs[idx] = {'NS.objects': [plistlib.UID(x) for x in vals], '$class': plistlib.UID(self.cls('NSArray'))}
        else:
            self.objs[idx] = v
        return idx

    def cls(self, name):
        c = {'$classname': name, '$classes': [name, 'NSObject']}
        self.objs.append(c)
        return len(self.objs) - 1

    def dump(self, root):
        r = self.add(root)
        return plistlib.dumps({'$archiver': 'NSKeyedArchiver', '$version': 100000,
                               '$top': {'root': plistlib.UID(r)}, '$objects': self.objs}, fmt=plistlib.FMT_BINARY)


def uarp(bdid):
    payload_meta = {'Personalization Manifest Prefix': 'USBPortController',
                    'Personalization Board ID (64 bits)': bdid,
                    'Personalization Matching Data': [{
                        'Personalization Matching Data Product Revision Minimum': 0,
                        'Personalization Matching Data Product Revision Maximum': 15,
                        'Personalization Matching Data Payload Tags': 'DA01 DA02'}]}
    plist = Archive().dump({'SuperBinary Payloads': [{'Payload 4CC': 'PT01', 'Payload MetaData': payload_meta}]})
    toc_off, entry = 44, 40
    toc_end = toc_off + 3 * entry
    blobs = [b'P' * 24, b'1' * 16, b'2' * 12]
    offs, o = [], toc_end
    for b in blobs:
        offs.append(o)
        o += len(b)
    toc = b''
    for cc, (off, b), ver in zip([b'PT01', b'DA01', b'DA02'], zip(offs, blobs), [(1, 2, 3, 0), (4, 5, 6, 0), (7, 8, 9, 0)]):
        toc += struct.pack('>I4s4I4I', entry, cc, *ver, 0, 0, off, len(b))[0:0] or (
            struct.pack('>I', entry) + cc + struct.pack('>4I', *ver) + struct.pack('>IIII', 0, 0, off, len(b)))
    hdr = struct.pack('>11I', 2, 44, o, 0, 0, 0, 0, 0, 0, toc_off, toc_end)
    return hdr + toc + b''.join(blobs) + plist


tss_ace = plistlib.dumps({'USBPortController1,Ticket': b'IM4M' + bytes(range(40))}, fmt=plistlib.FMT_XML)
emit('fuzz_ace3', 'board_0x10', framed(0x00, uarp(0x10), tss_ace))
emit('fuzz_ace3', 'board_0x11_rev3', framed(0x31, uarp(0x11), tss_ace))


# ---- ipsw -----------------------------------------------------------------------------------------------
def ipsw(path, manifest, restore):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as z:
        for name, obj in (('BuildManifest.plist', manifest), ('Restore.plist', restore)):
            zi = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            z.writestr(zi, plistlib.dumps(obj, fmt=plistlib.FMT_XML))


manifest = {
    'ProductVersion': '17.4', 'ProductBuildVersion': '21E219', 'SupportedProductTypes': ['iPhone15,2'],
    'BuildIdentities': [{
        'ApChipID': '0x8120', 'ApBoardID': '0x0C', 'Info': {'DeviceClass': 'd73ap', 'RestoreBehavior': 'Erase',
                                                           'Variant': 'Customer Erase Install (IPSW)'},
        'Manifest': {'iBSS': {'Info': {'Path': 'Firmware/dfu/iBSS.d73.RELEASE.im4p'}},
                     'KernelCache': {'Info': {'Path': 'kernelcache.release.iphone15'}}}}]}
restore = {'ProductType': 'iPhone15,2', 'SupportedProductTypeIDs': {'DFU': [0x8120], 'Recovery': [0x8120]},
           'DeviceMap': [{'BoardConfig': 'd73ap', 'Platform': 't8120', 'SDOM': 1, 'BDID': 12, 'CPID': 0x8120}]}
os.makedirs(os.path.join(ROOT, 'fuzz_ipsw', 'testsuite'), exist_ok=True)
ipsw(os.path.join(ROOT, 'fuzz_ipsw', 'testsuite', 'iphone_ipsw.zip'), manifest, restore)
emit('fuzz_ipsw', 'plain_manifest.plist', plistlib.dumps(manifest, fmt=plistlib.FMT_XML))
print('seeds written', file=sys.stderr)
