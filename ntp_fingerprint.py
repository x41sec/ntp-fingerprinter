#!/usr/bin/python3
#
# fingerprinter for NTP servers, written by eric.sesterhenn@x41-dsec.de
# Released under GNU Affero General Public License v3.0
#
# Additional fingerprint ideas:
#  - ntpv4 packet with cookie extension field and non client/server mode
#  - ntpv4 packet with cookie placeholder but not extension field
#
# This tool blindly sends a buch of packets and checks whether the target
# replies or not. Not all of the tests are helpful with the current set
# of fingerprints. The process could be faster by using a bisecing
# approach, but it does it job good enough for now and I do not expect
# another 300 NTP implementations to appear.
#
#
# Version 0.1 - 2025-07-xx
# 		Initial Release
import sys
import socket
import binascii
import argparse

# global variables
debug=False
serverAddressPort = ()
timeout = 2

# Send packet to NTP server
def udpsend(data):
    global serverAddressPort
    global debug
    global timeout

    if debug:
        print("> %s" % binascii.hexlify(data))
    else:
        print(".", end="")
        sys.stdout.flush()

    try:
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(data, serverAddressPort)
        r = s.recvfrom(1024)
    except socket.timeout:
        if debug:
            print("< None")
        return 0
    except socket.gaierror:
        print("Cannot resolve host: %s" % serverAddressPort[0])
        raise SystemExit(1)
    if debug:
        print("< %s" % binascii.hexlify(r[0]))
    return 1

# Various test packets to use for fingerprinting
ntpv4msg = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45")

ntpv4msgshort = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b")

ntpv4msgbrokenauthlen = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "00000000000000000000000000000000" +
    "00000000000000000000000000000000" +
    "00000000")

ntpv4msgbroadcast = binascii.unhexlify("e50003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45")

ntpv4msgsymacc = binascii.unhexlify("e10003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45")

ntpv4msgbadmode = binascii.unhexlify("e70003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45")

ntpv7msg = binascii.unhexlify("fb0003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45")

ntpv0msg = binascii.unhexlify("c30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45")

ntpv4msgallzero = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "00000000000000000000000000000000")

ntpv4badextlen = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45" +
    "0404FFFF000000000000000000000000" + 
    "00000000000000000000000000000000")

ntpv4ext0 = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45" +
    "00000020000000000000000000000000" +
    "00000000000000000000000000000000")

ntpv4ext4 = binascii.unhexlify("e30003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45" +
    "04040020000000000000000000000000" +
    "00000000000000000000000000000000")

ntpv3ext0 = binascii.unhexlify("db0003fa000100000001000000000000" +
    "00000000000000000000000000000000" +
    "0000000000000000ec04cd98f5472b45" +
    "00000020000000000000000000000000" +
    "00000000000000000000000000000000")


# Parse arguments and set defaults
parser = argparse.ArgumentParser()
parser.add_argument("target", help="Hostname or IP of target NTP server")
parser.add_argument("-d", "--debug", action="store_true")
parser.add_argument("-t", "--timeout", type=int, help="Socket timeout in seconds", default=2)
args = parser.parse_args()

debug = args.debug
timeout = args.timeout
serverAddressPort = (args.target, 123)

# create list with info on whether we got a response or not
res = []
res.append(udpsend(ntpv4msg))
res.append(udpsend(ntpv4msgshort))
res.append(udpsend(ntpv4msgbrokenauthlen))
res.append(udpsend(ntpv4msgbroadcast))
res.append(udpsend(ntpv4msgsymacc))
res.append(udpsend(ntpv4msgbadmode))
res.append(udpsend(ntpv7msg))
res.append(udpsend(ntpv0msg))
res.append(udpsend(ntpv4msgallzero))
res.append(udpsend(ntpv4badextlen))
res.append(udpsend(ntpv4ext0))
res.append(udpsend(ntpv4ext4))
res.append(udpsend(ntpv3ext0))

print("")

# check responses against known patterns
fingerprints = (
    ("Chrony",      [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0]),
    ("ntpsec",      [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
    ("openntpd",    [1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1]),
    ("Windows ntp", [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]),
    ("ntp-rs",      [1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0]),
    ("ntp.org ntpd",[1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1]),
    ("rsntp",       [1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1]),
    ("an unreachable system", [0, 0, 0, 0, 0, 0, 0, 0, 0]))

for f in fingerprints:
    name = f[0]
    fp = f[1]

    # test stored fingerprint against result
    # stored fingerprint might be shorter if more tests get added
    i = 0
    for r in fp:
        if res[i] != r:
            break
        i = i + 1

    if i == len(fp):
        print("Identified %s" % name)
        raise SystemExit(0)

print("Unable to identify NTP server: %s" % res)
