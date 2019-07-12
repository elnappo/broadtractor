#! /usr/bin/env python3
import json
from pprint import pprint
import logging
import argparse
import json

import dnslib
from scapy.all import *
import netaddr


HOST_INFO = dict()

# source: https://code.google.com/p/dpkt/source/browse/trunk/dpkt/netbios.py
# removed ord(nbname..) because we already have the ords
def decode_name(nbname):
    """Return the NetBIOS first-level decoded nbname."""
    if len(nbname) != 32:
        return nbname

    l = []

    for i in range(0, 32, 2):
        l.append(chr(((nbname[i] - 0x41) << 4) |
                     ((nbname[i + 1] - 0x41) & 0xf)))
    return ''.join(l).split('\x00', 1)[0]


def find_browser(pkt):
    if pkt["src_port"] == 138 and pkt["dst_port"] == 138:

        # host announcement
        if pkt["payload"][168] == 1:
            HOST_INFO[pkt["src_mac"]]["browser_hostname"].add(
                pkt["payload"][168 + 6:168 + 6 + 16].replace(b'\x00', b'').decode("utf-8", "ignore"))
            host_comment = pkt["payload"][168 + 6 + 16 + 2 + 8:-1].decode("utf-8", "ignore")
            HOST_INFO[pkt["src_mac"]]["browser_host_comment"].add(host_comment)
            HOST_INFO[pkt["src_mac"]]["hostname"] = host_comment
            HOST_INFO["hostnames"].add(host_comment)
            HOST_INFO[pkt["src_mac"]]["browser_version_major"].add(ord(str(pkt["payload"])[168 + 6 + 16]))
            HOST_INFO[pkt["src_mac"]]["browser_version_minor"].add(ord(str(pkt["payload"])[168 + 6 + 17]))

            logging.info("Found BROWSER, IP: %s MAC: %s Hostname: %s" % (pkt["src_ip"], pkt["src_mac"], host_comment))
            return True
    return False


def find_mdns(pkt):
    if pkt["dst_port"] == 5353:

        try:
            d = dnslib.DNSRecord.parse(pkt["payload"])
            # mDNS query responses
            if d.header.qr == 1:
                if pkt["ip_version"] == 4:
                    rtype = 1
                else:
                    # ipv6
                    rtype = 28
                # find A or AAAA records in {answer,authority,addition} RR's
                a_rec = list(filter(lambda x: x.rtype == rtype, d.rr + d.auth + d.ar))
                if len(a_rec) > 0:
                    hostname = a_rec[0].rname.label[0].decode()
                    HOST_INFO[pkt["src_mac"]]["mDNS_hostname"].add(hostname)
                    HOST_INFO[pkt["src_mac"]]["hostname"] = hostname
                    HOST_INFO["hostnames"].add(hostname)

                    logging.info("Found mDNS, IP: %s MAC: %s Hostname: %s" % (pkt["src_ip"], pkt["src_mac"], hostname))
                    return True
        except:
            pass
    return False


def find_llmnr(pkt):
    if pkt["dst_port"] == 5355:
        d = dnslib.DNSRecord.parse(pkt["payload"])
        label = d.q.get_qname().label
        if len(label) == 0:
            return False
        hostname = " ".join(label[0].decode().split())
        HOST_INFO[pkt["src_mac"]]["llmnr_hostname"].add(hostname)
        HOST_INFO["hostnames"].add(hostname)

        logging.info("Found LLMNR, IP: %s MAC: %s Hostname: %s" % (pkt["src_ip"], pkt["src_mac"], hostname))

        return True
    return False


def find_nbns(pkt):
    if pkt["dst_port"] == 137:
        # only registrations for registrations
        # note: we could do this only for unique names later
        if pkt["payload"][2:4] == b"\x29\x10":
            hostname = " ".join(decode_name(pkt["payload"][13:13 + 32]).split())
            HOST_INFO[pkt["src_mac"]]["nbns_hostname"].add(hostname)
            HOST_INFO["hostnames"].add(hostname)

            logging.info("Found NBNS, IP: %s MAC: %s Hostname: %s" % (pkt["src_ip"], pkt["src_mac"], hostname))
        return True
    return False


def find_dropbox(pkt):
    if pkt["dst_port"] == 17500:
        dropbox_json = json.loads(pkt["payload"].decode("ascii"))
        host_int = int(dropbox_json["host_int"])
        HOST_INFO[pkt["src_mac"]]["dropbox_host_int"].add(host_int)
        for share in dropbox_json["namespaces"]:
            HOST_INFO[pkt["src_mac"]]["dropbox_share_ids"].add(int(share))

        logging.info("Found Dropbox LanSync, IP: %s MAC: %s" % (pkt["src_ip"], pkt["src_mac"]))
        return True
    return False


def find_btsync(pkt):
    if pkt["dst_port"] == 3838 and pkt["payload"].startswith(b'BSYNC'):
        host_id = pkt["payload"][25:45]
        HOST_INFO[pkt["src_mac"]]["btsync_host_id"].add(host_id)
        share_ids = pkt["payload"][70:-2].split(b'20:')
        for share in share_ids:
            HOST_INFO[pkt["src_mac"]]["btsync_share_ids"].add(share)

        logging.info("Found BitTorrent Sync, IP: %s MAC: %s" % (pkt["src_ip"], pkt["src_mac"]))
        return True
    return False


def find_spotify(pkt):
    if pkt["dst_port"] == 57621 and pkt["payload"].startswith(b'SpotUdp'):
        HOST_INFO[pkt["src_mac"]]["spotify_user"] = True

        logging.info("Found Spotify User, IP: %s MAC: %s" % (pkt["src_ip"], pkt["src_mac"]))
        return True
    return False


def find_steam(pkt):
    if pkt["dst_port"] == 27036 and pkt["payload"].startswith(b'\xff\xff\xff\xff'):
        HOST_INFO[pkt["src_mac"]]["steam_user"] = True

        logging.info("Found Steam User, IP: %s MAC: %s" % (pkt["src_ip"], pkt["src_mac"]))
        return True
    return False


def find_office_mac(pkt):
    if pkt["dst_port"] == 2223 and pkt["payload"].startswith(b'MSOPID'):
        HOST_INFO[pkt["src_mac"]]["office_mac_user"] = True

        logging.info("Found MS Office (OSX) User, IP: %s MAC: %s" % (pkt["src_ip"], pkt["src_mac"]))
        return True
    return False


def find_canon(pkt):
    if pkt["dst_port"] == 8612 and pkt["payload"].startswith((b'BJNP', b'BNJB', b'BJNB', b'PNJB', b'PJNB')):
        HOST_INFO[pkt["src_mac"]]["canon_bjnp"] = True

        logging.info("Found Canon BJNP, IP: %s MAC: %s" % (pkt["src_ip"], pkt["src_mac"]))
        return True
    return False


def find_remotemouse(pkt):
    if pkt["dst_port"] == 2008 and pkt["payload"].startswith(b'BC'):
        hostname = pkt["payload"][5:].decode("utf-8", "ignore")
        HOST_INFO[pkt["src_mac"]]["remotemouse_hostname"].add(hostname)
        HOST_INFO["hostnames"].add(hostname)

        logging.info("Found remotemouse, IP: %s MAC: %s Hostname: %s" % (pkt["src_ip"], pkt["src_mac"], hostname))
        return True
    return False


def search(pkt):
    search_funcs = [find_browser, find_mdns, find_nbns, find_llmnr, find_dropbox, find_btsync, find_spotify, find_steam,
                    find_office_mac, find_canon, find_remotemouse]
    for func in search_funcs:
        if func(pkt):
            break


def pkt_callback(raw_pkt):
    pkt = dict()
    global HOST_INFO

    HOST_INFO["packet_counter"] += 1
    try:
        if Ether in raw_pkt:
            pkt["size"] = len(raw_pkt)
            pkt["src_mac"] = raw_pkt[Ether].src
            pkt["dst_mac"] = raw_pkt[Ether].dst
            if pkt["src_mac"] not in HOST_INFO:
                HOST_INFO[pkt["src_mac"]] = defaultdict(set)

            HOST_INFO["macs"].add(pkt["src_mac"])
            try:
                vendor = netaddr.EUI(pkt["src_mac"]).oui.registration().org
                HOST_INFO[pkt["src_mac"]]["vendor"] = vendor
            except netaddr.core.NotRegisteredError:
                HOST_INFO[pkt["src_mac"]]["vendor"] = "unknown"

            if IP in raw_pkt:
                pkt["src_ip"] = raw_pkt[IP].src
                pkt["dst_ip"] = raw_pkt[IP].dst
                pkt["ip_version"] = 4

                HOST_INFO[pkt["src_mac"]]["ips"].add(pkt["src_ip"])
                HOST_INFO["ips"].add(pkt["src_ip"])

            elif IPv6 in raw_pkt:
                pkt["src_ip"] = raw_pkt[IPv6].src
                pkt["dst_ip"] = raw_pkt[IPv6].dst
                pkt["ip_version"] = 6

                HOST_INFO[pkt["src_mac"]]["ipv6s"].add(pkt["src_ip"])
                HOST_INFO["ipv6s"].add(pkt["src_ip"])

            if raw_pkt.haslayer(UDP):
                pkt["src_port"] = raw_pkt[UDP].sport
                pkt["dst_port"] = raw_pkt[UDP].dport
                pkt["payload"] = bytes(raw_pkt[UDP].payload)

                search(pkt)
    except:
        logging.error("Error while analysing packet!")


def init_dict():
    HOST_INFO["macs"] = set()
    HOST_INFO["ips"] = set()
    HOST_INFO["ipv6s"] = set()
    HOST_INFO["hostnames"] = set()
    HOST_INFO["packet_counter"] = 0


def main(args, bpf="multicast or broadcast"):
    global HOST_INFO
    init_dict()

    if args.interface:
        print("Hit Ctrl-C to stop")
        sniff(prn=pkt_callback, iface=args.interface, filter=bpf)
    elif args.pcap:
        sniff(prn=pkt_callback, offline=args.pcap, filter=bpf)
    else:
        sys.exit("Please provide either interface or pcap file.")


if __name__ == "__main__":
    FORMAT = "%(levelname)s: %(message)s"

    parser = argparse.ArgumentParser(description="Sniff broadcast traffic and print host info's")
    parser.add_argument("-i", "--interface", type=str, help="Interface to sniff")
    parser.add_argument("-p", "--pcap", type=str, help="PCAP file to read")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(format=FORMAT, level=logging.INFO)
    else:
        logging.basicConfig(format=FORMAT, level=logging.WARNING)

    main(args)
    print("\nFrom %d multicast or broadcast packages the following information's were extract:" % HOST_INFO["packet_counter"])
    pprint(HOST_INFO)
