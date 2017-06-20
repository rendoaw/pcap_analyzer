#!/usr/bin/env python

import sys
from scapy.all import PcapReader
import json
import time
import datetime
import socket
import pyshark


def print_current_time():
    ts = time.time()
    print datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    return


def decode_pyshark(input_file):
    packets = []
    fo = open(input_file+'.txt', 'w')
    pcap_reader = pyshark.FileCapture(input_file)
    for pkt in pcap_reader:
        data = {}
        
        if not 'ip' in pkt:
            packets.append(data)
            continue
        if not 'tcp' in pkt:
            packets.append(data)
            continue

        index = int(pkt.number)
        ts = float(pkt.sniff_timestamp)
        p_ip = pkt.ip
        p_tcp = pkt.tcp
        data['src_ip'] = p_ip.src
        data['dst_ip'] = p_ip.dst
        try:
            data['src_hostname'] = socket.getfqdn(p_ip.src)
        except:
            data['src_hostname'] = p_ip.src
        try:
            data['dst_hostname'] = socket.getfqdn(p_ip.dst)
        except:
            data['dst_hostname'] = p_ip.dst

        data['src_port'] = p_tcp.srcport
        data['dst_port'] = p_tcp.dstport
        data['ts'] = ts
        data['tcp_flags'] = int(p_tcp.flags, 0)
        #if p_tcp.flags != 16:
        data['tcp_seq'] = p_tcp.seq
        data['tcp_ack'] = p_tcp.ack
        try:
            data['data_len'] = p_tcp.len
        except:
            data['data_len'] = 0
        if data['data_len'] == 0:
            data['tcp_expected_ack'] = data['tcp_seq'] + data['data_len'] + 1
        else:
            data['tcp_expected_ack'] = data['tcp_seq'] + data['data_len']
        data['tcp_acked'] = False
        data['tcp_rtd_ms'] = 0
        data['index'] = index
        data['tcp_ack_index'] = 0
        #data['tcp_ack_data'] = {}
        packets.append(data)
        fo.write(json.dumps(data, sort_keys=True)+"\n")
    
    fo.close()
    return packets



def decode_scapy(input_file):
    packets = []
    index = 0
    fo = open(input_file+'.txt', 'w')
    with PcapReader(input_file) as pcap_reader:
        for pkt in pcap_reader:
            index = index + 1
            p = pkt.payload

            data = {}
            if not p.haslayer('IP'):
                packets.append(data)
                continue
            if not p.haslayer('TCP'):
                packets.append(data)
                continue

            ts = pkt.time
            p_ip = p.getlayer('IP')
            p_tcp = p.getlayer('TCP')
            data['src_ip'] = p_ip.src
            data['dst_ip'] = p_ip.dst
            try:
                data['src_hostname'] = socket.getfqdn(p_ip.src)
            except:
                data['src_hostname'] = p_ip.src
            try:
                data['dst_hostname'] = socket.getfqdn(p_ip.dst)
            except:
                data['dst_hostname'] = p_ip.dst

            data['src_port'] = p_tcp.sport
            data['dst_port'] = p_tcp.dport
            data['ts'] = ts
            data['tcp_flags'] = p_tcp.flags
            #if p_tcp.flags != 16:
            data['tcp_seq'] = p_tcp.seq
            data['tcp_ack'] = p_tcp.ack
            try:
                data['data_len'] = len(p.getlayer(Raw))
            except:
                data['data_len'] = 0
            if data['data_len'] == 0:
                data['tcp_expected_ack'] = data['tcp_seq'] + data['data_len'] + 1
            else:
                data['tcp_expected_ack'] = data['tcp_seq'] + data['data_len']
            data['tcp_acked'] = False
            data['tcp_rtd_ms'] = 0
            data['index'] = index
            data['tcp_ack_index'] = 0
            #data['tcp_ack_data'] = {}
            packets.append(data)
            fo.write(json.dumps(data, sort_keys=True)+"\n")
    
    fo.close()
    return packets





input_file = sys.argv[1]


print "Decode PCAP"
print_current_time()
#packets = decode_scapy(input_file)
packets = decode_pyshark(input_file)


print
print
print
print
print "Analyzing TCP ..."
print_current_time()


result = []
num_of_data = len(packets) - 1
print "len: "+str(len)
fo = open(input_file+'.checked', 'w')
for index, p  in enumerate(packets):
    if 'src_ip' not in  p:
        continue
    for index2 in range(index, num_of_data):
        p2 = packets[index2]
        if 'src_ip' not in  p2:
            continue
        if p['src_ip'] != p2['dst_ip']:
            continue
        if p['src_port'] != p2['dst_port']:
            continue
        if p['tcp_acked'] == True:
            continue
        if p['tcp_expected_ack'] == p2['tcp_ack']:
            p['tcp_acked'] = True
            p['tcp_rtd_ms'] = 1000 * float(p2['ts'] - p['ts'])
            p['tcp_ack_index'] = p2['index'] + 1
            if p2['tcp_flags'] == 17 and p['tcp_rtd_ms'] > 10:
                fo.write("FIN/ACK RTD > 1000 ms: "+json.dumps(p, sort_keys=True)+"\n")
            elif p['tcp_rtd_ms'] > 1000:
                fo.write("RTD > 1000 ms: "+json.dumps(p, sort_keys=True)+"\n")
            elif p['tcp_rtd_ms'] > 100:
                fo.write("RTD > 100 ms: "+json.dumps(p, sort_keys=True)+"\n")
            elif p['tcp_rtd_ms'] > 10:
                fo.write("RTD > 10 ms: "+json.dumps(p, sort_keys=True)+"\n")
            elif p['tcp_rtd_ms'] > 1:
                fo.write("RTD > 1 ms:"+json.dumps(p, sort_keys=True)+"\n")
            break
    result.append(p)
fo.close()


fo = open(input_file+'.json', 'w')
json.dump(result, fo, sort_keys=True, indent=4)
fo.close()

print_current_time()

summary = {}
summary['min'] = {}
summary['min']['min_ms'] = 1000
summary['max'] = {}
summary['max']['max_ms'] = 0
summary['avg'] = {}
summary['avg']['avg_ms'] = 0
sum = 0
count = 0

for index, p  in enumerate(packets):
    if 'src_ip' not in  p:
        continue
    print index, p
    if 'tcp_flags' in p:
        if p['tcp_flags'] & 4 == 4:
            print "TCP RST Found: "+str(p)
    if p['tcp_rtd_ms'] == 0 or p['tcp_acked'] == False:
        continue
    rtd = p['tcp_rtd_ms']
    sum += rtd
    if rtd < summary['min']['min_ms']:
        summary['min']['min_ms'] = rtd
        summary['min']['min_packet'] = p
    if rtd > summary['max']['max_ms']:
        summary['max']['max_ms'] = rtd
        summary['max']['max_packet'] = p
    count += 1

summary['avg']['avg_ms'] = float(sum / count)

print "summary one line: "+str(summary)

print
print "Summary:"
print json.dumps(summary, indent = 4)


print_current_time()

