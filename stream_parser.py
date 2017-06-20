#!/usr/bin/env python

import sys
from scapy.all import PcapReader
import json
import time
import datetime
import socket
import pyshark
import copy


flow_template = {}
flow_template['is_closed'] = False
flow_template['packets'] = []

packet_template = {}
packet_template['src_ip'] = ""
packet_template['dst_ip'] = ""
packet_template['src_hostname'] = ""
packet_template['dst_hostname'] = ""
packet_template['src_port'] = 0
packet_template['dst_port'] = 0 
packet_template['proto'] = ""
packet_template['ts'] = 0
packet_template['tcp_flags'] = 0
packet_template['tcp_flags_string'] = []
packet_template['tcp_seq'] = 0
packet_template['tcp_ack'] = 0
packet_template['data_len'] = -1
packet_template['tcp_expected_ack'] = 0
packet_template['tcp_acked'] = False
packet_template['tcp_rtd_ms'] = 0
packet_template['index'] = 0
packet_template['tcp_ack_index'] = 0
packet_template['notes'] = []



def print_current_time():
    ts = time.time()
    print datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    return


def decode_pyshark(input_file):
    packets = []
    fo = open(input_file+'.txt', 'w')
    pcap_reader = pyshark.FileCapture(input_file)
    for pkt in pcap_reader:
        data = copy.deepcopy(packet_template)
        
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

        data['src_port'] = int(p_tcp.srcport)
        data['dst_port'] = int(p_tcp.dstport)
        data['ts'] = ts
        data['tcp_flags'] = int(p_tcp.flags, 0)
        if data['tcp_flags'] & 1 == 1:
            data['tcp_flags_string'].append('FIN')
        if data['tcp_flags'] & 2 == 2:
            data['tcp_flags_string'].append('SYN')
        if data['tcp_flags'] & 4 == 4:
            data['tcp_flags_string'].append('RST')
        if data['tcp_flags'] & 8 == 8:
            data['tcp_flags_string'].append('PSH')
        if data['tcp_flags'] & 16 == 16:
            data['tcp_flags_string'].append('ACK')
        if data['tcp_flags'] & 32 == 32:
            data['tcp_flags_string'].append('U')
        if data['tcp_flags'] & 64 == 64:
            data['tcp_flags_string'].append('E')
        #if p_tcp.flags != 16:
        data['tcp_seq'] = int(p_tcp.seq)
        data['tcp_ack'] = int(p_tcp.ack)
        try:
            data['data_len'] = int(p_tcp.len)
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

            data = copy.deepcopy(packet_template)
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

            data['src_port'] = int(p_tcp.sport)
            data['dst_port'] = int(p_tcp.dport)
            data['ts'] = ts
            data['tcp_flags'] = int(p_tcp.flags)
            if data['tcp_flags'] & 1 == 1:
                data['tcp_flags_string'].append('FIN')
            if data['tcp_flags'] & 2 == 2:
                data['tcp_flags_string'].append('SYN')
            if data['tcp_flags'] & 4 == 4:
                data['tcp_flags_string'].append('RST')
            if data['tcp_flags'] & 8 == 8:
                data['tcp_flags_string'].append('PSH')
            if data['tcp_flags'] & 16 == 16:
                data['tcp_flags_string'].append('ACK')
            if data['tcp_flags'] & 32 == 32:
                data['tcp_flags_string'].append('U')
            if data['tcp_flags'] & 64 == 64:
                data['tcp_flags_string'].append('E')
            data['tcp_seq'] = int(p_tcp.seq)
            data['tcp_ack'] = int(p_tcp.ack)
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


print "Reading the pcap"
print_current_time()
#pcap = rdpcap(input_file)


print "Decode PCAP"
print_current_time()
packets = decode_scapy(input_file)
#packets = decode_pyshark(input_file)


print
print
print
print
print "Analyzing TCP: grouping the stream ..."
print_current_time()



data = {}
for index, p  in enumerate(packets):
    if 'src_ip' not in  p or p['src_ip'] == "":
        continue
    key1 = p['src_ip']+"_"+p['dst_ip']+"_"+str(p['src_port'])+"_"+str(p['dst_port'])
    key2 = p['dst_ip']+"_"+p['src_ip']+"_"+str(p['dst_port'])+"_"+str(p['src_port'])
   
    is_found = False
    for item in data:
        if item == key1:
            key = key1
            is_found = True
            flows = data[key]
        elif item == key2:
            key = key2
            is_found = True
            flows = data[key]
    
    if not is_found:
        key = key1
        data[key] = []
        flows = data[key]

    if len(flows) > 0:
        if p['tcp_flags'] & 1 == 1 or p['tcp_flags'] & 16 == 16:
            flow = flows[-1]
        elif 'is_closed' in flows[-1] and flows[-1]['is_closed'] == False:
            flow = flows[-1]
        else:
            flow = copy.deepcopy(flow_template)
            flows.append(flow)
    else:
        flow = copy.deepcopy(flow_template)
        flows.append(flow)


    flow['packets'].append(p)
    if len(flow['packets']) > 1:
        flow['packets'][-1]['delta_ts'] = p['ts'] - flow['packets'][-2]['ts']
    else:
        flow['packets'][-1]['delta_ts'] = 0


    if p['tcp_flags'] & 1 == 1:
        flow['is_closed'] = True



#print json.dumps(data, sort_keys=True, indent=4)



print "Analyzing TCP: measuring delay  ..."
print_current_time()

print "len: "+str(len)
fo = open(input_file+'.checked', 'w')



for flows in data:
    for flow in data[flows]:
        summary = {}
        summary['min'] = {}
        summary['min']['min_ms'] = 1000
        summary['max'] = {}
        summary['max']['max_ms'] = 0
        summary['avg'] = {}
        summary['avg']['avg_ms'] = 0
        sum = 0
        count = 0
        
        for index, p in enumerate(flow['packets']):
            num_of_data = len(flow['packets']) - 1
            if num_of_data < 1:
                continue
            for index2 in range(index+1, num_of_data):
                p2 = flow['packets'][index2]
                if p['src_ip'] != p2['dst_ip']:
                    continue
                if p['src_port'] != p2['dst_port']:
                    continue
                if p['tcp_acked'] == True:
                    continue
                if p['tcp_expected_ack'] == p2['tcp_ack']:
                    p['tcp_acked'] = True
                    p['tcp_rtd_ms'] = 1000 * float(p2['ts'] - p['ts'])
                    p['tcp_ack_index'] = p2['index'] 
                    if p2['tcp_flags'] == 17 and p['tcp_rtd_ms'] > 10:
                        fo.write("FIN/ACK RTD > 1000 ms: "+json.dumps(p, sort_keys=True)+"\n")
                        p['notes'].append("FIN/ACK RTD > 1000 ms")
                        #print "FIN/ACK RTD > 1000 ms: "+str(p)
                    elif p['tcp_rtd_ms'] > 1000:
                        fo.write("RTD > 1000 ms: "+json.dumps(p, sort_keys=True)+"\n")
                        p['notes'].append("RTD > 1000 ms")
                        #print "RTD > 1000 ms: "+str(p)
                    elif p['tcp_rtd_ms'] > 100:
                        fo.write("RTD > 100 ms: "+json.dumps(p, sort_keys=True)+"\n")
                        p['notes'].append("RTD > 100 ms")
                        #print "RTD > 100 ms: "+str(p)
                    elif p['tcp_rtd_ms'] > 10:
                        fo.write("RTD > 10 ms: "+json.dumps(p, sort_keys=True)+"\n")
                        p['notes'].append("RTD > 10 ms")
                        #print "RTD > 10 ms: "+str(p)
                    elif p['tcp_rtd_ms'] > 1:
                        fo.write("RTD > 1 ms:"+json.dumps(p, sort_keys=True)+"\n")
                        p['notes'].append("RTD > 1 ms")
                    break
            
            
            if p['tcp_flags'] & 4 == 4:
                p['notes'].append("TCP RST Found")
            if p['tcp_rtd_ms'] == 0 or p['tcp_acked'] == False:
                continue
            rtd = p['tcp_rtd_ms']
            sum += rtd
            if rtd < summary['min']['min_ms']:
                summary['min']['min_ms'] = rtd
                summary['min']['min_packet_index'] = p['index']
            if rtd > summary['max']['max_ms']:
                summary['max']['max_ms'] = rtd
                summary['max']['max_packet_index'] = p['index']
            count += 1

        if sum > 0:
            summary['avg']['avg_ms'] = float(sum / count)
        else:
            summary['avg']['avg_ms'] = 0
        flow['summary'] = summary


fo.close()


fo = open(input_file+'.json', 'w')
json.dump(data, fo, sort_keys=True, indent=4)
fo.close()


print_current_time()


