#!/usr/bin/env python3
import pyshark



file = "/home/bradleymmar/Downloads/SS.pcapng"
pcap = pyshark.FileCapture(input_file=file)
detection = 0

scans = {

    'tcp_sS':["0x0002", "0x0014"],


}

pktNum = 0
pktStreamDict = {}

for pkt in pcap:
    pktNum= pktNum+1


packets=range(0,pktNum,1)

for pktNum in packets:
    pack = pcap[pktNum].tcp.stream
    pktStreamDict.setdefault(pack, [])
    pktStreamDict[pack].append(pcap[pktNum].frame_info.number)


for pack in pktStreamDict:
    pkt = pktStreamDict[pack]
    flagList = []
    tempStream=pktStreamDict[pack]
    for i in tempStream:
        i = int(i)-1
        pktFlag=pcap[i].tcp.flags
        flagList.append(pktFlag)
    for i in scans.keys():
        if flagList == scans[i]:
            detection = detection+1




            
print(detection)
print(flagList)
