import pyshark


fileclear=open('discovered.txt', 'w')
fileclear.write("")
fileclear.close()
file1=open('discovered.txt', 'a')

pcap = input("Please input a full file path (If on windows use double backslashes and no quotations): ")



tcp_scan = pyshark.FileCapture(input_file=pcap, display_filter='tcp and tcp.flags == 0x014')
stealth = pyshark.FileCapture(input_file=pcap, display_filter='tcp and tcp.flags == 0x004')
fin = pyshark.FileCapture(input_file=pcap, display_filter='tcp and tcp.flags.fin')
null = pyshark.FileCapture(input_file=pcap, display_filter='tcp and tcp.flags==0x000')
udp = pyshark.FileCapture(input_file=pcap, display_filter='icmp.code == 3')


for pkt in tcp_scan:
    file1.write("TCP Connect: " )
    file1.write(pkt.number)
    file1.write("\n")

for pkt in stealth:
    file1.write("TCP Stealth: " )
    file1.write(pkt.number)
    file1.write("\n")

for pkt in fin:
    file1.write("TCP Fin: " )
    file1.write(pkt.number)
    file1.write("\n")

for pkt in null:
    file1.write("TCP Null/XMAS: " )
    file1.write(pkt.number)
    file1.write("\n")

for pkt in udp:
    file1.write("UDP: ")
    file1.write(pkt.number)
    file1.write("\n")

print("All done!")
