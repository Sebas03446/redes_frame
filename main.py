import scapy.all as scapy
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11AssoReq


def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        if packet[scapy.IP].src == '***.***.***.***':
            print(packet.show())
            
    if packet.haslayer(Dot11):
        dot11_layer = packet[Dot11]
        print(f"802.11 Frame Captured: Type={dot11_layer.type}, Subtype={dot11_layer.subtype}")
        print(packet.show())
    
    if packet.haslayer(Dot11Beacon):
        dot11_layer = packet[Dot11Beacon]
        print(f"802.11 Beacon Frame Captured: Type={dot11_layer.type}, Subtype={dot11_layer.subtype}")
        print(packet.show())
    
    if packet.haslayer(Dot11AssoReq):
        dot11_layer = packet[Dot11AssoReq]
        print(f"802.11 Association Request Frame Captured: Type={dot11_layer.type}, Subtype={dot11_layer.subtype}")
        print(packet.show())

scapy.sniff(iface="wlo1", prn=packet_handler, store=0)
