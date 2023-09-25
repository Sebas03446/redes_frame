from scapy.all import *
from scapy.layers.l2 import Ether, Dot3FCS

def packet_callback(packet):
    if packet.haslayer(Ether):
        if packet[Ether].type <= 1500:  # Assuming it is an IEEE 802.3 frame based on the Length/Type field
            print("\n802.3 Frame captured:")
            print("Destination MAC: ", packet[Ether].dst)
            print("Source MAC: ", packet[Ether].src)
            print("Length: ", packet[Ether].type)  # Length in 802.3 frames
            
            if packet.haslayer(Raw):  # If there is a Payload
                print("Payload: ", packet[Raw].load)
            
            if packet.haslayer(Dot3FCS):  # If there is a Frame Check Sequence
                print("Frame Check Sequence: ", packet[Dot3FCS].fcs)

print("Capturing IEEE 802.3 Frames...")
sniff(prn=packet_callback, store=0)
