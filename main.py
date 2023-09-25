import scapy.all as scapy
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11AssoReq, Dot11QoS,Dot11WEP, Dot11WPA, Dot11WPA2


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
        capability_info = packet[Dot11Beacon].capability
        # 5.2
        if capability_info.privacy == 1:
            print("Security: Enabled")
            # Analizar más a fondo los elementos para determinar WEP, WPA, WPA2, WPA3
            if packet.haslayer(Dot11WEP):
                print("Encryption: WEP")
            elif packet.haslayer(Dot11WPA):
                print("Encryption: WPA")
            elif packet.haslayer(Dot11WPA2):
                print("Encryption: WPA2")
            else:
                print("Security: Disabled")
    
    if packet.haslayer(Dot11AssoReq):
        dot11_layer = packet[Dot11AssoReq]
        print(f"802.11 Association Request Frame Captured: Type={dot11_layer.type}, Subtype={dot11_layer.subtype}")
        print(packet.show())
        # 5.2
        if capability_info.privacy == 1:
            print("Security: Enabled")
            # Analizar más a fondo los elementos para determinar WEP, WPA, WPA2, WPA3
            if packet.haslayer(Dot11WEP):
                print("Encryption: WEP")
            elif packet.haslayer(Dot11WPA):
                print("Encryption: WPA")
            elif packet.haslayer(Dot11WPA2):
                print("Encryption: WPA2")
            else:
                print("Security: Disabled")
    
    # 5.2
    if packet.haslayer(Dot11QoS):
            print("\n802.11 Data Frame with QoS captured:")
            print(f"Priority: {packet[Dot11QoS].TID}")
    
    

scapy.sniff(iface="wlo1", prn=packet_handler, store=0)
