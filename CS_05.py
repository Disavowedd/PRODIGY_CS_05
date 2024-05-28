from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    global continue_sniffing
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

      
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {tcp_layer.payload}")

      
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {udp_layer.payload}")

        print("\n" + "-"*50 + "\n")
        
        input("Press Enter to show the next captured packet (or 'q' to quit): ")
    if continue_sniffing:
        continue_sniffing = False
    else:
        return False


print("Starting packet sniffing...")
continue_sniffing = True
sniff(prn=packet_callback, store=0)
