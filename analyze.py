from scapy.all import rdpcap, TCP, Raw, IP
from entropy import calculate_entropy

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    results = []

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            entropy = calculate_entropy(payload)

            results.append({
                "Source IP": pkt[IP].src,
                "Destination IP": pkt[IP].dst,
                "Source Port": pkt[TCP].sport,
                "Destination Port": pkt[TCP].dport,
                "Payload Size": len(payload),
                "Entropy": round(entropy, 2)
            })

    return results
