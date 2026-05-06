from scapy.all import IP, TCP, UDP, ICMP, DNS, ARP
from collections import Counter


def get_protocol(packet):
    """Correct protocol detection (FIXED ORDER)"""
    if DNS in packet:
        return 'DNS'
    elif TCP in packet:
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            return 'HTTPS'
        return 'TCP'
    elif UDP in packet:
        return 'UDP'
    elif ICMP in packet:
        return 'ICMP'
    elif ARP in packet:
        return 'ARP'
    elif IP in packet:
        return 'IP'
    return 'OTHER'


def extract_features(packets):
    """Extract features from packet list"""

    if not packets:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_distribution": {},
            "packet_sizes": [],
            "timestamps": [],
            "mean_packet_size": 0,
            "max_packet_size": 0,
            "min_packet_size": 0,
            "unique_ips": [],
            "unique_ips_count": 0,
            "dns_queries": [],
            "inter_arrival_times": []
        }

    total_packets = len(packets)
    packet_sizes = [len(pkt) for pkt in packets]
    total_bytes = sum(packet_sizes)
    timestamps = [pkt.time for pkt in packets]

    # Protocol distribution
    protocols = [get_protocol(pkt) for pkt in packets]
    protocol_counts = Counter(protocols)
    protocol_percentages = {
        proto: (count / total_packets) * 100
        for proto, count in protocol_counts.items()
    }

    # Unique IPs
    unique_ips = set()
    dest_pairs = set()

    for pkt in packets:
        if IP in pkt:
            ip = pkt[IP].dst
            unique_ips.add(ip)

            if TCP in pkt:
                dest_pairs.add((ip, pkt[TCP].dport))
            elif UDP in pkt:
                dest_pairs.add((ip, pkt[UDP].dport))

    # DNS queries
    dns_queries = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
            try:
                dns_queries.append(pkt[DNS].qd.qname.decode().rstrip('.'))
            except:
                pass

    # Inter-arrival times
    inter_arrival_times = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    # Timeline (bytes/sec)
    bytes_per_second = []
    if timestamps:
        start = timestamps[0]
        duration = int(timestamps[-1] - start) + 1

        for i in range(duration):
            total = sum(
                len(pkt) for pkt in packets
                if start + i <= pkt.time < start + i + 1
            )
            bytes_per_second.append(total)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_distribution": protocol_percentages,
        "packet_sizes": packet_sizes,
        "timestamps": bytes_per_second,
        "mean_packet_size": round(sum(packet_sizes) / total_packets, 2) if total_packets > 0 else 0,
        "max_packet_size": max(packet_sizes),
        "min_packet_size": min(packet_sizes),
        "unique_ips": list(unique_ips),
        "unique_ips_count": len(unique_ips),
        "dest_ip_ports": list(dest_pairs),
        "dns_queries": dns_queries,
        "inter_arrival_times": inter_arrival_times
    }