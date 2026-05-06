from scapy.all import sniff, IP, DNS
import socket
import time

target_ips = []

def resolve_url_to_ips(url):
    """Resolve URL to IP addresses"""
    global target_ips
    target_ips = []

    try:
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        print(f"[DNS] Resolving: {hostname}")
        
        # Get all IPs for the hostname
        addrinfo = socket.getaddrinfo(hostname, None)
        
        for addr in addrinfo:
            ip = addr[4][0]
            if ip not in target_ips and not ip.startswith('127.'):
                target_ips.append(ip)
        
        # If no IPs found, try again
        if not target_ips:
            addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for addr in addrinfo:
                ip = addr[4][0]
                if ip not in target_ips:
                    target_ips.append(ip)

        print(f"[DNS] Resolved {hostname} → {target_ips}")

    except Exception as e:
        print(f"[DNS] Resolution error: {e}")

    return target_ips


def capture_packets(duration=10, url=None):
    """Capture packets for a specific URL with improved filtering"""
    global target_ips

    if url:
        resolve_url_to_ips(url)

    print(f"[CAPTURE] Starting capture for {duration} seconds...")
    print(f"[CAPTURE] Target IPs: {target_ips if target_ips else 'All IPs'}")

    # Capture ALL packets first (more reliable than lfilter)
    packets = sniff(timeout=duration, store=True)
    
    print(f"[CAPTURE] Raw capture: {len(packets)} total packets")

    # Filter packets related to target URL
    if target_ips:
        filtered_packets = []
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                # Check if packet involves our target IPs
                if src_ip in target_ips or dst_ip in target_ips:
                    filtered_packets.append(pkt)
                # Also capture DNS packets (they help find the site)
                elif DNS in pkt:
                    filtered_packets.append(pkt)
        packets = filtered_packets
        print(f"[CAPTURE] Filtered to {len(packets)} relevant packets")
    else:
        print(f"[CAPTURE] No target IPs resolved, keeping all {len(packets)} packets")

    # If still no packets, try without IP filtering as fallback
    if len(packets) == 0 and target_ips:
        print(f"[CAPTURE] No packets found with target IPs. Capturing all traffic as fallback...")
        packets = sniff(timeout=5, store=True)
        print(f"[CAPTURE] Fallback capture: {len(packets)} packets")

    return packets