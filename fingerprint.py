from datetime import datetime
def generate_fingerprint(url, features):
    """Generate structured fingerprint"""

    # Top protocol
    if features["protocol_distribution"]:
        top_protocol = max(
            features["protocol_distribution"],
            key=features["protocol_distribution"].get
        )
    else:
        top_protocol = "None"

    return {
        "site_url": url,
        "capture_timestamp": datetime.now().isoformat(),
        "total_packets": features["total_packets"],
        "total_bytes": features["total_bytes"],
        "top_protocol": top_protocol,
        "unique_ips_count": features["unique_ips_count"],  # FIXED
        "unique_ips": features["unique_ips"],
        "dns_queries": features["dns_queries"],
        "mean_packet_size": features["mean_packet_size"],
        "max_packet_size": features["max_packet_size"],
        "min_packet_size": features["min_packet_size"],
        "packet_sizes": features["packet_sizes"],
        "timestamps": features["timestamps"],
        "protocol_distribution": {
            k: round(v, 2)
            for k, v in features["protocol_distribution"].items()
        }
    }