def classify_behavior(fingerprint):
    """Improved rule-based classification with URL detection"""
    
    total_packets = fingerprint.get("total_packets", 0)
    mean_size = fingerprint.get("mean_packet_size", 0)
    total_bytes = fingerprint.get("total_bytes", 0)
    unique_ips = fingerprint.get("unique_ips_count", 0)
    top_protocol = fingerprint.get("top_protocol", "")
    site_url = fingerprint.get("site_url", "").lower()
    
    # ============================================
    # URL-BASED CLASSIFICATION (Highest Priority)
    # ============================================
    
    # Streaming Services
    streaming_sites = ['youtube', 'netflix', 'twitch', 'hulu', 'disney+', 'primevideo', 
                       'hotstar', 'vimeo', 'dailymotion', 'crunchyroll', 'hbomax']
    for site in streaming_sites:
        if site in site_url:
            return "Streaming", 92
    
    # Social Media Platforms
    social_sites = ['facebook', 'twitter', 'instagram', 'tiktok', 'linkedin', 'pinterest',
                    'snapchat', 'reddit', 'tumblr', 'whatsapp', 'telegram', 'discord']
    for site in social_sites:
        if site in site_url:
            return "Social Media", 88
    
    # Search Engines
    search_sites = ['google', 'bing', 'yahoo', 'duckduckgo', 'baidu', 'yandex']
    for site in search_sites:
        if site in site_url:
            return "Static Content", 85
    
    # E-commerce Sites
    ecommerce_sites = ['amazon', 'ebay', 'alibaba', 'walmart', 'target', 'bestbuy', 
                       'flipkart', 'shopify', 'etsy']
    for site in ecommerce_sites:
        if site in site_url:
            return "API-Heavy", 75
    
    # ============================================
    # DATA-BASED CLASSIFICATION (Fallback)
    # ============================================
    
    # 1. Streaming (high data volume, large packets)
    if total_bytes > 500000 or mean_size > 1000:
        return "Streaming", 85 if mean_size > 1200 else 70
    
    # 2. Social Media (many packets, many unique IPs)
    if total_packets > 100 and unique_ips > 10:
        return "Social Media", 80 if unique_ips > 15 else 65
    
    # 3. API-Heavy (many small packets)
    if total_packets > 50 and mean_size < 300:
        return "API-Heavy", 75
    
    # 4. Static Content (few packets, small sizes)
    if total_packets < 30 and mean_size < 500:
        return "Static Content", 90
    
    # 5. DNS-Heavy
    if top_protocol == "DNS":
        return "DNS-Heavy", 70
    
    # 6. Based on packet count
    if total_packets > 80:
        return "Social Media", 60
    elif total_packets > 40:
        return "API-Heavy", 55
    elif total_packets > 10:
        return "Static Content", 60
    
    # Default
    return "Unknown", 40