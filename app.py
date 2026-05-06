from flask import Flask, render_template, request, jsonify
from capture import capture_packets
from extract import extract_features
from fingerprint import generate_fingerprint
from classify import classify_behavior
import requests
import threading
import time

app = Flask(__name__)


# -------------------------------
# Helper: Fetch Website Traffic
# -------------------------------
def fetch_website(url):
    """Send request to generate traffic"""
    try:
        print(f"[FETCH] Starting request to {url}")
        response = requests.get(
            url,
            timeout=15,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            verify=False  # Ignore SSL errors for testing
        )
        print(f"[FETCH] Completed {url} | Status: {response.status_code} | Size: {len(response.content)} bytes")
        return response
    except Exception as e:
        print(f"[FETCH] Failed to fetch {url}: {e}")
        return None


# -------------------------------
# Home Route
# -------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# -------------------------------
# Analyze Single Website
# -------------------------------
@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')

    # Validation
    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        # Step 1: Start packet capture FIRST (in background thread)
        capture_result = {'packets': None}
        
        def capture_wrapper():
            capture_result['packets'] = capture_packets(duration=12, url=url)
        
        capture_thread = threading.Thread(target=capture_wrapper)
        capture_thread.start()
        
        # Small delay to ensure capture is running
        time.sleep(1)
        
        # Step 2: Fetch the website to generate traffic
        fetch_website(url)
        
        # Step 3: Wait for capture to complete
        capture_thread.join(timeout=15)
        
        packets = capture_result['packets']
        
        if not packets:
            packets = []
            print(f"[WARNING] No packets captured for {url}")

        # Step 4: Extract features
        features = extract_features(packets)

        # Step 5: Generate fingerprint
        fingerprint = generate_fingerprint(url, features)

        # Step 6: Classification
        behavior, confidence = classify_behavior(fingerprint)
        fingerprint["behavior_label"] = behavior
        fingerprint["behavior_confidence"] = confidence

        print(f"[RESULT] {url} | Packets: {fingerprint['total_packets']} | Behavior: {behavior} ({confidence}%)")
        
        return jsonify(fingerprint)

    except Exception as e:
        print(f"[ERROR] Analyze failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


# -------------------------------
# Compare Two Websites
# -------------------------------
@app.route('/api/compare', methods=['POST'])
def compare():
    data = request.get_json()
    url1 = data.get('url1')
    url2 = data.get('url2')

    if not url1 or not url2:
        return jsonify({"error": "Both URLs are required"}), 400

    try:
        print(f"[COMPARE] Analyzing first website: {url1}")
        result1 = analyze_single(url1)
        
        print(f"[COMPARE] Analyzing second website: {url2}")
        result2 = analyze_single(url2)

        # Calculate comparison metrics
        packets1 = result1.get("total_packets", 0)
        packets2 = result2.get("total_packets", 0)
        bytes1 = result1.get("total_bytes", 0)
        bytes2 = result2.get("total_bytes", 0)
        size1 = result1.get("mean_packet_size", 0)
        size2 = result2.get("mean_packet_size", 0)
        ips1 = result1.get("unique_ips_count", 0)
        ips2 = result2.get("unique_ips_count", 0)

        comparison = {
            "packet_diff": packets1 - packets2,
            "bytes_diff": bytes1 - bytes2,
            "size_diff": size1 - size2,
            "ips_diff": ips1 - ips2,
            "more_packets": url1 if packets1 > packets2 else url2,
            "more_bytes": url1 if bytes1 > bytes2 else url2,
            "larger_packets": url1 if size1 > size2 else url2
        }

        return jsonify({
            "website1": result1,
            "website2": result2,
            "comparison": comparison
        })

    except Exception as e:
        print(f"[ERROR] Compare failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Comparison failed: {str(e)}"}), 500


# -------------------------------
# Helper Function (Reusable)
# -------------------------------
def analyze_single(url):
    """Analyze one website (used in compare)"""
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Start capture first
    capture_result = {'packets': None}
    
    def capture_wrapper():
        capture_result['packets'] = capture_packets(duration=12, url=url)
    
    capture_thread = threading.Thread(target=capture_wrapper)
    capture_thread.start()
    
    # Small delay
    time.sleep(1)
    
    # Fetch website
    fetch_website(url)
    
    # Wait for capture
    capture_thread.join(timeout=15)
    
    packets = capture_result['packets']
    
    if not packets:
        packets = []
    
    # Extract features
    features = extract_features(packets)
    
    # Generate fingerprint
    fingerprint = generate_fingerprint(url, features)
    
    # Classify
    behavior, confidence = classify_behavior(fingerprint)
    fingerprint["behavior_label"] = behavior
    fingerprint["behavior_confidence"] = confidence
    
    return fingerprint


# -------------------------------
# Run Server
# -------------------------------
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Network Fingerprint Tool Running")
    print("👉 Open: http://127.0.0.1:5000")
    print("=" * 60)
    
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    app.run(debug=True, host='127.0.0.1', port=5000)