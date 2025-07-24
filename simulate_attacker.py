import requests
import time
import hmac
import hashlib

BASE_URL = "http://127.0.0.1:5000"

# Create a session that doesn't interfere with browser session
session = requests.Session()
session.headers.update({'User-Agent': 'attacker-sim'})

spoofed_mac = "DE:AD:BE:EF:00:01"
spoofed_timestamp = str(int(time.time()) - 1000)

SECRET_KEY = b"wrongkey"
fake_hmac = hmac.new(SECRET_KEY, f"{spoofed_mac}{spoofed_timestamp}".encode(), hashlib.sha256).hexdigest()

payload = {
    "mac": spoofed_mac,
    "timestamp": spoofed_timestamp,
    "hmac": fake_hmac
}

try:
    response = session.post(f"{BASE_URL}/connect", json=payload)
    print("MITM/Spoofing Attempt Response:")
    print(response.json())
except requests.exceptions.RequestException as e:
    print("❌ ERROR: Unable to reach server.")
    print(e)
