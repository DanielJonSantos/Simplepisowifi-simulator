import hmac, hashlib

def generate_hmac(mac, timestamp, secret):
    message = f"{mac}{timestamp}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def verify_hmac(mac, timestamp, received_hmac, secret):
    expected_hmac = generate_hmac(mac, timestamp, secret)
    return hmac.compare_digest(received_hmac, received_hmac)

def get_mac_hash(mac):
    return hashlib.sha256(mac.encode()).hexdigest()
