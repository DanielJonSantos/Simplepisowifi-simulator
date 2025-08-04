from flask import Flask, request, jsonify, render_template, redirect, session, url_for
import time, hmac, hashlib
from secure_utils import verify_hmac, get_mac_hash
import qrcode
import os
import secrets
import webbrowser
import json
import base64
from threading import Timer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Load server's private key
with open("private_key.pem", "rb") as key_file:
    PRIVATE_KEY = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

app = Flask(__name__)
app.secret_key = 'sessionsecret'

SECRET_KEY = b'supersecretkey'
SECURITY_MODE = True

MAC_WHITELIST = {
    "AA:BB:CC:11:22:33": get_mac_hash("AA:BB:CC:11:22:33")
}

# Store logs and sessions in-memory
session_log = []
user_sessions = {}

@app.route('/register')
def register():
    mac = request.args.get('mac')
    if not mac:
        return "MAC address required", 400

    # Create secret and expiration
    secret = secrets.token_hex(16)
    expiry = time.time() + 300  # 5 min

    user_sessions[mac] = {
        'secret': secret,
        'expires_at': expiry
    }

    # Create message payload
    payload = {
        "mac": mac,
        "secret": secret,
        "timestamp": int(expiry)
    }

    payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    # Sign the payload with fixed salt length
    signature = PRIVATE_KEY.sign(
        payload_str.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32  # Fixed salt length for client compatibility
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()

    # Final QR data
    qr_data = {
        "payload": payload,
        "signature": signature_b64
    }

    qr_string = json.dumps(qr_data)

    # Generate and save QR code
    qr = qrcode.make(qr_string)
    qr_folder = "static/qrcodes"
    os.makedirs(qr_folder, exist_ok=True)
    filename = os.path.join(qr_folder, f"{mac.replace(':', '-')}.png")
    qr.save(filename)

    print(f"[QR Generated] Secret expires at: {time.ctime(expiry)}")
    print(f"[Access URL] http://127.0.0.1:5000/register?mac={mac}")
    return render_template("show_qr.html", mac=mac, qr_path=f"/{filename}")

@app.route('/secret/<mac>')
def show_secret(mac):
    """
    Display secret key with signature verification
    Fixed version with proper JSON handling and matching salt length
    """
    info = user_sessions.get(mac)
    if not info:
        return "No secret found for this MAC address.", 404

    payload = {
        "mac": mac,
        "secret": info['secret'],
        "timestamp": int(info['expires_at'])
    }

    # Create canonical JSON string (same as client expects)
    payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    print(f"[DEBUG] Canonical payload string: {payload_str}")

    # Sign with RSA-PSS using fixed salt length (32 bytes) to match client
    signature = PRIVATE_KEY.sign(
        payload_str.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32  # Fixed salt length instead of MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()
    print(f"[DEBUG] Signature (base64): {signature_b64}")

    return render_template("show_secret.html",
        mac=mac,
        payload_json=json.dumps(payload),  # Pass as JSON string for template
        signature=signature_b64.strip()
    )

@app.route('/')
def index():
    return render_template('index.html', logs=session_log)

@app.route('/set-security', methods=['POST'])
def set_security():
    global SECURITY_MODE
    data = request.get_json()
    SECURITY_MODE = data.get('enabled', True)
    print(f"[Security] Mode set to: {'ENABLED' if SECURITY_MODE else 'DISABLED'}")
    return jsonify({'SECURITY_MODE': SECURITY_MODE})

@app.route('/generate-hmac', methods=['POST'])
def generate_hmac_route():
    data = request.get_json()
    mac = data.get('mac')
    timestamp = data.get('timestamp')
    hmac_hash = hmac.new(SECRET_KEY, f"{mac}{timestamp}".encode(), hashlib.sha256).hexdigest()
    return jsonify({'hmac': hmac_hash, 'server_time': int(time.time())})

@app.route('/connect', methods=['POST'])
def connect():
    session['connected'] = False  # Reset session every new connect

    data = request.get_json()
    mac = data.get('mac')
    timestamp = data.get('timestamp')
    hmac_signature = data.get('hmac')
    result = {}

    print(f"[Connection Attempt] MAC: {mac}, Security: {'ON' if SECURITY_MODE else 'OFF'}")

    if SECURITY_MODE:
        if not verify_hmac(mac, timestamp, hmac_signature, SECRET_KEY):
            result = {'status': 'rejected', 'reason': 'HMAC tampering detected'}
            print(f"[REJECTED] HMAC verification failed for {mac}")
        else:
            try:
                ts = int(timestamp)
                current_time = int(time.time())
                time_diff = abs(current_time - ts)
                
                if time_diff > 30:
                    result = {'status': 'rejected', 'reason': f'Request expired (replay suspected) - {time_diff}s old'}
                    print(f"[REJECTED] Timestamp too old: {time_diff}s for {mac}")
                elif get_mac_hash(mac) not in MAC_WHITELIST.values():
                    result = {'status': 'rejected', 'reason': 'MAC spoofing suspected'}
                    print(f"[REJECTED] MAC not whitelisted: {mac}")
                else:
                    result = {'status': 'connected', 'message': '✅ Secure connection established.'}
                    print(f"[CONNECTED] Secure connection for {mac}")
            except Exception as e:
                result = {'status': 'rejected', 'reason': f'Invalid timestamp: {str(e)}'}
                print(f"[REJECTED] Timestamp error for {mac}: {e}")
    else:
        result = {'status': 'insecure', 'message': '❌ Insecure connection – security checks bypassed.'}
        print(f"[INSECURE] Security bypassed for {mac}")

    # Log every attempt (legit or attack)
    session_log.append({
        'mac': mac,
        'timestamp': timestamp,
        'security': SECURITY_MODE,
        'result': result['status'],
        'reason': result.get('reason', result.get('message'))
    })

    # Only allow session entry if successful
    if result['status'] in ["connected", "insecure"]:
        session['connected'] = True
        user_sessions[mac] = user_sessions.get(mac, {})
        user_sessions[mac]['coins'] = user_sessions[mac].get('coins', 0)

    return jsonify(result)

@app.route('/session')
def session_page():
    if not session.get('connected'):
        return redirect(url_for('index'))
    return render_template('session.html')

@app.route('/add-coin', methods=['POST'])
def add_coin():
    mac = request.json.get('mac')
    if mac in user_sessions:
        user_sessions[mac]['coins'] = user_sessions[mac].get('coins', 0) + 1
        total_minutes = user_sessions[mac]['coins'] * 10
        print(f"[Coin Added] {mac}: {user_sessions[mac]['coins']} coins = {total_minutes} minutes")
        return jsonify({'coins': user_sessions[mac]['coins'], 'minutes': total_minutes})
    return jsonify({'error': 'MAC not found'}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/debug/sessions')
def debug_sessions():
    """Debug endpoint to view active sessions"""
    return jsonify({
        'active_sessions': user_sessions,
        'session_log': session_log[-10:],  # Last 10 entries
        'security_mode': SECURITY_MODE
    })

# Auto-open QR page on app start
def open_qr_page():
    mac = "AA:BB:CC:11:22:33"
    url = f"http://127.0.0.1:5000/register?mac={mac}"
    print(f"[Auto-Opening] {url}")
    webbrowser.open_new(url)

if __name__ == '__main__':
    import os
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        # Only run this in the actual main process (not the reloader)
        Timer(1.25, open_qr_page).start()
    
    print("=" * 60)
    print("🔐 PisoWiFi Secure Simulator Starting...")
    print("=" * 60)
    print("📱 Auto-opening registration page...")
    print("🌐 Manual access: http://127.0.0.1:5000")
    print("🔧 Debug endpoint: http://127.0.0.1:5000/debug/sessions")
    print("=" * 60)
    
    app.run(debug=True)