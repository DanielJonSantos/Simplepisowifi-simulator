from flask import Flask, request, jsonify, render_template, redirect, session, url_for
import time, hmac, hashlib
from secure_utils import verify_hmac, get_mac_hash

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

@app.route('/')
def index():
    return render_template('index.html', logs=session_log)

@app.route('/set-security', methods=['POST'])
def set_security():
    global SECURITY_MODE
    data = request.get_json()
    SECURITY_MODE = data.get('enabled', True)
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
    
    if SECURITY_MODE:
        if not verify_hmac(mac, timestamp, hmac_signature, SECRET_KEY):
            result = {'status': 'rejected', 'reason': 'HMAC tampering detected'}
        else:
            try:
                ts = int(timestamp)
                if abs(int(time.time()) - ts) > 30:
                    result = {'status': 'rejected', 'reason': 'Request expired (replay suspected)'}
                elif get_mac_hash(mac) not in MAC_WHITELIST.values():
                    result = {'status': 'rejected', 'reason': 'MAC spoofing suspected'}
                else:
                    result = {'status': 'connected', 'message': '✅ Secure connection established.'}
            except:
                result = {'status': 'rejected', 'reason': 'Invalid timestamp'}
    else:
        result = {'status': 'insecure', 'message': '❌ Insecure connection – security checks bypassed.'}

    # Log every attempt (legit or attack)
    session_log.append({
        'mac': mac,
        'timestamp': timestamp,
        'security': SECURITY_MODE,
        'result': result['status'],
        'reason': result.get('reason', result.get('message'))
    })

    # ✅ Only allow session entry if successful
    if result['status'] in ["connected", "insecure"]:
        session['connected'] = True
        user_sessions[mac] = {'coins': 0}

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
        user_sessions[mac]['coins'] += 1
        total_minutes = user_sessions[mac]['coins'] * 10
        return jsonify({'coins': user_sessions[mac]['coins'], 'minutes': total_minutes})
    return jsonify({'error': 'MAC not found'}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
