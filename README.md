# 🔐 Simple PisoWiFi Secure Simulator

A full-stack simulation of a PisoWiFi system that demonstrates **enterprise-grade security protocols** to defend against network-based attacks such as Man-in-the-Middle (MITM), MAC address spoofing, and replay attacks.

## 🚀 Key Features

- ✅ **RSA-PSS Digital Signatures** for QR code authenticity
- 🔐 **HMAC Authentication** using shared secret key
- 🕒 **Timestamp Validation** to prevent replay attacks
- 🧿 **MAC Address Hashing** and whitelisting
- 🧨 **Simulated MITM** and spoofing attacker script
- 🔀 **Toggle Switch** to enable/disable security protocols
- 🧠 **Real-time Frontend** log display for connection attempts
- ⏳ **Post-connection Session** with coin-to-time system (₱1 = 10 minutes)
- 🐛 **Debug Endpoints** for troubleshooting
- 📋 **SPDL Documentation** (Security Protocol Description Language)

## 🏗️ Project Structure

```
SimplePisoWiFi/
├── app.py                    # Flask backend (UPDATED)
├── simulate_attacker.py      # Attacker script to simulate spoofing/MITM
├── secure_utils.py          # Helper methods: HMAC + MAC hashing
├── private_key.pem          # Server's RSA private key
├── templates/
│   ├── index.html           # Secure portal frontend
│   ├── show_qr.html         # QR code display page
│   ├── show_secret.html     # Secret key verification (FIXED)
│   └── session.html         # Post-connection session UI
├── static/
│   ├── public_key.pem       # Server's RSA public key
│   ├── verifySignature.js   # RSA signature verification (FIXED)
│   └── qrcodes/            # Generated QR code images
├── docs/
│   └── SPDL.md             # Security Protocol Description Language
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 Installation & Setup

### Prerequisites
- Python 3.7+
- pip package manager

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/DanielJonSantos/Simplepisowifi-simulator.git
cd Simplepisowifi-simulator
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Generate RSA keys** (if not included)
```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out static/public_key.pem
```

4. **Run the application**
```bash
python app.py
```

5. **Access the simulator**
   - Main portal: [http://127.0.0.1:5000](http://127.0.0.1:5000)
   - Auto-opens QR registration page
   - Debug endpoint: [http://127.0.0.1:5000/debug/sessions](http://127.0.0.1:5000/debug/sessions)

## 🎯 How to Test

### Testing Secure Connection
1. **Generate QR Code**: Visit the auto-opened registration page
2. **Scan QR Code**: Use your mobile device or inspect the generated PNG
3. **Verify Signature**: The system will cryptographically verify the QR code
4. **Connect to WiFi**: Use the displayed secret key to connect

### Testing Attack Simulation
In a new terminal, run the attacker script:
```bash
python simulate_attacker.py
```
Watch how the backend detects and logs malicious attempts in the frontend portal.

## 🛡️ Security Protocols

### 1. **QR Code Security (RSA-PSS)**
- **Algorithm**: RSA-PSS with SHA-256 and 32-byte salt
- **Key Size**: 2048-bit RSA key pair
- **Purpose**: Cryptographic proof of QR code authenticity
- **Protection**: Prevents QR code forgery and tampering

### 2. **Network Authentication (HMAC)**
- **Algorithm**: HMAC-SHA256
- **Message**: `MAC_ADDRESS || TIMESTAMP`
- **Purpose**: Authenticate network connection requests
- **Protection**: Prevents request tampering and replay attacks

### 3. **Temporal Security**
- **QR Expiry**: 5-minute validity window
- **Timestamp Tolerance**: ±30 seconds for network requests
- **Purpose**: Prevent replay attacks and limit exposure window

### 4. **Device Authorization**
- **Method**: Hashed MAC address whitelisting
- **Storage**: SHA-256 hashes of approved MAC addresses
- **Purpose**: Prevent unauthorized device access

## 🔍 Security Analysis

### **Cryptographic Strength: 9/10**
- Uses industry-standard RSA-PSS signatures
- Implements proper HMAC authentication
- Secure random number generation

### **Attack Resistance**
- ✅ **MITM Attacks**: HMAC integrity protection
- ✅ **Replay Attacks**: Timestamp validation
- ✅ **QR Tampering**: RSA signature verification
- ✅ **MAC Spoofing**: Whitelist + HMAC authentication
- ✅ **Signature Forgery**: RSA-2048 computational security

### **Implemented Defenses**
| Attack Vector | Detection Method | Mitigation |
|---------------|------------------|------------|
| MITM | HMAC verification failure | Request rejection |
| Replay | Timestamp out of window | Request rejection |
| MAC Spoofing | MAC not in whitelist | Connection denied |
| QR Forgery | RSA signature invalid | Secret not displayed |
| Tampering | Digital signature check | Cryptographic proof |

## 🐛 Debugging Features

### Debug Endpoint
Visit `http://127.0.0.1:5000/debug/sessions` to view:
- Active user sessions
- Recent connection attempts
- Current security mode status

### Console Logging
The application provides detailed console output for:
- QR code generation events
- Signature verification steps
- Connection attempt results
- Security violation details

### Browser Debug Tools
- Open Developer Tools (F12) on the secret page
- Enable "Show Debug Info" button for detailed verification logs
- Console shows step-by-step signature verification process

## 📋 Protocol Documentation

See `docs/SPDL.md` for the complete **Security Protocol Description Language** specification including:
- Formal protocol flows
- Security assumptions
- Attack resistance analysis
- Cryptographic specifications

## 🚀 Recent Updates (v2.0)

### 🔧 **Bug Fixes**
- ✅ Fixed RSA signature verification in `show_secret.html`
- ✅ Corrected salt length mismatch between server and client
- ✅ Resolved JSON encoding issues in Flask templates
- ✅ Improved error handling and debugging output

### 🛡️ **Security Enhancements**
- ✅ Added comprehensive SPDL documentation
- ✅ Implemented detailed security analysis
- ✅ Enhanced debug logging and troubleshooting tools
- ✅ Improved cryptographic parameter consistency

### 🎯 **User Experience**
- ✅ Added debug endpoint for system monitoring
- ✅ Enhanced console logging with detailed steps
- ✅ Improved error messages and user feedback
- ✅ Added visual debug information panel

## 🎮 Demo Features

### Real-time Security Monitoring
- 📊 Live connection attempt logs
- 🚨 Attack detection alerts
- 📈 Security protocol effectiveness display

### Interactive Testing
- 🔐 Toggle security on/off to see the difference
- 🧪 Built-in attacker simulation
- 📱 Mobile-friendly QR code interface

## 🔮 Future Enhancements

- [ ] 🔄 Auto-refresh logs without page reload (AJAX/WebSocket)
- [ ] 📶 Real-time attack visualizer with alerts
- [ ] 📱 Responsive design for mobile PisoWiFi screens
- [ ] 🧪 Unit tests for cryptographic functions
- [ ] 📊 Analytics dashboard for administrators
- [ ] 🔐 CAPTCHA integration for bot resistance
- [ ] 📄 Downloadable CSV log exports
- [ ] 🌐 Docker containerization
- [ ] ☁️ Cloud deployment (Render/Railway)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Developer

**Daniel Jon Santos**  
- GitHub: [@DanielJonSantos](https://github.com/DanielJonSantos)
- Project: Secure PisoWiFi System Simulation

---

## 🏆 Security Achievement

This simulator demonstrates **enterprise-grade security principles** typically found in:
- 🏦 Banking systems (digital signatures)
- 🌐 HTTPS/TLS protocols (RSA cryptography)
- 🔐 Code signing systems (integrity verification)
- 🏢 Corporate networks (multi-factor authentication)

**Educational Value**: Perfect for learning modern cryptographic protocols and network security concepts in a practical, hands-on environment.

---

*Built with ❤️ for cybersecurity education and WiFi access control simulation*