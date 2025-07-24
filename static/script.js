
async function connect() {
    const mac = "AA:BB:CC:11:22:33";  // Simulated MAC
    const timestamp = Date.now().toString();

    const hmac = await fetch("/generate-hmac", {
        method: "POST",
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ mac, timestamp })
    }).then(res => res.json()).then(data => data.hmac);

    const response = await fetch("/connect", {
        method: "POST",
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ mac, timestamp, hmac })
    }).then(res => res.json());

    document.getElementById("response").innerText = JSON.stringify(response, null, 2);
}
