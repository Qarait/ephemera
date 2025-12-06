document.addEventListener('DOMContentLoaded', async () => {
    // Check Auth
    try {
        const res = await fetch('/api/me');
        if (!res.ok) {
            window.location.href = '/login.html';
            return;
        }
        const user = await res.json();
        document.getElementById('currentUser').textContent = user.username;
    } catch (e) {
        window.location.href = '/login.html';
        return;
    }

    // Load Audit Log
    loadAudit();

    // Event Listeners
    document.getElementById('generateBtn').addEventListener('click', generateCert);
    document.getElementById('downloadBtn').addEventListener('click', downloadCert);

    const regBtn = document.getElementById('registerWebAuthnBtn');
    if (regBtn) regBtn.addEventListener('click', registerWebAuthn);
});

// --- WebAuthn Helpers ---
function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let string = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        string += String.fromCharCode(bytes[i]);
    }
    return btoa(string).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64URLToBuffer(base64URL) {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLen, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function registerWebAuthn() {
    try {
        // 1. Get Options
        const res = await fetch('/api/webauthn/register/options', { method: 'POST' });
        if (!res.ok) throw new Error('Failed to get options');
        const options = await res.json();

        // 2. Decode challenge & user.id
        options.challenge = base64URLToBuffer(options.challenge);
        options.user.id = base64URLToBuffer(options.user.id);

        // 3. Create Credential
        const credential = await navigator.credentials.create({ publicKey: options });

        // 4. Encode response
        const credentialJSON = {
            id: credential.id,
            rawId: bufferToBase64URL(credential.rawId),
            response: {
                attestationObject: bufferToBase64URL(credential.response.attestationObject),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
            },
            type: credential.type,
        };

        // 5. Verify
        const verifyRes = await fetch('/api/webauthn/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialJSON)
        });

        if (verifyRes.ok) {
            alert('Security Key Registered Successfully!');
        } else {
            const err = await verifyRes.json();
            alert(`Registration Failed: ${err.error}`);
        }
    } catch (e) {
        console.error(e);
        alert(`Error: ${e.message}`);
    }
}

async function loginWebAuthn() {
    const username = document.getElementById('username').value;
    if (!username) {
        alert('Please enter your username first.');
        return;
    }

    try {
        // 1. Get Options
        const res = await fetch('/api/webauthn/login/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Failed to get login options');
        }

        const options = await res.json();

        // 2. Decode challenge & allowCredentials
        options.challenge = base64URLToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials.forEach(c => {
                c.id = base64URLToBuffer(c.id);
            });
        }

        // 3. Get Assertion
        const credential = await navigator.credentials.get({ publicKey: options });

        // 4. Encode response
        const credentialJSON = {
            id: credential.id,
            rawId: bufferToBase64URL(credential.rawId),
            response: {
                authenticatorData: bufferToBase64URL(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
                signature: bufferToBase64URL(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64URL(credential.response.userHandle) : null,
            },
            type: credential.type,
        };

        // 5. Verify
        const verifyRes = await fetch('/api/webauthn/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialJSON)
        });

        if (verifyRes.ok) {
            window.location.href = '/index.html';
        } else {
            const err = await verifyRes.json();
            alert(`Login Failed: ${err.error}`);
        }
    } catch (e) {
        console.error(e);
        alert(`Error: ${e.message}`);
    }
}

async function generateCert() {
    const btn = document.getElementById('generateBtn');
    const status = document.getElementById('statusMsg');
    const resultArea = document.getElementById('resultArea');
    const publicKey = document.getElementById('publicKey').value.trim();
    const validity = document.getElementById('validity').value;

    if (!publicKey) {
        status.textContent = 'Please enter a public key.';
        status.style.color = 'var(--error)';
        return;
    }

    btn.disabled = true;
    status.textContent = 'Generating...';
    status.style.color = 'inherit';
    resultArea.classList.add('hidden');

    try {
        const res = await fetch('/api/cert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                publicKey: publicKey,
                validityMinutes: parseInt(validity)
            })
        });

        const data = await res.json();

        if (res.ok) {
            status.textContent = 'Certificate generated successfully!';
            status.style.color = 'var(--success)';
            document.getElementById('certContent').value = data.certificate;
            resultArea.classList.remove('hidden');
            loadAudit(); // Refresh log
        } else {
            status.textContent = `Error: ${data.error}`;
            status.style.color = 'var(--error)';
        }
    } catch (e) {
        status.textContent = 'Network error occurred.';
        status.style.color = 'var(--error)';
    } finally {
        btn.disabled = false;
    }
}

function downloadCert() {
    const content = document.getElementById('certContent').value;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'id_rsa-cert.pub'; // Default name, user can rename
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

async function loadAudit() {
    const tbody = document.querySelector('#auditTable tbody');
    try {
        const res = await fetch('/api/audit');
        const logs = await res.json();

        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>${log.username}</td>
                <td>${new Date(log.issuedAt).toLocaleString()}</td>
                <td>${new Date(log.expiresAt).toLocaleString()}</td>
                <td>${log.validityMinutes}m</td>
                <td style="font-family: monospace; font-size: 0.8em">${log.id.substring(0, 8)}...</td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5">Failed to load logs</td></tr>';
    }
}

async function verifyLedger() {
    try {
        const res = await fetch('/api/audit/verify', { method: 'POST' });
        const data = await res.json();

        if (data.valid) {
            alert(`✅ Ledger Integrity Verified!\n${data.message}`);
        } else {
            alert(`❌ Ledger Verification FAILED!\n\nErrors:\n${data.errors.join('\n')}`);
        }
    } catch (e) {
        alert(`Error verifying ledger: ${e.message}`);
    }
}

function logout() {
    // For this simple MVP, just clearing the cookie on client side isn't enough strictly speaking
    // if it's httpOnly, but we can just redirect to login.
    // Ideally we'd have a logout endpoint, but clearing session state via reload/redirect is okay for MVP.
    // To be cleaner, let's just redirect to login, the session cookie will persist but
    // the user is effectively "logged out" of the UI.
    // A real app would hit a POST /api/logout endpoint.
    document.cookie = "sessionId=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    window.location.href = '/login.html';
}

async function startRenewal() {
    const status = document.getElementById('statusMsg');
    const resultArea = document.getElementById('certResult');
    const publicKey = document.getElementById('renewPublicKey').value.trim();
    const btn = document.getElementById('renewBtn');

    if (!publicKey) {
        status.textContent = 'Please enter your SSH Public Key.';
        status.style.color = 'red';
        return;
    }

    btn.disabled = true;
    status.textContent = 'Touch your security key...';
    status.style.color = 'inherit';
    resultArea.style.display = 'none';

    try {
        // 1. Get Options
        const res = await fetch('/api/webauthn/renew/start', { method: 'POST' });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Failed to start renewal');
        }
        const options = await res.json();

        // 2. Decode challenge & allowCredentials
        options.challenge = base64URLToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials.forEach(c => {
                c.id = base64URLToBuffer(c.id);
            });
        }

        // 3. Get Assertion
        const credential = await navigator.credentials.get({ publicKey: options });

        // 4. Encode response
        const credentialJSON = {
            id: credential.id,
            rawId: bufferToBase64URL(credential.rawId),
            response: {
                authenticatorData: bufferToBase64URL(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
                signature: bufferToBase64URL(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64URL(credential.response.userHandle) : null,
            },
            type: credential.type,
            sshPublicKey: publicKey // Send the key to sign
        };

        // 5. Finish
        const verifyRes = await fetch('/api/webauthn/renew/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialJSON)
        });

        const data = await verifyRes.json();

        if (verifyRes.ok) {
            status.textContent = 'Renewal Successful!';
            status.style.color = 'green';
            document.getElementById('newCertContent').value = data.certificate;
            document.getElementById('expiresAt').textContent = new Date(data.expires_at).toLocaleString();
            resultArea.style.display = 'block';
        } else {
            if (data.error === 'No pending challenge') {
                throw new Error('WebAuthn challenge expired — please restart renewal.');
            }
            throw new Error(data.error || 'Renewal failed');
        }

    } catch (e) {
        console.error(e);
        status.textContent = `Error: ${e.message}`;
        status.style.color = 'red';
    } finally {
        btn.disabled = false;
    }
}
