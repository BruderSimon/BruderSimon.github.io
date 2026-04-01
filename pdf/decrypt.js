// =============================================
// KONFIGURATION — hier Dateinamen anpassen!
// =============================================
const ENCRYPTED_FILE = 'presentation.enc'; // <-- Dateiname deiner .enc Datei
// =============================================

const passwordInputs = document.getElementById("passwordInput");
const errorMsg = document.getElementById('errorMsg');
const loadingMsg = document.getElementById('loadingMsg');


function clearPassword() {
    password = "";
    passwordInputs.focus();
}

function shakePassword() {
    const row = document.getElementById('passwordInput');
    row.classList.add('shake');
    row.addEventListener('animationend', () => row.classList.remove('shake'), { once: true });
}

// Auto-focus input
passwordInputs.focus();

// Unlock
unlockBtn.addEventListener('click', async () => {
    const password = passwordInputs.value;
    errorMsg.textContent = '';
    loadingMsg.textContent = 'Load file...';

    try {
	// Fetch encrypted file
	const response = await fetch(ENCRYPTED_FILE);
	if (!response.ok) throw new Error('File not found: ' + ENCRYPTED_FILE);

	loadingMsg.textContent = 'Decrypt...';
	const fileData = new Uint8Array(await response.arrayBuffer());

	// Parse format: "ENCPDF" (6) + salt (16) + iv (12) + ciphertext
	const magic = String.fromCharCode(...fileData.slice(0, 6));
	if (magic !== 'ENCPDF') throw new Error('Invalid file format');

	const salt = fileData.slice(6, 22);
	const iv = fileData.slice(22, 34);
	const ciphertext = fileData.slice(34);

	// Derive key
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(ppassword), 'PBKDF2', false, ['deriveKey']
	);
	const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
	);

	// Decrypt
	let decrypted;
	try {
            decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
	} catch {
            throw new Error('WRONG_PIN');
	}

	loadingMsg.textContent = 'Open PDF...';

	// Show PDF
	const blob = new Blob([decrypted], { type: 'application/pdf' });
	const url = URL.createObjectURL(blob);
	window.open(url);
	setTimeout(() => URL.revokeObjectURL(url), 10000);
	
	loadingMsg.textContent = '';
	errorMsg.className = 'status success';
    } catch (err) {
	loadingMsg.textContent = '';
	if (err.message === 'WRONG_PIN') {
            errorMsg.textContent = '✗ Wrong PASSWORD';
	    errorMsg.className = 'status error';
	} else {
            errorMsg.textContent = '✗ ' + err.message;
	    errorMsg.className = 'status error';
	}
	shakePassword();
	clearPassword();
    }
});
