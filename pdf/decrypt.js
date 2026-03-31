// =============================================
// KONFIGURATION — hier Dateinamen anpassen!
// =============================================
const ENCRYPTED_FILE = 'presentation.enc'; // <-- Dateiname deiner .enc Datei
// =============================================

const pinInputs = document.querySelectorAll('#pinRow input');
const unlockBtn = document.getElementById('unlockBtn');
const errorMsg = document.getElementById('errorMsg');
const loadingMsg = document.getElementById('loadingMsg');

// PIN input handling
pinInputs.forEach((input, i) => {
    input.addEventListener('input', () => {
	const val = input.value.replace(/[^0-9]/g, '');
	input.value = val.slice(-1);
	if (val && i < pinInputs.length - 1) pinInputs[i + 1].focus();
	unlockBtn.disabled = getPin().length !== 6;
	errorMsg.textContent = '';
    });    input.addEventListener('keydown', (e) => {
	if (e.key === 'Backspace' && !input.value && i > 0) {
            pinInputs[i - 1].focus();
	}
	if (e.key === 'Enter' && getPin().length === 6) {
            unlockBtn.click();
	}
    });
    input.addEventListener('paste', (e) => {
	e.preventDefault();
	const pasted = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
	[...pasted].forEach((ch, j) => { if (pinInputs[j]) pinInputs[j].value = ch; });
	unlockBtn.disabled = getPin().length !== 6;
    });
});

function getPin() {
    return [...pinInputs].map(i => i.value).join('');
}

function clearPin() {
    pinInputs.forEach(i => i.value = '');
    pin = null;
    pinInputs[0].focus();
    unlockBtn.disabled = true;
}

function shakePin() {
    const row = document.getElementById('pinRow');
    row.classList.add('shake');
    row.addEventListener('animationend', () => row.classList.remove('shake'), { once: true });
}

// Auto-focus first input
pinInputs[0].focus();

// Unlock
unlockBtn.addEventListener('click', async () => {
    const pin = getPin();
    unlockBtn.disabled = true;
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
            'raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']
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
	
	document.getElementById('viewerFilename').textContent =
            ENCRYPTED_FILE.replace('.enc', '.pdf');

	document.getElementById('lockScreen').classList.add('hidden');
	document.getElementById('viewer').classList.add('visible');
	loadingMsg.textContent = '';
	errorMsg.className = 'status success';
    } catch (err) {
	loadingMsg.textContent = '';
	if (err.message === 'WRONG_PIN') {
            errorMsg.textContent = '✗ Wrong PIN';
	    errorMsg.className = 'status error';
	} else {
            errorMsg.textContent = '✗ ' + err.message;
	    errorMsg.className = 'status error';
	}
	shakePin();
	clearPin();
    }
});

// Lock button
document.getElementById('lockBtn').addEventListener('click', () => {
    document.getElementById('pdfEmbed').src = '';
    document.getElementById('lockScreen').classList.remove('hidden');
    document.getElementById('viewer').classList.remove('visible');
    clearPin();
});
