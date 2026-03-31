// --- PIN Input Logic ---
function setupPinInputs(containerId) {
    const inputs = document.querySelectorAll(`#${containerId} input`);
    inputs.forEach((input, i) => {
	input.addEventListener('input', () => {
            const val = input.value.replace(/[^0-9]/g, '');
            input.value = val.slice(-1);
            if (val && i < inputs.length - 1) inputs[i + 1].focus();
            checkPins();
	});      input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !input.value && i > 0) {
		inputs[i - 1].focus();
            }
	});
	input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasted = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
            [...pasted].forEach((ch, j) => {
		if (inputs[j]) inputs[j].value = ch;
            });
            checkPins();
	});
    });
}

setupPinInputs('pin1Inputs');
setupPinInputs('pin2Inputs');

function getPin(containerId) {
    return [...document.querySelectorAll(`#${containerId} input`)]
	.map(i => i.value).join('');
}

function checkPins() {
    const p1 = getPin('pin1Inputs');
    const p2 = getPin('pin2Inputs');
    const match = document.getElementById('pinMatch');
    if (p1.length === 6 && p2.length === 6) {
	if (p1 === p2) {
            match.textContent = '✓ PINs match';
            match.className = 'pin-match ok';
	} else {
            match.textContent = '✗ PINs do not match';
            match.className = 'pin-match fail';
	}
    } else {
	match.textContent = '';
	match.className = 'pin-match';
    }
    updateBtn();
}

// --- File Selection ---
let selectedFile = null;

document.getElementById('fileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file && file.type === 'application/pdf') {
	selectedFile = file;
	document.getElementById('fileName').textContent = file.name;
	document.getElementById('fileSelected').classList.add('show');
	updateBtn();
    }
});

const dropZone = document.getElementById('dropZone');
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file && file.type === 'application/pdf') {
	selectedFile = file;
	document.getElementById('fileName').textContent = file.name;
	document.getElementById('fileSelected').classList.add('show');
	updateBtn();
    }
});

function updateBtn() {
    const p1 = getPin('pin1Inputs');
    const p2 = getPin('pin2Inputs');
    document.getElementById('encryptBtn').disabled =
	!(selectedFile && p1.length === 6 && p2.length === 6 && p1 === p2);
}

// --- Encryption ---
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const pin = getPin('pin1Inputs');
    const status = document.getElementById('status');
    const progressBar = document.getElementById('progressBar');
    const progressFill = document.getElementById('progressFill');
    const btn = document.getElementById('encryptBtn');

    btn.disabled = true;
    progressBar.classList.add('show');
    status.textContent = 'Read File...';
    status.className = 'status';
    progressFill.style.width = '10%';

    try {
	const fileData = await selectedFile.arrayBuffer();
	progressFill.style.width = '30%';
	status.textContent = 'Derive key (PBKDF2)...';

	// Derive key from PIN
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']
	);

	const salt = crypto.getRandomValues(new Uint8Array(16));
	const iv = crypto.getRandomValues(new Uint8Array(12));

	const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
	);

	progressFill.style.width = '60%';
	status.textContent = 'Decrypt...';

	const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            fileData
	);

	progressFill.style.width = '85%';
	status.textContent = 'Create download...';

	// Format: "ENCPDF" magic + salt (16) + iv (12) + ciphertext
	const magic = new TextEncoder().encode('ENCPDF');
	const result = new Uint8Array(
            magic.length + salt.length + iv.length + encrypted.byteLength
	);
	let offset = 0;
	result.set(magic, offset); offset += magic.length;
	result.set(salt, offset); offset += salt.length;
	result.set(iv, offset); offset += iv.length;
	result.set(new Uint8Array(encrypted), offset);

	const blob = new Blob([result], { type: 'application/octet-stream' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	const baseName = selectedFile.name.replace(/\.pdf$/i, '');
	a.download = baseName + '.enc';
	a.click();
	URL.revokeObjectURL(url);

	progressFill.style.width = '100%';
	status.textContent = `✓ ${baseName}.enc downloaded`;
	status.className = 'status success';
    } catch (err) {
	status.textContent = '✗ Erroor: ' + err.message;
	status.className = 'status error';
	progressFill.style.width = '0%';
    }
    btn.disabled = false;
});
