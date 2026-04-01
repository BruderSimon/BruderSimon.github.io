function checkPassword() {
    const p1 = document.getElementById("passwordInput").value;
    const p2 = document.getElementById("passwordConfirm").value;
    const match = document.getElementById('pinMatch');
    if (p1.length === p2.length) {
	if (p1 === p2) {
            match.textContent = '✓ Passwords match';
            match.className = 'pin-match ok';
	} else {
            match.textContent = '✗ Passwords do not match';
            match.className = 'pin-match fail';
	}
    } else {
	match.textContent = '';
	match.className = 'pin-match';
    }
    updateBtn();
}

document.getElementById("passwordConfirm").addEventListener("input", (e) => checkPassword());

// --- File Selection ---
let selectedFile = null;

document.getElementById('fileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file && (file.type === 'application/pdf' || file.name.toLowerCase().endsWith(".pdf"))) {
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
    if (file && (file.type === 'application/pdf' || file.name.toLowerCase().endsWith(".pdf"))) {
	selectedFile = file;
	document.getElementById('fileName').textContent = file.name;
	document.getElementById('fileSelected').classList.add('show');
	updateBtn();
    }
});

function updateBtn() {
    const p1 = document.getElementById("passwordInput").value;
    const p2 = ocument.getElementById("passwordConfirm").value;
    document.getElementById('encryptBtn').disabled =
	!(selectedFile && p1 === p2);
}

// --- Encryption ---
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const password = document.getElementById("passwordInput").value;
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

	// Derive key from Password
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
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
	status.textContent = 'Encrypt...';

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
