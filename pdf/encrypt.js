const passwordInput = document.getElementById("passwordInput")
const passwordConfirm = document.getElementById("passwordConfirm")

function checkPassword() {
    const p1 = passwordInput.value;
    const p2 = passwordConfirm.value;
    const match = document.getElementById('pinMatch');
    if (p1 === p2 && p1.length > 0) {
	match.textContent = '✓ Passwords match';
	match.className = 'pin-match ok';
    } else if (p2.length > 0) {
	match.textContent = '✗ Passwords do not match';
	match.className = 'pin-match fail';
    } else {
	match.textContent = '';
    }
    updateBtn();
}

passwordInput.addEventListener('input', checkPassword);
passwordConfirm.addEventListener('input', checkPassword);
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
    const p1 = passwordInput.value;
    const p2 = passwordConfirm.value;
    document.getElementById('encryptBtn').disabled = !(selectedFile && p1 === p2 && p1.length > 0);
}

function uint8ToBase64(bytes) {
    let binary = '';
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk)
	binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    return btoa(binary);
}

async function deriveKey(password, salt){
    const result = await argon2.hash({
	pass: password,
	salt: uint8ToBase64(salt),
	type: argon2.ArgonType.Argon2id,
	hashLen: 32,
	time: 3,    // iterations
	mem: 65536, //64 MB memory
	parallelism: 1
    });
    return crypto.subtle.importKey(
	"raw",
	result.hash,
	{ name: "AES-GCM" },
	false,
	["encrypt","decrypt"]
    );
}

// --- Encryption ---
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const password = passwordInput.value;
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
	status.textContent = 'Derive key (Argon2)...';

	// Derive key from Password
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const iv = crypto.getRandomValues(new Uint8Array(12));

	const key = await  deriveKey(password, salt);

	progressFill.style.width = '60%';
	status.textContent = 'Encrypt...';

	const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            fileData
	);

	progressFill.style.width = '75%';
	status.textContent = 'Generate file...';

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

	const b64 = uint8ToBase64(result);
	
	progressFill.style.width = '95%';
	status.textContent = 'Create download...';

	const css_fetch = await fetch('https://simonengel.net/style.css');
	const js_fetch = await fetch('https://simonengel.net/pdf/decrypt.js');
	const argon2_fetch = await fetch('https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-bundled.min.js');
	
	if (!css_fetch.ok || !js_fetch.ok || !argon2_fetch.ok) throw new Error('Network response was not ok');
	const css_content = await css_fetch.text(); 
	const js_content = await js_fetch.text();
	const argon2_content = await argon2_fetch.text();
	
	const css_short = `<link rel="stylesheet"; href="https://simonengel.net/style.css">`;
	const js_short = `<script src="https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-bundled.min.js"></script>\n<script>const B64 ="${b64}"; </script><script src="https://simonengel.net/pdf/decrypt.js"></script>`;
	
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Decrypt</title>
<style>${css_content}</style>
</head>
<body>
  <div id="lockScreen">
    <div class="card">
      <div class="header">
        <div class="tag">Protected content</div>
        <h1>Enter <span style="color: var(--surimiOrange)">Password</span></h1>
      </div>
      <input id="passwordInput" class="password-input" type="password" placeholder="Password">
      <button class="btn" id="unlockBtn">Decrypt</button>
      <div class="status"id="errorMsg"></div>
      <div class="loading-msg" id="loadingMsg"></div>
    </div>
  </div>
  <script>${argon2_content}</script>
  <script> const B64 ="${b64}";
  ${js_content}</script>
</body>
</html>`;
	
	const blob = new Blob([html], { type: 'application/octet-stream' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	const baseName = selectedFile.name.replace(/\.pdf$/i,'').replace(/[^a-z0-9_\-]/gi,'_');
	a.download = baseName + '.html';
	a.click();
	URL.revokeObjectURL(url);

	progressFill.style.width = '100%';
	status.textContent = `✓ ${baseName}.html downloaded`;
	status.className = 'status success';
    } catch (err) {
	status.textContent = '✗ Error: ' + err.message;
	status.className = 'status error';
	progressFill.style.width = '0%';
    }
    btn.disabled = false;
});
