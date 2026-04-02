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

	const css_long = "<style>* { margin: 0; padding: 0; box-sizing: border-box; } body { font-family: monospace; font-size: 1.2rem; background-color: #181820; color:  #DCD7BA; display: flex; align-items: center; justify-content: center; min-height: 100vh; }  h1 { font-size: 1.5em; margin-bottom: 1rem; color: #FF5D62; } @keyframes shake { 0%,100% { transform: translateX(0); } 20%,60% { transform: translateX(-6px); } 40%,80% { transform: translateX(6px); }} .card { padding: 2rem; } .tag { font-size: 0.7rem; color: #9CABCA; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.75rem; } .password-input { width: 50%; padding: 0.6rem; background: #363646; border-color: #D27E99; color:  #DCD7BA; outline: none; font-size: 1rem; } .password-input.shake { animation: shake 0.4s ease; } .btn { width: 100%; padding: 1rem; background: #363646; border: none; font-family: monospace; font-size: 0.85rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer; margin-top: 1.5rem; } .btn:hover { background: #FFA066; } .status { font-size: 0.75rem; margin-top: 0.75rem; min-height: 1.2rem; } .status.success { color: #98BB6C; } .status.error { color: #E82424;}</style>";

	const css_fetch = await fetch('https://simonengel.net/style.css');
	const js_fetch = await fetch('https://simonengel.net/pdf/decrypt.js');
	const argon2_fetch = await fetch('https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-bundled.min.js');
	
	if (!css_fetch.ok || !js_fetch.ok || !argon2_fetch.ok) throw new Error('Network response was not ok');
	const css_content = await css_fetch.text(); 
	const js_content = await js_fetch.text();
	const argon2_content = await argon2_fetch.text();
	
	const css_short = `<link rel="stylesheet"; href="https://simonengel.net/style.css">`;
	const js_short = `<script src="https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-bundled.min.js"></script><script>const B64 ="${b64}";</script><script src="https://simonengel.net/pdf/decrypt.js"></script>`;
	const js_long = `<script src="https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-bundled.min.js"></script><script>const B64 ="${b64}";const passwordInputs = document.getElementById("passwordInput");const unlockBtn = document.getElementById('unlockBtn');const errorMsg = document.getElementById('errorMsg');const loadingMsg = document.getElementById('loadingMsg');passwordInputs.focus();function shakePassword(){passwordInputs.classList.add('shake');passwordInputs.addEventListener('animationend', () => passwordInputs.classList.remove('shake'), { once: true });}const b2u = b => Uint8Array.from(atob(b), c => c.charCodeAt(0));async function deriveKey(password, salt) {const result = await argon2.hash({pass: password, uint8ToBase64(salt),type: argon2.ArgonType.Argon2id,hashLen: 32, time: 3, mem: 65536, parallelism: 1});return crypto.subtle.importKey("raw", result.hash, { name: "AES-GCM" }, false, ["decrypt"]);}unlockBtn.addEventListener('click', async () => {errorMsg.textContent = ''; loadingMsg.textContent = 'Decrypt...'; try {const fileData = b2u(B64);if (String.fromCharCode(...fileData.slice(0, 6)) !== 'ENCPDF') throw new Error('Invalid file');	const key = await deriveKey(passwordInputs.value, fileData.slice(6, 22)); let decrypted;try {decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fileData.slice(22, 34) }, key, fileData.slice(34));} catch {throw new Error('WRONG');}loadingMsg.textContent = 'Open PDF...'; const url = URL.createObjectURL(new Blob([decrypted], { type: 'application/pdf' })); window.open(url); setTimeout(() => URL.revokeObjectURL(url), 10000); loadingMsg.textContent = ''; } catch (err) { loadingMsg.textContent = ''; errorMsg.textContent = err.message === "WRONG"?"✗ Wrong PASSWORD":'✗ ' + err.message; errorMsg.className = 'status error'; shakePassword(); passwordInputs.value = ''; passwordInputs.focus();}});`;
	const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Decrypt</title><style>${css_content}</style></head><body><div id="lockScreen"><div class="card"><div class="header"><div class="tag">Protected content</div><h1>Enter <span style="color: var(--surimiOrange)">Password</span></h1></div><input id="passwordInput" class="password-input" type="password" placeholder="Password"><button class="btn" id="unlockBtn">Decrypt</button><div class="status"id="errorMsg"></div><div class="loading-msg" id="loadingMsg"></div></div></div><script>${argon2_content} const B64 ="${b64}" ${js_content}</script></body></html>`;
	
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
