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
	const safeName = pdfName.replace(/"/g, '&quot;');
	
	progressFill.style.width = '95%';
	status.textContent = 'Create download...';

	const css_long = "<style>* { margin: 0; padding: 0; box-sizing: border-box; } body { font-family: monospace; font-size: 1.2rem; background-color: #181820; color:  #DCD7BA; display: flex; align-items: center; justify-content: center; min-height: 100vh; }  h1 { font-size: 1.5em; margin-bottom: 1rem; color: #FF5D62; } @keyframes shake { 0%,100% { transform: translateX(0); } 20%,60% { transform: translateX(-6px); } 40%,80% { transform: translateX(6px); }} .card { padding: 2rem; } .tag { font-size: 0.7rem; color: #9CABCA; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.75rem; } .password-input { width: 50%; padding: 0.6rem; background: #363646; border-color: #D27E99; color:  #DCD7BA; outline: none; font-size: 1rem; } .password-input.shake { animation: shake 0.4s ease; } .btn { width: 100%; padding: 1rem; background: #363646; border: none; font-family: monospace; font-size: 0.85rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer; margin-top: 1.5rem; } .btn:hover { background: #FFA066; } .status { font-size: 0.75rem; margin-top: 0.75rem; min-height: 1.2rem; } .status.success { color: #98BB6C; } .status.error { color: #E82424;}</style>";
	const css_short = "<link rel=&quot;stylesheet&quot; href=&quot;https://simonengel.net/style.css&quot;>";
	const js_short = "<script src=&quot;https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2-bundled.min.js&quot;></script><script>const B64 =&quot;${b64}&quot;;</script><script src=&quot;https://simonengel.net/pdf/decrypt.js&quot;></script>";
	const js_long = "";
	const html = "<!DOCTYPE html><html lang=&quot;en&quot;><head><meta charset=&quot;UTF-8&quot;><meta name=&quot;viewport&quot; content=&quot;width=device-width, initial-scale=1.0&quot;><title>Decrypt</title>${css_short} ${js_short}</head><body><div id=&quot;lockScreen&quot;><div class=&quot;card&quot;><div class=&quot;header&quot;><div class=&quot;tag&quot;>Protected content</div><h1>Enter <span style=&quot;color: var(--surimiOrange)&quot;>Password</span></h1></div><input id=&quot;passwordInput&quot; class=&quot;password-input&quot; type=&quot;password&quot; placeholder=&quot;Password&quot;><button class=&quot;btn&quot; id=&quot;unlockBtn&quot;>Decrypt</button><div class=&quot;status&quot; id=&quot;errorMsg&quot;></div><div class=&quot;loading-msg&quot; id=&quot;loadingMsg&quot;></div></div></div></body></html>";
	
	const blob = new Blob([result], { type: 'application/octet-stream' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	const baseName = selectedFile.name.replace(/\.pdf$/i,'').replace(/[^a-z0-9_\-]/gi,'_');
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
