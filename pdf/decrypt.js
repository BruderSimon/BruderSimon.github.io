const passwordInputs = document.getElementById("passwordInput");
const unlockBtn = document.getElementById('unlockBtn');
const errorMsg = document.getElementById('errorMsg');
const loadingMsg = document.getElementById('loadingMsg');

passwordInputs.focus();

function uint8ToBase64(bytes) {
    let binary = '';
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk)
	binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    return btoa(binary);
}

function shakePassword() {
    passwordInputs.classList.add('shake');
    passwordInputs.addEventListener('animationend', () => passwordInputs.classList.remove('shake'), { once: true });
}

const b2u = b => Uint8Array.from(atob(b), c => c.charCodeAt(0));

async function deriveKey(password, salt) {
    const result = await argon2.hash({
        pass: password,
	salt: uint8ToBase64(salt),
        type: argon2.ArgonType.Argon2id,
        hashLen: 32, time: 3, mem: 65536, parallelism: 1});
    return crypto.subtle.importKey("raw", result.hash, { name: "AES-GCM" }, false, ["decrypt"]);
}

unlockBtn.addEventListener('click', async () => {
    errorMsg.textContent = '';
    loadingMsg.textContent = 'Decrypt...';
    try {
	const fileData = b2u(B64);
	if (String.fromCharCode(...fileData.slice(0, 6)) !== 'ENCPDF') throw new Error('Invalid file');
	const key = await deriveKey(passwordInputs.value, fileData.slice(6, 22));
	let decrypted;
	try {
            decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fileData.slice(22, 34) }, key, fileData.slice(34));
        } catch {
            throw new Error('WRONG');
        }
	loadingMsg.textContent = 'Open PDF...';
	const url = URL.createObjectURL(new Blob([decrypted], { type: 'application/pdf' }));
        window.open(url);
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        loadingMsg.textContent = '';
    } catch (err) {
	loadingMsg.textContent = '';
	errorMsg.textContent = err.message === "WRONG"?"✗ Wrong PASSWORD":'✗ ' + err.message;
	errorMsg.className = 'status error';
	shakePassword();
	passwordInputs.value = '';
        passwordInputs.focus();
    }
});
