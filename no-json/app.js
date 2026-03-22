// GLOBAL VARIABLES untuk download data
let encryptionData = { hexResult: null };
let decryptionData = { resultBytes: null, format: null, isImage: false };

/* 
   0. CHECKSUM FUNCTION (INTEGRITY CHECK)
    */
const Checksum = {
    compute: function(bytes) {
        let hash = 5381;
        for (let i = 0; i < bytes.length; i++) {
            hash = ((hash << 5) + hash) + bytes[i];
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16);
    }
};

/* 
   1. KEY DERIVATION (DETERMINISTIC dari symmetric key)
    */
const KeyDerivation = {
    // Generate IV deterministically dari symmetric key
    deriveIV: function(keyStr) {
        let keyBytes = new TextEncoder().encode(keyStr);
        let hash = Checksum.compute(keyBytes);
        // Convert hash string ke bytes (8 bytes untuk IV)
        let ivBytes = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            let hex = hash.substr((i * 2) % hash.length, 2) || '00';
            ivBytes[i] = parseInt(hex, 16) || (i * 10 + 20);
        }
        return ivBytes;
    },
    
    // Generate RSA Private Key deterministically dari symmetric key
    derivePrivateKey: function(keyStr) {
        let keyBytes = new TextEncoder().encode(keyStr);
        let hash = Checksum.compute(keyBytes);
        // Untuk simple: gunakan hash values sebagai d, n adalah fixed (61*53=3233)
        let d = BigInt('0x' + hash.substr(0, Math.min(8, hash.length)).padEnd(8, '0'));
        let n = 3233n;  // p=61, q=53
        return { d, n };
    }
};

/* 
   2. RSA (ASIMETRIK)
   */
const RSA = {
    modPow: function(base, exp, mod) {
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) res = (res * base) % mod;
            exp = exp / 2n;
            base = (base * base) % mod;
        }
        return res;
    },
    modInverse: function(e, phi) {
        let m0 = phi, t, q, x0 = 0n, x1 = 1n;
        if (phi === 1n) return 0n;
        while (e > 1n) {
            q = e / phi; t = phi; phi = e % phi; e = t; t = x0; x0 = x1 - q * x0; x1 = t;
        }
        return x1 < 0n ? x1 + m0 : x1;
    },
    generateKeys: function() {
        let p = 61n, q = 53n;
        let n = p * q, phi = (p - 1n) * (q - 1n), e = 17n;
        let d = this.modInverse(e, phi);
        return { pub: { e: e, n: n }, priv: { d: d, n: n } };
    },
    encrypt: function(msgBytes, pubKey) {
        let arr = [];
        for (let i = 0; i < msgBytes.length; i++) {
            arr.push(this.modPow(BigInt(msgBytes[i]), pubKey.e, pubKey.n).toString());
        }
        return arr;
    },
    decrypt: function(encArr, privKey) {
        let bytes = new Uint8Array(encArr.length);
        for (let i = 0; i < encArr.length; i++) {
            bytes[i] = Number(this.modPow(BigInt(encArr[i]), privKey.d, privKey.n));
        }
        return bytes;
    }
};

/* 
   3. BLOCK CIPHER (MODE CBC)
    */
class BlockCipher {
    constructor(keyStr, ivBytes = null) {
        this.key = new Uint8Array(8);
        for (let i = 0; i < 8; i++) this.key[i] = keyStr.charCodeAt(i);
        if (ivBytes) {
            this.iv = ivBytes;
        } else {
            this.iv = KeyDerivation.deriveIV(keyStr);
        }
    }

    sub(val) { return (val + 33) % 256; }
    invSub(val) { return (val - 33 + 256) % 256; }

    shift(block) {
        let t = block[0];
        for (let i = 0; i < 7; i++) block[i] = block[i + 1];
        block[7] = t;
        return block;
    }
    invShift(block) {
        let t = block[7];
        for (let i = 7; i > 0; i--) block[i] = block[i - 1];
        block[0] = t;
        return block;
    }

    encryptBlock(block) {
        let out = new Uint8Array(8);
        for (let i = 0; i < 8; i++) out[i] = this.sub(block[i]);
        return this.shift(out);
    }

    decryptBlock(block) {
        let out = this.invShift(new Uint8Array(block));
        for (let i = 0; i < 8; i++) out[i] = this.invSub(out[i]);
        return out;
    }

    process(data, isEncrypt) {
        let pad = isEncrypt ? 8 - (data.length % 8) : 0;
        let padded = new Uint8Array(data.length + pad);
        padded.set(data);
        if (isEncrypt) padded.fill(pad, data.length);

        let res = new Uint8Array(padded.length);
        let prev = new Uint8Array(this.iv);

        for (let i = 0; i < padded.length; i += 8) {
            let curr = padded.slice(i, i + 8);
            if (isEncrypt) {
                for (let j = 0; j < 8; j++) curr[j] ^= prev[j];
                let enc = this.encryptBlock(curr);
                res.set(enc, i);
                prev = enc;
            } else {
                let dec = this.decryptBlock(curr);
                for (let j = 0; j < 8; j++) dec[j] ^= prev[j];
                res.set(dec, i);
                prev = curr;
            }
        }
        return isEncrypt ? res : res.slice(0, res.length - res[res.length - 1]);
    }
}

/* 
   4. UI HELPERS
    */
const UI = {
    showMsg: function(msg, isError = false, context = null) {
        let outputBox, textareaId;
        if (!context) {
            let activeElement = document.activeElement;
            if (activeElement && activeElement.id === 'btnEncrypt') context = 'enc';
            else if (activeElement && activeElement.id === 'btnDecrypt') context = 'dec';
            else context = 'enc';
        }
        
        outputBox = document.getElementById(context === 'dec' ? 'decOutput' : 'encOutput');
        textareaId = context === 'dec' ? 'decResultText' : 'encResultText';
        
        if (isError) {
            let oldSuccess = outputBox.querySelector('.success-notification');
            if (oldSuccess) oldSuccess.remove();
            let oldError = outputBox.querySelector('.error-notification');
            if (oldError) oldError.remove();
            
            let errDiv = document.createElement('div');
            errDiv.className = 'error-notification';
            errDiv.textContent = msg;
            outputBox.insertBefore(errDiv, outputBox.firstChild);
            outputBox.style.display = 'block';
            
            setTimeout(() => {
                outputBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 100);
        } else {
            let textarea = document.getElementById(textareaId);
            if (textarea) {
                let textareaParent = textarea.parentElement;
                let existingNotif = textareaParent.querySelector('.success-notification');
                if (existingNotif) existingNotif.remove();
                let notifDiv = document.createElement('div');
                notifDiv.className = 'success-notification';
                notifDiv.textContent = msg;
                textarea.parentElement.insertBefore(notifDiv, textarea);
            }
            outputBox.style.display = 'block';
            
            setTimeout(() => {
                outputBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 100);
        }
    },
    toHex: function(bytes) {
        let hexStr = "";
        for (let i = 0; i < bytes.length; i++) {
            let hex = bytes[i].toString(16);
            hexStr += (hex.length === 1 ? "0" : "") + hex;
        }
        return hexStr.toUpperCase();
    },
    fromHex: function(hexStr) {
        if (!hexStr || hexStr.trim().length === 0) {
            throw new Error("Hex string kosong! Paste hasil enkripsi atau upload file hex.");
        }
        
        let cleaned = hexStr.replace(/[\s\-:]/g, '').toUpperCase();
        
        if (!/^[0-9A-F]*$/.test(cleaned)) {
            let invalidChars = cleaned.replace(/[0-9A-F]/g, '').split('');
            let unique = [...new Set(invalidChars)];
            throw new Error(`❌ Hex berisi karakter tidak valid: ${unique.join(', ')}\n\nHex hanya boleh mengandung 0-9 dan A-F.`);
        }
        
        if (cleaned.length % 2 !== 0) {
            throw new Error(`❌ Panjang hex GANJIL (${cleaned.length} chars)!\n\nHex harus panjang GENAP (setiap 2 karakter = 1 byte).`);
        }
        
        let bytes = new Uint8Array(cleaned.length / 2);
        for (let i = 0; i < cleaned.length; i += 2) {
            let chunk = cleaned.substr(i, 2);
            let byte = parseInt(chunk, 16);
            if (isNaN(byte)) {
                throw new Error(`❌ Gagal parse hex di posisi ${i/2}: ${chunk}`);
            }
            bytes[i / 2] = byte;
        }
        return bytes;
    },
    getImageFormat: function(filename) {
        let ext = filename.toLowerCase();
        if (ext.endsWith('.bmp')) return 'bmp';
        if (ext.endsWith('.png')) return 'png';
        if (ext.endsWith('.jpg') || ext.endsWith('.jpeg')) return 'jpg';
        if (ext.endsWith('.gif')) return 'gif';
        return null;
    },
    validateImageFile: function(buffer, format) {
        let view = new Uint8Array(buffer);
        if (format === 'bmp') {
            if (view[0] !== 0x42 || view[1] !== 0x4D) {
                throw new Error("File BMP tidak valid! Magic bytes tidak sesuai.");
            }
        } else if (format === 'png') {
            if (!(view[0] === 0x89 && view[1] === 0x50 && view[2] === 0x4E && view[3] === 0x47)) {
                throw new Error("File PNG tidak valid! Magic bytes tidak sesuai.");
            }
        } else if (format === 'jpg') {
            if (!(view[0] === 0xFF && view[1] === 0xD8)) {
                throw new Error("File JPG/JPEG tidak valid! Magic bytes tidak sesuai.");
            }
        } else if (format === 'gif') {
            if (!(view[0] === 0x47 && view[1] === 0x49 && view[2] === 0x46)) {
                throw new Error("File GIF tidak valid! Magic bytes tidak sesuai.");
            }
        }
        return true;
    },
    extractImageHeader: function(bytes, format) {
        let header = new Uint8Array();
        let body = bytes;
        if (format === 'bmp') {
            let offset = bytes[10] | (bytes[11]<<8) | (bytes[12]<<16) | (bytes[13]<<24);
            header = bytes.slice(0, offset);
            body = bytes.slice(offset);
        } else if (format === 'png') {
            let headerSize = 33;
            if (bytes.length < headerSize) {
                throw new Error("File PNG terlalu kecil atau corrupt!");
            }
            header = bytes.slice(0, headerSize);
            body = bytes.slice(headerSize);
        } else if (format === 'jpg') {
            let pos = 2;
            let headerSize = 2;
            while (pos < bytes.length - 1) {
                if (bytes[pos] !== 0xFF) {
                    headerSize = pos;
                    break;
                }
                let marker = bytes[pos + 1];
                if (marker === 0xDA) {
                    let sosLen = (bytes[pos + 2] << 8) | bytes[pos + 3];
                    headerSize = pos + 2 + sosLen;
                    break;
                } else if (marker === 0xD9) {
                    headerSize = bytes.length;
                    break;
                } else if (marker === 0x00 || (marker >= 0xD0 && marker <= 0xD9)) {
                    pos += 2;
                } else {
                    let len = (bytes[pos + 2] << 8) | bytes[pos + 3];
                    pos += 2 + len;
                }
            }
            if (headerSize === 2 && pos > 2) headerSize = Math.min(pos, bytes.length);
            if (headerSize < 2) headerSize = Math.min(100, bytes.length);
            header = bytes.slice(0, headerSize);
            body = bytes.slice(headerSize);
        } else if (format === 'gif') {
            let minHeader = 13;
            if (bytes.length < minHeader) {
                throw new Error("File GIF terlalu kecil atau corrupt!");
            }
            let flags = bytes[10];
            let hasGCT = (flags & 0x80) !== 0;
            let gctSize = hasGCT ? (Math.pow(2, (flags & 0x07) + 1) * 3) : 0;
            let headerSize = 13 + gctSize;
            header = bytes.slice(0, headerSize);
            body = bytes.slice(headerSize);
        }
        return { header, body };
    }
};

function displayHexResult(hexStr) {
    let previewDiv = document.getElementById('hexPreview');
    previewDiv.innerHTML = `✓ Total ${hexStr.length} characters (${Math.ceil(hexStr.length / 2)} bytes)`;
    return hexStr;
}

function copyToClipboard(elementId) {
    let element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    alert('Disalin ke clipboard!');
}

function downloadEncHex() {
    if (!encryptionData.hexResult) {
        alert('⚠️ Tidak ada data hex!');
        return;
    }
    let blob = new Blob([encryptionData.hexResult], { type: 'text/plain' });
    let url = URL.createObjectURL(blob);
    let a = document.createElement('a');
    a.href = url;
    a.download = 'Hasil_Enkripsi.txt';
    a.click();
    URL.revokeObjectURL(url);
}

function downloadDecResult() {
    if (!decryptionData.resultBytes) {
        alert('⚠️ Tidak ada data hasil dekripsi!');
        return;
    }
    let fileName = 'Hasil_Dekripsi';
    let mimeType = 'text/plain';
    if (decryptionData.isImage) {
        let mimeTypes = {
            bmp: 'image/bmp',
            png: 'image/png',
            jpg: 'image/jpeg',
            gif: 'image/gif'
        };
        fileName += {bmp: '.bmp', png: '.png', jpg: '.jpg', gif: '.gif'}[decryptionData.format] || '.bin';
        mimeType = mimeTypes[decryptionData.format] || 'application/octet-stream';
    } else {
        fileName += '.txt';
    }
    let blob = new Blob([decryptionData.resultBytes], { type: mimeType });
    let url = URL.createObjectURL(blob);
    let a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
}

// Toggle modes
document.querySelectorAll('input[name="encMode"]').forEach(r => r.addEventListener('change', e => {
    document.getElementById('encTextContainer').style.display = e.target.value === 'text' ? 'block' : 'none';
    document.getElementById('encTxtFileContainer').style.display = e.target.value === 'txt-file' ? 'block' : 'none';
    document.getElementById('encImageContainer').style.display = e.target.value === 'image' ? 'block' : 'none';
}));

document.querySelectorAll('input[name="decMode"]').forEach(r => r.addEventListener('change', e => {
    document.getElementById('decPasteContainer').style.display = e.target.value === 'paste' ? 'block' : 'none';
    document.getElementById('decFileContainer').style.display = e.target.value === 'file' ? 'block' : 'none';
}));

document.getElementById('encTxtFileInput').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let info = `✓ File: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
        document.getElementById('encTxtFileInfo').innerHTML = info;
        document.getElementById('encTxtFileInfo').style.display = 'block';
    }
});

document.getElementById('encImageInput').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let imageFormat = UI.getImageFormat(file.name);
        if (!imageFormat) {
            alert('Format gambar tidak didukung!');
            e.target.value = '';
            return;
        }
        let info = `✓ File: ${file.name} (${(file.size / 1024).toFixed(2)} KB) - ${imageFormat.toUpperCase()}`;
        document.getElementById('encImageInfo').innerHTML = info;
        document.getElementById('encImageInfo').style.display = 'block';
    }
});

// --- ENCRYPTION ---
document.getElementById('btnEncrypt').addEventListener('click', async () => {
    try {
        encryptionData = { hexResult: null };
        let encOutput = document.getElementById('encOutput');
        let encResultText = document.getElementById('encResultText');
        
        if (encOutput) encOutput.style.display = 'none';
        if (encResultText) encResultText.value = '';
        if (encOutput) {
            encOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        }
        
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let mode = document.querySelector('input[name="encMode"]:checked').value;
        let keyStr = document.getElementById('encKeyInput').value;
        if (keyStr.length !== 8) throw new Error("Kunci Simetrik wajib 8 karakter!");

        let cipher = new BlockCipher(keyStr);

        if (mode === 'text') {
            let txt = document.getElementById('encTextInput').value;
            if (!txt) throw new Error("Pesan tidak boleh kosong!");
            
            let plainBytes = new TextEncoder().encode(txt);
            let plainChecksum = Checksum.compute(plainBytes);
            let encBytes = cipher.process(plainBytes, true);
            let hexResult = UI.toHex(encBytes);
            
            // Format: CHECKSUM|HEX
            hexResult = plainChecksum + '|' + hexResult;
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = displayHexResult(hexResult);
            encryptionData.hexResult = hexResult;
            
            UI.showMsg("✅ Enkripsi Text Sukses! Hex siap di-copy atau download.", false, 'enc');

        } else if (mode === 'txt-file') {
            let file = document.getElementById('encTxtFileInput').files[0];
            if (!file) throw new Error("Pilih file TXT terlebih dahulu!");

            let buffer = await file.arrayBuffer();
            let plainBytes = new Uint8Array(buffer);
            
            let text = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
            if (!text || text.length === 0) throw new Error("File TXT kosong!");
            
            let plainChecksum = Checksum.compute(plainBytes);
            let encBytes = cipher.process(plainBytes, true);
            let hexResult = UI.toHex(encBytes);
            
            hexResult = plainChecksum + '|txt|' + hexResult;
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = displayHexResult(hexResult);
            encryptionData.hexResult = hexResult;
            
            document.getElementById('encTxtFileInput').value = '';
            document.getElementById('encTxtFileInfo').style.display = 'none';
            
            UI.showMsg("✅ Enkripsi File TXT Sukses! Hex siap di-copy atau download.", false, 'enc');

        } else if (mode === 'image') {
            let file = document.getElementById('encImageInput').files[0];
            if (!file) throw new Error("Pilih file gambar terlebih dahulu!");

            let imageFormat = UI.getImageFormat(file.name);
            if (!imageFormat) throw new Error("Format gambar tidak didukung!");

            let buffer = await file.arrayBuffer();
            let imageBytes = new Uint8Array(buffer);
            
            UI.validateImageFile(imageBytes, imageFormat);
            
            let { header, body } = UI.extractImageHeader(imageBytes, imageFormat);
            let bodyChecksum = Checksum.compute(body);
            let encBodyBytes = cipher.process(body, true);
            let hexResult = UI.toHex(encBodyBytes);
            
            let headerBase64 = btoa(String.fromCharCode(...header));
            hexResult = bodyChecksum + '|' + imageFormat + '|' + headerBase64 + '|' + hexResult;
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = displayHexResult(hexResult);
            encryptionData.hexResult = hexResult;
            
            document.getElementById('encImageInput').value = '';
            document.getElementById('encImageInfo').style.display = 'none';
            
            UI.showMsg(`✅ Enkripsi Gambar (${imageFormat.toUpperCase()}) Sukses!`, false, 'enc');
        }
    } catch (err) { UI.showMsg(err.message, true, 'enc'); }
});

// --- DECRYPTION ---
document.getElementById('btnDecrypt').addEventListener('click', async () => {
    try {
        decryptionData = { resultBytes: null, format: null, isImage: false };
        let decOutput = document.getElementById('decOutput');
        let decResultText = document.getElementById('decResultText');
        let downloadDecBtn = document.getElementById('downloadDecBtn');
        
        if (decOutput) decOutput.style.display = 'none';
        if (decResultText) decResultText.value = '';
        if (downloadDecBtn) downloadDecBtn.style.display = 'none';
        if (decOutput) {
            decOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        }
        
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let userKeyInput = document.getElementById('decKeyInput').value;
        if (userKeyInput.length !== 8) {
            throw new Error("❌ Kunci Simetrik wajib 8 karakter!");
        }
        
        let decMode = document.querySelector('input[name="decMode"]:checked').value;
        let hexInput = '';
        
        if (decMode === 'paste') {
            hexInput = document.getElementById('decTextInput').value;
            if (!hexInput) throw new Error("Teks sandi kosong!");
        } else {
            let hexFile = document.getElementById('decHexFile').files[0];
            if (!hexFile) throw new Error("Harap upload file Hex!");
            hexInput = await hexFile.text();
            if (!hexInput) throw new Error("File hex kosong!");
        }
        
        // Parse format dari hex string
        let parts = hexInput.split('|');
        if (parts.length < 2) throw new Error("Format hex tidak valid!");
        
        let checksum = parts[0];
        let format = 'txt';
        let imageHeader = null;
        let cipherText = '';
        
        if (parts.length === 2) {
            // Text: CHECKSUM|HEX
            cipherText = parts[1];
        } else if (parts.length === 4 && (parts[1] === 'txt' || parts[1] === 'txt')) {
            // TXT: CHECKSUM|txt|HEX
            format = parts[1];
            cipherText = parts[3];
        } else if (parts.length >= 4 && ['bmp', 'png', 'jpg', 'gif'].includes(parts[1])) {
            // IMAGE: CHECKSUM|FORMAT|HEADER_B64|HEX
            format = parts[1];
            imageHeader = parts[2];
            cipherText = parts[3];
        }
        
        let cipher = new BlockCipher(userKeyInput);
        let encryptedBytes = UI.fromHex(cipherText);
        let decBody = cipher.process(encryptedBytes, false);
        
        let decryptedChecksum = Checksum.compute(decBody);
        if (decryptedChecksum !== checksum) {
            throw new Error("❌ Integritas data rusak atau kunci salah!");
        }
        
        document.getElementById('decOutput').style.display = 'block';
        
        if (format !== 'txt' && imageHeader) {
            // Image reconstruction
            let headerStr = atob(imageHeader);
            let header = new Uint8Array(headerStr.length);
            for (let i = 0; i < headerStr.length; i++) {
                header[i] = headerStr.charCodeAt(i);
            }
            
            let reconstructedImage = new Uint8Array(header.length + decBody.length);
            reconstructedImage.set(header, 0);
            reconstructedImage.set(decBody, header.length);
            
            UI.validateImageFile(reconstructedImage, format);
            
            decryptionData.format = format;
            decryptionData.isImage = true;
            decryptionData.resultBytes = reconstructedImage;
            
            let previewText = `[Gambar ${format.toUpperCase()} - ${reconstructedImage.length} bytes]`;
            document.getElementById('decResultText').value = previewText;
            document.getElementById('downloadDecBtn').style.display = 'block';
            document.getElementById('downloadDecBtn').textContent = `⬇️ Download ${format.toUpperCase()}`;
            
            UI.showMsg(`✅ Dekripsi Gambar (${format.toUpperCase()}) Sukses! ✓ Kunci ✓ Checksum ✓ Magic Bytes`, false, 'dec');
        } else {
            // Text file
            decryptionData.format = 'txt';
            decryptionData.isImage = false;
            decryptionData.resultBytes = decBody;
            
            document.getElementById('decResultText').value = new TextDecoder().decode(decBody);
            document.getElementById('downloadDecBtn').style.display = 'block';
            document.getElementById('downloadDecBtn').textContent = '⬇️ Download TXT';
            
            UI.showMsg("✅ Dekripsi Sukses! Kunci ✓ Checksum ✓ Integritas ✓", false, 'dec');
        }
        
    } catch (err) { UI.showMsg("❌ " + err.message, true, 'dec'); }
});
