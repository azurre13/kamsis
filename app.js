// GLOBAL VARIABLES untuk download data
let encryptionData = { hexResult: null, jsonData: null };
let decryptionData = { resultBytes: null, format: null, isImage: false };

/* 
   0. CHECKSUM FUNCTION (INTEGRITY CHECK)
    */
const Checksum = {
    // Simple hash function untuk integrity check
    compute: function(bytes) {
        let hash = 5381;
        for (let i = 0; i < bytes.length; i++) {
            hash = ((hash << 5) + hash) + bytes[i];
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16); // Return as hex string
    }
};

/* 
   1. RSA (ASIMETRIK)
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
   2.  BLOCK CIPHER (MODE CBC)
    */
class BlockCipher {
    constructor(keyStr, ivBytes = null) {
        this.key = new Uint8Array(8);
        for (let i = 0; i < 8; i++) this.key[i] = keyStr.charCodeAt(i) || 0;
        if (ivBytes) {
            this.iv = ivBytes;
        } else {
            this.iv = new Uint8Array(8);
            for (let i = 0; i < 8; i++) this.iv[i] = Math.floor(Math.random() * 256);
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
        for (let i = 0; i < 8; i++) out[i] = this.sub(block[i] ^ this.key[i]);
        return this.shift(out);
    }

    decryptBlock(block) {
        let out = this.invShift(new Uint8Array(block));
        for (let i = 0; i < 8; i++) out[i] = this.invSub(out[i]) ^ this.key[i];
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
   3. LOGIKA UI & HANDLING EVENT (TANPA LIBRARY)
    */
const UI = {
    showMsg: function(msg, isError = false, context = null) {
        // Determine context (enc or dec) jika tidak specified
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
            // ERROR: Jangan hapus struktur DOM output, cukup tampilkan notif merah
            let oldSuccess = outputBox.querySelector('.success-notification');
            if (oldSuccess) oldSuccess.remove();

            let oldError = outputBox.querySelector('.error-notification');
            if (oldError) oldError.remove();

            let errDiv = document.createElement('div');
            errDiv.className = 'error-notification';
            errDiv.textContent = msg;
            outputBox.insertBefore(errDiv, outputBox.firstChild);
            outputBox.style.display = 'block';
            
            // Auto-scroll ke output box
            setTimeout(() => {
                outputBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 100);
        } else {
            // SUCCESS: Prepend notif hijau di atas textarea (struktur existing dipertahankan)
            let textarea = document.getElementById(textareaId);
            if (textarea) {
                // Prepend success message sebelum textarea
                let textareaParent = textarea.parentElement;
                let existingNotif = textareaParent.querySelector('.success-notification');
                if (existingNotif) {
                    existingNotif.remove();  // Remove old notif
                }
                let notifDiv = document.createElement('div');
                notifDiv.className = 'success-notification';
                notifDiv.textContent = msg;
                textarea.parentElement.insertBefore(notifDiv, textarea);
            }
            outputBox.style.display = 'block';
            
            // Auto-scroll ke output box
            setTimeout(() => {
                outputBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 100);
        }
    },
    download: function(data, filename) {
        let mimeType = "application/octet-stream";
        let finalData = data;
        
        if (filename.endsWith('.json')) {
            mimeType = "application/json";
            if (typeof data !== 'string') {
                finalData = JSON.stringify(data);
            }
        }
        else if (filename.endsWith('.txt')) mimeType = "text/plain";
        else if (filename.endsWith('.bmp')) mimeType = "image/bmp";
        
        let blob = new Blob([finalData], { type: mimeType });
        let url = URL.createObjectURL(blob);
        let link = document.createElement('a');
        link.href = url;
        link.download = filename;
        
        document.body.appendChild(link);
        link.click();
        
        setTimeout(() => {
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }, 100);
    },
    // FIX #5: Support more hex separators (spasi, dash, colon)
    toHex: function(bytes) {
        let hexStr = "";
        for (let i = 0; i < bytes.length; i++) {
            let hex = bytes[i].toString(16);
            hexStr += (hex.length === 1 ? "0" : "") + hex;
        }
        return hexStr.toUpperCase();
    },
    fromHex: function(hexStr) {
        // Validasi dan clean hex string
        if (!hexStr || hexStr.trim().length === 0) {
            throw new Error("Hex string kosong! Paste hasil enkripsi atau upload file hex.");
        }
        
        // Remove whitespace, dash, colon
        let cleaned = hexStr.replace(/[\s\-:]/g, '').toUpperCase();
        
        // Check karakter valid
        if (!/^[0-9A-F]*$/.test(cleaned)) {
            let invalidChars = cleaned.replace(/[0-9A-F]/g, '').split('');
            let unique = [...new Set(invalidChars)];
            throw new Error(`❌ Hex berisi karakter tidak valid: ${unique.join(', ')}\n\nHex hanya boleh mengandung 0-9 dan A-F.`);
        }
        
        // Check panjang genap
        if (cleaned.length % 2 !== 0) {
            throw new Error(`❌ Panjang hex GANJIL (${cleaned.length} chars)!\n\nHex harus panjang GENAP (setiap 2 karakter = 1 byte).`);
        }
        
        // Parse ke bytes
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
    isValidText: function(bytes) {
        try {
            let text = new TextDecoder().decode(bytes);
            if (text.length === 0) return false;
            
            let printable = 0, suspicious = 0;
            for (let i = 0; i < text.length; i++) {
                let code = text.charCodeAt(i);
                // Valid: printable ASCII (32-126) + whitespace (9,10,13)
                if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
                    printable++;
                }
                // Suspicious: control chars (0-8, 11-12, 14-31) - indicator dekripsi salah
                else if (code < 32) {
                    suspicious++;
                }
            }
            
            // KETAT: Perlu > 85% printable DAN minimal ada sedikit kontrol chars (tidak boleh banyak)
            let printableRatio = printable / text.length;
            let suspiciousRatio = suspicious / text.length;
            
            // Reject jika: printable < 85% ATAU suspicious > 10%
            return printableRatio > 0.85 && suspiciousRatio < 0.1;
        } catch (e) {
            return false;
        }
    },
    // FIX #4: Validate BMP magic bytes
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
            // BMP: Offset di bytes 10-13 (little endian)
            let offset = bytes[10] | (bytes[11]<<8) | (bytes[12]<<16) | (bytes[13]<<24);
            header = bytes.slice(0, offset);
            body = bytes.slice(offset);
        } else if (format === 'png') {
            // PNG: Signature 8 bytes + IHDR chunk (25 bytes minimal) = 33 bytes
            // IHDR = 4 (length) + 4 (type 'IHDR') + 13 (data) + 4 (CRC) = 25 bytes
            let headerSize = 33;
            if (bytes.length < headerSize) {
                throw new Error("File PNG terlalu kecil atau corrupt!");
            }
            header = bytes.slice(0, headerSize);
            body = bytes.slice(headerSize);
        } else if (format === 'jpg') {
            // JPG: Parse segments sampai start of actual image data
            // SOI (D8) + APP0/APP1/... + DQT + DHT + SOF + SOS
            let pos = 2;  // Skip SOI marker (FFD8)
            let headerSize = 2;
            while (pos < bytes.length - 1) {
                if (bytes[pos] !== 0xFF) {
                    headerSize = pos;
                    break;
                }
                let marker = bytes[pos + 1];
                
                if (marker === 0xDA) {
                    // SOS (Start of Scan) - dari sini mulai actual image data
                    let sosLen = (bytes[pos + 2] << 8) | bytes[pos + 3];
                    headerSize = pos + 2 + sosLen;
                    break;
                } else if (marker === 0xD9) {
                    // EOI - end of file
                    headerSize = bytes.length;
                    break;
                } else if (marker === 0x00 || (marker >= 0xD0 && marker <= 0xD9)) {
                    // Markers tanpa length field (padding, RSTn)
                    pos += 2;
                } else {
                    // Markers dengan length field
                    let len = (bytes[pos + 2] << 8) | bytes[pos + 3];
                    pos += 2 + len;
                }
            }
            // Fallback jika loop tidak set headerSize
            if (headerSize === 2 && pos > 2) headerSize = Math.min(pos, bytes.length);
            if (headerSize < 2) headerSize = Math.min(100, bytes.length);
            header = bytes.slice(0, headerSize);
            body = bytes.slice(headerSize);
        } else if (format === 'gif') {
            // GIF: Header 6 bytes + screen descriptor 7 bytes + optional color table
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

// FIX #2: Handle large hex display
function displayHexResult(hexStr) {
    let previewDiv = document.getElementById('hexPreview');
    previewDiv.innerHTML = `✓ Total ${hexStr.length} characters (${Math.ceil(hexStr.length / 2)} bytes) - Semua hex tersimpan di Hasil_Enkripsi.txt`;
    return hexStr;  // Tampilkan semua hex di textarea (dengan scroll)
}

// Helper: Show success output dengan result content
function showSuccessOutput(context, successMsg, htmlContent) {
    let outputBox = document.getElementById(context === 'dec' ? 'decOutput' : 'encOutput');
    let successNotif = `<div class="success-notification">${successMsg}</div>`;
    outputBox.innerHTML = successNotif + htmlContent;
    outputBox.style.display = 'block';
}

// Copy to clipboard function
function copyToClipboard(elementId) {
    let element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    alert('Disalin ke clipboard!');
}

// Download functions untuk enkripsi
function downloadEncHex() {
    if (!encryptionData.hexResult) {
        alert('⚠️ Tidak ada data hex! Lakukan enkripsi terlebih dahulu.');
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

function downloadEncJson() {
    if (!encryptionData.jsonData) {
        alert('⚠️ Tidak ada data kunci! Lakukan enkripsi terlebih dahulu.');
        return;
    }
    let blob = new Blob([encryptionData.jsonData], { type: 'application/json' });
    let url = URL.createObjectURL(blob);
    let a = document.createElement('a');
    a.href = url;
    a.download = 'Kunci_Akses.json';
    a.click();
    URL.revokeObjectURL(url);
}

// Download function untuk dekripsi
function downloadDecResult() {
    if (!decryptionData.resultBytes) {
        alert('⚠️ Tidak ada data hasil dekripsi!');
        return;
    }
    let fileName = 'Hasil_Dekripsi';
    let mimeType = 'text/plain';
    if (decryptionData.isImage) {
        // Proper MIME types untuk images
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

// Toggle UI Input untuk 3 mode enkripsi (text + txt file + image)
document.querySelectorAll('input[name="encMode"]').forEach(r => r.addEventListener('change', e => {
    document.getElementById('encTextContainer').style.display = e.target.value === 'text' ? 'block' : 'none';
    document.getElementById('encTxtFileContainer').style.display = e.target.value === 'txt-file' ? 'block' : 'none';
    document.getElementById('encImageContainer').style.display = e.target.value === 'image' ? 'block' : 'none';
}));

// Toggle Dekripsi Input (Paste vs File)
document.querySelectorAll('input[name="decMode"]').forEach(r => r.addEventListener('change', e => {
    document.getElementById('decPasteContainer').style.display = e.target.value === 'paste' ? 'block' : 'none';
    document.getElementById('decFileContainer').style.display = e.target.value === 'file' ? 'block' : 'none';
}));

// Show file info for txt file
document.getElementById('encTxtFileInput').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let info = `✓ File: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
        document.getElementById('encTxtFileInfo').innerHTML = info;
        document.getElementById('encTxtFileInfo').style.display = 'block';
    }
});

// Show file info for image file
document.getElementById('encImageInput').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let imageFormat = UI.getImageFormat(file.name);
        if (!imageFormat) {
            alert('Format gambar tidak didukung! Gunakan PNG, JPG, BMP, atau GIF.');
            e.target.value = '';
            return;
        }
        let info = `✓ File: ${file.name} (${(file.size / 1024).toFixed(2)} KB) - Format: ${imageFormat.toUpperCase()}`;
        document.getElementById('encImageInfo').innerHTML = info;
        document.getElementById('encImageInfo').style.display = 'block';
    }
});

// --- EKSEKUSI ENKRIPSI ---
document.getElementById('btnEncrypt').addEventListener('click', async () => {
    try {
        // CLEAR STATE LAMA sebelum mulai enkripsi (dengan null-check)
        encryptionData = { hexResult: null, jsonData: null };
        let encOutput = document.getElementById('encOutput');
        let encResultText = document.getElementById('encResultText');
        
        if (encOutput) encOutput.style.display = 'none';
        if (encResultText) encResultText.value = '';
        if (encOutput) {
            encOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        }
        
        // CLEAR ERROR MESSAGE dari attempt sebelumnya
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let mode = document.querySelector('input[name="encMode"]:checked').value;
        let keyStr = document.getElementById('encKeyInput').value;
        if (keyStr.length !== 8) throw new Error("Kunci Simetrik wajib 8 karakter!");

        let cipher = new BlockCipher(keyStr);
        let keysRSA = RSA.generateKeys();
        let encKeyRSA = RSA.encrypt(new TextEncoder().encode(keyStr), keysRSA.pub);

        let accessKeyFile = JSON.stringify({
            encryptedKey: encKeyRSA,
            privateKey: { d: keysRSA.priv.d.toString(), n: keysRSA.priv.n.toString() },
            iv: Array.from(cipher.iv)
        });

        if (mode === 'text') {
            let txt = document.getElementById('encTextInput').value;
            if (!txt) throw new Error("Pesan tidak boleh kosong!");
            
            let plainBytes = new TextEncoder().encode(txt);
            let plainChecksum = Checksum.compute(plainBytes);  // HITUNG CHECKSUM PLAINTEXT
            let encBytes = cipher.process(plainBytes, true);
            let hexResult = UI.toHex(encBytes);
            
            // UPDATE JSON dengan checksum
            let accessKeyFile = JSON.stringify({
                encryptedKey: encKeyRSA,
                privateKey: { d: keysRSA.priv.d.toString(), n: keysRSA.priv.n.toString() },
                iv: Array.from(cipher.iv),
                checksum: plainChecksum  // ← ADD CHECKSUM
            });
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = displayHexResult(hexResult);
            
            // STORE DATA untuk download manual
            encryptionData.hexResult = hexResult;
            encryptionData.jsonData = accessKeyFile;
            
            UI.showMsg("✅ Enkripsi Text Sukses! Gunakan tombol di bawah untuk download hasil.", false, 'enc');

        } else if (mode === 'txt-file') {
            // MODE 2: Upload File TXT
            let file = document.getElementById('encTxtFileInput').files[0];
            if (!file) throw new Error("Pilih file TXT terlebih dahulu!");

            let buffer = await file.arrayBuffer();
            let plainBytes = new Uint8Array(buffer);
            
            // Validate TXT content
            let text = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
            if (!text || text.length === 0) throw new Error("File TXT kosong!");
            
            let plainChecksum = Checksum.compute(plainBytes);
            let encBytes = cipher.process(plainBytes, true);
            let hexResult = UI.toHex(encBytes);
            
            // UPDATE JSON dengan checksum
            let accessKeyFile = JSON.stringify({
                encryptedKey: encKeyRSA,
                privateKey: { d: keysRSA.priv.d.toString(), n: keysRSA.priv.n.toString() },
                iv: Array.from(cipher.iv),
                checksum: plainChecksum,
                imageFormat: 'txt',
                isImage: false
            });
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = displayHexResult(hexResult);
            
            // STORE DATA untuk download manual
            encryptionData.hexResult = hexResult;
            encryptionData.jsonData = accessKeyFile;
            
            // Clear file input after encryption
            document.getElementById('encTxtFileInput').value = '';
            document.getElementById('encTxtFileInfo').style.display = 'none';
            
            UI.showMsg("✅ Enkripsi File TXT Sukses! Gunakan tombol di bawah untuk download hasil.", false, 'enc');

        } else if (mode === 'image') {
            // MODE 3: Upload Gambar
            let file = document.getElementById('encImageInput').files[0];
            if (!file) throw new Error("Pilih file gambar terlebih dahulu!");

            let imageFormat = UI.getImageFormat(file.name);
            if (!imageFormat) throw new Error("Format gambar tidak didukung! Gunakan PNG, JPG, BMP, atau GIF.");

            let buffer = await file.arrayBuffer();
            let imageBytes = new Uint8Array(buffer);
            
            // Validasi magic bytes image
            UI.validateImageFile(imageBytes, imageFormat);
            
            // Extract header dan body (header tidak di-encrypt, hanya body)
            let { header, body } = UI.extractImageHeader(imageBytes, imageFormat);
            
            // Encrypt HANYA body (image data)
            let bodyChecksum = Checksum.compute(body);
            let encBodyBytes = cipher.process(body, true);
            let hexResult = UI.toHex(encBodyBytes);
            
            // Header disimpan as base64 (safe untuk JSON)
            let headerBase64 = btoa(String.fromCharCode(...header));
            
            // UPDATE JSON dengan header + checksum body
            let accessKeyFile = JSON.stringify({
                encryptedKey: encKeyRSA,
                privateKey: { d: keysRSA.priv.d.toString(), n: keysRSA.priv.n.toString() },
                iv: Array.from(cipher.iv),
                checksum: bodyChecksum,  // Checksum hanya untuk body
                imageFormat: imageFormat,
                isImage: true,
                imageHeader: headerBase64,  // Header untuk rekonstruksi
                headerSize: header.length
            });
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = displayHexResult(hexResult);
            
            // STORE DATA untuk download manual
            encryptionData.hexResult = hexResult;
            encryptionData.jsonData = accessKeyFile;
            
            // Clear file input after encryption
            document.getElementById('encImageInput').value = '';
            document.getElementById('encImageInfo').style.display = 'none';
            
            UI.showMsg(`✅ Enkripsi Gambar (${imageFormat.toUpperCase()}) Sukses! Gunakan tombol di bawah untuk download hasil.`, false, 'enc');

        }
    } catch (err) { UI.showMsg(err.message, true, 'enc'); }
});

// --- EKSEKUSI DEKRIPSI ---
document.getElementById('btnDecrypt').addEventListener('click', async () => {
    try {
        // CLEAR STATE LAMA sebelum mulai dekripsi (dengan null-check)
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
        
        // CLEAR ERROR MESSAGE dari attempt sebelumnya
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let fileAccessKey = document.getElementById('decAccessKeyFile').files[0];

        if (!fileAccessKey) throw new Error("Harap upload file Kunci_Akses.json!");

        let accessData = JSON.parse(await fileAccessKey.text());
        
        // Validasi structure JSON
        if (!accessData.encryptedKey || !accessData.privateKey || accessData.iv === undefined) {
            throw new Error("File Kunci_Akses.json corrupt atau format tidak sesuai!");
        }
        
        let privKey = { d: BigInt(accessData.privateKey.d), n: BigInt(accessData.privateKey.n) };
        
        // VALIDASI KUNCI SIMETRIK USER
        let userKeyInput = document.getElementById('decKeyInput').value;
        if (userKeyInput.length !== 8) {
            throw new Error("❌ Kunci Simetrik wajib 8 karakter! Input yang benar untuk melanjutkan dekripsi.");
        }
        
        // DEKRIPSI KUNCI DARI RSA
        let decKeyBytes = RSA.decrypt(accessData.encryptedKey, privKey);
        let originalKeyStr = new TextDecoder().decode(decKeyBytes);
        
        // VERIFY - KUNCI USER HARUS COCOK DENGAN KUNCI ORIGINAL
        if (userKeyInput !== originalKeyStr) {
            throw new Error("❌ KUNCI SIMETRIK SALAH!\n\nKunci yang Anda input tidak cocok dengan kunci saat enkripsi.\nMeskipun cuma 1 karakter berbeda, dekripsi akan GAGAL.\n\nPastikan kunci tepat sama!");
        }
        
        let ivBytes = new Uint8Array(accessData.iv || [10, 20, 30, 40, 50, 60, 70, 80]);
        let cipher = new BlockCipher(userKeyInput, ivBytes);  // Gunakan kunci yang sudah verified
        let imageFormat = accessData.imageFormat || (accessData.isBmp ? 'bmp' : 'txt');  // Backward compatibility

        // GET HEX INPUT - BISA DARI PASTE ATAU UPLOAD FILE
        let hexInput = '';
        let decMode = document.querySelector('input[name="decMode"]:checked').value;
        
        if (decMode === 'paste') {
            hexInput = document.getElementById('decTextInput').value;
            if (!hexInput) throw new Error("Teks sandi kosong!");
        } else {
            let hexFile = document.getElementById('decHexFile').files[0];
            if (!hexFile) throw new Error("Harap upload file Hex (Hasil_Enkripsi.txt)!");
            hexInput = await hexFile.text();
            if (!hexInput) throw new Error("File hex kosong!");
        }
        
        // Validasi checksum harus ada di file kunci
        if (!accessData.checksum) {
            throw new Error("❌ File Kunci_Akses.json tidak punya checksum! Mungkin dibuat dari versi lama. Encrypt ulang dengan versi terbaru!");
        }
        
        // Validasi hex dulu (terpisah)
        let encryptedBytes = UI.fromHex(hexInput);  // Ini akan throw error detail jika format salah
        
        try {
            // Decrypt semuanya (text only)
            let decBody = cipher.process(encryptedBytes, false);
            
            // VERIFY CHECKSUM - INI YANG KRUSIAL!
            let decryptedChecksum = Checksum.compute(decBody);
            
            if (decryptedChecksum !== accessData.checksum) {
                // ❌ CHECKSUM TIDAK COCOK = LANGSUNG ERROR! (tanpa output)
                throw new Error("❌ GAGAL: Integritas data rusak!\n\nChecksum tidak cocok. Penyebab:\n1. 🔑 Kunci_Akses.json SALAH atau dari file berbeda\n2. 📝 Hex text salah atau berubah (bahkan 1 bit pun akan gagal)\n3. 🗝️ Kunci simetrik tidak sesuai\n\n⚠️ Data tidak valid! Output TIDAK ditampilkan untuk keamanan.");
            }
            
            document.getElementById('decOutput').style.display = 'block';
            
            // Handle image vs text
            if (accessData.isImage && accessData.imageHeader) {
                // IMAGE RECONSTRUCTION
                // Decode header dari base64
                let headerBase64 = accessData.imageHeader;
                let headerStr = atob(headerBase64);
                let header = new Uint8Array(headerStr.length);
                for (let i = 0; i < headerStr.length; i++) {
                    header[i] = headerStr.charCodeAt(i);
                }
                
                // Reconstruct gambar: header + decrypted body
                let reconstructedImage = new Uint8Array(header.length + decBody.length);
                reconstructedImage.set(header, 0);
                reconstructedImage.set(decBody, header.length);
                
                // Validasi magic bytes setelah reconstruct
                UI.validateImageFile(reconstructedImage, accessData.imageFormat);
                
                // STORE DATA untuk download image
                decryptionData.format = accessData.imageFormat;
                decryptionData.isImage = true;
                decryptionData.resultBytes = reconstructedImage;
                
                // Tampilkan preview sukses
                let previewText = `[Gambar ${accessData.imageFormat.toUpperCase()} - ${reconstructedImage.length} bytes]`;
                document.getElementById('decResultText').value = previewText;
                // SHOW download button untuk image
                document.getElementById('downloadDecBtn').style.display = 'block';
                document.getElementById('downloadDecBtn').textContent = `⬇️ Download ${accessData.imageFormat.toUpperCase()}`;
                
                UI.showMsg(`✅ Dekripsi Gambar (${accessData.imageFormat.toUpperCase()}) Sukses! Kunci ✓ + Checksum ✓ + Integritas ✓ + Magic Bytes ✓`, false, 'dec');
                
            } else {
                // TEXT FILE DECRYPTION
                // STORE DATA untuk download txt file hasil dekripsi
                decryptionData.format = 'txt';
                decryptionData.isImage = false;
                decryptionData.resultBytes = decBody;
                
                // Tampilkan text hasil dekripsi
                document.getElementById('decResultText').value = new TextDecoder().decode(decBody);
                // SHOW download button untuk txt file
                document.getElementById('downloadDecBtn').style.display = 'block';
                document.getElementById('downloadDecBtn').textContent = '⬇️ Download TXT';
                
                UI.showMsg("✅ Dekripsi Sukses! Kunci ✓ + Checksum ✓ + Integritas ✓", false, 'dec');
            }
        } catch (decErr) {
            throw decErr;  // Pass through semua error (format, checksum, etc)
        }

    } catch (err) { UI.showMsg("❌ " + err.message, true, 'dec'); }
});
