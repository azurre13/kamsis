// GLOBAL VARIABLES
let encryptionData = { packResult: null };
let decryptionData = { resultBytes: null, format: null, isImage: false };

/* =====================================================
   CUSTOM BASE64 ENCODER/DECODER (FROM SCRATCH - NO LIBRARY)
   ===================================================== */
const Base64Custom = {
    alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    
    encode: function(bytes) {
        let result = '';
        
        // Process setiap 3 bytes jadi 4 Base64 chars
        for (let i = 0; i < bytes.length; i += 3) {
            let b1 = bytes[i];
            let b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
            let b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;
            
            let has2 = i + 1 < bytes.length;
            let has3 = i + 2 < bytes.length;
            
            // Extract 6-bit chunks
            let c1 = (b1 >> 2) & 0x3F;
            let c2 = ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F);
            let c3 = ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03);
            let c4 = b3 & 0x3F;
            
            // Encode to Base64
            result += this.alphabet[c1];
            result += this.alphabet[c2];
            result += has2 ? this.alphabet[c3] : '=';
            result += has3 ? this.alphabet[c4] : '=';
        }
        
        return result;
    },
    
    decode: function(str) {
        let bytes = [];
        
        // Validasi length harus multiple of 4
        if (str.length % 4 !== 0) {
            throw new Error("❌ Base64 decode gagal - length tidak valid (harus multiple of 4)!");
        }
        
        // Process 4 characters at a time
        for (let i = 0; i < str.length; i += 4) {
            let c1 = this.alphabet.indexOf(str[i]);
            let c2 = this.alphabet.indexOf(str[i + 1]);
            let c3 = str[i + 2] === '=' ? 0 : this.alphabet.indexOf(str[i + 2]);
            let c4 = str[i + 3] === '=' ? 0 : this.alphabet.indexOf(str[i + 3]);
            
            if (c1 === -1 || c2 === -1 || (str[i + 2] !== '=' && c3 === -1) || (str[i + 3] !== '=' && c4 === -1)) {
                throw new Error("❌ Base64 decode gagal - karakter tidak valid!");
            }
            
            // Validasi padding
            let isLastChunk = (i + 4 >= str.length);
            
            if (!isLastChunk) {
                // Bukan chunk terakhir - TIDAK BOLEH ADA PADDING
                if (str[i + 2] === '=' || str[i + 3] === '=') {
                    throw new Error("❌ Base64 decode gagal - padding hanya boleh di akhir!");
                }
            } else {
                // Chunk terakhir - cek pattern yang INVALID
                // Valid: XXXX, XXX=, XX==
                // Invalid: ??=X (padding di index 2 tapi tidak di index 3)
                if (str[i + 2] === '=' && str[i + 3] !== '=') {
                    throw new Error("❌ Base64 decode gagal - padding pattern salah!");
                }
            }
            
            // Reconstruct bytes
            let b1 = (c1 << 2) | (c2 >> 4);
            let b2 = ((c2 & 0x0F) << 4) | (c3 >> 2);
            let b3 = ((c3 & 0x03) << 6) | c4;
            
            bytes.push(b1);
            if (str[i + 2] !== '=') bytes.push(b2);
            if (str[i + 3] !== '=') bytes.push(b3);
        }
        
        return new Uint8Array(bytes);
    }
};

/* =====================================================
   0. CHECKSUM FUNCTION (INTEGRITY CHECK)
   ===================================================== */
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

/* =====================================================
   1. RSA (ASYMMETRIC)
   ===================================================== */
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

/* =====================================================
   2. BLOCK CIPHER (MODE CBC)
   ===================================================== */
class BlockCipher {
    constructor(keyStr, ivBytes = null) {
        this.key = new Uint8Array(8);
        for (let i = 0; i < 8; i++) this.key[i] = keyStr.charCodeAt(i);
        if (ivBytes) {
            this.iv = ivBytes;
        } else {
            this.iv = new Uint8Array(8);
            for (let i = 0; i < 8; i++) this.iv[i] = (i + 1) * 10 + Math.floor(Math.random() * 20);
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

/* =====================================================
   3. UI HELPERS & CONVERSIONS
   ===================================================== */
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
            throw new Error("Hex string kosong!");
        }
        
        let cleaned = hexStr.replace(/[\s\-:]/g, '').toUpperCase();
        
        if (!/^[0-9A-F]*$/.test(cleaned)) {
            let invalidChars = cleaned.replace(/[0-9A-F]/g, '').split('');
            let unique = [...new Set(invalidChars)];
            throw new Error(`❌ Hex berisi karakter tidak valid: ${unique.join(', ')}`);
        }
        
        if (cleaned.length % 2 !== 0) {
            throw new Error(`❌ Panjang hex GANJIL (${cleaned.length} chars)!`);
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

    getFileFormat: function(filename) {
        let ext = filename.toLowerCase();
        if (ext.endsWith('.txt')) return 'txt';
        return null;
    },
    
    validateImageFile: function(buffer, format) {
        let view = new Uint8Array(buffer);
        if (format === 'bmp') {
            if (view[0] !== 0x42 || view[1] !== 0x4D) {
                throw new Error("File BMP tidak valid!");
            }
        } else if (format === 'png') {
            if (!(view[0] === 0x89 && view[1] === 0x50 && view[2] === 0x4E && view[3] === 0x47)) {
                throw new Error("File PNG tidak valid!");
            }
        } else if (format === 'jpg') {
            if (!(view[0] === 0xFF && view[1] === 0xD8)) {
                throw new Error("File JPG tidak valid!");
            }
        } else if (format === 'gif') {
            if (!(view[0] === 0x47 && view[1] === 0x49 && view[2] === 0x46)) {
                throw new Error("File GIF tidak valid!");
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
                throw new Error("File PNG terlalu kecil!");
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
                throw new Error("File GIF terlalu kecil!");
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

function copyToClipboard(elementId) {
    let element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    UI.showMsg('✓ Copied to clipboard!', false);
}

function downloadEncResult() {
    if (!encryptionData.packResult) {
        alert('⚠️ Tidak ada data!');
        return;
    }
    let blob = new Blob([encryptionData.packResult], { type: 'text/plain' });
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

/* ========================================
   TAB NAVIGATION & MODE SWITCHING
   ======================================== */

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        let tabName = btn.getAttribute('data-tab');
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update tab content
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        document.getElementById(tabName + 'Section').classList.add('active');
    });
});

// Encryption Mode Selection
document.querySelectorAll('#encryptSection .seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        let mode = btn.getAttribute('data-mode');
        
        // Update button state
        document.querySelectorAll('#encryptSection .seg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Toggle input sections
        document.getElementById('encTextMode').style.display = mode === 'text' ? 'block' : 'none';
        document.getElementById('encTxtFileMode').style.display = mode === 'txt-file' ? 'block' : 'none';
        document.getElementById('encImageMode').style.display = mode === 'image' ? 'block' : 'none';
    });
});

// Decryption Mode Selection
document.querySelectorAll('#decryptSection .seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        let mode = btn.getAttribute('data-dec-mode');
        
        // Update button state
        document.querySelectorAll('#decryptSection .seg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Toggle input sections
        document.getElementById('decPasteMode').style.display = mode === 'paste' ? 'block' : 'none';
        document.getElementById('decFileMode').style.display = mode === 'file' ? 'block' : 'none';
    });
});

/* ========================================
   BYTE COUNTERS FOR TEXTAREA/INPUT
   ======================================== */

document.getElementById('encTextInput').addEventListener('input', e => {
    let bytes = new TextEncoder().encode(e.target.value).length;
    document.getElementById('encTextByteCount').textContent = bytes;
});

document.getElementById('encKeyInput').addEventListener('input', e => {
    document.getElementById('encKeyCount').textContent = e.target.value.length;
});

document.getElementById('decTextInput').addEventListener('input', e => {
    let bytes = new TextEncoder().encode(e.target.value).length;
    document.getElementById('decTextByteCount').textContent = bytes;
});

document.getElementById('decKeyInput').addEventListener('input', e => {
    document.getElementById('decKeyCount').textContent = e.target.value.length;
});

/* ========================================
   KEY VISIBILITY TOGGLE (EYE ICON)
   ======================================== */

// Encryption Key Toggle
document.getElementById('encEyeToggle').addEventListener('click', e => {
    e.preventDefault();
    let input = document.getElementById('encKeyInput');
    let btn = document.getElementById('encEyeToggle');
    let eyeOpen = btn.querySelector('.eye-open');
    let eyeClosed = btn.querySelector('.eye-closed');
    
    if (input.type === 'password') {
        input.type = 'text';
        eyeOpen.style.display = 'none';
        eyeClosed.style.display = 'block';
    } else {
        input.type = 'password';
        eyeOpen.style.display = 'block';
        eyeClosed.style.display = 'none';
    }
});

// Decryption Key Toggle
document.getElementById('decEyeToggle').addEventListener('click', e => {
    e.preventDefault();
    let input = document.getElementById('decKeyInput');
    let btn = document.getElementById('decEyeToggle');
    let eyeOpen = btn.querySelector('.eye-open');
    let eyeClosed = btn.querySelector('.eye-closed');
    
    if (input.type === 'password') {
        input.type = 'text';
        eyeOpen.style.display = 'none';
        eyeClosed.style.display = 'block';
    } else {
        input.type = 'password';
        eyeOpen.style.display = 'block';
        eyeClosed.style.display = 'none';
    }
});

// Auto-hide key when user clicks outside or blurs away
function setupAutoHideKey(inputId, btnId) {
    let input = document.getElementById(inputId);
    let btn = document.getElementById(btnId);
    
    if (!input || !btn) return;
    
    input.addEventListener('blur', () => {
        // Reset to hidden (password) mode on blur
        if (input.type === 'text') {
            input.type = 'password';
            let eyeOpen = btn.querySelector('.eye-open');
            let eyeClosed = btn.querySelector('.eye-closed');
            eyeOpen.style.display = 'block';
            eyeClosed.style.display = 'none';
        }
    });
}

// Setup auto-hide for both encryption and decryption key inputs
setupAutoHideKey('encKeyInput', 'encEyeToggle');
setupAutoHideKey('decKeyInput', 'decEyeToggle');

/* ========================================
   DRAG & DROP SUPPORT
   ======================================== */

function setupDragDrop(dragAreaId, inputId, fileInfoId) {
    let dragArea = document.getElementById(dragAreaId);
    let fileInput = document.getElementById(inputId);
    let fileInfo = document.getElementById(fileInfoId);

    if (!dragArea) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dragArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dragArea.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dragArea.addEventListener(eventName, unhighlight, false);
    });

    function highlight(e) {
        dragArea.classList.add('drag-over');
    }

    function unhighlight(e) {
        dragArea.classList.remove('drag-over');
    }

    dragArea.addEventListener('drop', handleDrop, false);

    function handleDrop(e) {
        let dt = e.dataTransfer;
        let files = dt.files;
        fileInput.files = files;
        
        // Trigger change event
        let event = new Event('change', { bubbles: true });
        fileInput.dispatchEvent(event);
    }

    dragArea.addEventListener('click', () => fileInput.click());
}

// Setup drag & drop areas
setupDragDrop('encTxtDragArea', 'encTxtFileInput', 'encTxtFileInfo');
setupDragDrop('encImageDragArea', 'encImageInput', 'encImageInfo');
setupDragDrop('decFileDragArea', 'decHexFile', 'decFileInfo');

/* ========================================
   FILE INPUT HANDLERS
   ======================================== */

document.getElementById('encTxtFileInput').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let sizeKB = (file.size / 1024).toFixed(2);
        let info = `✓ ${file.name} · ${sizeKB} KB`;
        let clearBtn = `<button class="file-clear-btn" id="clearEncTxtFileBtn">Hapus</button>`;
        document.getElementById('encTxtFileInfo').innerHTML = `<div class="file-info-content">${info}</div>${clearBtn}`;
        document.getElementById('encTxtFileInfo').style.display = 'flex';
        
        document.getElementById('clearEncTxtFileBtn').addEventListener('click', () => {
            document.getElementById('encTxtFileInput').value = '';
            document.getElementById('encTxtFileInfo').innerHTML = '';
            document.getElementById('encTxtFileInfo').style.display = 'none';
        });
    }
});

document.getElementById('encImageInput').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let imageFormat = UI.getImageFormat(file.name);
        if (!imageFormat) {
            UI.showMsg("Format gambar tidak didukung!", true, 'enc');
            e.target.value = '';
            return;
        }
        let sizeKB = (file.size / 1024).toFixed(2);
        
        // Read file and show preview
        let reader = new FileReader();
        reader.onload = function(evt) {
            let info = `✓ ${file.name} · ${sizeKB} KB · ${imageFormat.toUpperCase()}`;
            let preview = `<div class="file-preview"><img src="${evt.target.result}" class="file-preview-image" alt="Preview"></div>`;
            let clearBtn = `<button class="file-clear-btn" id="clearEncImageBtn">Hapus</button>`;
            document.getElementById('encImageInfo').innerHTML = `<div class="file-info-content">${info}${preview}</div>${clearBtn}`;
            document.getElementById('encImageInfo').style.display = 'flex';
            
            document.getElementById('clearEncImageBtn').addEventListener('click', () => {
                document.getElementById('encImageInput').value = '';
                document.getElementById('encImageInfo').innerHTML = '';
                document.getElementById('encImageInfo').style.display = 'none';
            });
        };
        reader.readAsDataURL(file);
    }
});

document.getElementById('decHexFile').addEventListener('change', e => {
    let file = e.target.files[0];
    if (file) {
        let fileFormat = UI.getFileFormat(file.name);
        if (!fileFormat) {
            UI.showMsg("Format file tidak didukung! Hanya .txt yang diterima.", true, 'dec');
            e.target.value = '';
            return;
        }
        let sizeKB = (file.size / 1024).toFixed(2);
        let info = `✓ ${file.name} · ${sizeKB} KB`;
        let clearBtn = `<button class="file-clear-btn" id="clearDecFileBtn">Hapus</button>`;
        document.getElementById('decFileInfo').innerHTML = `<div class="file-info-content">${info}</div>${clearBtn}`;
        document.getElementById('decFileInfo').style.display = 'flex';
        
        document.getElementById('clearDecFileBtn').addEventListener('click', () => {
            document.getElementById('decHexFile').value = '';
            document.getElementById('decFileInfo').innerHTML = '';
            document.getElementById('decFileInfo').style.display = 'none';
        });
    }
});

// --- ENCRYPTION ---
document.getElementById('btnEncrypt').addEventListener('click', async () => {
    try {
        encryptionData = { packResult: null };
        let encOutput = document.getElementById('encOutput');
        let encResultText = document.getElementById('encResultText');
        
        if (encOutput) encOutput.style.display = 'none';
        if (encResultText) encResultText.value = '';
        if (encOutput) {
            encOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        }
        
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        // Get mode from active segmented button
        let modeBtn = document.querySelector('#encryptSection .seg-btn.active');
        let mode = modeBtn ? modeBtn.getAttribute('data-mode') : 'text';
        
        let keyStr = document.getElementById('encKeyInput').value;
        if (keyStr.length !== 8) throw new Error("🔑 Kunci Simetrik wajib 8 karakter!");

        let cipher = new BlockCipher(keyStr);
        let keysRSA = RSA.generateKeys();
        
        // HYBRID ENCRYPTION: RSA encrypt key + CBC encrypt data
        // Convert key to bytes dan RSA encrypt
        let keyBytes = new TextEncoder().encode(keyStr);
        let encryptedKeyArray = RSA.encrypt(keyBytes, keysRSA.pub);
        let encryptedKeyHex = encryptedKeyArray.map(n => {
            let hex = BigInt(n).toString(16).toUpperCase();  // Standardize ke UPPERCASE
            return hex.length === 1 ? '0' + hex : hex;
        }).join('-');
        
        // Siapkan data untuk packing
        let ivHex = UI.toHex(cipher.iv);
        let rsaNStr = keysRSA.priv.n.toString();
        let isImage = 'false';
        let imageFormat = 'txt';
        let imageHeaderHex = '';
        let ciphertextHex = '';

        if (mode === 'text') {
            let txt = document.getElementById('encTextInput').value;
            if (!txt) throw new Error("📝 Pesan tidak boleh kosong!");
            
            let plainBytes = new TextEncoder().encode(txt);
            let plainChecksum = Checksum.compute(plainBytes);
            let encBytes = cipher.process(plainBytes, true);
            ciphertextHex = UI.toHex(encBytes);
            
            let headerLen = '0';
            let safeHeaderHex = 'NA';
            let packString = `${ivHex}|${plainChecksum}|${encryptedKeyHex}|${rsaNStr}|${isImage}|${imageFormat}|${headerLen}|${safeHeaderHex}|||${ciphertextHex}`;
            let packBytes = new TextEncoder().encode(packString);
            let packB64 = Base64Custom.encode(packBytes);
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = packB64;
            document.getElementById('encOutputByteCount').textContent = packB64.length;
            encryptionData.packResult = packB64;
            
            UI.showMsg("✅ Enkripsi Text Sukses! Silakan copy atau download hasilnya.", false, 'enc');

        } else if (mode === 'txt-file') {
            let file = document.getElementById('encTxtFileInput').files[0];
            if (!file) throw new Error("📄 Pilih file TXT terlebih dahulu!");

            let buffer = await file.arrayBuffer();
            let plainBytes = new Uint8Array(buffer);
            
            let text = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
            if (!text || text.length === 0) throw new Error("📄 File TXT kosong!");
            
            let plainChecksum = Checksum.compute(plainBytes);
            let encBytes = cipher.process(plainBytes, true);
            ciphertextHex = UI.toHex(encBytes);
            
            let headerLen = '0';
            let safeHeaderHex = 'NA';
            let packString = `${ivHex}|${plainChecksum}|${encryptedKeyHex}|${rsaNStr}|${isImage}|txt|${headerLen}|${safeHeaderHex}|||${ciphertextHex}`;
            let packBytes = new TextEncoder().encode(packString);
            let packB64 = Base64Custom.encode(packBytes);
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = packB64;
            document.getElementById('encOutputByteCount').textContent = packB64.length;
            encryptionData.packResult = packB64;
            
            document.getElementById('encTxtFileInput').value = '';
            document.getElementById('encTxtFileInfo').style.display = 'none';
            
            UI.showMsg("✅ Enkripsi File TXT Sukses! Silakan copy atau download hasilnya.", false, 'enc');

        } else if (mode === 'image') {
            let file = document.getElementById('encImageInput').files[0];
            if (!file) throw new Error("🖼️ Pilih file gambar terlebih dahulu!");

            let imgFormat = UI.getImageFormat(file.name);
            if (!imgFormat) throw new Error("🖼️ Format gambar tidak didukung!");

            let buffer = await file.arrayBuffer();
            let imageBytes = new Uint8Array(buffer);
            
            UI.validateImageFile(imageBytes, imgFormat);
            
            let { header, body } = UI.extractImageHeader(imageBytes, imgFormat);
            let bodyChecksum = Checksum.compute(body);
            let encBodyBytes = cipher.process(body, true);
            ciphertextHex = UI.toHex(encBodyBytes);
            
            imageHeaderHex = UI.toHex(header);
            isImage = 'true';
            imageFormat = imgFormat;
            
            let headerLen = (header.length).toString();
            let packString = `${ivHex}|${bodyChecksum}|${encryptedKeyHex}|${rsaNStr}|${isImage}|${imageFormat}|${headerLen}|${imageHeaderHex}|||${ciphertextHex}`;
            let packBytes = new TextEncoder().encode(packString);
            let packB64 = Base64Custom.encode(packBytes);
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = packB64;
            document.getElementById('encOutputByteCount').textContent = packB64.length;
            encryptionData.packResult = packB64;
            
            document.getElementById('encImageInput').value = '';
            document.getElementById('encImageInfo').style.display = 'none';
            
            UI.showMsg(`✅ Enkripsi Gambar (${imgFormat.toUpperCase()}) Sukses! Silakan download hasilnya.`, false, 'enc');
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
        let copyDecBtn = document.getElementById('copyDecBtn');
        let decImagePreview = document.getElementById('decImagePreview');
        let decTextOutput = document.getElementById('decTextOutput');
        
        if (decOutput) decOutput.style.display = 'none';
        if (decResultText) decResultText.value = '';
        if (downloadDecBtn) downloadDecBtn.style.display = 'none';
        if (copyDecBtn) copyDecBtn.style.display = 'none';
        if (decImagePreview) decImagePreview.style.display = 'none';
        if (decTextOutput) decTextOutput.style.display = 'none';
        if (decOutput) {
            decOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        }
        
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let userKeyInput = document.getElementById('decKeyInput').value;
        if (userKeyInput.length !== 8) {
            throw new Error("🔑 Kunci Simetrik wajib 8 karakter!");
        }
        
        // Get mode from active segmented button
        let modeBtn = document.querySelector('#decryptSection .seg-btn.active');
        let decMode = modeBtn ? modeBtn.getAttribute('data-dec-mode') : 'paste';
        let packB64Input = '';
        
        if (decMode === 'paste') {
            packB64Input = document.getElementById('decTextInput').value;
            if (!packB64Input) throw new Error("📝 Teks ciphertext kosong!");
        } else {
            let hexFile = document.getElementById('decHexFile').files[0];
            if (!hexFile) throw new Error("📁 Harap upload file Hasil_Enkripsi.txt!");
            packB64Input = await hexFile.text();
            if (!packB64Input) throw new Error("📁 File kosong!");
        }
        
        // Decode Base64 (trim untuk handle trailing newline dari file)
        let packBytes = Base64Custom.decode(packB64Input.trim());
        let packString = new TextDecoder().decode(packBytes);
        
        // Parse metadata safely from the LAST separator
        let sepIndex = packString.lastIndexOf('|||');
        if (sepIndex === -1) throw new Error("❌ Format ciphertext tidak valid!");

        let metadataPart = packString.slice(0, sepIndex);
        let ciphertextHex = packString.slice(sepIndex + 3);
        let metadata = metadataPart.split('|');

        // Validasi metadata length
        if (metadata.length < 8) {
            throw new Error(`❌ Metadata tidak lengkap! Expected >= 8, got ${metadata.length}`);
        }
        
        let ivHex, checksum, encryptedKeyHex, rsaN, isImageFlag, imageFormat, headerLen, imageHeaderHex;

        // New format: IV|Checksum|RSA_encrypted_key|RSA_n|isImage|imageFormat|headerLen|imageHeader
        if (metadata.length >= 8) {
            ivHex = metadata[0];
            checksum = metadata[1];
            encryptedKeyHex = metadata[2];
            rsaN = metadata[3];
            isImageFlag = metadata[4] === 'true';
            imageFormat = metadata[5] || 'txt';
            headerLen = parseInt(metadata[6], 10) || 0;
            imageHeaderHex = metadata[7] || '';
            
            // Validasi format
            if (!ivHex || !checksum || !encryptedKeyHex || !rsaN) {
                throw new Error("❌ Metadata element kosong atau tidak valid!");
            }
        } else {
            throw new Error(`❌ Format metadata tidak sesuai! Expected >= 8 elements, got ${metadata.length}`);
        }
        
        // HYBRID DECRYPTION: RSA verify key + CBC decrypt data
        // Reconstruct RSA private key (same p, q)
        let p = 61n, q = 53n;
        let n = p * q;
        let phi = (p - 1n) * (q - 1n);
        let e = 17n;
        let d = RSA.modInverse(e, phi);
        
        // Parse encrypted key (split by - and convert from hex)
        let encryptedKeyParts = encryptedKeyHex.split('-'); // SUDAH DIPERBAIKI: Menggunakan '-'
        let encryptedKeyArray = encryptedKeyParts.map(hex => BigInt('0x' + hex).toString());
        
        // RSA decrypt the key
        let decryptedKeyArray = RSA.decrypt(encryptedKeyArray, { d: d, n: n });
        let decryptedKeyStr = new TextDecoder().decode(decryptedKeyArray);
        
        // Verify key matches user input
        if (decryptedKeyStr !== userKeyInput) {
            throw new Error("❌ Kunci salah! RSA decryption tidak sesuai.");
        }
        
        // Convert IV from hex
        let ivBytes = UI.fromHex(ivHex);
        
        // Create cipher dengan IV yang sudah stored dan verified key
        let cipher = new BlockCipher(userKeyInput, ivBytes);
        
        // Decrypt ciphertext
        let ciphertextBytes = UI.fromHex(ciphertextHex);
        let decBody = cipher.process(ciphertextBytes, false);
        
        // Verify checksum
        let decryptedChecksum = Checksum.compute(decBody);
        if (decryptedChecksum !== checksum) {
            throw new Error("❌ Integritas data rusak atau kunci salah!");
        }
        
        document.getElementById('decOutput').style.display = 'block';
        
        if (isImageFlag && headerLen > 0 && imageHeaderHex) {
            // Image reconstruction
            let headerBytes = UI.fromHex(imageHeaderHex);
            let reconstructedImage = new Uint8Array(headerBytes.length + decBody.length);
            reconstructedImage.set(headerBytes, 0);
            reconstructedImage.set(decBody, headerBytes.length);
            
            UI.validateImageFile(reconstructedImage, imageFormat);
            
            decryptionData.format = imageFormat;
            decryptionData.isImage = true;
            decryptionData.resultBytes = reconstructedImage;
            
            // Show image preview
            if (decImagePreview) {
                let previewImage = document.getElementById('previewImage');
                let blob = new Blob([reconstructedImage], { type: {
                    bmp: 'image/bmp',
                    png: 'image/png',
                    jpg: 'image/jpeg',
                    gif: 'image/gif'
                }[imageFormat] || 'application/octet-stream' });
                let dataUrl = URL.createObjectURL(blob);
                previewImage.src = dataUrl;
                decImagePreview.style.display = 'block';
            }
            
            if (decTextOutput) decTextOutput.style.display = 'none';
            if (copyDecBtn) copyDecBtn.style.display = 'none';
            if (downloadDecBtn) {
                downloadDecBtn.style.display = 'block';
                downloadDecBtn.textContent = `⬇️ Download ${imageFormat.toUpperCase()}`;
            }
            
            UI.showMsg(`✅ Dekripsi Gambar (${imageFormat.toUpperCase()}) Sukses! ✓ Kunci ✓ Checksum ✓ Magic Bytes`, false, 'dec');
        } else {
            // Text file
            decryptionData.format = 'txt';
            decryptionData.isImage = false;
            decryptionData.resultBytes = decBody;
            
            let decodedText = new TextDecoder().decode(decBody);
            if (decResultText) {
                decResultText.value = decodedText;
                document.getElementById('decOutputByteCount').textContent = decBody.length;
            }
            
            if (decTextOutput) decTextOutput.style.display = 'block';
            if (decImagePreview) decImagePreview.style.display = 'none';
            if (copyDecBtn) copyDecBtn.style.display = 'block';
            if (downloadDecBtn) {
                downloadDecBtn.style.display = 'block';
                downloadDecBtn.textContent = '⬇️ Download TXT';
            }
            
            UI.showMsg("✅ Dekripsi Sukses! ✓ Kunci ✓ Checksum ✓ Integritas", false, 'dec');
        }
        
    } catch (err) { UI.showMsg("❌ " + err.message, true, 'dec'); }
});

// Attach download button handler
document.getElementById('downloadDecBtn').addEventListener('click', downloadDecResult);