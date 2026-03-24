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
        for (let i = 0; i < bytes.length; i += 3) {
            let b1 = bytes[i];
            let b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
            let b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;
            
            let has2 = i + 1 < bytes.length;
            let has3 = i + 2 < bytes.length;
            
            let c1 = (b1 >> 2) & 0x3F;
            let c2 = ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F);
            let c3 = ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03);
            let c4 = b3 & 0x3F;
            
            result += this.alphabet[c1];
            result += this.alphabet[c2];
            result += has2 ? this.alphabet[c3] : '=';
            result += has3 ? this.alphabet[c4] : '=';
        }
        return result;
    },
    
    decode: function(str) {
        let bytes = [];
        if (str.length % 4 !== 0) {
            throw new Error("❌ Base64 decode gagal - length tidak valid (harus kelipatan 4)!");
        }
        
        for (let i = 0; i < str.length; i += 4) {
            let c1 = this.alphabet.indexOf(str[i]);
            let c2 = this.alphabet.indexOf(str[i + 1]);
            let c3 = str[i + 2] === '=' ? 0 : this.alphabet.indexOf(str[i + 2]);
            let c4 = str[i + 3] === '=' ? 0 : this.alphabet.indexOf(str[i + 3]);
            
            if (c1 === -1 || c2 === -1 || (str[i + 2] !== '=' && c3 === -1) || (str[i + 3] !== '=' && c4 === -1)) {
                throw new Error("❌ Base64 decode gagal - karakter tidak valid!");
            }
            
            let b1 = (c1 << 2) | (c2 >> 4);
            let b2 = ((c2 & 0x0F) << 4) | (c3 >> 2);
            let b3 = ((c3 & 0x03) << 6) | c4;
            
            bytes.push(b1);
            if (str[i + 2] !== '=') bytes.push(b2);
            if (str[i + 3] !== '=') bytes.push(b3);
        }
        return new Uint8Array(bytes);
    },

    // FUNGSI BARU: Untuk mengacak String Metadata
    encodeStr: function(str) {
        return this.encode(new TextEncoder().encode(str));
    },
    
    // FUNGSI BARU: Untuk mengembalikan String Metadata
    decodeStr: function(b64) {
        return new TextDecoder().decode(this.decode(b64));
    }
};

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
        return Math.abs(hash).toString(36);
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

let tabScrollPositions = { encryptSection: 0, decryptSection: 0 };

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        let tabName = btn.getAttribute('data-tab');
        let newTabId = tabName + 'Section';
        
        let currentActiveTab = document.querySelector('.tab-content.active');
        if (currentActiveTab) {
            tabScrollPositions[currentActiveTab.id] = window.scrollY;
        }
        
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        document.getElementById(newTabId).classList.add('active');
        
        requestAnimationFrame(() => {
            window.scrollTo(0, tabScrollPositions[newTabId]);
        });
    });
});

document.querySelectorAll('#encryptSection .seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        let mode = btn.getAttribute('data-mode');
        document.querySelectorAll('#encryptSection .seg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('encTextMode').style.display = mode === 'text' ? 'block' : 'none';
        document.getElementById('encTxtFileMode').style.display = mode === 'txt-file' ? 'block' : 'none';
        document.getElementById('encImageMode').style.display = mode === 'image' ? 'block' : 'none';
    });
});

document.querySelectorAll('#decryptSection .seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        let mode = btn.getAttribute('data-dec-mode');
        document.querySelectorAll('#decryptSection .seg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
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
   KEY VISIBILITY TOGGLE & AUTO-HIDE
   ======================================== */

document.getElementById('encEyeToggle').addEventListener('click', e => {
    e.preventDefault();
    togglePassword('encKeyInput', 'encEyeToggle');
});

document.getElementById('decEyeToggle').addEventListener('click', e => {
    e.preventDefault();
    togglePassword('decKeyInput', 'decEyeToggle');
});

function togglePassword(inputId, btnId) {
    let input = document.getElementById(inputId);
    let btn = document.getElementById(btnId);
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
}

function setupAutoHideKey(inputId, btnId) {
    let input = document.getElementById(inputId);
    let btn = document.getElementById(btnId);
    if (!input || !btn) return;
    
    let wrapper = input.closest('.key-input-wrapper');
    input.addEventListener('blur', () => hideKeyInput(input, btn));
    document.addEventListener('click', (e) => {
        if (wrapper && !wrapper.contains(e.target) && input.type === 'text') {
            hideKeyInput(input, btn);
        }
    });
}

function hideKeyInput(input, btn) {
    if (input.type === 'text') {
        input.type = 'password';
        let eyeOpen = btn.querySelector('.eye-open');
        let eyeClosed = btn.querySelector('.eye-closed');
        if (eyeOpen && eyeClosed) {
            eyeOpen.style.display = 'block';
            eyeClosed.style.display = 'none';
        }
    }
}

setupAutoHideKey('encKeyInput', 'encEyeToggle');
setupAutoHideKey('decKeyInput', 'decEyeToggle');

/* ========================================
   DRAG & DROP SUPPORT
   ======================================== */

function setupDragDrop(dragAreaId, inputId, fileInfoId) {
    let dragArea = document.getElementById(dragAreaId);
    let fileInput = document.getElementById(inputId);
    
    if (!dragArea) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dragArea.addEventListener(eventName, e => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dragArea.addEventListener(eventName, () => dragArea.classList.add('drag-over'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dragArea.addEventListener(eventName, () => dragArea.classList.remove('drag-over'), false);
    });

    dragArea.addEventListener('drop', e => {
        fileInput.files = e.dataTransfer.files;
        fileInput.dispatchEvent(new Event('change', { bubbles: true }));
    }, false);

    dragArea.addEventListener('click', () => fileInput.click());
}

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
        if (encOutput) encOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let modeBtn = document.querySelector('#encryptSection .seg-btn.active');
        let mode = modeBtn ? modeBtn.getAttribute('data-mode') : 'text';
        
        let keyStr = document.getElementById('encKeyInput').value;
        if (keyStr.length !== 8) throw new Error("🔑 Kunci Simetrik wajib 8 karakter!");

        let cipher = new BlockCipher(keyStr);
        let keysRSA = RSA.generateKeys();
        
        // RSA encrypt key 
        let keyBytes = new TextEncoder().encode(keyStr);
        let encryptedKeyArray = RSA.encrypt(keyBytes, keysRSA.pub);
        let encryptedKeyStr = encryptedKeyArray.map(n => n.toString()).join('-');
        
        // Encode SEMUA metadata ke Base64 agar wujud aslinya hilang (Alien Gibberish)
        let ivB64 = Base64Custom.encode(cipher.iv);
        let encryptedKeyB64 = Base64Custom.encodeStr(encryptedKeyStr);
        let rsaNB64 = Base64Custom.encodeStr(keysRSA.priv.n.toString());
        
        let isImageB64 = Base64Custom.encodeStr('false');
        let imageFormatB64 = Base64Custom.encodeStr('txt');
        let headerB64 = Base64Custom.encodeStr('NA');
        let cipherB64 = '';

        if (mode === 'text') {
            let txt = document.getElementById('encTextInput').value;
            if (!txt) throw new Error("📝 Pesan tidak boleh kosong!");
            
            let plainBytes = new TextEncoder().encode(txt);
            let plainChecksum = Checksum.compute(plainBytes);
            let encBytes = cipher.process(plainBytes, true);
            
            cipherB64 = Base64Custom.encode(encBytes);
            let checksumB64 = Base64Custom.encodeStr(plainChecksum);
            let headerLenB64 = Base64Custom.encodeStr('0');
            
            // Format 100% Base64 dipisah titik
            let packResult = `${ivB64}.${checksumB64}.${encryptedKeyB64}.${rsaNB64}.${isImageB64}.${imageFormatB64}.${headerLenB64}.${headerB64}.${cipherB64}`;
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = packResult;
            document.getElementById('encOutputByteCount').textContent = packResult.length;
            encryptionData.packResult = packResult;
            
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
            
            cipherB64 = Base64Custom.encode(encBytes);
            let checksumB64 = Base64Custom.encodeStr(plainChecksum);
            let headerLenB64 = Base64Custom.encodeStr('0');
            
            let packResult = `${ivB64}.${checksumB64}.${encryptedKeyB64}.${rsaNB64}.${isImageB64}.${imageFormatB64}.${headerLenB64}.${headerB64}.${cipherB64}`;
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = packResult;
            document.getElementById('encOutputByteCount').textContent = packResult.length;
            encryptionData.packResult = packResult;
            
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
            
            cipherB64 = Base64Custom.encode(encBodyBytes);
            headerB64 = Base64Custom.encode(header);
            
            isImageB64 = Base64Custom.encodeStr('true');
            imageFormatB64 = Base64Custom.encodeStr(imgFormat);
            let checksumB64 = Base64Custom.encodeStr(bodyChecksum);
            let headerLenB64 = Base64Custom.encodeStr((header.length).toString());
            
            let packResult = `${ivB64}.${checksumB64}.${encryptedKeyB64}.${rsaNB64}.${isImageB64}.${imageFormatB64}.${headerLenB64}.${headerB64}.${cipherB64}`;
            
            document.getElementById('encOutput').style.display = 'block';
            document.getElementById('encResultText').value = packResult;
            document.getElementById('encOutputByteCount').textContent = packResult.length;
            encryptionData.packResult = packResult;
            
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
        if (decOutput) decOutput.querySelectorAll('.error-notification, .success-notification').forEach(el => el.remove());
        
        let statusBox = document.getElementById('statusBox');
        if (statusBox) statusBox.style.display = 'none';
        
        let userKeyInput = document.getElementById('decKeyInput').value;
        if (userKeyInput.length !== 8) {
            throw new Error("🔑 Kunci Simetrik wajib 8 karakter!");
        }
        
        let modeBtn = document.querySelector('#decryptSection .seg-btn.active');
        let decMode = modeBtn ? modeBtn.getAttribute('data-dec-mode') : 'paste';
        let packInput = '';
        
        if (decMode === 'paste') {
            packInput = document.getElementById('decTextInput').value;
            if (!packInput) throw new Error("📝 Teks ciphertext kosong!");
        } else {
            let fileInput = document.getElementById('decHexFile').files[0];
            if (!fileInput) throw new Error("📁 Harap upload file Hasil_Enkripsi.txt!");
            packInput = await fileInput.text();
            if (!packInput) throw new Error("📁 File kosong!");
        }
        
        // Membersihkan spasi/newline
        packInput = packInput.replace(/\s/g, '');
        let metadata = packInput.split('.');

        if (metadata.length < 9) {
            throw new Error(`❌ Format ciphertext tidak valid atau metadata kurang!`);
        }
        
        let ivB64 = metadata[0];
        
        // Dekode Metadata yang sudah di-Base64-kan kembali menjadi String
        let checksum = Base64Custom.decodeStr(metadata[1]);
        let encryptedKeyStr = Base64Custom.decodeStr(metadata[2]);
        let rsaN = Base64Custom.decodeStr(metadata[3]);
        let isImageFlag = Base64Custom.decodeStr(metadata[4]) === 'true';
        let imageFormat = Base64Custom.decodeStr(metadata[5]);
        let headerLen = parseInt(Base64Custom.decodeStr(metadata[6]), 10);
        
        let headerB64 = metadata[7];
        let cipherB64 = metadata[8];
        
        if (!ivB64 || !checksum || !encryptedKeyStr || !rsaN || !cipherB64) {
            throw new Error("❌ Metadata element kosong atau tidak valid!");
        }
        
        // HYBRID DECRYPTION
        let p = 61n, q = 53n;
        let n = p * q;
        let phi = (p - 1n) * (q - 1n);
        let e = 17n;
        let d = RSA.modInverse(e, phi);
        
        // RSA decrypt the key
        let encryptedKeyParts = encryptedKeyStr.split('-'); 
        let decryptedKeyArray = RSA.decrypt(encryptedKeyParts, { d: d, n: n });
        let decryptedKeyStr = new TextDecoder().decode(decryptedKeyArray);
        
        // Verifikasi Kunci
        if (decryptedKeyStr !== userKeyInput) {
            throw new Error("❌ Kunci salah! RSA decryption tidak sesuai.");
        }
        
        // Ekstrak IV dan inisialisasi cipher
        let ivBytes = Base64Custom.decode(ivB64);
        let cipher = new BlockCipher(userKeyInput, ivBytes);
        
        // Decrypt ciphertext
        let ciphertextBytes = Base64Custom.decode(cipherB64);
        let decBody = cipher.process(ciphertextBytes, false);
        
        // Verifikasi Checksum
        let decryptedChecksum = Checksum.compute(decBody);
        if (decryptedChecksum !== checksum) {
            throw new Error("❌ Integritas data rusak atau kunci salah!");
        }
        
        document.getElementById('decOutput').style.display = 'block';
        
        if (isImageFlag && headerLen > 0) {
            // Image reconstruction
            let headerBytes = Base64Custom.decode(headerB64);
            let reconstructedImage = new Uint8Array(headerBytes.length + decBody.length);
            reconstructedImage.set(headerBytes, 0);
            reconstructedImage.set(decBody, headerBytes.length);
            
            UI.validateImageFile(reconstructedImage, imageFormat);
            
            decryptionData.format = imageFormat;
            decryptionData.isImage = true;
            decryptionData.resultBytes = reconstructedImage;
            
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
            }
            
            UI.showMsg("✅ Dekripsi Sukses! ✓ Kunci ✓ Checksum ✓ Integritas", false, 'dec');
        }
        
    } catch (err) { UI.showMsg("❌ " + err.message, true, 'dec'); }
});

// Attach download button handler
document.getElementById('downloadDecBtn').addEventListener('click', downloadDecResult);