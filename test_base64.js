// TEST SCRIPT untuk Custom Base64 Encoder/Decoder

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
        
        // Count padding to determine output bytes
        let paddingCount = 0;
        if (str.endsWith('==')) paddingCount = 2;
        else if (str.endsWith('=')) paddingCount = 1;
        
        // Process 4 characters at a time
        for (let i = 0; i < str.length; i += 4) {
            let c1 = this.alphabet.indexOf(str[i]);
            let c2 = this.alphabet.indexOf(str[i + 1]);
            let c3 = str[i + 2] === '=' ? 0 : this.alphabet.indexOf(str[i + 2]);
            let c4 = str[i + 3] === '=' ? 0 : this.alphabet.indexOf(str[i + 3]);
            
            if (c1 === -1 || c2 === -1 || (str[i + 2] !== '=' && c3 === -1) || (str[i + 3] !== '=' && c4 === -1)) {
                throw new Error("Base64 decode gagal - karakter tidak valid!");
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

// TEST 1: Simple text encoding
console.log("=== TEST 1: Simple Text ===");
let text1 = "Hello";
let bytes1 = new Uint8Array(new TextEncoder().encode(text1));
let encoded1 = Base64Custom.encode(bytes1);
console.log("Original:", text1);
console.log("Encoded:", encoded1);
console.log("Expected: SGVsbG8=");
console.log("Match:", encoded1 === "SGVsbG8=" ? "✓ PASS" : "✗ FAIL");

// TEST 2: Empty string
console.log("\n=== TEST 2: Empty String ===");
let bytes2 = new Uint8Array([]);
let encoded2 = Base64Custom.encode(bytes2);
console.log("Encoded:", encoded2);
console.log("Expected: (empty)");
console.log("Match:", encoded2 === "" ? "✓ PASS" : "✗ FAIL");

// TEST 3: Single byte
console.log("\n=== TEST 3: Single Byte ===");
let bytes3 = new Uint8Array([65]); // 'A' = 65
let encoded3 = Base64Custom.encode(bytes3);
console.log("Encoded:", encoded3);
console.log("Expected: QQ==");
console.log("Match:", encoded3 === "QQ==" ? "✓ PASS" : "✗ FAIL");

// TEST 4: Binary data with all byte values (sample)
console.log("\n=== TEST 4: Binary Data ===");
let bytes4 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
let encoded4 = Base64Custom.encode(bytes4);
console.log("Encoded:", encoded4);
let decoded4 = Base64Custom.decode(encoded4);
console.log("Decoded matches original:", 
    decoded4.length === bytes4.length && 
    Array.from(decoded4).every((v, i) => v === bytes4[i]) ? "✓ PASS" : "✗ FAIL");

// TEST 5: Roundtrip test (encode -> decode -> encode should match)
console.log("\n=== TEST 5: Roundtrip Test ===");
let text5 = "The quick brown fox jumps over the lazy dog";
let bytes5 = new Uint8Array(new TextEncoder().encode(text5));
let encoded5a = Base64Custom.encode(bytes5);
let decoded5 = Base64Custom.decode(encoded5a);
let encoded5b = Base64Custom.encode(decoded5);
console.log("Original encode:", encoded5a);
console.log("After roundtrip:", encoded5b);
console.log("Match:", encoded5a === encoded5b ? "✓ PASS" : "✗ FAIL");

// TEST 6: Data packing format with new structure
console.log("\n=== TEST 6: Data Packing Format (New 8-field) ===");
let packString = "1a2b3c|abcd123|5|7|false|txt|0|||||9e8d7c6b";
let packBytes = new TextEncoder().encode(packString);
let packEncoded = Base64Custom.encode(packBytes);
console.log("Pack string:", packString);
console.log("Encoded pack:", packEncoded);
let packDecoded = Base64Custom.decode(packEncoded);
let packString2 = new TextDecoder().decode(packDecoded);
console.log("Decoded back:", packString2);
console.log("Match:", packString === packString2 ? "✓ PASS" : "✗ FAIL");

// TEST 7: Image packing format
console.log("\n=== TEST 7: Image Packing Format ===");
let packString3 = "1a2b3c|abcd123|5|7|true|png|25|89504e470d0a1a0a|||9e8d7c6b";
let packBytes3 = new TextEncoder().encode(packString3);
let packEncoded3 = Base64Custom.encode(packBytes3);
console.log("Pack string:", packString3);
console.log("Encoded pack:", packEncoded3);
let packDecoded3 = Base64Custom.decode(packEncoded3);
let packString4 = new TextDecoder().decode(packDecoded3);
console.log("Decoded back:", packString4);
console.log("Match:", packString3 === packString4 ? "✓ PASS" : "✗ FAIL");

console.log("\n=== ALL TESTS COMPLETED ===");

