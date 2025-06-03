  // الدوال الأساسية
        async function encrypt() {
            const input = document.getElementById("inputText").value;
            const method = document.getElementById("method").value;
            const key = document.getElementById("cipherKey")?.value || "";
            let output = "";

            try {
                switch (method) {
                    case "base64":
                        output = btoa(unescape(encodeURIComponent(input)));
                        break;
                    case "caesar":
                        output = caesarCipher(input, 3);
                        break;
                    case "xor":
                        output = xorEncrypt(input, 7);
                        break;
                    case "rot13":
                        output = rot13(input);
                        break;
                    case "reverse":
                        output = input.split("").reverse().join("");
                        break;
                    case "hex":
                        output = input.split("").map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(" ");
                        break;
                    case "url":
                        output = encodeURIComponent(input);
                        break;
                    case "atbash":
                        output = atbashCipher(input);
                        break;
                    case "bcrypt":
                        output = await bcryptHash(input);
                        break;
                    case "sha256":
                        output = sha256Hash(input);
                        break;
                    case "rc4":
                        output = rc4Encrypt(input, key || "secretKey");
                        break;
                    case "vigenere":
                        output = vigenereCipher(input, key || "KEY", true);
                        break;
                    case "bat":
                        output = batObfuscate(input);
                        break;
                    default:
                        output = "❌ Unknown Method";
                }
            } catch (e) {
                output = "⚠️ Encryption Error: " + e.message;
            }

            document.getElementById("outputText").value = output;
        }

        async function decrypt() {
            const input = document.getElementById("inputText").value;
            const method = document.getElementById("method").value;
            const key = document.getElementById("cipherKey")?.value || "";
            let output = "";

            try {
                switch (method) {
                    case "base64":
                        output = decodeURIComponent(escape(atob(input)));
                        break;
                    case "caesar":
                        output = caesarCipher(input, -3);
                        break;
                    case "xor":
                        output = xorEncrypt(input, 7);
                        break;
                    case "rot13":
                        output = rot13(input);
                        break;
                    case "reverse":
                        output = input.split("").reverse().join("");
                        break;
                    case "hex":
                        output = input.split(" ").map(h => String.fromCharCode(parseInt(h, 16))).join("");
                        break;
                    case "url":
                        output = decodeURIComponent(input);
                        break;
                    case "atbash":
                        output = atbashCipher(input);
                        break;
                    case "rc4":
                        output = rc4Encrypt(input, key || "secretKey");
                        break;
                    case "vigenere":
                        output = vigenereCipher(input, key || "KEY", false);
                        break;
                    case "bcrypt":
                    case "sha256":
                        output = "❌ Cannot decrypt the hash";
                        break;
                    case "bat":
                        output = "❌ Cannot decrypt BAT files";
                        break;
                    default:
                        output = "❌ Unknown Method";
                }
            } catch (e) {
                output = "⚠️ Decryption Error: " + e.message;
            }

            document.getElementById("outputText").value = output;
        }

        // ===== خوارزميات التشفير الجديدة =====
        // Bcrypt Hashing
        async function bcryptHash(input) {
            // في بيئة حقيقية سيتم استخدام مكتبة bcryptjs
            return "⚠❌ Not supported in this version (requires server)";
        }

        // SHA-256 Hashing
        function sha256Hash(input) {
            const hash = CryptoJS.SHA256(input);
            return hash.toString(CryptoJS.enc.Hex);
        }

        // RC4 Encryption
        function rc4Encrypt(str, key) {
            let s = [], j = 0, output = '';
            for (let i = 0; i < 256; i++) {
                s[i] = i;
            }
            for (let i = 0; i < 256; i++) {
                j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
                [s[i], s[j]] = [s[j], s[i]];
            }
            let i = 0;
            j = 0;
            for (let k = 0; k < str.length; k++) {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                [s[i], s[j]] = [s[j], s[i]];
                const charCode = str.charCodeAt(k) ^ s[(s[i] + s[j]) % 256];
                output += String.fromCharCode(charCode);
            }
            return output;
        }

        // Vigenère Cipher
        function vigenereCipher(input, key, encrypt) {
            let output = '';
            key = key.toUpperCase();
            for (let i = 0, j = 0; i < input.length; i++) {
                const c = input[i];
                if (c.match(/[a-z]/i)) {
                    const offset = c === c.toUpperCase() ? 65 : 97;
                    const k = key[j % key.length].charCodeAt(0) - 65;
                    const code = c.charCodeAt(0) - offset;
                    const shifted = encrypt ? 
                        (code + k) % 26 : 
                        (code - k + 26) % 26;
                    output += String.fromCharCode(shifted + offset);
                    j++;
                } else {
                    output += c;
                }
            }
            return output;
        }

        // BAT Obfuscation
function batObfuscate(str) {
    const parts = [];
    const chars = str.split('');
    const unique = [...new Set(chars)];
    const charMap = {};

    // توليد أسماء متغيرات عشوائية للحروف
    unique.forEach(c => {
        const code = c.charCodeAt(0);
        const varName = `c${code}`; // يمكن جعله مشوش أكثر مثل `cx${code}a`
        charMap[c] = `!${varName}!`;
    });

    // إنشاء المتغيرات
    const defs = unique.map(c => {
        const code = c.charCodeAt(0);
        return `set "c${code}=${c}"`;
    }).join('\n');

    // تجزئة النص إلى أجزاء عشوائية
    const chunkSize = 5; // عدد الأحرف لكل جزء
    for (let i = 0; i < chars.length; i += chunkSize) {
        const chunk = chars.slice(i, i + chunkSize).map(c => charMap[c]).join('');
        parts.push(`set "part${i}=${chunk}"`);
    }

    // تجميع الأجزاء في متغير line
    const lineSet = `set "line=${parts.map((_, i) => `!part${i * chunkSize}!`).join('')}"`;

    return `@echo off
setlocal EnableDelayedExpansion

:: تعريف الحروف
${defs}

:: تجميع الأجزاء
${parts.join('\n')}
${lineSet}

:: تنفيذ
echo !line! > "%temp%\\~decoded.bat"
call "%temp%\\~decoded.bat"
del "%temp%\\~decoded.bat"
endlocal`;
}



        // ===== التحديثات الأصلية =====
        // Caesar Cipher
        function caesarCipher(str, shift) {
            return str.split('').map(char => {
                let code = char.charCodeAt(0);
                return String.fromCharCode(code + shift);
            }).join('');
        }

        // XOR Encryption
        function xorEncrypt(str, key) {
            return str.split('').map(char =>
                String.fromCharCode(char.charCodeAt(0) ^ key)
            ).join('');
        }

        // ROT13
        function rot13(str) {
            return str.replace(/[a-zA-Z]/g, function(c) {
                return String.fromCharCode(
                    c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)
                );
            });
        }

        // Atbash Cipher
        function atbashCipher(str) {
            return str.split('').map(c => {
                let code = c.charCodeAt(0);
                if (c >= 'A' && c <= 'Z') return String.fromCharCode(90 - (code - 65));
                if (c >= 'a' && c <= 'z') return String.fromCharCode(122 - (code - 97));
                return c;
            }).join('');
        }

        // ===== واجهة المستخدم والوظائف المساعدة =====
        // نسخ النتيجة
        function copyResult() {
            const output = document.getElementById("outputText");
            output.select();
            document.execCommand("copy");
            alert("✅ Result copied!");
        }

        // توليد كود الديكريبت
        function generateCode(lang) {
            const method = document.getElementById("method").value;
            const key = document.getElementById("cipherKey")?.value || "YOUR_KEY";
            let code = "";
            
            const methods = {
                "base64": "Base64",
                "caesar": "Caesar",
                "xor": "XOR",
                "rot13": "ROT13",
                "reverse": "Reverse",
                "hex": "Hexadecimal",
                "url": "URL Encoding",
                "atbash": "Atbash",
                "rc4": "RC4",
                "vigenere": "Vigenère"
            };
            
            const methodName = methods[method] || "Unknown";
            
            if (lang === "vbnet") {
                code = `' فك تشفير ${methodName} لـ VB.NET
        Public Function Decrypt${methodName}(input As String) As String
            ${getDecryptionCodeVB(method, key)}
        End Function`;
            } else {
                code = `// فك تشفير ${methodName} لـ C#
        public string Decrypt${methodName}(string input) 
        {
            ${getDecryptionCodeCS(method, key)}
        }`;
            }
            
            const codeOutput = document.getElementById("codeOutput");
            codeOutput.innerHTML = `<h3>Decryption code for ${methodName} (${lang.toUpperCase()})</h3>
                                    <pre>${code}</pre>`;
            codeOutput.style.display = "block";
        }

        function getDecryptionCodeVB(method, key) {
            switch (method) {
                case "base64":
                    return `Return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(input))`;
                case "caesar":
                    return `Return New String(input.Select(Function(c) Chr(Asc(c) - 3)).ToArray())`;
                case "xor":
                    return `Return New String(input.Select(Function(c) Chr(Asc(c) Xor 7)).ToArray())`;
                case "rc4":
                    return `' RC4 implementation needed here\n    Return input`;
                case "vigenere":
                    return `' Vigenère implementation needed here\n    Return input`;
                default:
                    return `' Not supported







\n    Return input`;
            }
        }

        function getDecryptionCodeCS(method, key) {
            switch (method) {
                case "base64":
                    return `return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(input));`;
                case "caesar":
                    return `return new string(input.Select(c => (char)(c - 3)).ToArray();`;
                case "xor":
                    return `return new string(input.Select(c => (char)(c ^ 7)).ToArray();`;
                case "rc4":
                    return `// RC4 implementation needed here\n    return input;`;
                case "vigenere":
                    return `// Vigenère implementation needed here\n    return input;`;
                default:
                    return `// Not supported







\n    return input;`;
            }
        }

        // تحليل التشفير التلقائي
        function analyzeCipher() {
            const input = document.getElementById("inputText").value;
            if (!input) {
                alert("⚠️ Please enter text for analysis");
                return;
            }
            
            const analysis = performCipherAnalysis(input);
            const analysisResult = document.getElementById("analysisResult");
            
            analysisResult.innerHTML = `
                <h3><i class="fas fa-chart-bar"></i> Encryption Analysis Results</h3>
                <div class="result-item"><strong>Possible Encryption Type:</strong> ${analysis.cipherType}</div>
                <div class="result-item"><strong>Similarity Index with English:</strong> ${analysis.englishScore.toFixed(2)}%</div>
                <div class="result-item"><strong>Character Distribution:</strong> ${analysis.charDistribution}</div>
                <div class="result-item"><strong>Length:</strong> ${input.length} حرف</div>
                <div class="result-item"><strong>Patterns:</strong> ${analysis.patterns}</div>
            `;
            
            analysisResult.style.display = "block";
        }

        function performCipherAnalysis(input) {
            // تحليل توزيع الأحرف
            const charCount = {};
            for (const char of input) {
                charCount[char] = (charCount[char] || 0) + 1;
            }
            
            // حساب مؤشر اللغة الإنجليزية
            const englishFreq = {
                'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 13.0,
                'f': 2.2, 'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15,
                'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7, 'o': 7.5,
                'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1,
                'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074
            };
            
            let score = 0;
            const totalChars = input.replace(/[^a-z]/gi, '').length || 1;
            
            for (const char in charCount) {
                if (/[a-z]/i.test(char)) {
                    const lowerChar = char.toLowerCase();
                    const freq = (charCount[char] / totalChars) * 100;
                    const englishFreqValue = englishFreq[lowerChar] || 0;
                    score += Math.abs(freq - englishFreqValue);
                }
            }
            
            score = 100 - (score / Object.keys(englishFreq).length);
            
            // تحديد نوع التشفير
            let cipherType = "Unknown";
            const patterns = [];
            
            if (/^[A-Za-z0-9+/=]+$/.test(input) && input.length % 4 === 0) {
                cipherType = "Base64";
                patterns.push("Base64 Format");
            }
            
            if (input.includes('%') && input.includes('=')) {
                cipherType = "URL Encoding";
                patterns.push("URL Encoding");
            }
            
            if (input.split(' ').every(part => /^[0-9a-fA-F]{2}$/.test(part))) {
                cipherType = "Hexadecimal";
                patterns.push("Hexadecimal Encoding");
            }
            
            if (input === input.split('').reverse().join('')) {
                cipherType = "Text Reversal";
                patterns.push("Reversed Text");
            }
            
            // النتائج
            return {
                cipherType: cipherType,
                englishScore: score,
                charDistribution: Object.entries(charCount)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5)
                    .map(([char, count]) => `${char}: ${count}`)
                    .join(', '),
                patterns: patterns.join('، ') || "لNo clear patterns found"
            };
        }

        // مسح الكل
        function clearAll() {
            document.getElementById("inputText").value = "";
            document.getElementById("outputText").value = "";
            document.getElementById("codeOutput").style.display = "none";
            document.getElementById("analysisResult").style.display = "none";
        }

        // تبديل خيارات المفتاح
        document.getElementById("method").addEventListener("change", function() {
            const keyContainer = document.getElementById("keyContainer");
            const keyMethods = ["rc4", "vigenere"];
            
            if (keyMethods.includes(this.value)) {
                keyContainer.style.display = "block";
            } else {
                keyContainer.style.display = "none";
            }
        });

        // تهيئة الصفحة
        window.onload = function() {
            document.getElementById("keyContainer").style.display = "none";
        };