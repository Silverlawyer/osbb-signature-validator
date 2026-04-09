// server.js — ГІБРИДНА ВЕРСІЯ + детальні помилки мережі
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// 🔐 OAuth та share — на бойовому домені
const OAUTH_BASE = "https://paperless.com.ua";
const SHARE_BASE = "https://paperless.com.ua";

// 📤 Upload — на предрелізному (як у робочому curl)
const UPLOAD_BASE = "https://paperless.privatbank.ua";

app.use(express.raw({ type: 'application/pdf', limit: '10mb' }));

app.post('/upload-proxy', async (req, res) => {
  console.log("📥 [PROXY] Отримано PDF, розмір:", req.body.length);
  try {
    const pdfBuffer = req.body;
    
    // Отримуємо токен (на paperless.com.ua)
    const token = await getAccessToken();
    const authCookie = `sessionId="Bearer ${token}, Id ${CLIENT_ID}"`;

    const boundary = '41810675712638257'; 
    const crlf = "\r\n";
    
    const header = `--${boundary}${crlf}` +
      `Content-Disposition: form-data; name="file"; filename="test.pdf"${crlf}` +
      `Content-Type: application/octet-stream${crlf}` +
      `Content-Transfer-Encoding: binary${crlf}${crlf}`;
    
    const footer = `${crlf}--${boundary}--${crlf}`;
    const multipartBody = Buffer.concat([Buffer.from(header), pdfBuffer, Buffer.from(footer)]);

    console.log("📤 [PROXY] Відправка upload на", UPLOAD_BASE);

    const response = await fetch(`${UPLOAD_BASE}/api2/checked/upload`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'curl/7.81.0',
        'Content-Type': `multipart/form-data; boundary=${boundary}; charset=UTF-8`,
        'Content-Length': multipartBody.length.toString(),
        'Cookie': authCookie
      },
      body: multipartBody
    }).catch(err => {
      // 🚨 Детальна обробка мережевих помилок
      console.error("🔥 [NETWORK] fetch error details:", {
        name: err.name,
        message: err.message,
        code: err.code,
        errno: err.errno,
        syscall: err.syscall,
        address: err.address,
        port: err.port
      });
      throw err;
    });

    const result = await response.json();
    console.log("✅ [PROXY] Upload статус:", response.status, "Відповідь:", JSON.stringify(result).substring(0, 300));

    if (!response.ok) {
      throw new Error(`Paperless Error: ${response.status} - ${JSON.stringify(result)}`);
    }
    
    res.json({ success: true,  result });
  } catch (error) {
    console.error("❌ [PROXY] Помилка:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

async function getAccessToken() {
  // 🔐 OAuth на paperless.com.ua
  const baseUrl = `${OAUTH_BASE}/PplsService/oauth`;
  console.log("🔐 [AUTH] Запит authorize на", baseUrl);
  
  try {
    const authResp = await fetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body: new URLSearchParams({ 
        "response_type": "code", 
        "agentCheck": "true", 
        "client_id": CLIENT_ID 
      })
    }).catch(err => {
      console.error("🔥 [AUTH NETWORK] authorize error:", {
        name: err.name, message: err.message, code: err.code
      });
      throw err;
    });
    
    const authText = await authResp.text();
    console.log("🔐 [AUTH] Статус:", authResp.status, "Тіло:", authText.substring(0, 150));
    
    let code = null;
    try { 
      const json = JSON.parse(authText); 
      code = json.code; 
      console.log("🔑 Код з JSON");
    } catch {
      const m = authText.match(/<code>([^<]+)<\/code>/); 
      if (m) { code = m[1]; console.log("🔑 Код з HTML"); }
    }
    if (!code) throw new Error("No auth code. Response: " + authText.substring(0, 200));

    console.log("🔐 [AUTH] Генерація dynamic secret...");
    const crypto = require('crypto');
    const input = CLIENT_ID + CLIENT_SECRET + code;
    const dynamicSecret = crypto.createHash('sha512').update(input).digest('hex');

    console.log("🔐 [AUTH] Запит token...");
    const tokenResp = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body: new URLSearchParams({ 
        "grant_type": "authorization_code", 
        "client_id": CLIENT_ID, 
        "client_secret": dynamicSecret, 
        "code": code 
      })
    }).catch(err => {
      console.error("🔥 [AUTH NETWORK] token error:", {
        name: err.name, message: err.message, code: err.code
      });
      throw err;
    });
    
    const tokenText = await tokenResp.text();
    console.log("🔐 [AUTH] Token статус:", tokenResp.status);
    
    let token = null;
    try { 
      token = JSON.parse(tokenText).access_token; 
    } catch {
      const m = tokenText.match(/<access_token>([^<]+)<\/access_token>/); 
      if (m) token = m[1];
    }
    if (!token) throw new Error("No token. Response: " + tokenText.substring(0, 200));
    
    return token;
  } catch (err) {
    console.error("❌ [AUTH] Загальна помилка:", err.message);
    throw err;
  }
}

app.listen(port, () => { 
  console.log(`🚀 [PROXY] Live on port ${port}`); 
  console.log(`   OAuth/Share: ${OAUTH_BASE}`);
  console.log(`   Upload: ${UPLOAD_BASE}`);
});
