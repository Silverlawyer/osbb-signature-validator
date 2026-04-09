// server.js — Виправлений формат multipart (без зайвих заголовків)
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const API_BASE = "https://paperless.com.ua";

app.use(express.raw({ type: 'application/pdf', limit: '10mb' }));

app.post('/upload-proxy', async (req, res) => {
  console.log("📥 [PROXY] Отримано PDF, розмір:", req.body.length);
  try {
    const pdfBuffer = req.body;
    const token = await getAccessToken();
    const authCookie = `sessionId="Bearer ${token}, Id ${CLIENT_ID}"`;

    const boundary = '41810675712638257'; 
    const crlf = "\r\n";
    
    // 🎯 Виправлено: без Content-Transfer-Encoding, тип application/pdf
    const header = `--${boundary}${crlf}` +
      `Content-Disposition: form-data; name="file"; filename="test.pdf"${crlf}` +
      `Content-Type: application/pdf${crlf}` +  // 🎯 Змінено на application/pdf
      `${crlf}`;  // 🎯 Прибрано Content-Transfer-Encoding
    
    const footer = `${crlf}--${boundary}--${crlf}`;
    
    const multipartBody = Buffer.concat([
      Buffer.from(header),
      pdfBuffer,
      Buffer.from(footer)
    ]);

    console.log("📤 [PROXY] Відправка upload...");

    const response = await fetch(`${API_BASE}/api2/checked/upload`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'curl/7.81.0',
        // 🎯 Прибрано charset=UTF-8
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': multipartBody.length.toString(),
        'Cookie': authCookie
      },
      body: multipartBody
    });

    const result = await response.json();
    console.log("✅ [PROXY] Статус:", response.status, "Тіло:", JSON.stringify(result));

    // 🎯 ПЕРЕВІРЯЄМО state В ТІЛІ, а не тільки HTTP статус
    if (result.state === "err") {
      throw new Error(`Paperless app error: ${result.code} - ${result.desc}`);
    }
    
    if (!response.ok) {
      throw new Error(`HTTP Error: ${response.status}`);
    }
    
    res.json({ success: true,  result });
  } catch (error) {
    console.error("❌ [PROXY] Помилка:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

async function getAccessToken() {
  const baseUrl = `${API_BASE}/PplsService/oauth`;
  console.log("🔐 [AUTH] Запит authorize...");
  
  const authResp = await fetch(`${baseUrl}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
    body: new URLSearchParams({ "response_type": "code", "agentCheck": "true", "client_id": CLIENT_ID })
  });
  const authText = await authResp.text();
  let code = null;
  try { code = JSON.parse(authText).code; } catch {
    const m = authText.match(/<code>([^<]+)<\/code>/); if (m) code = m[1];
  }
  if (!code) throw new Error("No auth code");

  const crypto = require('crypto');
  const input = CLIENT_ID + CLIENT_SECRET + code;
  const dynamicSecret = crypto.createHash('sha512').update(input).digest('hex');

  const tokenResp = await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
    body: new URLSearchParams({ "grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": dynamicSecret, "code": code })
  });
  const tokenText = await tokenResp.text();
  let token = null;
  try { token = JSON.parse(tokenText).access_token; } catch {
    const m = tokenText.match(/<access_token>([^<]+)<\/access_token>/); if (m) token = m[1];
  }
  if (!token) throw new Error("No token");
  return token;
}

app.listen(port, () => { console.log(`🚀 [PROXY] Live, API: ${API_BASE}`); });
