// server.js — Виправлена версія (розпізнає HTML та JSON відповіді банку)
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

const PAPERLESS_API = "https://paperless.com.ua";
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

app.use(express.raw({ type: 'application/pdf', limit: '10mb' }));

app.post('/upload-proxy', async (req, res) => {
  console.log("📥 [PROXY] Отримано запит на завантаження PDF");
  try {
    const pdfBuffer = req.body;
    const token = await getAccessToken();
    const authCookie = `sessionId="Bearer ${token}, Id ${CLIENT_ID}"`;

    const boundary = '41810675712638257'; 
    const crlf = "\r\n";
    const header = `--${boundary}${crlf}` +
      `Content-Disposition: form-data; name="file"; filename="document.pdf"${crlf}` +
      `Content-Type: application/octet-stream${crlf}` +
      `Content-Transfer-Encoding: binary${crlf}${crlf}`;
    const footer = `${crlf}--${boundary}--${crlf}`;
    const multipartBody = Buffer.concat([Buffer.from(header), pdfBuffer, Buffer.from(footer)]);

    console.log("📤 [PROXY] Відправка на Paperless API...");
    const response = await fetch(`${PAPERLESS_API}/api2/checked/upload`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': `multipart/form-data; boundary=${boundary}; charset=UTF-8`,
        'Content-Length': multipartBody.length.toString(),
        'Cookie': authCookie
      },
      body: multipartBody
    });

    const result = await response.json();
    console.log("✅ [PROXY] Банк відповів:", JSON.stringify(result).substring(0, 200));
    if (!response.ok) throw new Error(`Paperless Error: ${JSON.stringify(result)}`);
    
    res.json({ success: true, data: result });
  } catch (error) {
    console.error("❌ [PROXY] Помилка:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

async function getAccessToken() {
  const baseUrl = `${PAPERLESS_API}/PplsService/oauth`;
  console.log("🔐 [AUTH] Крок 1: Запит authorize...");
  
  const authResp = await fetch(`${baseUrl}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ "response_type": "code", "agentCheck": "true", "client_id": CLIENT_ID })
  });
  const authText = await authResp.text();
  console.log("🔐 [AUTH] Статус:", authResp.status, "Тіло:", authText.substring(0, 120));

  let code = null;
  try {
    const json = JSON.parse(authText);
    code = json.code;
    console.log("🔑 [AUTH] Код знайдено в JSON");
  } catch {
    const match = authText.match(/<code>([^<]+)<\/code>/);
    if (match) {
      code = match[1];
      console.log("🔑 [AUTH] Код знайдено в HTML");
    }
  }

  if (!code) throw new Error("No auth code from Bank. Response: " + authText.substring(0, 150));

  console.log("🔐 [AUTH] Крок 2: Генерація dynamic secret...");
  const crypto = require('crypto');
  const input = CLIENT_ID + CLIENT_SECRET + code;
  const dynamicSecret = crypto.createHash('sha512').update(input).digest('hex');

  console.log("🔐 [AUTH] Крок 3: Запит token...");
  const tokenResp = await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ "grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": dynamicSecret, "code": code })
  });
  const tokenText = await tokenResp.text();
  
  let token = null;
  try {
    const json = JSON.parse(tokenText);
    token = json.access_token;
  } catch {
    const match = tokenText.match(/<access_token>([^<]+)<\/access_token>/);
    if (match) token = match[1];
  }
  if (!token) throw new Error("No token from Bank. Response: " + tokenText.substring(0, 150));
  
  return token;
}

app.listen(port, () => { console.log(`🚀 [PROXY] Server running on port ${port}`); });
