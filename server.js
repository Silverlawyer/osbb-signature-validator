// server.js — Цей код живе на сервері Render
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// 🌐 Налаштування (беруться з безпечних змінних середовища Render)
const PAPERLESS_API = "https://paperless.com.ua";
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// Дозволяємо отримувати "сирі" дані (PDF файл)
app.use(express.raw({ type: 'application/pdf', limit: '10mb' }));

app.post('/upload-proxy', async (req, res) => {
  console.log("📥 [PROXY] Отримано запит на завантаження PDF");
  
  try {
    const pdfBuffer = req.body; // Тут лежить файл від вашого Воркера

    // 1. Отримуємо токен доступу
    const token = await getAccessToken();
    const authCookie = `sessionId="Bearer ${token}, Id ${CLIENT_ID}"`;

    // 2. Готуємо файл СПЕЦІАЛЬНО ДЛЯ БАНКУ (як у CURL)
    const boundary = '41810675712638257'; 
    const crlf = "\r\n";
    
    // Заголовок частини
    const header = `--${boundary}${crlf}` +
      `Content-Disposition: form-data; name="file"; filename="document.pdf"${crlf}` +
      `Content-Type: application/octet-stream${crlf}` +
      `Content-Transfer-Encoding: binary${crlf}${crlf}`;
    
    // Завершення
    const footer = `${crlf}--${boundary}--${crlf}`;

    // Збираємо все в один буфер: Заголовок + Файл + Завершення
    const multipartBody = Buffer.concat([
      Buffer.from(header),
      pdfBuffer,
      Buffer.from(footer)
    ]);

    console.log("📤 [PROXY] Відправка на Paperless API...");

    // 3. Відправляємо в Банк
    const response = await fetch(`${PAPERLESS_API}/api2/checked/upload`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': `multipart/form-data; boundary=${boundary}; charset=UTF-8`,
        'Content-Length': multipartBody.length.toString(), // ❗ Цей заголовок вирішує проблему NPE
        'Cookie': authCookie
      },
      body: multipartBody
    });

    const result = await response.json();
    console.log("✅ [PROXY] Банк відповів:", JSON.stringify(result));

    if (!response.ok) {
      throw new Error(`Paperless Error: ${JSON.stringify(result)}`);
    }

    // 4. Повертаємо результат Воркеру
    res.json({ success: true, data: result });

  } catch (error) {
    console.error("❌ [PROXY] Помилка:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Функція отримання токена (OAuth2) ---
async function getAccessToken() {
  const baseUrl = `${PAPERLESS_API}/PplsService/oauth`;
  
  // Крок 1: Код
  const authResp = await fetch(`${baseUrl}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ "response_type": "code", "agentCheck": "true", "client_id": CLIENT_ID })
  });
  const authText = await authResp.text();
  let code = null;
  try { code = JSON.parse(authText).code; } catch {}
  if (!code) throw new Error("No auth code from Bank");

  // Крок 2: Секрет
  const input = CLIENT_ID + CLIENT_SECRET + code;
  // В Node.js crypto працює інакше, ніж у Worker, використовуємо стандартний модуль
  const crypto = require('crypto');
  const dynamicSecret = crypto.createHash('sha512').update(input).digest('hex');

  // Крок 3: Токен
  const tokenResp = await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ "grant_type": "authorization_code", "client_id": CLIENT_ID, "client_secret": dynamicSecret, "code": code })
  });
  const tokenText = await tokenResp.text();
  let token = null;
  try { token = JSON.parse(tokenText).access_token; } catch {}
  if (!token) throw new Error("No token from Bank");
  
  return token;
}

app.listen(port, () => {
  console.log(`🚀 [PROXY] Server running on port ${port}`);
});
