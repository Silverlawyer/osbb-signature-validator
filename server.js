/**
 * =========================================================================
 * RAILWAY SERVER: Парсинг PKCS#7 підписів (jkurwa)
 * Версія 1.0 - Витягує РНОКПП та ПІБ з сертифіката КЕП
 * =========================================================================
 */

const express = require('express');
const { Message } = require('jkurwa/lib/models');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const PORT = process.env.PORT || 3000;

/**
 * POST /verify-signature
 * Отримує Base64 PKCS#7 контейнер
 * Повертає { valid, rnokpp, fullname, timestamp }
 */
app.post('/verify-signature', (req, res) => {
  try {
    const { signatureBase64 } = req.body;

    if (!signatureBase64 || typeof signatureBase64 !== 'string') {
      return res.status(400).json({ valid: false, error: 'Missing signatureBase64' });
    }

    // Декодуємо Base64 в бінарний буфер
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');

    // Парсимо PKCS#7 контейнер через jkurwa
    let msg;
    try {
      msg = new Message(signatureBuffer);
    } catch (e) {
      return res.status(400).json({ 
        valid: false, 
        error: 'Invalid PKCS#7 format',
        details: e.message 
      });
    }

    // Перевіряємо підпис
    if (!msg.verify()) {
      return res.status(400).json({ 
        valid: false, 
        error: 'Signature verification failed' 
      });
    }

    // Витягуємо сертифікат
    let certificate = null;
    try {
      const certs = msg.certs;
      if (!certs || certs.length === 0) {
        return res.status(400).json({ 
          valid: false, 
          error: 'No certificates found in signature' 
        });
      }
      certificate = certs[0];
    } catch (e) {
      return res.status(400).json({ 
        valid: false, 
        error: 'Cannot extract certificate',
        details: e.message 
      });
    }

    // Витягуємо CN (ПІБ) та SERIALNUMBER (РНОКПП) з сертифіката
    let fullname = null;
    let rnokpp = null;
    let timestamp = new Date().toISOString();

    try {
      const subject = certificate.subject;
      
      // CN (Common Name) = ПІБ
      const cnArray = subject.getField('CN');
      if (cnArray && cnArray.length > 0) {
        fullname = cnArray[0].value || null;
      }

      // SERIALNUMBER = РНОКПП
      const serialArray = subject.getField('serialNumber');
      if (serialArray && serialArray.length > 0) {
        const serial = serialArray[0].value || '';
        // Витягуємо цифри з TINUA-XXXXXXXXXX або NTRUA-XXXXXXXXXX
        const match = serial.match(/(?:TINUA|NTRUA)-(\d{8,10})/);
        if (match) {
          rnokpp = match[1];
        }
      }

      // Альтернативний метод - шукаємо в binaryString якщо CN/SERIALNUMBER не знайдені
      if (!rnokpp || !fullname) {
        const binaryString = signatureBuffer.toString('latin1');
        
        // Пошук TINUA або NTRUA
        if (!rnokpp) {
          const rnokppMatch = binaryString.match(/(?:TINUA|NTRUA)-(\d{8,10})/);
          if (rnokppMatch) {
            rnokpp = rnokppMatch[1];
          }
        }

        // Пошук ПІБ - зазвичай в CN або в UTF-8 рядку
        if (!fullname) {
          // Спробуємо витягти з структури
          const cnMatch = binaryString.match(/CN=([^,\x00]+)/);
          if (cnMatch) {
            fullname = cnMatch[1].trim();
          }
        }
      }
    } catch (e) {
      console.error('Certificate parsing error:', e.message);
      // Не повертаємо помилку, продовжуємо з тим що знайшли
    }

    // Перевіряємо що отримали хоча б РНОКПП
    if (!rnokpp) {
      return res.status(400).json({
        valid: false,
        error: 'Cannot extract RNOKPP from certificate',
        certificateInfo: {
          fullname: fullname,
          rnokpp: null
        }
      });
    }

    return res.json({
      valid: true,
      rnokpp: rnokpp,
      fullname: fullname || 'Користувач',
      timestamp: timestamp,
      certificateValidFrom: certificate.validFrom ? certificate.validFrom.toISOString() : null,
      certificateValidTo: certificate.validTo ? certificate.validTo.toISOString() : null
    });
  } catch (error) {
    console.error('Verification error:', error);
    return res.status(500).json({
      valid: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

/**
 * GET /health
 * Статус сервера
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0',
    service: 'PKCS#7 Signature Validator',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /parse-certificate
 * Debug endpoint - розбирає сертифікат деталізовано
 */
app.post('/parse-certificate', (req, res) => {
  try {
    const { signatureBase64 } = req.body;

    if (!signatureBase64) {
      return res.status(400).json({ error: 'Missing signatureBase64' });
    }

    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    const msg = new Message(signatureBuffer);

    const result = {
      signatureValid: msg.verify(),
      certificates: [],
      rawBinaryPreview: signatureBuffer.toString('latin1').substring(0, 500)
    };

    const certs = msg.certs;
    if (certs && certs.length > 0) {
      certs.forEach((cert, idx) => {
        const subject = cert.subject;
        const certInfo = {
          index: idx,
          subject: {},
          issuer: {},
          validFrom: cert.validFrom ? cert.validFrom.toISOString() : null,
          validTo: cert.validTo ? cert.validTo.toISOString() : null
        };

        // Витягуємо всі поля з subject
        if (subject) {
          const fields = ['CN', 'O', 'serialNumber', 'UID', 'OU', 'C', 'ST', 'L'];
          fields.forEach(field => {
            const fieldArray = subject.getField(field);
            if (fieldArray && fieldArray.length > 0) {
              certInfo.subject[field] = fieldArray[0].value;
            }
          });
        }

        result.certificates.push(certInfo);
      });
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({
      error: 'Parsing failed',
      details: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`✅ PKCS#7 Signature Validator listening on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`📍 Verify signature: POST http://localhost:${PORT}/verify-signature`);
});
