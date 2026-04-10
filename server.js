import http from "http";

// PKCS#7 / X.509
import * as asn1js from "asn1js";
import { ContentInfo } from "pkijs";
import { SignedData } from "pkijs";

const PORT = process.env.PORT || 3000;

function extractFromCertificate(cert) {
  let fullname = null;
  let rnokpp = null;

  // Subject (CN)
  cert.subject.typesAndValues.forEach(tv => {
    if (tv.type === "2.5.4.3") { // CN
      fullname = tv.value.valueBlock.value;
    }

    if (tv.type === "2.5.4.5") { // SERIALNUMBER
      rnokpp = tv.value.valueBlock.value;
    }
  });

  // Extensions (OID для ДРФО)
  if (cert.extensions) {
    for (const ext of cert.extensions) {
      if (ext.extnID === "1.2.804.2.1.1.1.11.1.4.1.1") {
        try {
          const value = new TextDecoder().decode(ext.extnValue.valueBlock.valueHex);
          rnokpp = value.replace(/\D/g, "");
        } catch (e) {}
      }
    }
  }

  return { fullname, rnokpp };
}

function parsePKCS7(base64) {
  const der = Buffer.from(base64, "base64");

  const asn1 = asn1js.fromBER(der.buffer);
  if (asn1.offset === -1) {
    throw new Error("ASN1 parse error");
  }

  const contentInfo = new ContentInfo({ schema: asn1.result });
  const signedData = new SignedData({ schema: contentInfo.content });

  if (!signedData.certificates || signedData.certificates.length === 0) {
    throw new Error("No certificates in PKCS#7");
  }

  const cert = signedData.certificates[0];
  return extractFromCertificate(cert);
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok" }));
  }

  if (req.method === "POST" && req.url === "/verify-signature") {
    let body = "";

    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const { signatureBase64 } = JSON.parse(body);

        if (!signatureBase64) {
          throw new Error("Missing signatureBase64");
        }

        const { fullname, rnokpp } = parsePKCS7(signatureBase64);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          valid: true,
          fullname,
          rnokpp
        }));

      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          valid: false,
          error: err.message
        }));
      }
    });

    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});