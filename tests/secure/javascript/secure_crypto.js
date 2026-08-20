const crypto = require("crypto");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function aesGcm(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { sha256, aesGcm };
