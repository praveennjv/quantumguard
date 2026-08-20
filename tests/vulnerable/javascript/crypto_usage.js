const crypto = require("crypto");
const jwt = require("jsonwebtoken");

function rsaKeys() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
}

function ecdh() {
  return crypto.createECDH("prime256v1");
}

function hashes(data) {
  crypto.createHash("md5").update(data).digest("hex");
  crypto.createHash("sha1").update(data).digest("hex");
}

function jwtSign(payload, key) {
  return jwt.sign(payload, key, { algorithm: "ES256" });
}

function dh() {
  return crypto.generateKeyPairSync("dh", { modulusLength: 2048 });
}

module.exports = { rsaKeys, ecdh, hashes, jwtSign, dh };
