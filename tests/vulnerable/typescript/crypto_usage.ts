import crypto from "node:crypto";
import jwt from "jsonwebtoken";

export function rsaKeys() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
}

export function ecdsa() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
}

export function md5(data: Buffer): string {
  return crypto.createHash("md5").update(data).digest("hex");
}

export function signToken(payload: object, key: string): string {
  return jwt.sign(payload, key, { algorithm: "RS256" });
}
