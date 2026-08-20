import crypto from "node:crypto";

export function sha384(data: Buffer): string {
  return crypto.createHash("sha384").update(data).digest("hex");
}
