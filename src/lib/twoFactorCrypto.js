import { createCipheriv, createDecipheriv, randomBytes, } from "node:crypto";
function getEncryptionKey() {
    const configuredKey = process.env.TWO_FACTOR_ENCRYPTION_KEY;
    if (!configuredKey) {
        throw new Error("The TWO_FACTOR_ENCRYPTION_KEY environment variable is not configured.");
    }
    let key;
    try {
        key = Buffer.from(configuredKey, "base64");
    }
    catch {
        throw new Error("The 2FA encryption key is invalid.");
    }
    if (key.length !== 32 ||
        key.toString("base64") !== configuredKey) {
        throw new Error("The 2FA encryption key must be valid Base64 encoding of 32 bytes.");
    }
    return key;
}
export function encryptTwoFactorSecret(secret) {
    const key = getEncryptionKey();
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([
        cipher.update(secret, "utf8"),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    return [
        "v1",
        iv.toString("base64"),
        authTag.toString("base64"),
        ciphertext.toString("base64"),
    ].join(":");
}
export function decryptTwoFactorSecret(encryptedSecret) {
    const parts = encryptedSecret.split(":");
    if (parts.length !== 4 || parts[0] !== "v1") {
        throw new Error("The stored 2FA secret has an unsupported format.");
    }
    const encodedIv = parts[1];
    const encodedAuthTag = parts[2];
    const encodedCiphertext = parts[3];
    if (!encodedIv || !encodedAuthTag || !encodedCiphertext) {
        throw new Error("The stored 2FA secret is incomplete.");
    }
    const iv = Buffer.from(encodedIv, "base64");
    const authTag = Buffer.from(encodedAuthTag, "base64");
    const ciphertext = Buffer.from(encodedCiphertext, "base64");
    if (iv.length !== 12 || authTag.length !== 16 || ciphertext.length === 0) {
        throw new Error("The stored 2FA secret is invalid.");
    }
    const decipher = createDecipheriv("aes-256-gcm", getEncryptionKey(), iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]).toString("utf8");
}
//# sourceMappingURL=twoFactorCrypto.js.map