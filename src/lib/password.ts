import { createHmac, randomBytes } from "node:crypto";
import argon2 from "argon2";

function getPepper(): string {
  const pepper = process.env.PEPPER;

  if (!pepper) {
    throw new Error("The PEPPER environment variable is not configured.");
  }

  return pepper;
}

function prehashPassword(password: string): string {
  return createHmac("sha256", getPepper())
    .update(password, "utf8")
    .digest("hex");
}

export async function hashPassword(password: string): Promise<{
  passwordHash: string;
  passwordSalt: string;
}> {
  const passwordSalt = randomBytes(16).toString("hex");
  const prehashedPassword = prehashPassword(password);

  const passwordHash = await argon2.hash(prehashedPassword, {
    type: argon2.argon2id,
    salt: Buffer.from(passwordSalt, "hex"),
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

  return { passwordHash, passwordSalt };
}

export async function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  const prehashedPassword = prehashPassword(password);

  return argon2.verify(passwordHash, prehashedPassword);
}