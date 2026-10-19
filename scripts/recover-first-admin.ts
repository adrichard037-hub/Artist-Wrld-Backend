import "dotenv/config";
import { createHash, randomBytes } from "node:crypto";
import { prisma } from "../src/lib/prisma.js";
import { hashPassword } from "../src/lib/password.js";

async function main() {
  const password = process.env.RECOVERY_PASSWORD;

  delete process.env.RECOVERY_PASSWORD;

  if (!password || password.length < 12 || password.length > 128) {
    throw new Error("The recovery password must contain 12–128 characters.");
  }

  const admin = await prisma.user.findFirst({
    where: {
      username: "admin",
      role: "ADMIN",
    },
    select: {
      id: true,
      isActive: true,
    },
  });

  if (!admin) {
    throw new Error(
      "The expected admin account was not found. No account was changed.",
    );
  }

  if (!admin.isActive) {
    throw new Error(
      "The admin account is inactive. No account was changed.",
    );
  }

  const { passwordHash, passwordSalt } = await hashPassword(password);

  const enrollmentToken = randomBytes(32).toString("hex");
  const enrollmentTokenHash = createHash("sha256")
    .update(enrollmentToken)
    .digest("hex");

  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await prisma.user.update({
    where: { id: admin.id },
    data: {
      passwordHash,
      passwordSalt,
      registrationComplete: false,
      registrationEnrollmentTokenHash: enrollmentTokenHash,
      registrationEnrollmentExpiresAt: expiresAt,
      registrationEnrollmentAttempts: 0,
      twoFactorEnabled: false,
      twoFactorSecret: null,
      twoFactorPendingSecret: null,
    },
  });

  console.log("\nAdmin recovery prepared successfully.");
  console.log("The existing account was updated; it was not recreated.");
  console.log("A new authenticator enrollment token expires at:");
  console.log(expiresAt.toISOString());
  console.log("\nOpen this one-time enrollment link in your frontend browser:");
  console.log(`http://localhost:5173/setup-authenticator#${enrollmentToken}`);
  console.log("\nDo not share the link. Use it before it expires.");
}

main()
  .catch((error: unknown) => {
    console.error(
      "Admin recovery failed:",
      error instanceof Error ? error.message : "Unknown error",
    );
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
