import "dotenv/config";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { prisma } from "../src/lib/prisma.js";

function csv(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

async function main() {
  const pepper = process.env.PEPPER;

  if (!pepper) {
    throw new Error("PEPPER is missing from the environment.");
  }

  const users = await prisma.user.findMany({
    select: {
      username: true,
      passwordHash: true,
      passwordSalt: true,
    },
    orderBy: {
      username: "asc",
    },
  });

  const headers = [
    "Username",
    "Hashed Password",
    "Salt",
    "Pepper",
  ];

  const rows = users.length
    ? users.map((user) => [
        user.username,
        user.passwordHash,
        user.passwordSalt,
        pepper,
      ])
    : [["", "", "", pepper]];

  const content = [
    headers.map(csv).join(","),
    ...rows.map((row) => row.map(csv).join(",")),
  ].join("\r\n");

  const outputDirectory = resolve(process.cwd(), "private");
  await mkdir(outputDirectory, { recursive: true });

  const filename = `security-report-${new Date()
    .toISOString()
    .replace(/[:.]/g, "-")}.csv`;

  const outputPath = resolve(outputDirectory, filename);

  await writeFile(outputPath, "\uFEFF" + content, "utf8");

  console.log(`Security report exported successfully.`);
  console.log(`Accounts exported: ${users.length}`);
  console.log(`File: ${outputPath}`);
}

main()
  .catch((error) => {
    console.error("Security report export failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });