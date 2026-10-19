import "dotenv/config";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { PrismaMariaDb } from "@prisma/adapter-mariadb";
import { PrismaClient } from "../generated/prisma/client.js";

function createAdapter(): PrismaMariaDb {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error("DATABASE_URL is not configured.");
  }

  const url = new URL(databaseUrl);

  if (url.protocol !== "mysql:" && url.protocol !== "mariadb:") {
    throw new Error("DATABASE_URL must use the MySQL or MariaDB protocol.");
  }

  const database = decodeURIComponent(url.pathname.replace(/^\/+/, ""));

  if (!database || !url.hostname || !url.username) {
    throw new Error("DATABASE_URL is missing required connection details.");
  }

  const isAiven = url.hostname.endsWith(".aivencloud.com");

  const adapterConfig = {
    host: url.hostname,
    port: Number(url.port || 3306),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database,
    connectionLimit: 5,
    ...(isAiven
      ? {
          ssl: {
            ca: readFileSync(process.env.RENDER ? "/etc/secrets/ca.pem" : resolve(process.cwd(), "ca.pem"), "utf8"),
            rejectUnauthorized: true,
          },
        }
      : {}),
  };

  return new PrismaMariaDb(adapterConfig);
}

const adapter = createAdapter();

export const prisma = new PrismaClient({ adapter });
