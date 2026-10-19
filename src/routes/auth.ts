import { Router } from "express";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { hashPassword, verifyPassword } from "../lib/password.js";
import { requireAuth } from "../middleware/auth.js";
import {
  decryptTwoFactorSecret,
  encryptTwoFactorSecret,
} from "../lib/twoFactorCrypto.js";
import { generateSecret, generateURI, verify } from "otplib";
import QRCode from "qrcode";

const router = Router();

const loginSchema = z.object({
  identifier: z.string().trim().min(1).max(254),
  password: z.string().min(1).max(128),
  rememberMe: z.boolean().optional().default(false),
});

const registrationSchema = z
  .object({
    fullName: z.string().trim().min(2).max(100),
    username: z
      .string()
      .trim()
      .min(3)
      .max(30)
      .regex(/^[a-zA-Z0-9._-]+$/),
    email: z.string().trim().email().max(254),
    role: z.enum(["buyer", "artist", "delivery"]),
    password: z.string().min(8).max(128),
    confirmPassword: z.string(),
    acceptedTerms: z.boolean(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  })
  .refine((data) => data.acceptedTerms, {
    message: "You must accept the terms and conditions.",
    path: ["acceptedTerms"],
  });

router.post("/register", async (req, res) => {
  const parsed = registrationSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Please check your registration details.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const data = parsed.data;
  const username = data.username.toLowerCase();
  const email = data.email.toLowerCase();

  try {
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
      select: {
        username: true,
        email: true,
      },
    });

    if (existingUser) {
      const errors: { field: string; message: string }[] = [];

      if (existingUser.username === username) {
        errors.push({
          field: "username",
          message: "This username is already taken.",
        });
      }

      if (existingUser.email === email) {
        errors.push({
          field: "email",
          message: "An account with this email already exists.",
        });
      }

      return res.status(409).json({
        message: "An account with those details already exists.",
        errors,
      });
    }

    const { passwordHash, passwordSalt } = await hashPassword(data.password);

    const enrollmentToken = randomBytes(32).toString("hex");
    const enrollmentTokenHash = createHash("sha256")
      .update(enrollmentToken)
      .digest("hex");

    const roleMap = {
      buyer: "BUYER",
      artist: "ARTIST",
      delivery: "DELIVERY_MAN",
    } as const;

    const user = await prisma.user.create({
      data: {
        fullName: data.fullName,
        username,
        email,
        passwordHash,
        passwordSalt,
        role: roleMap[data.role],
        registrationComplete: false,
        registrationEnrollmentTokenHash: enrollmentTokenHash,
        registrationEnrollmentExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
        registrationEnrollmentAttempts: 0,
      },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,

        role: user.role,
        action: "USER_REGISTERED",
        details: "A new account was registered.",

      },
    });

    return res.status(201).json({
      message: "Your account has been created. Set up your authenticator to finish registration.",
      enrollmentToken,
      expiresIn: 900,
      user,
    });
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "P2002"
    ) {
      return res.status(409).json({
        message: "That username or email address is already registered.",
      });
    }

    console.error("Registration failed:", error);

    return res.status(500).json({
      message: "Unable to complete registration at this time.",
    });
  }
});


router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Enter a valid email address and password.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const identifier = parsed.data.identifier.toLowerCase();
  const password = parsed.data.password;
  const rememberMe = parsed.data.rememberMe;

  try {
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: identifier },
          { username: identifier },
        ],
      },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        passwordHash: true,
        isActive: true,
        registrationComplete: true,
        twoFactorEnabled: true,
        twoFactorSecret: true,
        role: true,
      },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const passwordMatches = await verifyPassword(password, user.passwordHash);

    if (!passwordMatches || !user.isActive) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    if (
      !user.registrationComplete ||
      !user.twoFactorEnabled ||
      !user.twoFactorSecret
    ) {
      return res.status(403).json({
        requiresEnrollment: true,
        message: "Complete authenticator setup before signing in.",
      });
    }

    // Do not create a session until the second factor has been verified.
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      const challengeToken = randomBytes(32).toString("hex");
      const challengeTokenHash = createHash("sha256")
        .update(challengeToken)
        .digest("hex");

      await prisma.loginchallenge.create({
        data: {
          userId: user.id,
          tokenHash: challengeTokenHash,
          rememberMe,
          expiresAt: new Date(Date.now() + 5 * 60 * 1000),
        },
      });

      await prisma.auditlog.create({
        data: {
          username: user.username,

          role: user.role,
          action: "LOGIN_2FA_CHALLENGE_CREATED",
          details: "A temporary two-factor login challenge was created.",

        },
      });

      return res.status(200).json({
        requiresTwoFactor: true,
        challengeToken,
        expiresIn: 300,
        message: "Enter the verification code from your authenticator app.",
      });
    }

    const token = randomBytes(32).toString("hex");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const maxAge = rememberMe
      ? 30 * 24 * 60 * 60 * 1000
      : 8 * 60 * 60 * 1000;

    await prisma.session.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + maxAge),
      },
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,

        role: user.role,
        action: "USER_LOGIN",
        details: "User signed in successfully.",

      },
    });

    res.cookie("artist_wrld_session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge,
    });

    return res.status(200).json({
      message: "Login successful.",
      ...(req.get("X-Client-Platform")?.toLowerCase() === "mobile"
        ? { sessionToken: token }
        : {}),
      user: {
        id: user.id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(
      "Login failed:",
      error instanceof Error ? error.message : "Unknown error",
    );
    return res.status(500).json({
      message: "Unable to complete login at this time.",
    });
  }
});


// Set up an authenticator for a new, incomplete registration.
router.post("/registration-2fa/setup", async (req, res) => {
  const parsed = z.object({
    enrollmentToken: z.string().regex(/^[a-f0-9]{64}$/i),
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "A valid registration enrollment token is required.",
    });
  }

  const enrollmentTokenHash = createHash("sha256")
    .update(parsed.data.enrollmentToken)
    .digest("hex");

  try {
    const user = await prisma.user.findUnique({
      where: { registrationEnrollmentTokenHash: enrollmentTokenHash },
      select: {
        id: true,
        email: true,
        registrationComplete: true,
        registrationEnrollmentExpiresAt: true,
        registrationEnrollmentAttempts: true,
        twoFactorEnabled: true,
      },
    });

    if (
      !user ||
      user.registrationComplete ||
      user.twoFactorEnabled ||
      !user.registrationEnrollmentExpiresAt ||
      user.registrationEnrollmentExpiresAt.getTime() <= Date.now() ||
      user.registrationEnrollmentAttempts >= 5
    ) {
      return res.status(401).json({
        message: "The enrollment token is invalid, expired, or exhausted. Please register again.",
      });
    }

    const secret = generateSecret();
    const encryptedSecret = encryptTwoFactorSecret(secret);

    const uri = generateURI({
      issuer: "Artist-Wrld",
      label: user.email,
      secret,
    });

    const qrCodeDataUrl = await QRCode.toDataURL(uri);

    await prisma.user.update({
      where: { id: user.id },
      data: { twoFactorPendingSecret: encryptedSecret },
    });

    return res.status(200).json({
      message: "Scan the QR code with your authenticator app, then enter its six-digit code.",
      qrCodeDataUrl,
      manualEntryKey: secret,
      expiresIn: Math.floor(
        (user.registrationEnrollmentExpiresAt.getTime() - Date.now()) / 1000,
      ),
    });
  } catch (error) {
    console.error(
      "Registration authenticator setup failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to set up your authenticator at this time.",
    });
  }
});

// Verify the authenticator and complete a new registration.
router.post("/registration-2fa/enable", async (req, res) => {
  const parsed = z.object({
    enrollmentToken: z.string().regex(/^[a-f0-9]{64}$/i),
    code: z.string().regex(/^\d{6}$/, "Enter the six-digit code."),
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "A valid enrollment token and six-digit authenticator code are required.",
    });
  }

  const enrollmentTokenHash = createHash("sha256")
    .update(parsed.data.enrollmentToken)
    .digest("hex");

  try {
    const user = await prisma.user.findUnique({
      where: { registrationEnrollmentTokenHash: enrollmentTokenHash },
      select: {
        id: true,
        username: true,
        role: true,
        email: true,
        registrationComplete: true,
        registrationEnrollmentExpiresAt: true,
        registrationEnrollmentAttempts: true,
        twoFactorEnabled: true,
        twoFactorPendingSecret: true,
      },
    });

    if (
      !user ||
      user.registrationComplete ||
      user.twoFactorEnabled ||
      !user.registrationEnrollmentExpiresAt ||
      user.registrationEnrollmentExpiresAt.getTime() <= Date.now() ||
      user.registrationEnrollmentAttempts >= 5
    ) {
      return res.status(401).json({
        message: "The enrollment token is invalid, expired, or exhausted. Please register again.",
      });
    }

    if (!user.twoFactorPendingSecret) {
      return res.status(400).json({
        message: "Start authenticator setup before verifying a code.",
      });
    }

    const secret = decryptTwoFactorSecret(user.twoFactorPendingSecret);
    const result = await verify({
      secret,
      token: parsed.data.code,
    });

    if (!result.valid) {
      const updated = await prisma.user.updateMany({
        where: {
          id: user.id,
          registrationComplete: false,
          registrationEnrollmentTokenHash: enrollmentTokenHash,
          registrationEnrollmentAttempts: { lt: 5 },
        },
        data: {
          registrationEnrollmentAttempts: { increment: 1 },
        },
      });

      if (updated.count === 0) {
        return res.status(401).json({
          message: "The enrollment token is no longer valid. Please register again.",
        });
      }

      const attemptsRemaining = Math.max(
        0,
        5 - user.registrationEnrollmentAttempts - 1,
      );

      return res.status(400).json({
        message: attemptsRemaining === 0
          ? "Too many incorrect codes. Please register again."
          : "The verification code is incorrect or expired.",
        attemptsRemaining,
      });
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: {
          twoFactorEnabled: true,
          twoFactorSecret: user.twoFactorPendingSecret,
          twoFactorPendingSecret: null,
          registrationComplete: true,
          registrationEnrollmentTokenHash: null,
          registrationEnrollmentExpiresAt: null,
          registrationEnrollmentAttempts: 0,
        },
      }),
      prisma.auditlog.create({
        data: {
          username: user.username,

          role: user.role,
          action: "USER_REGISTRATION_2FA_ENABLED",
          details: "Registration completed after authenticator verification.",

        },
      }),
    ]);

    return res.status(200).json({
      message: "Authenticator verified. Registration is complete. You can now sign in.",
    });
  } catch (error) {
    console.error(
      "Registration authenticator verification failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to verify your authenticator at this time.",
    });
  }
});
// Set up authenticator-based two-factor authentication.
router.post("/2fa/setup", requireAuth, async (req, res) => {
  const authUser = req.authUser;

  if (!authUser) {
    return res.status(401).json({ message: "You must sign in first." });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: authUser.id },
      select: {
        email: true,
        twoFactorEnabled: true,
      },
    });

    if (!user) {
      return res.status(404).json({ message: "Account not found." });
    }

    if (user.twoFactorEnabled) {
      return res.status(409).json({
        message: "Two-factor authentication is already enabled.",
      });
    }

    const secret = generateSecret();
    const encryptedSecret = encryptTwoFactorSecret(secret);

    const uri = generateURI({
      issuer: "Artist-Wrld",
      label: user.email,
      secret,
    });

    const qrCodeDataUrl = await QRCode.toDataURL(uri);

    await prisma.user.update({
      where: { id: authUser.id },
      data: {
        twoFactorPendingSecret: encryptedSecret,
      },
    });

    return res.status(200).json({
      message: "Scan the QR code and verify a code to enable 2FA.",
      qrCodeDataUrl,
      manualEntryKey: secret,
    });
  } catch (error) {
    console.error(
      "2FA setup failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to set up two-factor authentication.",
    });
  }
});

// Enable 2FA only after verifying a code from the authenticator app.
router.post("/2fa/enable", requireAuth, async (req, res) => {
  const authUser = req.authUser;

  if (!authUser) {
    return res.status(401).json({ message: "You must sign in first." });
  }

  const parsed = z.object({
    code: z.string().regex(/^\d{6}$/, "Enter the six-digit code."),
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Enter a valid six-digit authenticator code.",
    });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: authUser.id },
      select: {
        twoFactorEnabled: true,
        twoFactorPendingSecret: true,
      },
    });

    if (!user) {
      return res.status(404).json({ message: "Account not found." });
    }

    if (user.twoFactorEnabled) {
      return res.status(409).json({
        message: "Two-factor authentication is already enabled.",
      });
    }

    if (!user.twoFactorPendingSecret) {
      return res.status(400).json({
        message: "Set up two-factor authentication before enabling it.",
      });
    }

    const secret = decryptTwoFactorSecret(user.twoFactorPendingSecret);
    const result = await verify({
      secret,
      token: parsed.data.code,
    });

    if (!result.valid) {
      return res.status(400).json({
        message: "The verification code is incorrect or expired.",
      });
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: authUser.id },
        data: {
          twoFactorEnabled: true,
          twoFactorSecret: user.twoFactorPendingSecret,
          twoFactorPendingSecret: null,
        },
      }),
      prisma.auditlog.create({
        data: {
          username: authUser.username,

          role: authUser.role,
          action: "TWO_FACTOR_ENABLED",
          details: "Two-factor authentication was enabled.",

        },
      }),
    ]);

    return res.status(200).json({
      message: "Two-factor authentication is now enabled.",
    });
  } catch (error) {
    console.error(
      "2FA enable failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to enable two-factor authentication.",
    });
  }
});

// Disable 2FA only after verifying the current authenticator code.
router.post("/2fa/disable", requireAuth, async (req, res) => {
  const authUser = req.authUser;

  if (!authUser) {
    return res.status(401).json({ message: "You must sign in first." });
  }

  const parsed = z.object({
    code: z.string().regex(/^\d{6}$/, "Enter the six-digit code."),
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Enter a valid six-digit authenticator code.",
    });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: authUser.id },
      select: {
        twoFactorEnabled: true,
        twoFactorSecret: true,
      },
    });

    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({
        message: "Two-factor authentication is not enabled.",
      });
    }

    const secret = decryptTwoFactorSecret(user.twoFactorSecret);
    const result = await verify({
      secret,
      token: parsed.data.code,
    });

    if (!result.valid) {
      return res.status(400).json({
        message: "The verification code is incorrect or expired.",
      });
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: authUser.id },
        data: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          twoFactorPendingSecret: null,
        },
      }),
      prisma.auditlog.create({
        data: {
          username: authUser.username,

          role: authUser.role,
          action: "TWO_FACTOR_DISABLED",
          details: "Two-factor authentication was disabled.",

        },
      }),
    ]);

    return res.status(200).json({
      message: "Two-factor authentication has been disabled.",
    });
  } catch (error) {
    console.error(
      "2FA disable failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to disable two-factor authentication.",
    });
  }
});

// Verify a temporary login challenge before creating an authenticated session.
router.post("/2fa/verify-login", async (req, res) => {
  const parsed = z.object({
    challengeToken: z.string().min(32).max(256),
    code: z.string().regex(/^\d{6}$/),
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "A valid login challenge and six-digit code are required.",
    });
  }

  const challengeTokenHash = createHash("sha256")
    .update(parsed.data.challengeToken)
    .digest("hex");

  try {
    const challenge = await prisma.loginchallenge.findUnique({
      where: { tokenHash: challengeTokenHash },
    });

    if (!challenge) {
      return res.status(401).json({
        message: "The login challenge is invalid or has expired.",
      });
    }

    if (
      challenge.expiresAt.getTime() <= Date.now() ||
      challenge.attempts >= 5
    ) {
      await prisma.loginchallenge.deleteMany({
        where: { id: challenge.id },
      });

      return res.status(401).json({
        message: "The login challenge is invalid or has expired.",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: challenge.userId },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        twoFactorEnabled: true,
        twoFactorSecret: true,
      },
    });

    if (
      !user ||
      !user.isActive ||
      !user.twoFactorEnabled ||
      !user.twoFactorSecret
    ) {
      await prisma.loginchallenge.deleteMany({
        where: { id: challenge.id },
      });

      return res.status(401).json({
        message: "The login challenge is no longer valid.",
      });
    }

    const secret = decryptTwoFactorSecret(user.twoFactorSecret);
    const result = await verify({
      secret,
      token: parsed.data.code,
    });

    if (!result.valid) {
      const nextAttempts = challenge.attempts + 1;

      if (nextAttempts >= 5) {
        await prisma.loginchallenge.deleteMany({
          where: { id: challenge.id },
        });
      } else {
        await prisma.loginchallenge.updateMany({
          where: {
            id: challenge.id,
            attempts: challenge.attempts,
          },
          data: { attempts: { increment: 1 } },
        });
      }

      return res.status(401).json({
        message: nextAttempts >= 5
          ? "Too many incorrect codes. Please sign in again."
          : "The verification code is incorrect or expired.",
        attemptsRemaining: Math.max(0, 5 - nextAttempts),
      });
    }

    const token = randomBytes(32).toString("hex");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const maxAge = challenge.rememberMe
      ? 30 * 24 * 60 * 60 * 1000
      : 8 * 60 * 60 * 1000;

    await prisma.$transaction([
      prisma.session.create({
        data: {
          userId: user.id,
          tokenHash,
          expiresAt: new Date(Date.now() + maxAge),
        },
      }),
      prisma.loginchallenge.delete({
        where: { id: challenge.id },
      }),
      prisma.auditlog.create({
        data: {
          username: user.username,

          role: user.role,
          action: "USER_LOGIN_2FA_SUCCESS",
          details: "Login completed after successful two-factor verification.",

        },
      }),
    ]);

    res.cookie("artist_wrld_session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge,
    });

    return res.status(200).json({
      message: "Login successful.",
      ...(req.get("X-Client-Platform")?.toLowerCase() === "mobile"
        ? { sessionToken: token }
        : {}),
      user: {
        id: user.id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(
      "2FA login verification failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to verify the login challenge.",
    });
  }
});
// Read a mobile Bearer token first, then fall back to the browser session cookie.
function getSessionToken(req: import("express").Request): string | null {
  const authorization = req.get("Authorization");

  if (authorization) {
    const match = authorization.match(/^Bearer\s+(\S+)$/i);
    if (match?.[1]) {
      return match[1];
    }
  }

  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return null;
  }

  for (const cookie of cookieHeader.split(";")) {
    const separatorIndex = cookie.indexOf("=");
    if (separatorIndex < 0) {
      continue;
    }

    const name = cookie.slice(0, separatorIndex).trim();
    const value = cookie.slice(separatorIndex + 1).trim();

    if (name === "artist_wrld_session" && value.length > 0) {
      return value;
    }
  }

  return null;
}

function clearSessionCookie(res: import("express").Response) {
  res.clearCookie("artist_wrld_session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });
}

// Return the account associated with the current, unexpired session.
router.get("/me", async (req, res) => {
  const token = getSessionToken(req);

  if (!token) {
    return res.status(401).json({
      message: "You must sign in to continue.",
    });
  }

  try {
    const tokenHash = createHash("sha256").update(token).digest("hex");

    const session = await prisma.session.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
      },
    });

    if (!session) {
      clearSessionCookie(res);

      return res.status(401).json({
        message: "Your session is invalid. Please sign in again.",
      });
    }

    if (session.expiresAt.getTime() <= Date.now()) {
      await prisma.session.deleteMany({
        where: { id: session.id },
      });

      clearSessionCookie(res);

      return res.status(401).json({
        message: "Your session has expired. Please sign in again.",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
      },
    });

    if (!user || !user.isActive) {
      await prisma.session.deleteMany({
        where: { id: session.id },
      });

      clearSessionCookie(res);

      return res.status(401).json({
        message: "This account is unavailable. Please contact support if you need assistance.",
      });
    }

    return res.status(200).json({
      authenticated: true,
      user: {
        id: user.id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(
      "Session validation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to validate your session at this time.",
    });
  }
});

// Revoke the current session and clear its browser cookie.
router.post("/logout", async (req, res) => {
  const token = getSessionToken(req);

  try {
    if (token) {
      const tokenHash = createHash("sha256").update(token).digest("hex");

      await prisma.session.deleteMany({
        where: { tokenHash },
      });
    }

    clearSessionCookie(res);

    return res.status(200).json({
      message: "You have been signed out successfully.",
    });
  } catch (error) {
    console.error(
      "Logout failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to complete logout at this time.",
    });
  }
});

export default router;







