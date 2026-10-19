import { createHash } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { prisma } from "../lib/prisma.js";

export type AppRole = "ADMIN" | "ARTIST" | "BUYER" | "DELIVERY_MAN";

export type AuthenticatedUser = {
  id: string;
  fullName: string;
  username: string;
  email: string;
  role: AppRole;
};

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthenticatedUser;
    }
  }
}

function getSessionToken(req: Request): string | null {
  const authorization = req.headers.authorization;

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

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = getSessionToken(req);

  if (!token) {
    res.status(401).json({
      message: "You must sign in to continue.",
    });
    return;
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
      res.status(401).json({
        message: "Your session is invalid. Please sign in again.",
      });
      return;
    }

    if (session.expiresAt.getTime() <= Date.now()) {
      await prisma.session.deleteMany({
        where: { id: session.id },
      });

      res.status(401).json({
        message: "Your session has expired. Please sign in again.",
      });
      return;
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

      res.status(401).json({
        message: "This account is unavailable.",
      });
      return;
    }

    req.authUser = {
      id: user.id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      role: user.role,
    };

    next();
  } catch (error) {
    console.error(
      "Authentication middleware failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    res.status(500).json({
      message: "Unable to authenticate this request.",
    });
  }
}

export function requireRole(...allowedRoles: AppRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.authUser) {
      res.status(401).json({
        message: "You must sign in to continue.",
      });
      return;
    }

    if (!allowedRoles.includes(req.authUser.role)) {
      res.status(403).json({
        message: "You do not have permission to perform this action.",
      });
      return;
    }

    next();
  };
}


// Only fully registered, approved artists may manage artwork.
export async function requireRegisteredArtist(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  if (!req.authUser) {
    res.status(401).json({
      message: "You must sign in to continue.",
    });
    return;
  }

  if (req.authUser.role !== "ARTIST") {
    res.status(403).json({
      message: "Only artists may manage artwork.",
    });
    return;
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.authUser.id },
      select: {
        role: true,
        isActive: true,
        registrationComplete: true,
        artistApprovalStatus: true,
      },
    });

    if (!user || !user.isActive) {
      res.status(401).json({
        message: "This account is unavailable.",
      });
      return;
    }

    if (user.role !== "ARTIST") {
      res.status(403).json({
        message: "Only artists may manage artwork.",
      });
      return;
    }

    if (!user.registrationComplete) {
      res.status(403).json({
        message: "Complete registration before managing artwork.",
      });
      return;
    }


    next();
  } catch (error) {
    console.error(
      "Artist approval check failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    res.status(500).json({
      message: "Unable to verify artist approval.",
    });
  }
}




