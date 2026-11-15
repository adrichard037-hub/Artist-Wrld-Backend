import { Router } from "express";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { hashPassword } from "../lib/password.js";
import { requireAuth, requireRole } from "../middleware/auth.js";

const router = Router();

router.use(requireAuth, requireRole("ADMIN"));

const createUserSchema = z.object({
  fullName: z.string().trim().min(2).max(100),
  username: z.string().trim().min(3).max(30).regex(/^[a-zA-Z0-9._-]+$/),
  email: z.string().trim().email().max(254),
  role: z.enum(["ADMIN", "ARTIST", "BUYER", "DELIVERY_MAN"]),
  password: z.string().min(8).max(128),
}).strict();

const updateUserSchema = z.object({
  fullName: z.string().trim().min(2).max(100).optional(),
  username: z.string().trim().min(3).max(30).regex(/^[a-zA-Z0-9._-]+$/).optional(),
  email: z.string().trim().email().max(254).optional(),
  role: z.enum(["ADMIN", "ARTIST", "BUYER", "DELIVERY_MAN"]).optional(),
  isActive: z.boolean().optional(),
}).strict().refine(
  (data) => Object.keys(data).length > 0,
  { message: "Provide at least one field to update." },
);

const deactivateSchema = z.object({
  reason: z.string().trim().max(500).optional(),
}).strict();

const permanentDeleteSchema = z.object({
  reason: z.string().trim().min(1).max(500),
}).strict();
const deletedUserQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
}).strict();

const userActivityQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(100),
}).strict();
function isUniqueConstraintError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "P2002"
  );
}

// Administrator-only security report. Never return the pepper itself.
router.get("/security-report", async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");

  try {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        username: true,
        passwordHash: true,
        passwordSalt: true,
      },
    });

    return res.status(200).json({
      users,
      pepperConfigured: Boolean(process.env.PEPPER),
    });
  } catch (error) {
    console.error(
      "Admin security report failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve the security report.",
    });
  }
});
// List accounts without exposing password hashes, salts, or 2FA secrets.
router.get("/users", async (_req, res) => {
  try {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        registrationComplete: true,
        twoFactorEnabled: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return res.status(200).json({ users });
  } catch (error) {
    console.error(
      "Admin user listing failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve user accounts.",
    });
  }
});

// Create an account that must complete authenticator enrollment.
router.post("/users", async (req, res) => {
  const parsed = createUserSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Please check the account details.",
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
    const { passwordHash, passwordSalt } = await hashPassword(data.password);

    const enrollmentToken = randomBytes(32).toString("hex");
    const enrollmentTokenHash = createHash("sha256")
      .update(enrollmentToken)
      .digest("hex");

    const user = await prisma.user.create({
      data: {
        fullName: data.fullName,
        username,
        email,
        passwordHash,
        passwordSalt,
        role: data.role,
        registrationComplete: false,
        registrationEnrollmentTokenHash: enrollmentTokenHash,
        registrationEnrollmentExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
        registrationEnrollmentAttempts: 0,
        isActive: true,
        twoFactorEnabled: false,
      },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        isActive: true,
        registrationComplete: true,
        createdAt: true,
      },
    });

    await prisma.auditlog.create({
      data: {
        username: req.authUser!.username,

        role: req.authUser!.role,
        action: "ADMIN_USER_CREATED",
        details: `Administrator created a ${user.role} account.`,

      },
    });

    return res.status(201).json({
      message: "Account created. The user must complete authenticator enrollment within 15 minutes.",
      user,
      enrollmentToken,
      expiresIn: 900,
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return res.status(409).json({
        message: "That username or email address is already registered.",
      });
    }

    console.error(
      "Admin account creation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to create the account.",
    });
  }
});

// Update account details and role.
router.patch("/users/:id", async (req, res) => {
  const parsed = updateUserSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide valid account fields to update.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const userId = req.params.id;

  if (typeof userId !== "string" || userId.length === 0) {
    return res.status(400).json({ message: "A valid user ID is required." });
  }

  const data = parsed.data;
  const adminId = req.authUser!.id;

  try {
    const existing = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        role: true,
        isActive: true,
      },
    });

    if (!existing) {
      return res.status(404).json({ message: "User account not found." });
    }

    // Prevent an administrator from locking themselves out.
    if (
      existing.id === adminId &&
      (data.isActive === false || (data.role !== undefined && data.role !== "ADMIN"))
    ) {
      return res.status(400).json({
        message: "You cannot deactivate your own account or remove your own administrator role.",
      });
    }

    if (
      existing.role === "ADMIN" &&
      existing.isActive &&
      (data.isActive === false || (data.role !== undefined && data.role !== "ADMIN"))
    ) {
      const activeAdminCount = await prisma.user.count({
        where: { role: "ADMIN", isActive: true },
      });

      if (activeAdminCount <= 1) {
        return res.status(409).json({
          message: "The last active administrator cannot be deactivated or demoted.",
        });
      }
    }

    const updated = await prisma.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id: userId },
        data: {
          ...(data.fullName !== undefined ? { fullName: data.fullName } : {}),
          ...(data.username !== undefined ? { username: data.username.toLowerCase() } : {}),
          ...(data.email !== undefined ? { email: data.email.toLowerCase() } : {}),
          ...(data.role !== undefined ? { role: data.role } : {}),
          ...(data.isActive !== undefined ? { isActive: data.isActive } : {}),
        },
        select: {
          id: true,
          fullName: true,
          username: true,
          email: true,
          role: true,
          isActive: true,
          registrationComplete: true,
          twoFactorEnabled: true,
          updatedAt: true,
        },
      });

      const roleChanged =
        data.role !== undefined && data.role !== existing.role;
      const accountDeactivated = data.isActive === false;

      if (roleChanged || accountDeactivated) {
        await tx.session.deleteMany({
          where: { userId },
        });

        await tx.loginchallenge.deleteMany({
          where: { userId },
        });
      }

      return user;
    });

    await prisma.auditlog.create({
      data: {
        username: req.authUser!.username,

        role: req.authUser!.role,
        action: "ADMIN_USER_UPDATED",
        details: "Administrator updated account details or permissions.",

      },
    });

    return res.status(200).json({
      message: "User account updated successfully.",
      user: updated,
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      return res.status(409).json({
        message: "That username or email address is already in use.",
      });
    }

    console.error(
      "Admin account update failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to update the user account.",
    });
  }
});

// Deactivate an account and revoke its existing sessions.
router.post("/users/:id/deactivate", async (req, res) => {
  const parsed = deactivateSchema.safeParse(req.body ?? {});

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide a valid deactivation reason.",
    });
  }

  const userId = req.params.id;
  const adminId = req.authUser!.id;

  if (typeof userId !== "string" || userId.length === 0) {
    return res.status(400).json({ message: "A valid user ID is required." });
  }

  if (userId === adminId) {
    return res.status(400).json({
      message: "You cannot deactivate your own account.",
    });
  }

  try {
    const target = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, role: true, isActive: true },
    });

    if (!target) {
      return res.status(404).json({ message: "User account not found." });
    }

    if (target.role === "ADMIN" && target.isActive) {
      const activeAdminCount = await prisma.user.count({
        where: { role: "ADMIN", isActive: true },
      });

      if (activeAdminCount <= 1) {
        return res.status(409).json({
          message: "The last active administrator cannot be deactivated.",
        });
      }
    }

    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { isActive: false },
      });

      await tx.session.deleteMany({
        where: { userId },
      });

      await tx.loginchallenge.deleteMany({
        where: { userId },
      });

      await tx.auditlog.create({
        data: {
          username: req.authUser!.username,

          role: req.authUser!.role,
          action: "ADMIN_USER_DEACTIVATED",
          details: parsed.data.reason
            ? `Account deactivated. Reason: ${parsed.data.reason}`
            : "Administrator deactivated the account.",

        },
      });
    });

    return res.status(200).json({
      message: "Account deactivated and existing sessions revoked.",
    });
  } catch (error) {
    console.error(
      "Admin account deactivation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to deactivate the account.",
    });
  }
});

// Permanently delete an eligible account and record the action atomically.
router.delete("/users/:id", async (req, res) => {
  const parsed = permanentDeleteSchema.safeParse(req.body ?? {});

  if (!parsed.success) {
    return res.status(400).json({
      message: "A deletion reason of 1 to 500 characters is required.",
    });
  }

  const userId = req.params.id;
  const adminId = req.authUser!.id;
  const reason = parsed.data.reason;

  if (typeof userId !== "string" || userId.length === 0) {
    return res.status(400).json({
      message: "A valid user ID is required.",
    });
  }

  if (userId === adminId) {
    return res.status(400).json({
      message: "You cannot permanently delete your own account.",
    });
  }

  try {
    const target = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
      },
    });

    if (!target) {
      return res.status(404).json({
        message: "User account not found.",
      });
    }

    if (target.role === "ADMIN") {
      return res.status(403).json({
        message: "Administrator accounts cannot be permanently deleted through this endpoint.",
      });
    }

    const result = await prisma.$transaction(async (tx) => {
      // Preserve artwork and delivery history associated with this account.
      const [artworkCount, assignmentCount] = await Promise.all([
        tx.artwork.count({
          where: { artistId: userId },
        }),
        tx.deliveryassignment.count({
          where: { deliveryManId: userId },
        }),
      ]);

      if (artworkCount > 0) {
        return {
          blocked:
            "This account owns artwork. Deactivate it instead so its artwork records are preserved.",
        };
      }

      if (assignmentCount > 0) {
        return {
          blocked:
            "This account has delivery assignments. Deactivate it instead so its delivery history is preserved.",
        };
      }

      // Record the deleted account before removing it.
      await tx.deleteduseraudit.create({
        data: {
          originalUserId: target.id,
          username: target.username,
          email: target.email,
          role: target.role,
          deletedBy: adminId,
          reason,
        },
      });

      // Remove dependent authentication and personal records.
      await tx.session.deleteMany({
        where: { userId },
      });

      await tx.loginchallenge.deleteMany({
        where: { userId },
      });

      await tx.buyerwishlistitem.deleteMany({
        where: { buyerId: userId },
      });

      await tx.artistprofile.deleteMany({
        where: { userId },
      });

      await tx.buyerprofile.deleteMany({
        where: { userId },
      });

      await tx.deliveryprofile.deleteMany({
        where: { userId },
      });

      await tx.dashboardpreference.deleteMany({
        where: { userId },
      });

      await tx.backupsnapshot.deleteMany({
        where: { ownerId: userId },
      });

      await tx.user.delete({
        where: { id: userId },
      });

      // Keep an administrative audit record of the action.
      await tx.auditlog.create({
        data: {
          username: req.authUser!.username,

          role: req.authUser!.role,
          action: "ADMIN_USER_PERMANENTLY_DELETED",
          details: `Permanently deleted account ${target.username}. Reason: ${reason}`,

        },
      });

      return { blocked: null };
    });

    if (result.blocked) {
      return res.status(409).json({
        message: result.blocked,
      });
    }

    return res.status(200).json({
      message: "Account permanently deleted and recorded in the audit trail.",
    });
  } catch (error) {
    console.error(
      "Admin permanent account deletion failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to permanently delete the account.",
    });
  }
});
// List recorded user activities. This router is restricted to authenticated admins.
router.get("/user-activity", async (req, res) => {
  const parsed = userActivityQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide valid activity pagination values.",
    });
  }

  const { page, limit } = parsed.data;

  try {
    res.setHeader("Cache-Control", "no-store");

    const [activities, total] = await Promise.all([
      prisma.auditlog.findMany({
        orderBy: { createdAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
        select: {
          id: true,
          username: true,
          role: true,
          action: true,
          details: true,
          createdAt: true,
        },
      }),
      prisma.auditlog.count(),
    ]);

    return res.status(200).json({
      activities,
      total,
      page,
      limit,
    });
  } catch (error) {
    console.error(
      "Admin user activity retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve user activity.",
    });
  }
});
// View the deleted-user audit trail with pagination.
router.get("/deleted-users", async (req, res) => {
  const parsed = deletedUserQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide valid pagination values.",
    });
  }

  const { page, limit } = parsed.data;

  try {
    const [deletedUsers, total] = await Promise.all([
      prisma.deleteduseraudit.findMany({
        orderBy: { deletedAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.deleteduseraudit.count(),
    ]);

    return res.status(200).json({
      deletedUsers,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error(
      "Deleted-user audit retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve deleted-user audit records.",
    });
  }
});


// List artist applications for administrator review.
// Only non-sensitive application and profile fields are returned.
const artistApplicationQuerySchema = z.object({
  status: z.enum(["PENDING", "APPROVED", "REJECTED"]).default("PENDING"),
}).strict();

const artistDecisionSchema = z.object({
  status: z.enum(["APPROVED", "REJECTED"]),
}).strict();

router.get("/artist-applications", async (req, res) => {
  const parsed = artistApplicationQuerySchema.safeParse(req.query);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide a valid artist application status.",
    });
  }

  try {
    res.setHeader("Cache-Control", "no-store");

    const applications = await prisma.user.findMany({
      where: {
        role: "ARTIST",
        artistApprovalStatus: parsed.data.status,
      },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        createdAt: true,
        registrationComplete: true,
        isActive: true,
        artistApprovalStatus: true,
      },
    });

    const profiles = applications.length
      ? await prisma.artistprofile.findMany({
          where: {
            userId: {
              in: applications.map((application) => application.id),
            },
          },
          select: {
            userId: true,
            bio: true,
            location: true,
            profileImage: true,
          },
        })
      : [];

    const profileByUserId = new Map(
      profiles.map((profile) => [profile.userId, profile]),
    );

    return res.status(200).json({
      applications: applications.map((application) => {
        const profile = profileByUserId.get(application.id);

        return {
          ...application,
          bio: profile?.bio ?? null,
          location: profile?.location ?? null,
          profileImage: profile?.profileImage ?? null,
        };
      }),
    });
  } catch (error) {
    console.error(
      "Artist application retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve artist applications.",
    });
  }
});

// Approve or reject an artist application.
router.post("/artist-applications/:id/decision", async (req, res) => {
  const parsed = artistDecisionSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Choose APPROVED or REJECTED as the decision.",
    });
  }

  const userId = req.params.id;

  if (typeof userId !== "string" || userId.length === 0) {
    return res.status(400).json({
      message: "A valid artist user ID is required.",
    });
  }

  try {
    const artist = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        role: true,
        isActive: true,
        registrationComplete: true,
        artistApprovalStatus: true,
      },
    });

    if (!artist || artist.role !== "ARTIST") {
      return res.status(404).json({
        message: "Artist application not found.",
      });
    }

    if (
      parsed.data.status === "APPROVED" &&
      (!artist.isActive || !artist.registrationComplete)
    ) {
      return res.status(400).json({
        message: "Only active artists who have completed registration can be approved.",
      });
    }

    if (artist.artistApprovalStatus === parsed.data.status) {
      return res.status(200).json({
        message: `Artist application is already ${parsed.data.status.toLowerCase()}.`,
        application: {
          id: artist.id,
          status: artist.artistApprovalStatus,
        },
      });
    }

    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: artist.id },
        data: {
          artistApprovalStatus: parsed.data.status,
        },
      });

      await tx.auditlog.create({
        data: {
          username: req.authUser!.username,
          role: req.authUser!.role,
          action:
            parsed.data.status === "APPROVED"
              ? "ADMIN_ARTIST_APPROVED"
              : "ADMIN_ARTIST_REJECTED",
          details:
            `Administrator ${req.authUser!.username} ` +
            `${parsed.data.status.toLowerCase()} artist application for ` +
            `${artist.username} (${artist.id}).`,
        },
      });
    });

    return res.status(200).json({
      message: `Artist application ${parsed.data.status.toLowerCase()} successfully.`,
      application: {
        id: artist.id,
        status: parsed.data.status,
      },
    });
  } catch (error) {
    console.error(
      "Artist application decision failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to save the artist application decision.",
    });
  }
});
export default router;



