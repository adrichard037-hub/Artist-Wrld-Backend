import { Router } from "express";
import { z } from "zod";
import { Prisma } from "../generated/prisma/client.js";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireRole } from "../middleware/auth.js";

const router = Router();

router.use(requireAuth);

const orderSchema = z.object({
  artworkId: z.string().trim().min(1).max(191),
  quantity: z.number().int().min(1).max(100),
  shippingAddress: z.string().trim().min(5).max(2000),
}).strict();

const messageSchema = z.object({
  recipientId: z.string().trim().min(1).max(191),
  subject: z.string().trim().min(1).max(200),
  body: z.string().trim().min(1).max(10000),
}).strict();

const configurationSchema = z.object({
  settings: z.record(z.string(), z.string().max(20000)),
}).strict();

const backupIdSchema = z.object({
  snapshotId: z.string().trim().min(1).max(191),
}).strict();

function isUniqueConstraintError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "P2002"
  );
}

// ------------------------------------------------------------
// ORDERS
// ------------------------------------------------------------

// Administrators see all orders; other roles see only permitted orders.
router.get("/orders", async (req, res) => {
  const user = req.authUser!;

  try {
    let where: Record<string, unknown>;

    if (user.role === "ADMIN") {
      where = {};
    } else if (user.role === "BUYER") {
      where = { buyerId: user.id };
    } else if (user.role === "ARTIST") {
      where = { artistId: user.id };
    } else {
      const assignments = await prisma.deliveryassignment.findMany({
        where: { deliveryManId: user.id },
        select: { orderReference: true },
      });

      const orderIds = assignments
        .map((item) => item.orderReference)
        .filter((id): id is string => Boolean(id));

      where = { id: { in: orderIds } };
    }

    const orders = await prisma.order.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: 200,
    });

    return res.status(200).json({ orders });
  } catch (error) {
    console.error(
      "Order retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve orders.",
    });
  }
});

// Buyers can create orders for published artwork.
// Creating an order does not itself confirm payment.
router.post("/orders", requireRole("BUYER"), async (req, res) => {
  const parsed = orderSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Please provide valid order details.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const buyer = req.authUser!;

  try {
    const artwork = await prisma.artwork.findFirst({
      where: {
        id: parsed.data.artworkId,
        status: "Published",
      },
      select: {
        id: true,
        artistId: true,
        title: true,
        price: true,
      },
    });

    if (!artwork) {
      return res.status(404).json({
        message: "Published artwork was not found.",
      });
    }

    const artist = await prisma.user.findFirst({
      where: {
        id: artwork.artistId,
        role: "ARTIST",
        isActive: true,
        registrationComplete: true,
        artistApprovalStatus: "APPROVED",
      },
      select: { id: true },
    });

    if (!artist) {
      return res.status(409).json({
        message: "This artist is not currently eligible to receive orders.",
      });
    }

    const unitPrice = Number(artwork.price);
    const total = unitPrice * parsed.data.quantity;

    if (
      !Number.isFinite(unitPrice) ||
      !Number.isFinite(total) ||
      unitPrice <= 0
    ) {
      return res.status(409).json({
        message: "The artwork price is invalid.",
      });
    }

    const order = await prisma.order.create({
      data: {
        buyerId: buyer.id,
        artistId: artwork.artistId,
        artworkId: artwork.id,
        artworkTitle: artwork.title,
        quantity: parsed.data.quantity,
        unitPrice: unitPrice.toFixed(2),
        total: total.toFixed(2),
        status: "PENDING",
        shippingAddress: parsed.data.shippingAddress,
      },
    });

    await prisma.auditlog.create({
      data: {
        username: buyer.username,
        role: buyer.role,
        action: "ORDER_CREATED",
        details: `Order ${order.id} was created with status PENDING.`,
      },
    });

    return res.status(201).json({
      message: "Order created. Payment has not been confirmed.",
      order,
    });
  } catch (error) {
    console.error(
      "Order creation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to create the order.",
    });
  }
});

// Only administrators may change order status.
// PAID must only be used after payment has actually been verified.
router.patch(
  "/orders/:id/status",
  requireRole("ADMIN"),
  async (req, res) => {
    const parsed = z.object({
      status: z.enum([
        "PENDING",
        "PAID",
        "PROCESSING",
        "SHIPPED",
        "DELIVERED",
        "CANCELLED",
      ]),
    }).strict().safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: "Choose a valid order status.",
      });
    }

    const orderId = req.params.id;

    if (typeof orderId !== "string" || !orderId) {
      return res.status(400).json({
        message: "A valid order ID is required.",
      });
    }

    try {
      const existing = await prisma.order.findUnique({
        where: { id: orderId },
        select: { id: true, status: true },
      });

      if (!existing) {
        return res.status(404).json({
          message: "Order not found.",
        });
      }

      const order = await prisma.order.update({
        where: { id: existing.id },
        data: { status: parsed.data.status },
      });

      await prisma.auditlog.create({
        data: {
          username: req.authUser!.username,
          role: req.authUser!.role,
          action: "ORDER_STATUS_UPDATED",
          details: `Order ${order.id} status changed from ${existing.status} to ${order.status}.`,
        },
      });

      return res.status(200).json({
        message: "Order status updated.",
        order,
      });
    } catch (error) {
      console.error(
        "Order status update failed:",
        error instanceof Error ? error.message : "Unknown error",
      );

      return res.status(500).json({
        message: "Unable to update order status.",
      });
    }
  },
);

// Sales summary. Only completed/paid orders count as sales.
router.get("/sales-summary", requireRole("ADMIN"), async (_req, res) => {
  try {
    const [orders, artworkCount, userCount] = await Promise.all([
      prisma.order.findMany({
        where: {
          status: { in: ["PAID", "PROCESSING", "SHIPPED", "DELIVERED"] },
        },
        select: {
          total: true,
          quantity: true,
          status: true,
        },
      }),
      prisma.artwork.count(),
      prisma.user.count(),
    ]);

    const salesTotal = orders.reduce(
      (sum, order) => sum + Number(order.total),
      0,
    );

    const unitsSold = orders.reduce(
      (sum, order) => sum + order.quantity,
      0,
    );

    return res.status(200).json({
      salesTotal: Number(salesTotal.toFixed(2)),
      paidOrderCount: orders.length,
      unitsSold,
      artworkCount,
      userCount,
      currency: "GHS",
    });
  } catch (error) {
    console.error(
      "Sales summary failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve sales totals.",
    });
  }
});

// ------------------------------------------------------------
// MESSAGES
// ------------------------------------------------------------

// Users can see messages they sent or received.
// Administrators can see all messages.
router.get("/messages", async (req, res) => {
  const user = req.authUser!;

  try {
    const messages = await prisma.message.findMany({
      where: user.role === "ADMIN"
        ? {}
        : {
            OR: [
              { senderId: user.id },
              { recipientId: user.id },
            ],
          },
      orderBy: { createdAt: "desc" },
      take: 200,
    });

    return res.status(200).json({ messages });
  } catch (error) {
    console.error(
      "Message retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve messages.",
    });
  }
});

router.post("/messages", async (req, res) => {
  const parsed = messageSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Please provide a recipient, subject, and message.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const sender = req.authUser!;

  try {
    const recipient = await prisma.user.findFirst({
      where: {
        id: parsed.data.recipientId,
        isActive: true,
      },
      select: { id: true },
    });

    if (!recipient) {
      return res.status(404).json({
        message: "The recipient account is unavailable.",
      });
    }

    const message = await prisma.message.create({
      data: {
        senderId: sender.id,
        recipientId: recipient.id,
        subject: parsed.data.subject,
        body: parsed.data.body,
      },
    });

    await prisma.auditlog.create({
      data: {
        username: sender.username,
        role: sender.role,
        action: "MESSAGE_SENT",
        details: "A dashboard message was sent.",
      },
    });

    return res.status(201).json({
      message: "Message sent successfully.",
      item: message,
    });
  } catch (error) {
    console.error(
      "Message creation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to send the message.",
    });
  }
});

router.patch("/messages/:id/read", async (req, res) => {
  const user = req.authUser!;
  const messageId = req.params.id;

  if (typeof messageId !== "string" || !messageId) {
    return res.status(400).json({
      message: "A valid message ID is required.",
    });
  }

  try {
    const existing = await prisma.message.findUnique({
      where: { id: messageId },
      select: {
        id: true,
        recipientId: true,
      },
    });

    if (!existing) {
      return res.status(404).json({
        message: "Message not found.",
      });
    }

    if (user.role !== "ADMIN" && existing.recipientId !== user.id) {
      return res.status(403).json({
        message: "You cannot mark another user's message as read.",
      });
    }

    const message = await prisma.message.update({
      where: { id: existing.id },
      data: { readAt: new Date() },
    });

    return res.status(200).json({
      message: "Message marked as read.",
      item: message,
    });
  } catch (error) {
    console.error(
      "Mark message as read failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to update the message.",
    });
  }
});

// ------------------------------------------------------------
// ADMIN CONFIGURATION
// ------------------------------------------------------------

router.get(
  "/configuration",
  requireRole("ADMIN"),
  async (_req, res) => {
    try {
      const settings = await prisma.configurationsetting.findMany({
        orderBy: { key: "asc" },
        select: {
          key: true,
          value: true,
          updatedAt: true,
        },
      });

      return res.status(200).json({ settings });
    } catch (error) {
      console.error(
        "Configuration retrieval failed:",
        error instanceof Error ? error.message : "Unknown error",
      );

      return res.status(500).json({
        message: "Unable to retrieve configuration settings.",
      });
    }
  },
);

router.put(
  "/configuration",
  requireRole("ADMIN"),
  async (req, res) => {
    const parsed = configurationSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: "Provide valid configuration settings.",
      });
    }

    const allowedKeys = new Set([
      "siteName",
      "registrationEnabled",
      "theme",
      "commission",
    ]);

    const entries = Object.entries(parsed.data.settings);

    if (
      entries.length === 0 ||
      entries.length > 30 ||
      entries.some(([key]) => !allowedKeys.has(key))
    ) {
      return res.status(400).json({
        message: "One or more configuration keys are not permitted.",
        allowedKeys: [...allowedKeys],
      });
    }

    try {
      const saved = await prisma.$transaction(
        entries.map(([key, value]) =>
          prisma.configurationsetting.upsert({
            where: { key },
            create: { key, value },
            update: { value },
            select: { key: true, value: true, updatedAt: true },
          }),
        ),
      );

      await prisma.auditlog.create({
        data: {
          username: req.authUser!.username,
          role: req.authUser!.role,
          action: "ADMIN_CONFIGURATION_UPDATED",
          details: `Administrator updated ${saved.length} configuration setting(s).`,
        },
      });

      return res.status(200).json({
        message: "Configuration settings saved.",
        settings: saved,
      });
    } catch (error) {
      console.error(
        "Configuration update failed:",
        error instanceof Error ? error.message : "Unknown error",
      );

      return res.status(500).json({
        message: "Unable to save configuration settings.",
      });
    }
  },
);

// ------------------------------------------------------------
// BACKUP SNAPSHOTS
// ------------------------------------------------------------

// This initial backup implementation stores an exportable snapshot.
// It excludes passwords, salts, 2FA secrets, and session tokens.
router.post("/backup", async (req, res) => {
  const user = req.authUser!;

  try {
    const data: Record<string, unknown> = {};

    data.preferences = await prisma.dashboardpreference.findMany({
      where: { userId: user.id },
      select: { key: true, value: true },
    });

    if (user.role === "ADMIN") {
      data.configuration = await prisma.configurationsetting.findMany({
        select: { key: true, value: true },
      });

      data.artworks = await prisma.artwork.findMany();
      data.deliveries = await prisma.deliveryassignment.findMany();
      data.orders = await prisma.order.findMany();
      data.messages = await prisma.message.findMany();
    } else if (user.role === "ARTIST") {
      data.profile = await prisma.artistprofile.findUnique({
        where: { userId: user.id },
      });

      data.artworks = await prisma.artwork.findMany({
        where: { artistId: user.id },
      });

      data.orders = await prisma.order.findMany({
        where: { artistId: user.id },
      });

      data.messages = await prisma.message.findMany({
        where: {
          OR: [
            { senderId: user.id },
            { recipientId: user.id },
          ],
        },
      });
    } else if (user.role === "BUYER") {
      data.profile = await prisma.buyerprofile.findUnique({
        where: { userId: user.id },
      });

      data.wishlist = await prisma.buyerwishlistitem.findMany({
        where: { buyerId: user.id },
      });

      data.orders = await prisma.order.findMany({
        where: { buyerId: user.id },
      });

      data.messages = await prisma.message.findMany({
        where: {
          OR: [
            { senderId: user.id },
            { recipientId: user.id },
          ],
        },
      });
    } else {
      data.profile = await prisma.deliveryprofile.findUnique({
        where: { userId: user.id },
      });

      data.deliveries = await prisma.deliveryassignment.findMany({
        where: { deliveryManId: user.id },
      });

      data.messages = await prisma.message.findMany({
        where: {
          OR: [
            { senderId: user.id },
            { recipientId: user.id },
          ],
        },
      });
    }

    const payload: Prisma.InputJsonValue = JSON.parse(JSON.stringify({
      format: "artist-wrld-backup-v1",
      ownerId: user.id,
      ownerRole: user.role,
      createdAt: new Date().toISOString(),
      data,
    }));

    const snapshot = await prisma.backupsnapshot.create({
      data: {
        ownerId: user.id,
        ownerRole: user.role,
        format: "artist-wrld-backup-v1",
        payload,
      },
      select: {
        id: true,
        format: true,
        createdAt: true,
      },
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,
        role: user.role,
        action: "BACKUP_CREATED",
        details: "A role-scoped backup snapshot was created.",
      },
    });

    res.setHeader("Cache-Control", "no-store");

    return res.status(201).json({
      message: "Backup created successfully.",
      snapshot,
      backup: payload,
    });
  } catch (error) {
    console.error(
      "Backup creation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to create a backup.",
    });
  }
});

// List only snapshots owned by the signed-in account.
router.get("/backups", async (req, res) => {
  const user = req.authUser!;

  try {
    const snapshots = await prisma.backupsnapshot.findMany({
      where: { ownerId: user.id, ownerRole: user.role },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        format: true,
        createdAt: true,
      },
      take: 50,
    });

    return res.status(200).json({ snapshots });
  } catch (error) {
    console.error(
      "Backup listing failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve backups.",
    });
  }
});

// Restore only from a snapshot owned by this same account and role.
// Restoration is create-only: existing records are never updated.
router.post("/restore", async (req, res) => {
  const parsed = backupIdSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide a valid backup snapshot ID.",
    });
  }

  const user = req.authUser!;

  try {
    const snapshot = await prisma.backupsnapshot.findFirst({
      where: {
        id: parsed.data.snapshotId,
        ownerId: user.id,
        ownerRole: user.role,
        format: "artist-wrld-backup-v1",
      },
    });

    if (!snapshot || !snapshot.payload || typeof snapshot.payload !== "object") {
      return res.status(404).json({
        message: "Backup not found for this account.",
      });
    }

    const payload = snapshot.payload as {
      format?: string;
      ownerId?: string;
      ownerRole?: string;
      data?: Record<string, unknown>;
    };

    if (
      payload.format !== "artist-wrld-backup-v1" ||
      payload.ownerId !== user.id ||
      payload.ownerRole !== user.role ||
      !payload.data ||
      typeof payload.data !== "object" ||
      Array.isArray(payload.data)
    ) {
      return res.status(400).json({
        message: "The backup structure is invalid.",
      });
    }

    const data = payload.data;
    const restored: Record<string, number> = {};

    const isRecord = (value: unknown): value is Record<string, unknown> =>
      typeof value === "object" && value !== null && !Array.isArray(value);

    const rows = (value: unknown): Record<string, unknown>[] =>
      Array.isArray(value) ? value.filter(isRecord) : [];

    const stringValue = (value: unknown): value is string =>
      typeof value === "string";

    const optionalString = (value: unknown): string | null =>
      typeof value === "string" ? value : null;

    const validDate = (value: unknown): Date | undefined => {
      if (typeof value !== "string") return undefined;
      const parsedDate = new Date(value);
      return Number.isNaN(parsedDate.getTime()) ? undefined : parsedDate;
    };

    const validMoney = (value: unknown): boolean => {
      if (typeof value !== "string" && typeof value !== "number") {
        return false;
      }

      const raw = String(value).trim();

      if (!/^\d{1,10}(?:\.\d{1,2})?$/.test(raw)) {
        return false;
      }

      const amount = Number(raw);

      return Number.isFinite(amount) &&
        amount > 0 &&
        amount <= 9999999999.99;
    };

    const moneyToMinorUnits = (value: unknown): number | undefined => {
      if (!validMoney(value)) return undefined;

      const amount = Number(value);
      const minorUnits = Math.round(amount * 100);

      return Number.isSafeInteger(minorUnits) ? minorUnits : undefined;
    };

    const orderTotalMatches = (
      unitPrice: unknown,
      quantity: unknown,
      total: unknown,
    ): boolean => {
      if (
        !Number.isSafeInteger(quantity) ||
        typeof quantity !== "number" ||
        quantity <= 0
      ) {
        return false;
      }

      const unitPriceMinor = moneyToMinorUnits(unitPrice);
      const totalMinor = moneyToMinorUnits(total);

      if (unitPriceMinor === undefined || totalMinor === undefined) {
        return false;
      }

      const expectedTotal = unitPriceMinor * quantity;

      return Number.isSafeInteger(expectedTotal) &&
        expectedTotal === totalMinor;
    };

    await prisma.$transaction(async (tx) => {
      // Preferences are restored for the signed-in account only.
      const preferences = rows(data.preferences)
        .filter(
          (item) =>
            stringValue(item.key) &&
            item.key.length > 0 &&
            item.key.length <= 100 &&
            stringValue(item.value),
        )
        .map((item) => ({
          userId: user.id,
          key: item.key as string,
          value: item.value as string,
        }));

      if (preferences.length) {
        const result = await tx.dashboardpreference.createMany({
          data: preferences,
          skipDuplicates: true,
        });
        restored.preferences = result.count;
      }

      // Restore only the profile belonging to the current account and role.
      if (isRecord(data.profile)) {
        const profile = data.profile;

        if (user.role === "ARTIST") {
          const bio = optionalString(profile.bio);
          const location = optionalString(profile.location);
          const profileImage = optionalString(profile.profileImage);

          const result = await tx.artistprofile.createMany({
            data: [{
              ...(stringValue(profile.id) ? { id: profile.id } : {}),
              userId: user.id,
              bio,
              location,
              profileImage,
            }] as never,
            skipDuplicates: true,
          });
          restored.profile = result.count;
        } else if (user.role === "BUYER") {
          const result = await tx.buyerprofile.createMany({
            data: [{
              ...(stringValue(profile.id) ? { id: profile.id } : {}),
              userId: user.id,
              location: optionalString(profile.location),
              profileImage: optionalString(profile.profileImage),
            }] as never,
            skipDuplicates: true,
          });
          restored.profile = result.count;
        } else if (user.role === "DELIVERY_MAN") {
          const result = await tx.deliveryprofile.createMany({
            data: [{
              ...(stringValue(profile.id) ? { id: profile.id } : {}),
              userId: user.id,
              phone: optionalString(profile.phone),
              serviceArea: optionalString(profile.serviceArea),
              avatar: optionalString(profile.avatar),
            }] as never,
            skipDuplicates: true,
          });
          restored.profile = result.count;
        }
      }

      // Administrators may restore system configuration.
      // Existing values are deliberately not overwritten.
      if (user.role === "ADMIN") {
        const settings = rows(data.configuration)
          .filter(
            (item) =>
              stringValue(item.key) &&
              ["siteName", "registrationEnabled", "theme", "commission"].includes(item.key) &&
              stringValue(item.value),
          )
          .map((item) => ({
            key: item.key as string,
            value: item.value as string,
          }));

        if (settings.length) {
          const result = await tx.configurationsetting.createMany({
            data: settings,
            skipDuplicates: true,
          });
          restored.configuration = result.count;
        }
      }

      // Restore artwork only for the owning artist, or through the
      // restricted administrator-wide workflow.
      if (user.role === "ADMIN" || user.role === "ARTIST") {
        const artworkRows = rows(data.artworks).filter((item) =>
          stringValue(item.id) &&
          stringValue(item.artistId) &&
          stringValue(item.title) &&
          item.title.length <= 150 &&
          stringValue(item.category) &&
          item.category.length <= 80 &&
          validMoney(item.price) &&
          (
            item.status === undefined ||
            item.status === null ||
            item.status === "" ||
            item.status === "Draft" ||
            item.status === "Published"
          ) &&
          (user.role === "ADMIN" || item.artistId === user.id),
        );

        const artistIds = [
          ...new Set(artworkRows.map((item) => item.artistId as string)),
        ];

        const existingArtists = artistIds.length
          ? await tx.user.findMany({
              where: { id: { in: artistIds }, role: "ARTIST" },
              select: { id: true },
            })
          : [];

        const validArtistIds = new Set(existingArtists.map((artist) => artist.id));

        const artworkData = artworkRows
          .filter((item) => validArtistIds.has(item.artistId as string))
          .map((item) => ({
            id: item.id as string,
            artistId: item.artistId as string,
            title: item.title as string,
            category: item.category as string,
            description: optionalString(item.description),
            price: String(item.price),
            image: optionalString(item.image),
            status: stringValue(item.status) ? item.status : "Draft",
            views: typeof item.views === "number" && Number.isInteger(item.views) && item.views >= 0
              ? item.views : 0,
            sales: typeof item.sales === "number" && Number.isInteger(item.sales) && item.sales >= 0
              ? item.sales : 0,
            ...(validDate(item.createdAt) ? { createdAt: validDate(item.createdAt) } : {}),
            ...(validDate(item.updatedAt) ? { updatedAt: validDate(item.updatedAt) } : {}),
          }));

        if (artworkData.length) {
          const result = await tx.artwork.createMany({
            data: artworkData as never,
            skipDuplicates: true,
          });
          restored.artworks = result.count;
        }
      }

      // Buyer wishlists are restricted to the current buyer.
      // Do not recreate wishlist entries whose artwork no longer exists.
      if (user.role === "BUYER") {
        const wishlistRows = rows(data.wishlist).filter(
          (item) =>
            stringValue(item.artworkId) &&
            (item.buyerId === undefined || item.buyerId === user.id),
        );

        const artworkIds = [
          ...new Set(wishlistRows.map((item) => item.artworkId as string)),
        ];

        const existingArtwork = artworkIds.length
          ? await tx.artwork.findMany({
              where: { id: { in: artworkIds } },
              select: { id: true },
            })
          : [];

        const validArtworkIds = new Set(existingArtwork.map((item) => item.id));

        const wishlistData = wishlistRows
          .filter((item) => validArtworkIds.has(item.artworkId as string))
          .map((item) => ({
            ...(stringValue(item.id) ? { id: item.id } : {}),
            buyerId: user.id,
            artworkId: item.artworkId as string,
            ...(validDate(item.createdAt) ? { createdAt: validDate(item.createdAt) } : {}),
          }));

        if (wishlistData.length) {
          const result = await tx.buyerwishlistitem.createMany({
            data: wishlistData as never,
            skipDuplicates: true,
          });
          restored.wishlist = result.count;
        }
      }

      // Restore orders only within the role's permitted scope.
      if (
        user.role === "ADMIN" ||
        user.role === "ARTIST" ||
        user.role === "BUYER"
      ) {
        const orderRows = rows(data.orders).filter((item) =>
          stringValue(item.id) &&
          stringValue(item.buyerId) &&
          stringValue(item.artistId) &&
          stringValue(item.artworkId) &&
          stringValue(item.artworkTitle) &&
          item.artworkTitle.length <= 150 &&
          (typeof item.quantity === "number") &&
          Number.isInteger(item.quantity) &&
          item.quantity > 0 &&
          orderTotalMatches(item.unitPrice, item.quantity, item.total) &&
          (
            item.status === undefined ||
            item.status === null ||
            item.status === "" ||
            item.status === "PENDING" ||
            item.status === "PAID" ||
            item.status === "PROCESSING" ||
            item.status === "SHIPPED" ||
            item.status === "DELIVERED" ||
            item.status === "CANCELLED"
          ) &&
          stringValue(item.shippingAddress) &&
          (user.role === "ADMIN" ||
            (user.role === "ARTIST" && item.artistId === user.id) ||
            (user.role === "BUYER" && item.buyerId === user.id)),
        );

        const orderUserIds = [
          ...new Set(orderRows.flatMap((item) => [
            item.buyerId as string,
            item.artistId as string,
          ])),
        ];

        // Validate both user existence and the required role.
        const existingOrderUsers = orderUserIds.length
          ? await tx.user.findMany({
              where: { id: { in: orderUserIds } },
              select: { id: true, role: true },
            })
          : [];

        const validBuyerIds = new Set(
          existingOrderUsers
            .filter((item) => item.role === "BUYER")
            .map((item) => item.id),
        );

        const validArtistIdsForOrders = new Set(
          existingOrderUsers
            .filter((item) => item.role === "ARTIST")
            .map((item) => item.id),
        );

        // Verify that each referenced artwork still exists and belongs
        // to the artist recorded on the order.
        const orderArtworkIds = [
          ...new Set(orderRows.map((item) => item.artworkId as string)),
        ];

        const existingOrderArtworks = orderArtworkIds.length
          ? await tx.artwork.findMany({
              where: { id: { in: orderArtworkIds } },
              select: { id: true, artistId: true },
            })
          : [];

        const artworkArtistById = new Map(
          existingOrderArtworks.map((item) => [item.id, item.artistId]),
        );

        const orderData = orderRows
          .filter((item) =>
            validBuyerIds.has(item.buyerId as string) &&
            validArtistIdsForOrders.has(item.artistId as string) &&
            artworkArtistById.get(item.artworkId as string) === item.artistId,
          )
          .map((item) => ({
            id: item.id as string,
            buyerId: item.buyerId as string,
            artistId: item.artistId as string,
            artworkId: item.artworkId as string,
            artworkTitle: item.artworkTitle as string,
            quantity: item.quantity as number,
            unitPrice: String(item.unitPrice),
            total: String(item.total),
            status: stringValue(item.status) ? item.status : "PENDING",
            shippingAddress: item.shippingAddress as string,
            ...(validDate(item.createdAt) ? { createdAt: validDate(item.createdAt) } : {}),
            ...(validDate(item.updatedAt) ? { updatedAt: validDate(item.updatedAt) } : {}),
          }));
        if (orderData.length) {
          const result = await tx.order.createMany({
            data: orderData as never,
            skipDuplicates: true,
          });
          restored.orders = result.count;
        }
      }

      // Delivery workers can restore only their own assignments.
      // Administrators can restore the assignments in their own snapshot.
      if (user.role === "ADMIN" || user.role === "DELIVERY_MAN") {
        const deliveryRows = rows(data.deliveries).filter((item) =>
          stringValue(item.id) &&
          stringValue(item.deliveryManId) &&
          (
            item.orderReference == null ||
            (
              typeof item.orderReference === "string" &&
              item.orderReference.length <= 100
            )
          ) &&
          (
            item.status == null ||
            ["Assigned", "Picked Up", "In Transit", "Delivered"].includes(
              item.status as string,
            )
          ) &&
          stringValue(item.artworkTitle) &&
          item.artworkTitle.length <= 150 &&
          stringValue(item.customerName) &&
          item.customerName.length <= 150 &&
          stringValue(item.pickup) &&
          item.pickup.length <= 255 &&
          stringValue(item.destination) &&
          item.destination.length <= 255 &&
          (user.role === "ADMIN" || item.deliveryManId === user.id),
        );

        const deliveryManIds = [
          ...new Set(deliveryRows.map((item) => item.deliveryManId as string)),
        ];

        const existingDeliveryUsers = deliveryManIds.length
          ? await tx.user.findMany({
              where: { id: { in: deliveryManIds }, role: "DELIVERY_MAN" },
              select: { id: true },
            })
          : [];

        const validDeliveryIds = new Set(existingDeliveryUsers.map((item) => item.id));

        const deliveryData = deliveryRows
          .filter((item) => validDeliveryIds.has(item.deliveryManId as string))
          .map((item) => ({
            id: item.id as string,
            deliveryManId: item.deliveryManId as string,
            orderReference: optionalString(item.orderReference),
            artworkTitle: item.artworkTitle as string,
            customerName: item.customerName as string,
            pickup: item.pickup as string,
            destination: item.destination as string,
            scheduledDate: validDate(item.scheduledDate) ?? null,
            status: stringValue(item.status) ? item.status : "Assigned",
            ...(validDate(item.createdAt) ? { createdAt: validDate(item.createdAt) } : {}),
            ...(validDate(item.updatedAt) ? { updatedAt: validDate(item.updatedAt) } : {}),
          }));

        if (deliveryData.length) {
          const result = await tx.deliveryassignment.createMany({
            data: deliveryData as never,
            skipDuplicates: true,
          });
          restored.deliveries = result.count;
        }
      }

      // Messages are restricted to the current account, except for admins
      // restoring their administrator-owned system snapshot.
      const messageRows = rows(data.messages).filter((item) =>
        stringValue(item.id) &&
        stringValue(item.senderId) &&
        stringValue(item.recipientId) &&
        stringValue(item.subject) &&
        item.subject.length <= 200 &&
        stringValue(item.body) &&
        (user.role === "ADMIN" ||
          item.senderId === user.id ||
          item.recipientId === user.id),
      );

      const messageUserIds = [
        ...new Set(messageRows.flatMap((item) => [
          item.senderId as string,
          item.recipientId as string,
        ])),
      ];

      const existingMessageUsers = messageUserIds.length
        ? await tx.user.findMany({
            where: { id: { in: messageUserIds } },
            select: { id: true },
          })
        : [];

      const validMessageUserIds = new Set(existingMessageUsers.map((item) => item.id));

      const messageData = messageRows
        .filter((item) =>
          validMessageUserIds.has(item.senderId as string) &&
          validMessageUserIds.has(item.recipientId as string),
        )
        .map((item) => ({
          id: item.id as string,
          senderId: item.senderId as string,
          recipientId: item.recipientId as string,
          subject: item.subject as string,
          body: item.body as string,
          readAt: validDate(item.readAt) ?? null,
          ...(validDate(item.createdAt) ? { createdAt: validDate(item.createdAt) } : {}),
        }));

      if (messageData.length) {
        const result = await tx.message.createMany({
          data: messageData as never,
          skipDuplicates: true,
        });
        restored.messages = result.count;
      }
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,
        role: user.role,
        action: "BACKUP_RESTORED",
        details: "A role-scoped backup was merged without updating existing records.",
      },
    });

    return res.status(200).json({
      message: "Restore completed. Existing records were not overwritten.",
      restored,
    });
  } catch (error) {
    console.error(
      "Backup restore failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to restore this backup.",
    });
  }
});
export default router;


