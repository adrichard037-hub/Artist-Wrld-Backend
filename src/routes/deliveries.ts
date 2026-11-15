import { Router } from "express";
import type { Response } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireRole } from "../middleware/auth.js";

const router = Router();

router.use(requireAuth);

const createAssignmentSchema = z.object({
  deliveryManId: z.string().trim().min(1).max(191),
  orderReference: z.string().trim().max(100).nullable().optional(),
  artworkTitle: z.string().trim().min(1).max(150),
  customerName: z.string().trim().min(1).max(150),
  pickup: z.string().trim().min(1).max(255),
  destination: z.string().trim().min(1).max(255),
  scheduledDate: z.string().datetime().nullable().optional(),
}).strict();

const statusSchema = z.object({
  status: z.enum(["Assigned", "Picked Up", "In Transit", "Delivered"]),
}).strict();

// Delivery workers see their own assignments; administrators can see all.
router.get("/", requireRole("DELIVERY_MAN", "ADMIN"), async (req, res) => {
  const user = req.authUser!;

  try {
    const assignments = await prisma.deliveryassignment.findMany({
      where: user.role === "ADMIN" ? {} : { deliveryManId: user.id },
      orderBy: { createdAt: "desc" },
    });

    const workerIds = [
      ...new Set(assignments.map((assignment) => assignment.deliveryManId)),
    ];
    const workers = workerIds.length
      ? await prisma.user.findMany({
          where: { id: { in: workerIds } },
          select: { id: true, fullName: true, username: true },
        })
      : [];
    const workerNameById = new Map(
      workers.map((worker) => [worker.id, worker.fullName || worker.username]),
    );

    return res.status(200).json({
      assignments: assignments.map((assignment) => ({
        ...assignment,
        deliveryManName: workerNameById.get(assignment.deliveryManId) ?? null,
      })),
    });
  } catch (error) {
    console.error(
      "Delivery assignment retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve delivery assignments.",
    });
  }
});

// Only administrators can create assignments.
router.post("/", requireRole("ADMIN"), async (req, res) => {
  const parsed = createAssignmentSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Please check the delivery assignment details.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const data = parsed.data;
  const admin = req.authUser!;

  try {
    const deliveryWorker = await prisma.user.findFirst({
      where: {
        id: data.deliveryManId,
        role: "DELIVERY_MAN",
        isActive: true,
        registrationComplete: true,
      },
      select: { id: true },
    });

    if (!deliveryWorker) {
      return res.status(400).json({
        message: "The selected delivery worker is unavailable.",
      });
    }

    const assignment = await prisma.deliveryassignment.create({
      data: {
        deliveryManId: deliveryWorker.id,
        orderReference: data.orderReference ?? null,
        artworkTitle: data.artworkTitle,
        customerName: data.customerName,
        pickup: data.pickup,
        destination: data.destination,
        scheduledDate: data.scheduledDate
          ? new Date(data.scheduledDate)
          : null,
      },
    });

    await prisma.auditlog.create({
      data: {
        username: admin.username,

        role: admin.role,
        action: "DELIVERY_ASSIGNMENT_CREATED",
        details: "Administrator created a delivery assignment.",
      },
    });

    return res.status(201).json({
      message: "Delivery assignment created successfully.",
      assignment,
    });
  } catch (error) {
    console.error(
      "Delivery assignment creation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to create the delivery assignment.",
    });
  }
});

const fromOrderSchema = z.object({
  orderId: z.string().trim().min(1).max(191),
  deliveryManId: z.string().trim().min(1).max(191),
  scheduledDate: z.string().datetime().nullable().optional(),
}).strict();

// Administrators create a delivery assignment straight from a paid order.
// Pickup, destination and customer details are copied from the order itself.
router.post("/from-order", requireRole("ADMIN"), async (req, res) => {
  const parsed = fromOrderSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Choose an order and a delivery worker.",
    });
  }

  const data = parsed.data;
  const admin = req.authUser!;

  try {
    const order = await prisma.order.findUnique({
      where: { id: data.orderId },
    });

    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }

    if (order.status !== "PAID" && order.status !== "PROCESSING") {
      return res.status(409).json({
        message:
          "Only paid orders can be sent for delivery. Mark the order as PAID after payment is verified.",
      });
    }

    const activeAssignment = await prisma.deliveryassignment.findFirst({
      where: { orderReference: order.id },
      select: { id: true },
    });

    if (activeAssignment) {
      return res.status(409).json({
        message: "This order already has a delivery assignment.",
      });
    }

    const [deliveryWorker, buyer, artistProfile, artist] = await Promise.all([
      prisma.user.findFirst({
        where: {
          id: data.deliveryManId,
          role: "DELIVERY_MAN",
          isActive: true,
          registrationComplete: true,
        },
        select: { id: true },
      }),
      prisma.user.findUnique({
        where: { id: order.buyerId },
        select: { fullName: true, username: true },
      }),
      prisma.artistprofile.findUnique({
        where: { userId: order.artistId },
        select: { location: true },
      }),
      prisma.user.findUnique({
        where: { id: order.artistId },
        select: { fullName: true, username: true },
      }),
    ]);

    if (!deliveryWorker) {
      return res.status(400).json({
        message: "The selected delivery worker is unavailable.",
      });
    }

    const artistName = artist?.fullName || artist?.username || "the artist";
    const pickup = (
      artistProfile?.location?.trim()
        ? `${artistName} - ${artistProfile.location.trim()}`
        : `Collect from ${artistName}`
    ).slice(0, 255);

    const [assignment] = await prisma.$transaction([
      prisma.deliveryassignment.create({
        data: {
          deliveryManId: deliveryWorker.id,
          orderReference: order.id,
          artworkTitle: order.artworkTitle.slice(0, 150),
          customerName: (buyer?.fullName || buyer?.username || "Customer").slice(0, 150),
          pickup,
          destination: order.shippingAddress.replace(/\s+/g, " ").trim().slice(0, 255),
          scheduledDate: data.scheduledDate ? new Date(data.scheduledDate) : null,
        },
      }),
      prisma.order.update({
        where: { id: order.id },
        data: { status: "PROCESSING" },
      }),
      prisma.auditlog.create({
        data: {
          username: admin.username,
          role: admin.role,
          action: "DELIVERY_ASSIGNED_FROM_ORDER",
          details: `Order ${order.id} assigned for delivery.`,
        },
      }),
    ]);

    return res.status(201).json({
      message: "Delivery assigned and the order is now processing.",
      assignment,
    });
  } catch (error) {
    console.error(
      "Delivery assignment from order failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to assign the delivery.",
    });
  }
});

// Delivery workers can update only their own assignments.
// Administrators can update any assignment.
router.patch("/:id/status", requireRole("DELIVERY_MAN", "ADMIN"), async (req, res: Response) => {
  const parsed = statusSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Choose a valid delivery status.",
    });
  }

  const user = req.authUser!;
  const assignmentId = req.params.id;

  if (typeof assignmentId !== "string" || assignmentId.length === 0) {
    return res.status(400).json({
      message: "A valid delivery assignment ID is required.",
    });
  }

  try {
    const existing = await prisma.deliveryassignment.findFirst({
      where: {
        id: assignmentId,
        ...(user.role === "DELIVERY_MAN"
          ? { deliveryManId: user.id }
          : {}),
      },
      select: {
        id: true,
        status: true,
      },
    });

    if (!existing) {
      return res.status(404).json({
        message: "Delivery assignment not found in your permitted records.",
      });
    }

    const assignment = await prisma.deliveryassignment.update({
      where: { id: existing.id },
      data: { status: parsed.data.status },
    });

    // Keep the linked order in step with the delivery so buyers, artists and
    // admins all see the same progress. Unpaid or cancelled orders are left alone.
    if (assignment.orderReference) {
      const orderStatusForDelivery: Record<string, string> = {
        Assigned: "PROCESSING",
        "Picked Up": "SHIPPED",
        "In Transit": "SHIPPED",
        Delivered: "DELIVERED",
      };
      const nextOrderStatus = orderStatusForDelivery[assignment.status];

      if (nextOrderStatus) {
        await prisma.order.updateMany({
          where: {
            id: assignment.orderReference,
            status: { notIn: ["PENDING", "CANCELLED"] },
          },
          data: { status: nextOrderStatus },
        });
      }
    }

    await prisma.auditlog.create({
      data: {
        username: user.username,

        role: user.role,
        action: "DELIVERY_STATUS_UPDATED",
        details: `Delivery status changed from "${existing.status}" to "${assignment.status}".`,
      },
    });

    return res.status(200).json({
      message: "Delivery status updated successfully.",
      assignment,
    });
  } catch (error) {
    console.error(
      "Delivery status update failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to update the delivery status.",
    });
  }
});

export default router;
