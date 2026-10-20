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

    return res.status(200).json({ assignments });
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
