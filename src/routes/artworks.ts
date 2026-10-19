import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireRole, requireRegisteredArtist } from "../middleware/auth.js";

const router = Router();

 // Public catalog: visitors can browse published artwork without signing in.
router.get("/public", async (_req, res) => {
  try {
    const artworks = await prisma.artwork.findMany({
      where: { status: "Published" },
      orderBy: { createdAt: "desc" },
    });

    const artistIds = [...new Set(artworks.map((artwork) => artwork.artistId))];

    const artists = artistIds.length > 0
      ? await prisma.user.findMany({
          where: {
            id: { in: artistIds },
            role: "ARTIST",
            isActive: true,
          },
          select: {
            id: true,
            fullName: true,
          },
        })
      : [];

    const artistNames = new Map(
      artists.map((artist) => [artist.id, artist.fullName]),
    );

    const publicArtworks = artworks
      .filter((artwork) => artistNames.has(artwork.artistId))
      .map((artwork) => ({
        ...artwork,
        price: Number(artwork.price),
        artist: artistNames.get(artwork.artistId),
      }));

    return res.status(200).json({ artworks: publicArtworks });
  } catch (error) {
    console.error(
      "Public artwork retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve published artwork.",
    });
  }
});


router.use(requireAuth);

const artworkSchema = z.object({
  title: z.string().trim().min(1).max(150),
  category: z.string().trim().min(1).max(80),
  description: z.string().max(10000).nullable().optional(),
  price: z.number().finite().positive().max(9999999999.99),
  image: z.string().max(7_500_000).refine(
    (value) => {
      if (value.startsWith("data:")) {
        return /^data:image\/(?:png|jpeg|webp|gif|avif);base64,[A-Za-z0-9+/]+={0,2}$/.test(value);
      }

      try {
        const parsed = new URL(value);
        return parsed.protocol === "https:" || parsed.protocol === "http:";
      } catch {
        return false;
      }
    },
    "Provide a valid image URL or supported Base64 image.",
  ).nullable().optional(),
  status: z.enum(["Draft", "Published"]).optional(),
}).strict();

const updateArtworkSchema = artworkSchema.partial().refine(
  (data) => Object.keys(data).length > 0,
  { message: "Provide at least one field to update." },
);

// List artwork according to the signed-in user's role.
router.get("/", async (req, res) => {
  const user = req.authUser!;

  try {
    let where;

    if (user.role === "ADMIN") {
      where = {};
    } else if (user.role === "ARTIST") {
      where = { artistId: user.id };
    } else {
      // Buyers and delivery staff can browse published artwork only.
      where = { status: "Published" };
    }

    const artworks = await prisma.artwork.findMany({
      where,
      orderBy: { createdAt: "desc" },
    });

    return res.status(200).json({ artworks });
  } catch (error) {
    console.error(
      "Artwork retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve artwork.",
    });
  }
});

// Create artwork for the authenticated artist.
router.post("/", requireRole("ARTIST"), requireRegisteredArtist, async (req, res) => {
  const parsed = artworkSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Please check the artwork details.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const user = req.authUser!;
  const data = parsed.data;

  try {
    if ((data.status ?? "Draft") === "Published") {
      const currentUser = await prisma.user.findUnique({
        where: { id: user.id },
        select: { artistApprovalStatus: true },
      });

      if (!currentUser || currentUser.artistApprovalStatus !== "APPROVED") {
        return res.status(403).json({
          message: "Your artist application must be approved before publishing artwork.",
        });
      }
    }

    const artwork = await prisma.artwork.create({
      data: {
        artistId: user.id,
        title: data.title,
        category: data.category,
        description: data.description ?? null,
        price: data.price,
        image: data.image ?? null,
        status: data.status ?? "Draft",
      },
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,

        role: user.role,
        action: "ARTWORK_CREATED",
        details: "Artist created artwork.",
      },
    });

    return res.status(201).json({
      message: "Artwork saved successfully.",
      artwork,
    });
  } catch (error) {
    console.error(
      "Artwork creation failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to save artwork.",
    });
  }
});

// Update artwork only when it belongs to the authenticated artist.
router.patch("/:id", requireRole("ARTIST"), requireRegisteredArtist, async (req, res) => {
  const parsed = updateArtworkSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      message: "Provide valid artwork fields to update.",
      errors: parsed.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const user = req.authUser!;
  const artworkId = req.params.id;

  if (typeof artworkId !== "string" || artworkId.length === 0) {
    return res.status(400).json({
      message: "A valid artwork ID is required.",
    });
  }

  try {
    const existing = await prisma.artwork.findFirst({
      where: {
        id: artworkId,
        artistId: user.id,
      },
      select: { id: true },
    });

    if (!existing) {
      return res.status(404).json({
        message: "Artwork not found in your account.",
      });
    }

    if (parsed.data.status === "Published") {
      const currentUser = await prisma.user.findUnique({
        where: { id: user.id },
        select: { artistApprovalStatus: true },
      });

      if (!currentUser || currentUser.artistApprovalStatus !== "APPROVED") {
        return res.status(403).json({
          message: "Your artist application must be approved before publishing artwork.",
        });
      }
    }

    const artwork = await prisma.artwork.update({
      where: { id: existing.id },
      data: {
        ...(parsed.data.title !== undefined && { title: parsed.data.title }),
        ...(parsed.data.category !== undefined && { category: parsed.data.category }),
        ...(parsed.data.description !== undefined && { description: parsed.data.description }),
        ...(parsed.data.price !== undefined && { price: parsed.data.price }),
        ...(parsed.data.image !== undefined && { image: parsed.data.image }),
        ...(parsed.data.status !== undefined && { status: parsed.data.status }),
      },
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,

        role: user.role,
        action: "ARTWORK_UPDATED",
        details: "Artist updated their artwork.",
      },
    });

    return res.status(200).json({
      message: "Artwork updated successfully.",
      artwork,
    });
  } catch (error) {
    console.error(
      "Artwork update failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to update artwork.",
    });
  }
});

// Delete only artwork owned by the authenticated artist.
router.delete("/:id", requireRole("ARTIST"), requireRegisteredArtist, async (req, res) => {
  const user = req.authUser!;
  const artworkId = req.params.id;

  if (typeof artworkId !== "string" || artworkId.length === 0) {
    return res.status(400).json({
      message: "A valid artwork ID is required.",
    });
  }

  try {
    const existing = await prisma.artwork.findFirst({
      where: {
        id: artworkId,
        artistId: user.id,
      },
      select: { id: true, title: true },
    });

    if (!existing) {
      return res.status(404).json({
        message: "Artwork not found in your account.",
      });
    }

    await prisma.artwork.delete({
      where: { id: existing.id },
    });

    await prisma.auditlog.create({
      data: {
        username: user.username,
        role: user.role,
        action: "ARTWORK_DELETED",
        details: "Artist removed artwork from their catalogue.",
      },
    });

    return res.status(200).json({
      message: "Artwork removed successfully.",
      id: existing.id,
    });
  } catch (error) {
    console.error(
      "Artwork deletion failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to remove artwork.",
    });
  }
});

export default router;



