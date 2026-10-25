import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
const router = Router();
router.use(requireAuth, requireRole("BUYER"));
const artworkIdSchema = z.object({
    artworkId: z.string().min(1).max(191),
}).strict();
// Retrieve the signed-in buyer's wishlist.
router.get("/", async (req, res) => {
    const user = req.authUser;
    try {
        const items = await prisma.buyerwishlistitem.findMany({
            where: { buyerId: user.id },
            include: {
                artwork: true,
            },
            orderBy: { createdAt: "desc" },
        });
        return res.status(200).json({ items });
    }
    catch (error) {
        console.error("Wishlist retrieval failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({ message: "Unable to retrieve your wishlist." });
    }
});
// Add a published artwork to the signed-in buyer's wishlist.
router.post("/", async (req, res) => {
    const parsed = artworkIdSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ message: "A valid artworkId is required." });
    }
    const user = req.authUser;
    try {
        const artwork = await prisma.artwork.findFirst({
            where: { id: parsed.data.artworkId, status: "Published" },
            select: { id: true },
        });
        if (!artwork) {
            return res.status(404).json({ message: "Published artwork not found." });
        }
        const item = await prisma.buyerwishlistitem.upsert({
            where: {
                buyerId_artworkId: {
                    buyerId: user.id,
                    artworkId: artwork.id,
                },
            },
            update: {},
            create: {
                buyerId: user.id,
                artworkId: artwork.id,
            },
            include: { artwork: true },
        });
        return res.status(200).json({ message: "Wishlist saved.", item });
    }
    catch (error) {
        console.error("Wishlist update failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({ message: "Unable to update your wishlist." });
    }
});
// Remove one item from the signed-in buyer's wishlist.
router.delete("/:artworkId", async (req, res) => {
    const artworkId = req.params.artworkId;
    if (typeof artworkId !== "string" || artworkId.length === 0) {
        return res.status(400).json({ message: "A valid artwork ID is required." });
    }
    const user = req.authUser;
    try {
        const result = await prisma.buyerwishlistitem.deleteMany({
            where: {
                buyerId: user.id,
                artworkId,
            },
        });
        if (result.count === 0) {
            return res.status(404).json({ message: "Wishlist item not found." });
        }
        return res.status(200).json({ message: "Artwork removed from your wishlist." });
    }
    catch (error) {
        console.error("Wishlist removal failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({ message: "Unable to remove the wishlist item." });
    }
});
export default router;
//# sourceMappingURL=wishlist.js.map