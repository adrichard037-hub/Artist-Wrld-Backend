import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth } from "../middleware/auth.js";
const router = Router();
router.use(requireAuth);
const profileSchema = z.object({
    fullName: z.string().trim().min(2).max(100).optional(),
    email: z.string().trim().email().max(254).optional(),
    bio: z.string().max(10000).nullable().optional(),
    location: z.string().max(255).nullable().optional(),
    profileImage: z.string().max(7_500_000).nullable().optional(),
    phone: z.string().max(40).nullable().optional(),
    serviceArea: z.string().max(255).nullable().optional(),
    avatar: z.string().max(7_500_000).nullable().optional(),
}).strict();
const preferenceSchema = z.object({
    key: z.string().trim().min(1).max(100),
    value: z.string().max(20000),
}).strict();
router.get("/profile", async (req, res) => {
    const authUser = req.authUser;
    try {
        const user = await prisma.user.findUnique({
            where: { id: authUser.id },
            select: {
                id: true,
                fullName: true,
                username: true,
                email: true,
                role: true,
            },
        });
        if (!user) {
            return res.status(404).json({ message: "Account not found." });
        }
        let profile = null;
        switch (authUser.role) {
            case "ARTIST": {
                const artistProfile = await prisma.artistprofile.findUnique({
                    where: { userId: authUser.id },
                });
                profile = artistProfile
                    ? { ...artistProfile, profileImage: artistProfile.profileImage }
                    : null;
                break;
            }
            case "BUYER": {
                const buyerProfile = await prisma.buyerprofile.findUnique({
                    where: { userId: authUser.id },
                });
                profile = buyerProfile
                    ? { ...buyerProfile, profileImage: buyerProfile.profileImage }
                    : null;
                break;
            }
            case "DELIVERY_MAN": {
                const deliveryProfile = await prisma.deliveryprofile.findUnique({
                    where: { userId: authUser.id },
                });
                profile = deliveryProfile
                    ? { ...deliveryProfile, profileImage: deliveryProfile.avatar }
                    : null;
                break;
            }
            case "ADMIN":
                profile = { profileImage: null };
                break;
        }
        return res.status(200).json({ user, profile });
    }
    catch (error) {
        console.error("Dashboard profile retrieval failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({
            message: "Unable to retrieve your profile.",
        });
    }
});
router.put("/profile", async (req, res) => {
    const parsed = profileSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({
            message: "Please check your profile details.",
            errors: parsed.error.issues.map((issue) => ({
                field: issue.path.join("."),
                message: issue.message,
            })),
        });
    }
    const authUser = req.authUser;
    const data = parsed.data;
    if (authUser.role === "ADMIN") {
        return res.status(403).json({
            message: "Admin profile editing is not available through this endpoint.",
        });
    }
    try {
        const userData = {};
        if (data.fullName !== undefined) {
            userData.fullName = data.fullName;
        }
        if (data.email !== undefined) {
            userData.email = data.email.toLowerCase();
        }
        if (Object.keys(userData).length > 0) {
            await prisma.user.update({
                where: { id: authUser.id },
                data: userData,
            });
        }
        let profile = null;
        switch (authUser.role) {
            case "ARTIST":
                profile = await prisma.artistprofile.upsert({
                    where: { userId: authUser.id },
                    create: {
                        userId: authUser.id,
                        bio: data.bio ?? null,
                        location: data.location ?? null,
                        profileImage: data.profileImage ?? null,
                    },
                    update: {
                        ...(data.bio !== undefined ? { bio: data.bio } : {}),
                        ...(data.location !== undefined ? { location: data.location } : {}),
                        ...(data.profileImage !== undefined
                            ? { profileImage: data.profileImage }
                            : {}),
                    },
                });
                break;
            case "BUYER":
                profile = await prisma.buyerprofile.upsert({
                    where: { userId: authUser.id },
                    create: {
                        userId: authUser.id,
                        location: data.location ?? null,
                        profileImage: data.profileImage ?? null,
                    },
                    update: {
                        ...(data.location !== undefined ? { location: data.location } : {}),
                        ...(data.profileImage !== undefined
                            ? { profileImage: data.profileImage }
                            : {}),
                    },
                });
                break;
            case "DELIVERY_MAN":
                profile = await prisma.deliveryprofile.upsert({
                    where: { userId: authUser.id },
                    create: {
                        userId: authUser.id,
                        phone: data.phone ?? null,
                        serviceArea: data.serviceArea ?? null,
                        avatar: data.avatar ?? null,
                    },
                    update: {
                        ...(data.phone !== undefined ? { phone: data.phone } : {}),
                        ...(data.serviceArea !== undefined
                            ? { serviceArea: data.serviceArea }
                            : {}),
                        ...(data.avatar !== undefined ? { avatar: data.avatar } : {}),
                    },
                });
                break;
        }
        const user = await prisma.user.findUnique({
            where: { id: authUser.id },
            select: {
                id: true,
                fullName: true,
                username: true,
                email: true,
                role: true,
            },
        });
        await prisma.auditlog.create({
            data: {
                username: authUser.username,
                role: authUser.role,
                action: "DASHBOARD_PROFILE_UPDATED",
                details: "The user updated their dashboard profile.",
            },
        });
        return res.status(200).json({
            message: "Profile saved successfully.",
            user,
            profile,
        });
    }
    catch (error) {
        if (typeof error === "object" &&
            error !== null &&
            "code" in error &&
            error.code === "P2002") {
            return res.status(409).json({
                message: "That email address is already in use.",
            });
        }
        console.error("Dashboard profile update failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({
            message: "Unable to save your profile.",
        });
    }
});
router.get("/preferences", async (req, res) => {
    const authUser = req.authUser;
    try {
        const preferences = await prisma.dashboardpreference.findMany({
            where: { userId: authUser.id },
            select: { key: true, value: true, updatedAt: true },
        });
        return res.status(200).json({ preferences });
    }
    catch (error) {
        console.error("Dashboard preference retrieval failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({
            message: "Unable to retrieve dashboard preferences.",
        });
    }
});
router.put("/preferences", async (req, res) => {
    const parsed = preferenceSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({
            message: "Provide a valid preference key and value.",
        });
    }
    const authUser = req.authUser;
    const { key, value } = parsed.data;
    try {
        const preference = await prisma.dashboardpreference.upsert({
            where: {
                userId_key: {
                    userId: authUser.id,
                    key,
                },
            },
            create: {
                userId: authUser.id,
                key,
                value,
            },
            update: { value },
            select: {
                key: true,
                value: true,
                updatedAt: true,
            },
        });
        return res.status(200).json({
            message: "Dashboard preference saved successfully.",
            preference,
        });
    }
    catch (error) {
        console.error("Dashboard preference update failed:", error instanceof Error ? error.message : "Unknown error");
        return res.status(500).json({
            message: "Unable to save dashboard preferences.",
        });
    }
});
export default router;
//# sourceMappingURL=dashboard.js.map