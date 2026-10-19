import { Router } from "express";
import { prisma } from "../lib/prisma.js";

const router = Router();

// Public directory: expose only public fields for active artist accounts.
router.get("/public", async (_req, res) => {
  try {
    const users = await prisma.user.findMany({
      where: {
        role: "ARTIST",
        isActive: true,
        artistApprovalStatus: "APPROVED",
        registrationComplete: true,
      },
      select: {
        id: true,
        fullName: true,
      },
      orderBy: {
        fullName: "asc",
      },
    });

    const userIds = users.map((user) => user.id);

    const [profiles, artworks] = await Promise.all([
      prisma.artistprofile.findMany({
        where: {
          userId: { in: userIds },
        },
        select: {
          userId: true,
          bio: true,
          location: true,
          profileImage: true,
        },
      }),
      prisma.artwork.findMany({
        where: {
          artistId: { in: userIds },
          status: "Published",
        },
        select: {
          artistId: true,
          category: true,
        },
      }),
    ]);

    const profileMap = new Map(
      profiles.map((profile) => [profile.userId, profile]),
    );

    const categoriesMap = new Map<string, Set<string>>();
    const countsMap = new Map<string, number>();

    for (const artwork of artworks) {
      if (!categoriesMap.has(artwork.artistId)) {
        categoriesMap.set(artwork.artistId, new Set<string>());
      }

      categoriesMap.get(artwork.artistId)!.add(artwork.category);

      countsMap.set(
        artwork.artistId,
        (countsMap.get(artwork.artistId) ?? 0) + 1,
      );
    }

    const artists = users.map((user) => {
      const profile = profileMap.get(user.id);
      const categories = [
        ...(categoriesMap.get(user.id) ?? new Set<string>()),
      ];

      return {
        id: user.id,
        slug: user.id,
        name: user.fullName,
        bio: profile?.bio ?? null,
        location: profile?.location ?? null,
        image: profile?.profileImage ?? null,
        specialty: categories.length > 0
          ? categories.join(", ")
          : "Artist",
        artworkCount: countsMap.get(user.id) ?? 0,
      };
    });

    return res.status(200).json({ artists });
  } catch (error) {
    console.error(
      "Public artist directory retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve artists.",
    });
  }
});

// Public profile: return one active artist and their published artwork.
router.get("/public/:id", async (req, res) => {
  try {
    const artist = await prisma.user.findFirst({
      where: {
        id: req.params.id,
        role: "ARTIST",
        isActive: true,
        artistApprovalStatus: "APPROVED",
        registrationComplete: true,
      },
      select: {
        id: true,
        fullName: true,
      },
    });

    if (!artist) {
      return res.status(404).json({
        message: "Artist not found.",
      });
    }

    const [profile, artworks] = await Promise.all([
      prisma.artistprofile.findUnique({
        where: {
          userId: artist.id,
        },
        select: {
          bio: true,
          location: true,
          profileImage: true,
        },
      }),
      prisma.artwork.findMany({
        where: {
          artistId: artist.id,
          status: "Published",
        },
        select: {
          id: true,
          title: true,
          category: true,
          description: true,
          price: true,
          image: true,
          createdAt: true,
        },
        orderBy: {
          createdAt: "desc",
        },
      }),
    ]);

    const categories = [
      ...new Set(artworks.map((artwork) => artwork.category)),
    ];

    return res.status(200).json({
      artist: {
        id: artist.id,
        slug: artist.id,
        name: artist.fullName,
        bio: profile?.bio ?? null,
        location: profile?.location ?? null,
        image: profile?.profileImage ?? null,
        specialty: categories.length > 0
          ? categories.join(", ")
          : "Artist",
      },
      artworks: artworks.map((artwork) => ({
        ...artwork,
        price: Number(artwork.price),
      })),
    });
  } catch (error) {
    console.error(
      "Public artist profile retrieval failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    return res.status(500).json({
      message: "Unable to retrieve the artist profile.",
    });
  }
});

export default router;
