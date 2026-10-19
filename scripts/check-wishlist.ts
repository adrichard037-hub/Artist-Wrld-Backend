import { prisma } from "../src/lib/prisma.js";

async function main() {
  const orphanedBuyers = await prisma.$queryRawUnsafe<
    Array<{ count: bigint }>
  >(
    "SELECT COUNT(*) AS count FROM BuyerWishlistItem w LEFT JOIN User u ON u.id = w.buyerId WHERE u.id IS NULL"
  );

  const orphanedArtwork = await prisma.$queryRawUnsafe<
    Array<{ count: bigint }>
  >(
    "SELECT COUNT(*) AS count FROM BuyerWishlistItem w LEFT JOIN Artwork a ON a.id = w.artworkId WHERE a.id IS NULL"
  );

  console.log("Orphaned buyer entries:", String(orphanedBuyers[0]?.count ?? 0));
  console.log("Orphaned artwork entries:", String(orphanedArtwork[0]?.count ?? 0));
}

main()
  .catch((error) => {
    console.error("Wishlist integrity check failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });