import { prisma } from "./prisma.js";

// Every artwork is a one-of-a-kind original, so it can be ordered only once.
//
// Availability is worked out from the orders themselves instead of being
// stored on the artwork. That means it can never get out of step: cancelling
// an order frees the artwork again, with nothing else to update.
export type ArtworkAvailability = "AVAILABLE" | "RESERVED" | "SOLD";

// A paid order (or any later stage) means the artwork has been sold.
export const SOLD_ORDER_STATUSES = ["PAID", "PROCESSING", "SHIPPED", "DELIVERED"];

// A PENDING order reserves the artwork while the buyer's payment is awaited.
export const ACTIVE_ORDER_STATUSES = ["PENDING", ...SOLD_ORDER_STATUSES];

// Orders that are still being worked on (not yet delivered or cancelled).
export const IN_PROGRESS_ORDER_STATUSES = ["PENDING", "PAID", "PROCESSING", "SHIPPED"];

// Adds an "availability" field to each artwork using a single query.
export async function attachAvailability<T extends { id: string }>(
  artworks: T[],
): Promise<Array<T & { availability: ArtworkAvailability }>> {
  const availabilityById = new Map<string, ArtworkAvailability>();

  if (artworks.length > 0) {
    const activeOrders = await prisma.order.findMany({
      where: {
        artworkId: { in: artworks.map((artwork) => artwork.id) },
        status: { in: ACTIVE_ORDER_STATUSES },
      },
      select: { artworkId: true, status: true },
    });

    for (const order of activeOrders) {
      if (SOLD_ORDER_STATUSES.includes(order.status)) {
        availabilityById.set(order.artworkId, "SOLD");
      } else if (!availabilityById.has(order.artworkId)) {
        availabilityById.set(order.artworkId, "RESERVED");
      }
    }
  }

  return artworks.map((artwork) => ({
    ...artwork,
    availability: availabilityById.get(artwork.id) ?? "AVAILABLE",
  }));
}
