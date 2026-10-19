import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authRoutes from "./routes/auth.js";
import dashboardRoutes from "./routes/dashboard.js";
import artworkRoutes from "./routes/artworks.js";
import artistRoutes from "./routes/artists.js";
import wishlistRoutes from "./routes/wishlist.js";
import adminRoutes from "./routes/admin.js";
import deliveryRoutes from "./routes/deliveries.js";
import workspaceRoutes from "./routes/workspace.js";

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    message: "Too many login attempts. Please try again later.",
  },
});
const app = express();
const port = Number(process.env.PORT || 4000);

const allowedOrigins = (
  process.env.FRONTEND_URL || "http://localhost:5173"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable("x-powered-by");

app.use(helmet());

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error("Origin is not allowed by CORS."));
    },
    credentials: true,
  }),
);

app.use(express.json({ limit: "10mb" }));

app.get("/api/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    message: "Artist-Wrld API is running.",
  });
});

app.use("/api/auth/login", loginRateLimit);
app.use("/api/auth/2fa/verify-login", loginRateLimit);

app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    skip: (req) => req.path === "/me",
  }),
  authRoutes,
);

app.use("/api/dashboard", dashboardRoutes);
app.use("/api/artworks", artworkRoutes);
app.use("/api/artists", artistRoutes);
app.use("/api/wishlist", wishlistRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/deliveries", deliveryRoutes);
app.use("/api/workspace", workspaceRoutes);

app.use((_req, res) => {
  res.status(404).json({
    message: "API endpoint not found.",
  });
});

app.use(
  (
    error: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    if (error instanceof SyntaxError) {
      res.status(400).json({
        message: "The request body contains invalid JSON.",
      });
      return;
    }

    console.error(
      "API request failed:",
      error instanceof Error ? error.message : "Unknown error",
    );

    res.status(500).json({
      message: "An unexpected server error occurred.",
    });
  },
);

app.listen(port, () => {
  console.log(`Artist-Wrld API is running on http://localhost:${port}`);
});












