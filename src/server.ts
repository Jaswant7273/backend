import express from "express";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.route.js";
import { config } from "./config/index.js";

// ------------------------------------------------------------------------------------------------------------------------------
//                                                    CREATE AN EXPRESS APPLICATION INSTANCE
// ------------------------------------------------------------------------------------------------------------------------------
const app = express();

// ------------------------------------------------------------------------------------------------------------------------------
//                            MIDDLEWARE: PARSES INCOMING JSON REQUEST BODIES AND MAKES THEM AVAILABLE IN REQ.BODY
// ------------------------------------------------------------------------------------------------------------------------------
app.use(express.json());

// ------------------------------------------------------------------------------------------------------------------------------
//                                                        ROUTES REGISTRATION
// ------------------------------------------------------------------------------------------------------------------------------
app.use("/auth", authRoutes);

// ------------------------------------------------------------------------------------------------------------------------------
//                                                        MAIN ROUTE (/)
// ------------------------------------------------------------------------------------------------------------------------------
app.get("/", (req, res) =>
  res.json({ ok: true, now: new Date().toISOString() })
);

// ------------------------------------------------------------------------------------------------------------------------------
//                                                        MONGOOSE CONNECTION AND TO START SERVER
// ------------------------------------------------------------------------------------------------------------------------------
(async function () {
  try {
    if (!config.mongoUri) throw new Error("MONGO_URI not provided");
    await mongoose.connect(config.mongoUri);
    console.log("Connected to MongoDB");

    app.listen(config.port, () => {
      console.log(`Server listening on http://localhost:${config.port}`);
    });
  } catch (err) {
    console.error("Failed to start", err);
    process.exit(1);
  }
})();
