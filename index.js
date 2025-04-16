// Required dependencies (ESM style)
import express from "express";
import cookieParser from "cookie-parser";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";

import authRoutes from "./routes/auth.routes.js";
import oauthRoutes from "./routes/oauth.routes.js";
import protectedRoutes from "./routes/protected.routes.js";


import mongoose from "mongoose";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());
app.get("/", (req, res) => {
    res.send("Welcome to the API! Use /api/auth for authentication routes.");
});

// Database connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1); // Exit the process with failure
  });

// Routes
app.use("/api/auth", authRoutes);
app.use("/api", protectedRoutes);
app.use("/auth", oauthRoutes);

// Start server
