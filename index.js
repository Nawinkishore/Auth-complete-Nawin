// Required dependencies (ESM style)
import express from 'express';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';

import authRoutes from './routes/auth.routes.js';
import oauthRoutes from './routes/oauth.routes.js';
import protectedRoutes from './routes/protected.routes.js';

import { connectDB } from './utils/db.js';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

// Database connection
connectDB();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);
app.use('/auth', oauthRoutes);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
