// routes/auth.routes.js
import express from 'express';
import { register, login, forgotPassword, resetPassword, verifyEmail, refreshToken } from '../controllers/auth.controller.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword); // Forgot password route
router.post('/reset-password/:token', resetPassword); // Reset password route
router.get('/verify-email/:token', verifyEmail); // Email verification route
router.post('/refresh-token', refreshToken); // Refresh token route

export default router;
