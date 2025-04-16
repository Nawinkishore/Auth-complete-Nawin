// routes/protected.routes.js
import express from 'express';
import { verifyAccessToken } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Protected route example
router.get('/protected', verifyAccessToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

export default router;
