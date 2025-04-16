// middlewares/auth.middleware.js
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

// Verify Access Token
export const verifyAccessToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_SECRET, async (err, decoded) => {
    if (err) return res.sendStatus(403);

    const user = await User.findById(decoded.userId);
    if (!user) return res.sendStatus(403);

    req.user = user;
    next();
  });
};
