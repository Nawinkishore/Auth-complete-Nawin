
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import User from '../models/User.js';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

// Create access and refresh tokens
const createAccessToken = (userId) =>
  jwt.sign({ userId }, process.env.ACCESS_SECRET, { expiresIn: '15m' });

const createRefreshToken = (userId) =>
  jwt.sign({ userId }, process.env.REFRESH_SECRET, { expiresIn: '7d' });


export const register = async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: 'Email already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = crypto.randomBytes(32).toString('hex');

  const user = new User({ email, password: hashedPassword, verificationToken });
  await user.save();

  const verificationLink = `${process.env.BASE_URL}/api/auth/verify-email/${verificationToken}`;

  try {
    await transporter.sendMail({
      to: email,
      subject: 'Email Verification',
      html: `<p>Click to verify: <a href="${verificationLink}">Verify Email</a></p>`,
    });
    res.status(200).json({ message: 'Check your email to verify your account.' });
  } catch (err) {
    console.error('Error sending email:', err);
    return res.status(500).json({ message: 'Failed to send verification email.' });
  }
};
export const verifyEmail = async (req, res) => {
  const { token } = req.params;
  const user = await User.findOne({ verificationToken: token });

  if (!user) return res.status(400).json({ message: 'Invalid or expired verification link.' });

  user.isVerified = true;
  user.verificationToken = undefined;
  await user.save();

  res.redirect(`${process.env.FRONTEND_URL}/login`);
};


export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(400).json({ message: 'Email not found.' });

  // Generate reset token and set expiration time (1 hour)
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenExpiration = Date.now() + 3600000;

  user.resetToken = resetToken;
  user.resetTokenExpiration = resetTokenExpiration;
  await user.save();

  const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

  try {
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Click the link below to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p>`,
    });
    res.status(200).json({ message: 'Password reset link sent to your email.' });
  } catch (err) {
    console.error('Error sending email:', err);
    res.status(500).json({ message: 'Failed to send reset email.' });
  }
};

export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: Date.now() },
  });

  if (!user) return res.status(400).json({ message: 'Invalid or expired reset token.' });

  const hashedPassword = await bcrypt.hash(password, 10);

  user.password = hashedPassword;
  user.resetToken = undefined;
  user.resetTokenExpiration = undefined;
  await user.save();

  res.status(200).json({ message: 'Password successfully reset.' });
};


export const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !user.isVerified) return res.status(400).json({ message: 'Invalid credentials or unverified email.' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  const accessToken = createAccessToken(user._id);
  const refreshToken = createRefreshToken(user._id);

  user.refreshToken = refreshToken;
  await user.save();

  res.cookie('refreshToken', refreshToken, { httpOnly: true });
  res.json({ accessToken });
};

// Refresh token logic (existing)
export const refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.refreshToken !== token) return res.sendStatus(403);

    const newAccessToken = createAccessToken(user._id);
    const newRefreshToken = createRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    await user.save();

    res.cookie('refreshToken', newRefreshToken, { httpOnly: true });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.sendStatus(403);
  }
};
