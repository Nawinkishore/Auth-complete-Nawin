
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name:{ type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  resetToken: { type: String },
  resetTokenExpiration: { type: Date },
  refreshToken: { type: String },
});

const User = mongoose.model('User', userSchema);

export default User;
