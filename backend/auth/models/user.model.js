const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  passwordHash: {
    type: String,
    required: true,
    select: false,
  },
  passwordAlgo: {
    type: String,
    enum: ['bcrypt', 'argon2id'],
    default: 'bcrypt',
    select: false,
  },
  role: {
    type: String,
    enum: ['SuperAdmin', 'Admin', 'User', 'ReadOnly'],
    default: 'User',
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  // MFA
  mfaEnabled: {
    type: Boolean,
    default: false,
  },
  mfaSecret: {
    type: String,
    select: false,
  },
  // Account lockout
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },
  lockoutUntil: {
    type: Date,
    default: null,
  },
  // Password reset
  passwordResetToken: {
    type: String,
    select: false,
  },
  passwordResetExpires: {
    type: Date,
    select: false,
  },
  lastLoginAt: {
    type: Date,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  toJSON: {
    transform: (doc, ret) => {
      delete ret.passwordHash;
      delete ret.passwordAlgo;
      delete ret.mfaSecret;
      delete ret.passwordResetToken;
      delete ret.passwordResetExpires;
      return ret;
    },
  },
});

userSchema.index({ email: 1 });
userSchema.index({ lockoutUntil: 1 });

module.exports = mongoose.model('User', userSchema);
