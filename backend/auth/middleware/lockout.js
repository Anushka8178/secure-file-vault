const User = require('../models/user.model');
const { AuthError } = require('../../shared/errors');

const MAX_ATTEMPTS = 10;
const BASE_DELAY_MS = 1000;

/**
 * Calculate lockout duration with exponential backoff
 * Attempt 1-4: no lockout
 * Attempt 5+: captcha required flag
 * Attempt 6+: exponential lockout
 */
const getLockoutDuration = (attempts) => {
  if (attempts < 6) return 0;
  // 2^(attempts-5) * 1 second, max 1 hour
  return Math.min(Math.pow(2, attempts - 5) * BASE_DELAY_MS, 3600_000);
};

/**
 * Check if account is locked before login
 */
const checkLockout = async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next();

  const user = await User.findOne({ email: email.toLowerCase() }).select(
    '+failedLoginAttempts +lockoutUntil'
  );
  if (!user) return next(); // Don't reveal existence

  if (user.lockoutUntil && user.lockoutUntil > new Date()) {
    const secondsLeft = Math.ceil((user.lockoutUntil - Date.now()) / 1000);
    throw new AuthError(
      `Account locked. Try again in ${secondsLeft} seconds.`,
      'ACCOUNT_LOCKED'
    );
  }

  // Attach to req for downstream use
  req._lockoutUser = user;
  next();
};

/**
 * Record a failed login attempt
 */
const recordFailedAttempt = async (userId) => {
  const user = await User.findById(userId).select('+failedLoginAttempts +lockoutUntil');
  if (!user) return;

  user.failedLoginAttempts += 1;
  const lockDuration = getLockoutDuration(user.failedLoginAttempts);

  if (lockDuration > 0) {
    user.lockoutUntil = new Date(Date.now() + lockDuration);
  }

  await user.save();

  return {
    attempts: user.failedLoginAttempts,
    requiresCaptcha: user.failedLoginAttempts >= 5,
    locked: lockDuration > 0,
    lockoutUntil: user.lockoutUntil,
  };
};

/**
 * Reset failed attempts on successful login
 */
const resetFailedAttempts = async (userId) => {
  await User.findByIdAndUpdate(userId, {
    failedLoginAttempts: 0,
    lockoutUntil: null,
  });
};

module.exports = { checkLockout, recordFailedAttempt, resetFailedAttempts };
