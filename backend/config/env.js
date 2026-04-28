require('dotenv').config();

const required = (key) => {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
};

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT || '5000', 10),

  // MongoDB
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/secure-vault',

  // Redis
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',

  // JWT
  JWT_SECRET: process.env.JWT_SECRET || 'dev-jwt-secret-change-in-prod',
  JWT_ALGORITHM: process.env.JWT_ALGORITHM || 'HS256', // HS256 | RS256
  JWT_ACCESS_TTL: process.env.JWT_ACCESS_TTL || '15m',
  JWT_REFRESH_TTL: process.env.JWT_REFRESH_TTL || '7d',

  // RS256 keys (base64-encoded PEM, used when JWT_ALGORITHM=RS256)
  JWT_PRIVATE_KEY: process.env.JWT_PRIVATE_KEY || '',
  JWT_PUBLIC_KEY: process.env.JWT_PUBLIC_KEY || '',

  // Bcrypt / Argon2
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  PASSWORD_ALGO: process.env.PASSWORD_ALGO || 'bcrypt', // bcrypt | argon2id

  // MFA
  MFA_ISSUER: process.env.MFA_ISSUER || 'SecureVault',
  MFA_BACKUP_ENCRYPTION_KEY: process.env.MFA_BACKUP_ENCRYPTION_KEY || 'backup-key-32-chars-change-prod!!',

  // Password reset
  RESET_TOKEN_SECRET: process.env.RESET_TOKEN_SECRET || 'reset-secret-change-in-prod',
  RESET_TOKEN_TTL_MINUTES: parseInt(process.env.RESET_TOKEN_TTL_MINUTES || '15', 10),

  // CSRF
  CSRF_SECRET: process.env.CSRF_SECRET || 'csrf-secret-change-in-prod',

  // Signed links
  SIGNED_LINK_SECRET: process.env.SIGNED_LINK_SECRET || 'link-secret-change-in-prod',
  SIGNED_LINK_DEFAULT_TTL: parseInt(process.env.SIGNED_LINK_DEFAULT_TTL || '3600', 10),

  // Frontend
  FRONTEND_URL: process.env.FRONTEND_URL || 'http://localhost:3000',

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
};
