-- Migration 001: Users table (PostgreSQL version if using SQL)
-- Note: Project uses MongoDB, this is for reference/documentation
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(30) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_algo VARCHAR(20) DEFAULT 'bcrypt',
  role VARCHAR(20) DEFAULT 'User' CHECK (role IN ('SuperAdmin','Admin','User','ReadOnly')),
  is_active BOOLEAN DEFAULT TRUE,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret TEXT,
  failed_login_attempts INT DEFAULT 0,
  lockout_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_lockout ON users(lockout_until);
