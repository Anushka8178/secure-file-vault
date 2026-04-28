CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  family UUID NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  invalidated BOOLEAN DEFAULT FALSE,
  user_agent TEXT,
  ip_address VARCHAR(45),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
