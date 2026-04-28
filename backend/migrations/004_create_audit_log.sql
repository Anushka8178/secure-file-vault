-- Append-only audit log (no UPDATE or DELETE permissions should be granted)
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event VARCHAR(100) NOT NULL,
  user_id UUID REFERENCES users(id),
  ip VARCHAR(45),
  user_agent TEXT,
  meta JSONB DEFAULT '{}',
  timestamp TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_event ON audit_logs(event);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
-- Prevent updates/deletes via row security in production:
-- ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
