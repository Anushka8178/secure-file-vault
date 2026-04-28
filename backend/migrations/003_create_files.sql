CREATE TABLE IF NOT EXISTS files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES users(id),
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  mime_type VARCHAR(255),
  size_bytes BIGINT,
  encrypted BOOLEAN DEFAULT TRUE,
  scan_status VARCHAR(20) DEFAULT 'pending' CHECK (scan_status IN ('pending','clean','infected','error')),
  storage_path TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_files_owner ON files(owner_id);
