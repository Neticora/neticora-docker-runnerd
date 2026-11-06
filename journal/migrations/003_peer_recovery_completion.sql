-- Finalization is durable before the platform can commit completion. This
-- record never grants mutation authority, including after approval expiry.
CREATE TABLE peer_recovery_completion_intents (
  approval_id TEXT PRIMARY KEY,
  approval_hash TEXT NOT NULL UNIQUE,
  progress BLOB NOT NULL,
  FOREIGN KEY (approval_id) REFERENCES peer_recovery_approvals(approval_id)
);
