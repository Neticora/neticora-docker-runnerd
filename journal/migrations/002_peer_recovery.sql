-- Immutable signed transition evidence. Outstanding execution/command/event
-- identities and permanent creation markers are never rewritten by recovery.
CREATE TABLE peer_recovery_approvals (
  approval_id TEXT PRIMARY KEY,
  approval_hash TEXT NOT NULL UNIQUE,
  approval BLOB NOT NULL,
  applied_revision INTEGER NOT NULL,
  completed INTEGER NOT NULL DEFAULT 0 CHECK (completed IN (0,1)),
  superseded INTEGER NOT NULL DEFAULT 0 CHECK (superseded IN (0,1))
);
CREATE UNIQUE INDEX one_open_peer_recovery ON peer_recovery_approvals(completed) WHERE completed=0 AND superseded=0;
