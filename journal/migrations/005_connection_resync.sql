-- Observation-only transitions. Never execution scope, receipts or reservations.
CREATE TABLE connection_resync (
 operation_id TEXT PRIMARY KEY,
 request BLOB NOT NULL,
 request_hash TEXT NOT NULL,
 response BLOB,
 completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)),
 write_revision INTEGER NOT NULL
);
CREATE UNIQUE INDEX connection_resync_one_pending ON connection_resync(completed) WHERE completed=0;
