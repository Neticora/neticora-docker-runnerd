CREATE TABLE metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  journal_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 0),
  scope BLOB,
  inventory_generation TEXT NOT NULL DEFAULT '0',
  inventory_observed_at TEXT NOT NULL DEFAULT '',
  runtime_known INTEGER NOT NULL DEFAULT 0 CHECK (runtime_known IN (0,1))
);
CREATE TABLE executions (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  identity BLOB NOT NULL,
  session_epoch TEXT NOT NULL,
  endpoint_identity TEXT NOT NULL,
  attempt_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  command BLOB NOT NULL,
  state TEXT NOT NULL DEFAULT 'accepted',
  runtime_terminal INTEGER NOT NULL DEFAULT 0 CHECK (runtime_terminal IN (0,1)),
  runtime_ref BLOB,
  cleanup_pending INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_pending IN (0,1)),
  last_sequence TEXT NOT NULL DEFAULT '00000000000000000000',
  ack_sequence TEXT NOT NULL DEFAULT '00000000000000000000',
  PRIMARY KEY (execution_id,generation)
);
CREATE TABLE commands (
  command_id TEXT PRIMARY KEY,
  payload_hash TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload BLOB NOT NULL,
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
CREATE TABLE reservations (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  resources BLOB NOT NULL,
  released INTEGER NOT NULL DEFAULT 0 CHECK (released IN (0,1)),
  PRIMARY KEY (execution_id,generation),
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
CREATE TABLE start_intents (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  start_request_id TEXT NOT NULL UNIQUE,
  request BLOB NOT NULL,
  PRIMARY KEY (execution_id,generation),
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
CREATE TABLE outbox_events (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  sequence TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  payload_hash TEXT NOT NULL,
  payload BLOB,
  PRIMARY KEY (execution_id,generation,sequence),
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
CREATE TABLE cleanup_tasks (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0,1)),
  evidence BLOB,
  PRIMARY KEY (execution_id,generation),
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
CREATE INDEX incomplete_executions ON executions(state,execution_id,generation);
