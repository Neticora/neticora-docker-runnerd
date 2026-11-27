CREATE TABLE kata_cache_volumes (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  name TEXT NOT NULL UNIQUE,
  parent_uuid TEXT NOT NULL,
  uuid TEXT NOT NULL DEFAULT '',
  filesystem_uuid TEXT NOT NULL DEFAULT '',
  clean_exit_at INTEGER NOT NULL DEFAULT 0 CHECK (clean_exit_at >= 0),
  state TEXT NOT NULL CHECK (state IN ('preparing','ready','retained','discard','cold')),
  PRIMARY KEY (execution_id,generation),
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
CREATE UNIQUE INDEX kata_cache_volume_uuid ON kata_cache_volumes(uuid) WHERE uuid <> '';
CREATE INDEX kata_cache_volume_retention ON kata_cache_volumes(cache_key,state);
CREATE TABLE kata_cache_heads (
  cache_key TEXT PRIMARY KEY,
  uuid TEXT NOT NULL
);
