-- Original ownership survives disposal and final acknowledgment.
CREATE TABLE execution_storage (
  execution_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  record BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('intent','allocated','retiring','disposed')),
  PRIMARY KEY (execution_id,generation),
  FOREIGN KEY (execution_id,generation) REFERENCES executions(execution_id,generation)
);
