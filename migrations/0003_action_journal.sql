-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE IF NOT EXISTS gate_action_enrollment (
 scope TEXT PRIMARY KEY REFERENCES gate_activation_cells(scope), registration TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gate_action_claims (
 scope TEXT NOT NULL REFERENCES gate_activation_cells(scope), operation TEXT NOT NULL,
 binding TEXT NOT NULL, claim TEXT NOT NULL, consumption TEXT,
 PRIMARY KEY(scope,operation)
);
CREATE TABLE IF NOT EXISTS gate_action_cancellations (
 scope TEXT NOT NULL REFERENCES gate_activation_cells(scope), operation TEXT NOT NULL,
 attempt TEXT NOT NULL, approval TEXT NOT NULL, withdrawal TEXT NOT NULL, receipt TEXT NOT NULL,
 PRIMARY KEY(scope,operation,attempt,approval), UNIQUE(scope,withdrawal)
);
CREATE TABLE IF NOT EXISTS gate_action_grants (
 scope TEXT NOT NULL, grant_id TEXT NOT NULL, operation TEXT NOT NULL,
 PRIMARY KEY(scope,grant_id), UNIQUE(scope,operation),
 FOREIGN KEY(scope,operation) REFERENCES gate_action_claims(scope,operation)
);
CREATE TABLE IF NOT EXISTS gate_action_reservations (
 scope TEXT NOT NULL, operation TEXT NOT NULL, bucket TEXT NOT NULL,
 window_start BIGINT NOT NULL, unresolved BOOLEAN NOT NULL DEFAULT TRUE,
 PRIMARY KEY(scope,operation,bucket),
 FOREIGN KEY(scope,operation) REFERENCES gate_action_claims(scope,operation)
);
CREATE TABLE IF NOT EXISTS gate_action_outbox (
 scope TEXT NOT NULL REFERENCES gate_activation_cells(scope), sequence BIGINT NOT NULL,
 event TEXT NOT NULL, acknowledgement TEXT, PRIMARY KEY(scope,sequence)
);
