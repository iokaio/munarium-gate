-- SPDX-License-Identifier: Apache-2.0
-- Gate owns this scope lock; future final-send and consumption must share it.
CREATE TABLE IF NOT EXISTS gate_activation_cells (
 scope TEXT PRIMARY KEY, initial_epoch BIGINT NOT NULL, initial_digest TEXT NOT NULL,
 epoch BIGINT NOT NULL, digest TEXT NOT NULL, paused BOOLEAN NOT NULL,
 transition_id TEXT
);
CREATE TABLE IF NOT EXISTS gate_activation_transitions (
 scope TEXT NOT NULL REFERENCES gate_activation_cells(scope), id TEXT NOT NULL,
 record TEXT NOT NULL, pause TEXT NOT NULL, applied TEXT, resumed BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(scope,id)
);
CREATE TABLE IF NOT EXISTS gate_activation_outbox (
 sequence BIGSERIAL PRIMARY KEY, scope TEXT NOT NULL, id TEXT NOT NULL,
 phase TEXT NOT NULL, record TEXT NOT NULL,
 UNIQUE(scope,id,phase),
 FOREIGN KEY(scope,id) REFERENCES gate_activation_transitions(scope,id)
);
