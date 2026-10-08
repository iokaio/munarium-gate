-- SPDX-License-Identifier: Apache-2.0
-- Additive custody evidence; retained participant intent remains unchanged.
CREATE TABLE IF NOT EXISTS gate_activation_delivery (
 scope TEXT NOT NULL REFERENCES gate_activation_cells(scope), id TEXT NOT NULL,
 sequence BIGINT NOT NULL, event TEXT NOT NULL, acknowledgement TEXT,
 PRIMARY KEY(scope,id), UNIQUE(scope,sequence)
);
