-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE IF NOT EXISTS gate_action_sources (
    scope TEXT NOT NULL,
    operation TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (scope, operation)
);
CREATE TABLE IF NOT EXISTS gate_action_dispatch (
    scope TEXT NOT NULL,
    operation TEXT NOT NULL,
    admission TEXT NOT NULL,
    outcome TEXT,
    PRIMARY KEY (scope, operation)
);
CREATE TABLE IF NOT EXISTS gate_execution_generation (
    scope TEXT PRIMARY KEY,
    generation BIGINT NOT NULL CHECK (generation > 0)
);
