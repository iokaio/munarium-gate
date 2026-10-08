-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE IF NOT EXISTS gate_action_reconciliations (
    scope TEXT NOT NULL, operation TEXT NOT NULL, receipt TEXT NOT NULL, event TEXT NOT NULL,
    PRIMARY KEY (scope,operation)
);
