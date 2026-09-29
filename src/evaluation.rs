// SPDX-License-Identifier: Apache-2.0
//! Evaluate a complete, pinned input bundle.
//!
//! Enrichment occurs before evaluation. Implementations must not make unrecorded network calls or manufacture permission when a required input is missing.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: evaluate a complete, pinned input bundle.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait Evaluator {
    /// Input whose concrete shape and validation rules are still to be specified.
    type InputBundle;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type Decision;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Evaluate a complete, pinned input bundle.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn evaluate(&self, input: &Self::InputBundle) -> Result<Self::Decision, Self::Error>;
}
