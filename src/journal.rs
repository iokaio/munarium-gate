// SPDX-License-Identifier: Apache-2.0
//! Durably establish a request-bound execution claim.
//!
//! Atomic acquisition, grant consumption, fencing, and recovery require a jointly reviewed storage protocol; this port provides none of those guarantees yet.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: durably establish a request-bound execution claim.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait ClaimJournal {
    /// Input whose concrete shape and validation rules are still to be specified.
    type ClaimRequest;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type DurableClaim;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Durably establish a request-bound execution claim.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn claim(&mut self, input: &Self::ClaimRequest) -> Result<Self::DurableClaim, Self::Error>;
}
