// SPDX-License-Identifier: Apache-2.0
//! Execute a fully authorized dispatch in the connector privilege domain.
//!
//! Only an isolated host may supply the target credential. Unknown remote outcomes remain unresolved; this interface supplies no retry helper.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: execute a fully authorized dispatch in the connector privilege domain.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait Connector {
    /// Input whose concrete shape and validation rules are still to be specified.
    type AuthorizedDispatch;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type Outcome;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Execute a fully authorized dispatch in the connector privilege domain.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn dispatch(&mut self, input: &Self::AuthorizedDispatch) -> Result<Self::Outcome, Self::Error>;
}
