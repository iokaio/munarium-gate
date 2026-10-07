// SPDX-License-Identifier: Apache-2.0
//! Munarium Gate: Stage 1 decision library.
//!
//! Deterministic decisions, durable execution claims, and isolated connector dispatch.
//!
//! The decision module implements the proposed Stage 1 candidate contracts.
//! Other modules retain proposed later-stage interfaces. There is no network listener
//! or execution admission. No production path is qualified.
//! See `docs/architecture.md` and `docs/implementation-plan.md` in this repository.
//!
//! The interfaces are provisional and may change before the first implementation.
//! Concrete cross-component types must follow an accepted hub decision and contract.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod connector;
pub mod decision;
pub mod evaluation;
pub mod journal;
pub mod opa;

#[path = "../vendor/warden-identity/identity-core/lib.rs"]
mod verifier;
pub use verifier::{encoding, error, policy, principal};
