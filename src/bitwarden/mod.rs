//! Isolated, test-only Bitwarden-compatible sync ingress spike.
//!
//! Production integration is intentionally not wired in until authentication,
//! crypto, archive filtering and cache lifecycle have passed acceptance.

pub mod sync_filter;
