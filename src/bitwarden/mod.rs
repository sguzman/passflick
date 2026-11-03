//! Isolated native Bitwarden-compatible sync-ingress spike.
//! Production integration is not wired in until authentication, crypto,
//! archive/permission filtering and transactional cache have passed acceptance.

pub mod envelope;
pub mod pipeline;
pub mod sync_filter;
pub mod transport;
