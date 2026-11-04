//! Isolated native Bitwarden-compatible sync-ingress spike.
//! Production integration is not wired in until authentication, crypto,
//! archive/permission filtering and transactional cache have passed acceptance.

pub mod auth;
pub mod cache_store;
pub mod decryptor;
pub mod envelope;
pub mod pipeline;
pub mod strict_json;
pub mod sync_filter;
pub mod transport;
