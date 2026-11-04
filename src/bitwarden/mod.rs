//! Isolated native Bitwarden-compatible sync-ingress spike.
//! Production integration is not wired in until authentication, crypto,
//! archive/permission filtering and transactional cache have passed acceptance.

pub mod auth;
pub mod cache_store;
pub mod decryptor;
pub mod envelope;
mod live_acceptance;
pub mod keywrap;
pub mod pipeline;
pub mod strict_json;
pub mod sync_filter;
mod tls_acceptance;
pub mod transport;
pub mod update;
