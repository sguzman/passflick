//! Isolated native Bitwarden-compatible sync-ingress spike.
//! Production integration is not wired in until authentication, crypto,
//! archive/permission filtering and transactional cache have passed acceptance.

pub mod auth;
pub mod cache_store;
#[cfg(feature = "vaultwarden-preview")]
pub mod command;
pub mod decryptor;
pub mod envelope;
pub mod keywrap;
#[cfg(test)]
mod live_acceptance;
#[cfg(feature = "vaultwarden-preview")]
pub mod offline_command;
pub mod pipeline;
#[cfg(feature = "vaultwarden-preview")]
pub mod projection_identity;
// Until the new offline picker consumes this search model, keep it as
// synthetic acceptance code. Do not ship dead preview-only interfaces.
#[cfg(all(test, feature = "vaultwarden-preview"))]
mod projection_search;
#[cfg(any(test, feature = "vaultwarden-preview"))]
pub mod session_cache;
pub mod strict_json;
pub mod sync_filter;
#[cfg(all(test, feature = "vaultwarden-preview"))]
mod terminal_acceptance;
#[cfg(test)]
mod tls_acceptance;
pub mod transport;
pub mod update;
