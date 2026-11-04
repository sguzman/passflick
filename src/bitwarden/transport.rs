//! Native read-only HTTPS synchronization transport (isolated integration spike).
//!
//! No account login, token storage, password decryption, cache replacement or
//! updater CLI is wired to production. The caller supplies an authenticated
//! session's bearer token and expected account ID. Sensitive network errors
//! and response bodies are never printed.

use std::io::Read;
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde_json::Value;
use zeroize::Zeroizing;

use super::envelope::{self, SyncEnvelopeError};

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_ACCOUNT_ID_BYTES: usize = 256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("server endpoint must be a valid HTTPS URL without credentials, query or fragment")]
    InvalidEndpoint,
    #[error("authentication token has an invalid format")]
    InvalidToken,
    #[error("expected account ID is missing or malformed")]
    InvalidAccount,
    #[error("could not initialize trusted HTTPS transport")]
    ClientSetup,
    #[error("HTTPS sync request failed")]
    Network,
    #[error("authentication required to synchronize vault")]
    Unauthorized,
    #[error("server returned HTTP status {0}")]
    UnexpectedStatus(u16),
    #[error("sync response exceeds permitted size")]
    Oversized,
    #[error("sync response could not be admitted: {0}")]
    Admission(#[from] SyncEnvelopeError),
}

/// A configured server root, not an arbitrary request URL. This preserves an
/// optional reverse-proxy path prefix while preventing access-token redirects
/// or user-controlled query/fragment injection.
pub struct ServerEndpoint {
    root: Url,
}

impl ServerEndpoint {
    pub fn parse(input: &str) -> Result<Self, TransportError> {
        let root = Url::parse(input).map_err(|_| TransportError::InvalidEndpoint)?;
        if root.scheme() != "https"
            || root.host_str().is_none()
            || !root.username().is_empty()
            || root.password().is_some()
            || root.query().is_some()
            || root.fragment().is_some()
        {
            return Err(TransportError::InvalidEndpoint);
        }
        Ok(Self { root })
    }

    /// Derive the official identity-service prelogin endpoint.
    pub(super) fn prelogin_url(&self) -> Url {
        self.identity_path(&["accounts", "prelogin"])
    }

    /// Derive the official identity-service token endpoint.
    pub(super) fn token_url(&self) -> Url {
        self.identity_path(&["connect", "token"])
    }

    fn identity_path(&self, segments: &[&str]) -> Url {
        let mut url = self.root.clone();
        let mut path = url.path_segments_mut().expect("HTTPS URL has authority");
        path.pop_if_empty().push("identity");
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        url
    }

    /// Canonical HTTPS origin and optional proxy prefix. Persist only this
    /// stable server identity inside authenticated local cache data.
    pub fn server_identity(&self) -> &str {
        self.root.as_str()
    }

    /// Construct only the Bitwarden-compatible read-only user sync endpoint.
    /// The caller cannot use this adapter to create, modify or delete ciphers.
    pub fn sync_url(&self) -> Url {
        let mut url = self.root.clone();
        url.path_segments_mut()
            .expect("HTTPS URL with authority supports path segments")
            .pop_if_empty()
            .push("api")
            .push("sync");
        url
    }
}

/// A concrete native Rust HTTPS client. The system's trusted CA roots are
/// honored by rustls; redirects are disallowed so bearer tokens are never
/// forwarded to a different origin through a server-issued redirect.
pub struct ReadOnlySyncTransport {
    client: Client,
}

impl ReadOnlySyncTransport {
    pub fn new() -> Result<Self, TransportError> {
        Self::with_builder(Client::builder())
    }

    /// Additional trusted private CA, never a bypass of TLS verification.
    /// The same hostname checks and redirect policy apply as in new().
    pub fn with_additional_root_pem(pem: &[u8]) -> Result<Self, TransportError> {
        let root = reqwest::Certificate::from_pem(pem).map_err(|_| TransportError::ClientSetup)?;
        Self::with_builder(Client::builder().add_root_certificate(root))
    }

    fn with_builder(builder: reqwest::blocking::ClientBuilder) -> Result<Self, TransportError> {
        let client = builder
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("passflick/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| TransportError::ClientSetup)?;
        Ok(Self { client })
    }

    /// Reuse the same trusted TLS and no-redirect policy for identity login.
    pub(super) fn client(&self) -> &Client {
        &self.client
    }

    /// Fetch one complete user sync without any upstream mutation. TLS
    /// validation is performed by the HTTPS client; there is no insecure mode.
    pub fn fetch_sync(
        &self,
        endpoint: &ServerEndpoint,
        bearer_token: &str,
        expected_account_id: &str,
    ) -> Result<Value, TransportError> {
        validate_token(bearer_token)?;
        validate_account(expected_account_id)?;
        let response = self
            .client
            .get(endpoint.sync_url())
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(bearer_token)
            .send()
            .map_err(|_| TransportError::Network)?;

        let status = response.status().as_u16();
        if status != 200 {
            return Err(status_error(status));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            return Err(TransportError::Oversized);
        }

        // Content-Length is not trustworthy: read at most the limit plus
        // one byte, including chunked responses. The encrypted sync body
        // is held in zeroizing memory until JSON decoding.
        let mut reader = response.take(MAX_BODY_BYTES as u64 + 1);
        let mut body = Zeroizing::new(Vec::new());
        reader
            .read_to_end(&mut body)
            .map_err(|_| TransportError::Network)?;
        validate_body(200, &body, expected_account_id)
    }
}

fn status_error(status: u16) -> TransportError {
    if status == 401 || status == 403 {
        TransportError::Unauthorized
    } else {
        TransportError::UnexpectedStatus(status)
    }
}

fn validate_token(token: &str) -> Result<(), TransportError> {
    // RFC 6750 b64token, rejecting CR/LF and all request-header injection.
    // Tokens do not appear in debug output, logs, or command arguments here.
    if token.is_empty()
        || token.len() > 8192
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
    {
        return Err(TransportError::InvalidToken);
    }
    Ok(())
}

fn validate_account(id: &str) -> Result<(), TransportError> {
    if id.is_empty()
        || id.len() > MAX_ACCOUNT_ID_BYTES
        || id.trim() != id
        || id.chars().any(char::is_control)
    {
        return Err(TransportError::InvalidAccount);
    }
    Ok(())
}

/// Validate the whole result before giving a caller any JSON to decrypt.
/// This helper also accepts synthetic HTTP fixtures to test failure paths
/// without a live account or an intentionally insecure HTTP transport.
fn validate_body(
    status: u16,
    body: &[u8],
    expected_account_id: &str,
) -> Result<Value, TransportError> {
    if status != 200 {
        return Err(status_error(status));
    }
    validate_account(expected_account_id)?;
    if body.len() > MAX_BODY_BYTES {
        return Err(TransportError::Oversized);
    }
    let value = envelope::parse_sync_json(body)?;
    envelope::admit(&value, Some(expected_account_id))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "object":"sync",
            "profile":{"id":"account-fixture"},
            "folders":[],
            "ciphers":[
                {"id":"synthetic-login","type":1,"login":{
                    "username":"2.encrypted-username","password":"2.encrypted-password"
                },"archivedDate":null,"deletedDate":null,"viewPassword":true}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn endpoint_requires_https_and_rejects_credentials_and_fragments() {
        for bad in [
            "http://vault.example.test",
            "https://user:pass@vault.example.test",
            "https://vault.example.test/?api=other",
            "https://vault.example.test/#fragment",
            "file:///tmp/vault",
            "https://",
            "not-an-endpoint",
        ] {
            assert!(matches!(
                ServerEndpoint::parse(bad),
                Err(TransportError::InvalidEndpoint)
            ));
        }
        let url = ServerEndpoint::parse("https://vault.example.test:8443/proxy")
            .unwrap()
            .sync_url();
        assert_eq!(
            url.as_str(),
            "https://vault.example.test:8443/proxy/api/sync"
        );
        assert_eq!(
            ServerEndpoint::parse("https://vault.example.test")
                .unwrap()
                .sync_url()
                .as_str(),
            "https://vault.example.test/api/sync"
        );
    }

    #[test]
    fn accepts_complete_bound_sync_and_preserves_raw_ciphertext() {
        let raw = sample();
        let value = validate_body(200, &raw, "account-fixture").unwrap();
        assert_eq!(
            value["ciphers"][0]["login"]["password"],
            "2.encrypted-password"
        );
    }

    #[test]
    fn rejects_bad_auth_and_server_responses_without_private_error_bodies() {
        let raw = sample();
        assert!(matches!(
            validate_body(401, &raw, "account-fixture"),
            Err(TransportError::Unauthorized)
        ));
        assert!(matches!(
            validate_body(302, &raw, "account-fixture"),
            Err(TransportError::UnexpectedStatus(302))
        ));
        assert!(matches!(
            validate_body(200, &raw, "different-account"),
            Err(TransportError::Admission(
                SyncEnvelopeError::AccountMismatch
            ))
        ));
        assert!(matches!(
            validate_body(200, b"{secret-ish", "account-fixture"),
            Err(TransportError::Admission(SyncEnvelopeError::InvalidJson))
        ));
    }

    #[test]
    fn size_caps_apply_even_without_content_length() {
        let huge = vec![b' '; MAX_BODY_BYTES + 1];
        assert!(matches!(
            validate_body(200, &huge, "account-fixture"),
            Err(TransportError::Oversized)
        ));
    }

    #[test]
    fn no_request_is_sent_with_invalid_token_or_account() {
        assert!(validate_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmeCJ9.signature").is_ok());
        for bad in ["", "with whitespace", "token\r\nInjected:yes", "🗝️"] {
            assert!(matches!(
                validate_token(bad),
                Err(TransportError::InvalidToken)
            ));
        }
        for bad in ["", " ", "wrong\nid"] {
            assert!(matches!(
                validate_account(bad),
                Err(TransportError::InvalidAccount)
            ));
        }
        let transport = ReadOnlySyncTransport::new().unwrap();
        let endpoint = ServerEndpoint::parse("https://vault.example.test").unwrap();
        assert!(matches!(
            transport.fetch_sync(&endpoint, "invalid token", "account-fixture"),
            Err(TransportError::InvalidToken)
        ));
        assert!(matches!(
            transport.fetch_sync(&endpoint, "synthetic-token", " "),
            Err(TransportError::InvalidAccount)
        ));
    }
}
