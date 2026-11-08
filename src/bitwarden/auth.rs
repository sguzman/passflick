//! Isolated native password-grant authentication for Vaultwarden.
//!
//! Shares the read-only transport's strict HTTPS/redirect policy. The rbw
//! MIT KDF implementation derives the Bitwarden password hash and wrapped
//! personal vault key. Tokens remain in zeroizing memory only; no persistence
//! or production CLI is enabled here. Only TOTP and email-code MFA are
//! supported by this prototype; other providers fail explicitly.
//!
//! Remote authentication naturally creates/updates an authenticated device
//! session. It never performs upstream *credential* writes.

use std::io::Read;
use std::time::{Duration, Instant};

use rbw::api::KdfType;
use rbw::identity::Identity;
use rbw::locked::{Password, Vec as LockedVec};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::decryptor::PersonalLoginDecryptor;
use super::transport::{ReadOnlySyncTransport, ServerEndpoint};

const MAX_REPLY: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid login or session settings")]
    InvalidSettings,
    #[error("HTTPS authentication request failed")]
    Transport,
    #[error("authentication rejected")]
    Rejected,
    #[error("server requires an MFA challenge")]
    MfaRequired,
    #[error("authentication response malformed")]
    InvalidResponse,
    #[error("authentication session belongs to a different server")]
    SessionEndpointMismatch,
    #[error("unsupported or excessive password KDF parameters")]
    UnsupportedKdf,
    #[error("could not unlock the returned personal vault key")]
    UnlockFailed,
}

#[derive(Clone, Copy)]
pub enum MfaProvider {
    Totp,
    EmailCode,
}

impl MfaProvider {
    fn number(self) -> u32 {
        match self {
            Self::Totp => 0,
            Self::EmailCode => 1,
        }
    }
}

pub struct MfaChallenge<'a> {
    pub provider: MfaProvider,
    pub code: &'a str,
}

#[derive(Deserialize)]
struct KdfSettings {
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    memory_mib: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    parallelism: Option<u32>,
}

impl KdfSettings {
    fn valid(&self) -> bool {
        match self.kdf {
            KdfType::Pbkdf2 => (1..=2_000_000).contains(&self.iterations),
            KdfType::Argon2id => {
                (1..=10).contains(&self.iterations)
                    && self.memory_mib.is_some_and(|m| (16..=256).contains(&m))
                    && self.parallelism.is_some_and(|p| (1..=8).contains(&p))
            }
        }
    }
}

#[derive(Serialize)]
struct PasswordGrant<'a> {
    grant_type: &'static str,
    scope: &'static str,
    client_id: &'static str,
    username: &'a str,
    password: &'a str,
    #[serde(rename = "deviceType")]
    device_type: u8,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: &'a str,
    #[serde(rename = "deviceName")]
    device_name: &'static str,
    #[serde(rename = "devicePushToken")]
    device_push_token: &'static str,
    #[serde(rename = "twoFactorProvider", skip_serializing_if = "Option::is_none")]
    two_factor_provider: Option<u32>,
    #[serde(rename = "twoFactorToken", skip_serializing_if = "Option::is_none")]
    two_factor_token: Option<&'a str>,
}

#[derive(Serialize)]
struct RefreshGrant<'a> {
    grant_type: &'static str,
    client_id: &'static str,
    refresh_token: &'a str,
}

// Protect each field as it is deserialized. A Drop impl on the complete
// reply cannot erase strings that were already allocated if serde rejects
// a later field: the partially built struct never reaches its own Drop.
#[derive(Deserialize)]
struct LoginReply {
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    #[serde(rename = "Key", alias = "key")]
    encrypted_user_key: Zeroizing<String>,
    expires_in: u64,
}

#[derive(Deserialize)]
struct RefreshReply {
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    expires_in: u64,
}

pub struct RemoteSession {
    endpoint_identity: String,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    expires_at: Instant,
}

impl RemoteSession {
    /// Prevent a cached bearer or refresh token from being sent to another
    /// origin or a different reverse-proxy root on the same origin.
    pub(crate) fn ensure_endpoint(&self, endpoint: &ServerEndpoint) -> Result<(), AuthError> {
        if self.endpoint_identity != endpoint.server_identity() {
            return Err(AuthError::SessionEndpointMismatch);
        }
        Ok(())
    }

    pub fn bearer_token(&self) -> Option<&str> {
        (Instant::now() < self.expires_at).then_some(self.access_token.as_str())
    }

    /// Simulate access-token expiry without sleeping in disposable fixture tests.
    /// No production caller can influence the token's expiration clock.
    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.expires_at = Instant::now();
    }

    fn new(reply: &mut LoginReply, endpoint: &ServerEndpoint) -> Result<Self, AuthError> {
        let expires_at = token_expiration(reply.expires_in)?;
        Ok(Self {
            endpoint_identity: endpoint.server_identity().to_owned(),
            access_token: std::mem::replace(
                &mut reply.access_token,
                Zeroizing::new(String::new()),
            ),
            refresh_token: std::mem::replace(
                &mut reply.refresh_token,
                Zeroizing::new(String::new()),
            ),
            expires_at,
        })
    }

    fn apply_refresh(&mut self, reply: &mut RefreshReply) -> Result<(), AuthError> {
        let expires_at = token_expiration(reply.expires_in)?;
        let access_token =
            std::mem::replace(&mut reply.access_token, Zeroizing::new(String::new()));
        let refresh_token =
            std::mem::replace(&mut reply.refresh_token, Zeroizing::new(String::new()));
        self.access_token = access_token;
        self.refresh_token = refresh_token;
        self.expires_at = expires_at;
        Ok(())
    }
}

fn token_expiration(seconds: u64) -> Result<Instant, AuthError> {
    if !(1..=86_400).contains(&seconds) {
        return Err(AuthError::InvalidResponse);
    }
    Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .ok_or(AuthError::InvalidResponse)
}

fn valid_email(email: &str) -> bool {
    email.len() <= 320
        && email.contains('@')
        && email.trim() == email
        && !email.chars().any(char::is_control)
}

fn valid_device_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn read_response(response: reqwest::blocking::Response) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if response.content_length().is_some_and(|len| len > MAX_REPLY) {
        return Err(AuthError::InvalidResponse);
    }
    let mut body = Zeroizing::new(Vec::new());
    response
        .take(MAX_REPLY + 1)
        .read_to_end(&mut body)
        .map_err(|_| AuthError::Transport)?;
    if body.len() as u64 > MAX_REPLY {
        return Err(AuthError::InvalidResponse);
    }
    Ok(body)
}

fn decode_login(raw: &[u8]) -> Result<LoginReply, AuthError> {
    let parsed: LoginReply = serde_json::from_slice(raw).map_err(|_| AuthError::InvalidResponse)?;
    if parsed.access_token.is_empty()
        || parsed.access_token.len() > 8192
        || parsed.refresh_token.is_empty()
        || parsed.refresh_token.len() > 8192
        || parsed.encrypted_user_key.len() > 8192
        || parsed.encrypted_user_key.is_empty()
    {
        return Err(AuthError::InvalidResponse);
    }
    token_expiration(parsed.expires_in)?;
    Ok(parsed)
}

fn decode_refresh(raw: &[u8]) -> Result<RefreshReply, AuthError> {
    let parsed: RefreshReply =
        serde_json::from_slice(raw).map_err(|_| AuthError::InvalidResponse)?;
    if parsed.access_token.is_empty()
        || parsed.access_token.len() > 8192
        || parsed.refresh_token.is_empty()
        || parsed.refresh_token.len() > 8192
    {
        return Err(AuthError::InvalidResponse);
    }
    token_expiration(parsed.expires_in)?;
    Ok(parsed)
}

fn mfa_required(raw: &[u8]) -> bool {
    // Do not render the server's error description. The presence of a
    // supported provider indicates a recoverable second-factor challenge.
    let Ok(value) = super::strict_json::parse(raw) else {
        return false;
    };
    value
        .get("TwoFactorProviders")
        .or_else(|| value.get("twoFactorProviders"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|providers| {
            providers.iter().any(|p| {
                p.as_u64().is_some_and(|v| v == 0 || v == 1)
                    || p.as_str().is_some_and(|v| v == "0" || v == "1")
            })
        })
}

impl ReadOnlySyncTransport {
    /// Perform the password-grant exchange without storing any tokens.
    /// On success the caller owns an in-memory session and unlocked personal
    /// key. The user sync still requires complete account-ID admission.
    pub fn authenticate(
        &self,
        endpoint: &ServerEndpoint,
        email: &str,
        master_password: &str,
        device_identifier: &str,
        mfa: Option<MfaChallenge<'_>>,
    ) -> Result<(RemoteSession, PersonalLoginDecryptor), AuthError> {
        if !valid_email(email)
            || master_password.is_empty()
            || master_password.len() > 8 * 1024
            || !valid_device_id(device_identifier)
            || mfa.as_ref().is_some_and(|challenge| {
                challenge.code.is_empty()
                    || challenge.code.len() > 128
                    || challenge.code.chars().any(char::is_control)
            })
        {
            return Err(AuthError::InvalidSettings);
        }

        let response = self
            .client()
            .post(endpoint.prelogin_url())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({"email":email}))
                    .map_err(|_| AuthError::InvalidSettings)?,
            )
            .send()
            .map_err(|_| AuthError::Transport)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AuthError::Rejected);
        }
        let body = read_response(response)?;
        let settings: KdfSettings =
            serde_json::from_slice(&body).map_err(|_| AuthError::InvalidResponse)?;
        if !settings.valid() {
            return Err(AuthError::UnsupportedKdf);
        }

        let mut locked_password = LockedVec::new();
        locked_password.extend(master_password.as_bytes().iter().copied());
        let password = Password::new(locked_password);
        let identity = Identity::new(
            email,
            &password,
            settings.kdf,
            settings.iterations,
            settings.memory_mib,
            settings.parallelism,
        )
        .map_err(|_| AuthError::UnsupportedKdf)?;

        let hash = Zeroizing::new(rbw::base64::encode(identity.master_password_hash.hash()));
        let normalized_email = email.to_lowercase();
        let grant = PasswordGrant {
            grant_type: "password",
            scope: "api offline_access",
            client_id: "cli",
            username: &normalized_email,
            password: hash.as_str(),
            device_type: 8,
            device_identifier,
            device_name: "passflick",
            device_push_token: "",
            two_factor_provider: mfa.as_ref().map(|value| value.provider.number()),
            two_factor_token: mfa.as_ref().map(|value| value.code),
        };
        let response = self
            .client()
            .post(endpoint.token_url())
            .header(
                "auth-email",
                rbw::base64::encode_url_safe_no_pad(&normalized_email),
            )
            .form(&grant)
            .send()
            .map_err(|_| AuthError::Transport)?;
        if response.status() != reqwest::StatusCode::OK {
            if response.status() == reqwest::StatusCode::BAD_REQUEST {
                let body = read_response(response)?;
                if mfa_required(&body) {
                    return Err(AuthError::MfaRequired);
                }
            }
            return Err(AuthError::Rejected);
        }
        let body = read_response(response)?;
        let mut reply = decode_login(&body)?;
        let decryptor = PersonalLoginDecryptor::unlock(
            &normalized_email,
            master_password,
            settings.kdf,
            settings.iterations,
            settings.memory_mib,
            settings.parallelism,
            &reply.encrypted_user_key,
        )
        .map_err(|_| AuthError::UnlockFailed)?;
        let session = RemoteSession::new(&mut reply, endpoint)?;
        Ok((session, decryptor))
    }

    /// Request renewed access only after an explicit update action. A failed
    /// response does not replace the already-held token pair. Refresh-token
    /// rotation is preserved if the server returns a new token.
    pub fn refresh_session(
        &self,
        endpoint: &ServerEndpoint,
        session: &mut RemoteSession,
    ) -> Result<(), AuthError> {
        session.ensure_endpoint(endpoint)?;
        if session.refresh_token.is_empty()
            || session.refresh_token.len() > 8192
            || session
                .refresh_token
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(AuthError::InvalidSettings);
        }
        let grant = RefreshGrant {
            grant_type: "refresh_token",
            client_id: "cli",
            refresh_token: session.refresh_token.as_str(),
        };
        let response = self
            .client()
            .post(endpoint.token_url())
            .form(&grant)
            .send()
            .map_err(|_| AuthError::Transport)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AuthError::Rejected);
        }
        let body = read_response(response)?;
        let mut reply = decode_refresh(&body)?;
        session.apply_refresh(&mut reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_rejects_bad_kdf_cost_before_crypto() {
        for raw in [
            r#"{"kdf":0,"kdfIterations":0}"#,
            r#"{"kdf":0,"kdfIterations":2000001}"#,
            r#"{"kdf":1,"kdfIterations":3}"#,
            r#"{"kdf":1,"kdfIterations":11,"kdfMemory":64,"kdfParallelism":1}"#,
            r#"{"kdf":1,"kdfIterations":3,"kdfMemory":512,"kdfParallelism":1}"#,
        ] {
            let settings: KdfSettings = serde_json::from_str(raw).unwrap();
            assert!(!settings.valid());
        }
        let settings: KdfSettings =
            serde_json::from_str(r#"{"Kdf":0,"KdfIterations":1500}"#).unwrap();
        assert!(settings.valid());
    }

    #[test]
    fn token_values_are_bounded_and_expiry_checked() {
        assert!(decode_login(
            br#"{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","Key":"2.key","expires_in":3600}"#
        ).is_ok());
        assert!(
            decode_login(br#"{"access_token":"","refresh_token":"r","Key":"k","expires_in":3600}"#)
                .is_err()
        );
        assert!(
            decode_login(br#"{"access_token":"a","refresh_token":"r","Key":"k","expires_in":0}"#)
                .is_err()
        );
        assert!(
            decode_refresh(
                br#"{"access_token":"new","refresh_token":"new-refresh","expires_in":3600}"#
            )
            .is_ok()
        );
        assert!(
            decode_refresh(br#"{"access_token":"new","refresh_token":"","expires_in":3600}"#)
                .is_err()
        );
    }

    #[test]
    fn partially_deserialized_auth_replies_fail_without_exposing_response_text() {
        // The access and refresh fields are allocated before a late parse
        // failure. Their Zeroizing wrappers now own them *during* serde
        // deserialization, including the error path.
        for raw in [
            br#"{"access_token":"fictional-access-secret","refresh_token":"fictional-refresh-secret","Key":"2.fixture","expires_in":"not-a-number"}"#.as_slice(),
            br#"{"access_token":"fictional-access-secret","refresh_token":"fictional-refresh-secret","Key":"2.fixture"}"#.as_slice(),
        ] {
            assert!(matches!(decode_login(raw), Err(AuthError::InvalidResponse)));
        }
        for raw in [
            br#"{"access_token":"fictional-access-secret","refresh_token":"fictional-refresh-secret","expires_in":"wrong"}"#.as_slice(),
            br#"{"access_token":"fictional-access-secret","refresh_token":"fictional-refresh-secret"}"#.as_slice(),
        ] {
            assert!(matches!(decode_refresh(raw), Err(AuthError::InvalidResponse)));
        }
    }

    #[test]
    fn remote_session_rotates_only_on_valid_refresh() {
        let mut login = decode_login(
            br#"{"access_token":"old-access","refresh_token":"old-refresh","Key":"2.key","expires_in":3600}"#
        ).unwrap();
        let mut session = RemoteSession::new(
            &mut login,
            &ServerEndpoint::parse("https://vault.example.test/").unwrap(),
        )
        .unwrap();
        assert_eq!(session.bearer_token(), Some("old-access"));

        let mut invalid = RefreshReply {
            access_token: Zeroizing::new("invalid".to_owned()),
            refresh_token: Zeroizing::new("invalid".to_owned()),
            expires_in: 0,
        };
        assert!(session.apply_refresh(&mut invalid).is_err());
        assert_eq!(session.bearer_token(), Some("old-access"));

        let mut valid = decode_refresh(
            br#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":60}"#,
        )
        .unwrap();
        session.apply_refresh(&mut valid).unwrap();
        assert_eq!(session.bearer_token(), Some("new-access"));
        assert_eq!(session.refresh_token.as_str(), "new-refresh");
    }

    #[test]
    fn mfa_challenges_are_classified_without_returning_private_error_text() {
        assert!(mfa_required(
            br#"{"TwoFactorProviders":[0,6],"error_description":"private"}"#
        ));
        assert!(mfa_required(br#"{"twoFactorProviders":[1]}"#));
        assert!(mfa_required(br#"{"TwoFactorProviders":["0","6"]}"#));
        assert!(mfa_required(br#"{"TwoFactorProviders":["1"]}"#));
        assert!(!mfa_required(br#"{"twoFactorProviders":[6]}"#));
        assert!(!mfa_required(
            br#"{"error_description":"invalid password"}"#
        ));
        assert_eq!(MfaProvider::Totp.number(), 0);
        assert_eq!(MfaProvider::EmailCode.number(), 1);
    }

    #[test]
    fn input_validation_precedes_all_https_requests() {
        let transport = ReadOnlySyncTransport::new().unwrap();
        let endpoint = ServerEndpoint::parse("https://vault.example.test").unwrap();
        assert!(matches!(
            transport.authenticate(&endpoint, "invalid-email", "fictional", "device-id", None),
            Err(AuthError::InvalidSettings)
        ));
        assert!(matches!(
            transport.authenticate(&endpoint, "user@example.test", "fictional", "bad id", None),
            Err(AuthError::InvalidSettings)
        ));
        assert!(matches!(
            transport.authenticate(
                &endpoint,
                "user@example.test",
                "fictional",
                "device-id",
                Some(MfaChallenge {
                    provider: MfaProvider::Totp,
                    code: "\n"
                })
            ),
            Err(AuthError::InvalidSettings)
        ));
    }

    #[test]
    fn refresh_rejects_empty_token_without_network_request() {
        let transport = ReadOnlySyncTransport::new().unwrap();
        let endpoint = ServerEndpoint::parse("https://vault.example.test").unwrap();
        let mut reply = LoginReply {
            access_token: Zeroizing::new("synthetic".to_owned()),
            refresh_token: Zeroizing::new(String::new()),
            encrypted_user_key: Zeroizing::new("2.example".to_owned()),
            expires_in: 60,
        };
        let mut session = RemoteSession::new(&mut reply, &endpoint).unwrap();
        assert!(matches!(
            transport.refresh_session(&endpoint, &mut session),
            Err(AuthError::InvalidSettings)
        ));
    }

    #[test]
    fn remote_session_rejects_other_host_and_proxy_root_before_token_send() {
        let transport = ReadOnlySyncTransport::new().unwrap();
        let original = ServerEndpoint::parse("https://vault.example.test/personal").unwrap();
        let other_host = ServerEndpoint::parse("https://attacker.example.test/personal").unwrap();
        let other_root = ServerEndpoint::parse("https://vault.example.test/another").unwrap();
        let mut login = decode_login(
            br#"{"access_token":"fictional-access","refresh_token":"fictional-refresh","Key":"2.fixture","expires_in":60}"#,
        )
        .unwrap();
        let mut session = RemoteSession::new(&mut login, &original).unwrap();
        assert_eq!(session.ensure_endpoint(&original), Ok(()));
        for wrong in [&other_host, &other_root] {
            assert_eq!(
                session.ensure_endpoint(wrong),
                Err(AuthError::SessionEndpointMismatch)
            );
            assert!(matches!(
                transport.refresh_session(wrong, &mut session),
                Err(AuthError::SessionEndpointMismatch)
            ));
        }
        assert_eq!(session.bearer_token(), Some("fictional-access"));
        assert_eq!(session.refresh_token.as_str(), "fictional-refresh");
    }

    #[test]
    fn token_endpoints_are_separate_from_vault_sync_path() {
        let endpoint = ServerEndpoint::parse("https://vault.example.test/prefix").unwrap();
        assert_eq!(
            endpoint.prelogin_url().as_str(),
            "https://vault.example.test/prefix/identity/accounts/prelogin"
        );
        assert_eq!(
            endpoint.token_url().as_str(),
            "https://vault.example.test/prefix/identity/connect/token"
        );
    }
}
