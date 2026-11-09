//! Opt-in end-to-end acceptance against a disposable real Vaultwarden 1.37.x.
//! Only the disposable fixture provisioning client performs upstream writes.
//! Passflick's transport remains read-only. Synthetic credentials only.
//! The test is ignored by ordinary cargo test and hard-bound to localhost.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
#[cfg(feature = "vaultwarden-preview")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

use rbw::api::KdfType;
use rbw::cipherstring::CipherString;
use rbw::identity::Identity;
use rbw::locked::{Keys, Password};
use reqwest::{Certificate, Url, blocking::Client, redirect::Policy};
use serde_json::{Value, json};

use super::{
    auth::{AuthError, MfaChallenge, MfaProvider},
    cache_store::{self},
    keywrap,
    transport::{ReadOnlySyncTransport, ServerEndpoint},
    update::{self, UpdateRequest},
};

const EMAIL: &str = "passflick-disposable@example.test";
const ARGON_EMAIL: &str = "passflick-argon-disposable@example.test";
const PASSWORD: &str = "fictional-passflick-master-2026";
const DEVICE_ID: &str = "passflick-disposable-acceptance";
const ACCOUNT_KEY: [u8; 64] = [71; 64];
const FIXTURE_URL: &str = "https://localhost:18443/";
const LOCAL_PASSPHRASE: &[u8] = b"fictional offline passphrase independent of remote login";
// A fictional Bitwarden login TOTP seed, NOT the separate account-level MFA
// secret. The projection is password-only and must never persist this field.
const LOGIN_TOTP: &str =
    "otpauth://totp/Passflick:fictional?secret=JBSWY3DPEHPK3PXP&issuer=Passflick";

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        let mut entropy = [0; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-vw-live-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self(dir)
    }

    fn cache(&self) -> PathBuf {
        self.0.join("projection.pfsnapshot")
    }

    fn keywrap(&self) -> PathBuf {
        self.0.join("projection.pfkey")
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn route(root: &str, path: &str) -> Url {
    Url::parse(root).unwrap().join(path).unwrap()
}

fn fixture_client(ca_pem: &[u8]) -> Client {
    let ca = Certificate::from_pem(ca_pem).expect("synthetic CA invalid");
    Client::builder()
        .add_root_certificate(ca)
        .redirect(Policy::none())
        .build()
        .expect("synthetic HTTPS client unavailable")
}

fn identity() -> Identity {
    let mut password = rbw::locked::Vec::new();
    password.extend(PASSWORD.as_bytes().iter().copied());
    Identity::new(
        EMAIL,
        &Password::new(password),
        KdfType::Pbkdf2,
        100_000,
        None,
        None,
    )
    .unwrap()
}

fn keys() -> Keys {
    let mut locked = rbw::locked::Vec::new();
    locked.extend(ACCOUNT_KEY.into_iter());
    Keys::new(locked)
}

fn encrypted(raw: &str) -> String {
    CipherString::encrypt_symmetric(&keys(), raw.as_bytes())
        .unwrap()
        .to_string()
}

fn register(client: &Client, base: &str) {
    let response = client
        .post(route(
            base,
            "identity/accounts/register/send-verification-email",
        ))
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&json!({"email":EMAIL,"name":"Synthetic Passflick Account"}))
        .send()
        .expect("disposable verification request failed");
    assert!(response.status().is_success(), "verification was rejected");
    let ticket: String = response.json().expect("expected JSON verification ticket");

    let identity = identity();
    let wrapped = CipherString::encrypt_symmetric(&identity.keys, &ACCOUNT_KEY)
        .unwrap()
        .to_string();
    let body = json!({
        "email": EMAIL,
        "emailVerificationToken": ticket,
        "masterPasswordHash": rbw::base64::encode(identity.master_password_hash.hash()),
        "key": wrapped,
        "kdf": 0,
        "kdfIterations": 100_000
    });
    let response = client
        .post(route(base, "identity/accounts/register/finish"))
        .json(&body)
        .send()
        .expect("disposable registration failed");
    assert!(
        response.status().is_success(),
        "disposable registration status {}",
        response.status()
    );
}

/// Separate disposable account exercising the *actual* Argon2id prelogin,
/// password grant, wrapped personal key and read-only sync compatibility.
/// The primary PBKDF2 fixture remains untouched; only this test client may
/// provision accounts or their fictional ciphers.
fn register_argon_account(client: &Client, base: &str) {
    let response = client
        .post(route(
            base,
            "identity/accounts/register/send-verification-email",
        ))
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&json!({"email":ARGON_EMAIL,"name":"Synthetic Argon2id Account"}))
        .send()
        .expect("Argon2id fixture verification request failed");
    assert!(
        response.status().is_success(),
        "Argon2id fixture verification request was rejected"
    );
    let ticket: String = response
        .json()
        .expect("Argon2id verification ticket missing");

    let mut locked = rbw::locked::Vec::new();
    locked.extend(PASSWORD.as_bytes().iter().copied());
    let identity = Identity::new(
        ARGON_EMAIL,
        &Password::new(locked),
        KdfType::Argon2id,
        3,
        Some(64),
        Some(2),
    )
    .expect("synthetic Argon2id KDF failed");
    let wrapped = CipherString::encrypt_symmetric(&identity.keys, &ACCOUNT_KEY)
        .unwrap()
        .to_string();
    let response = client
        .post(route(base, "identity/accounts/register/finish"))
        .json(&json!({
            "email": ARGON_EMAIL,
            "emailVerificationToken": ticket,
            "masterPasswordHash": rbw::base64::encode(identity.master_password_hash.hash()),
            "key": wrapped,
            "kdf": 1,
            "kdfIterations": 3,
            "kdfMemory": 64,
            "kdfParallelism": 2
        }))
        .send()
        .expect("Argon2id fixture registration request failed");
    assert!(
        response.status().is_success(),
        "disposable Argon2id account registration was rejected"
    );
}

fn fixture_cipher_payload(account: &str, secret: &str) -> Value {
    json!({
        "encryptedFor": account,
        "type": 1,
        "name": encrypted("Synthetic Vaultwarden Login"),
        "organizationId": null,
        "folderId": null,
        "reprompt": 0,
        "login": {
            "username": encrypted("mañana用户"),
            "password": encrypted(secret),
            "totp": encrypted(LOGIN_TOTP),
            "uris": [
                {"uri":encrypted("https://example.test/one")},
                {"uri":encrypted("https://alternative.example.test/two")}
            ]
        }
    })
}

/// Independently read the real disposable server's complete cipher records.
/// Compare server state without printing ciphertext or plaintext into CI logs.
/// The fixture client is separate from Passflick's network adapter.
fn fixture_server_cipher_state(client: &Client, base: &str, bearer: &str) -> Vec<Value> {
    let response = client
        .get(route(base, "api/sync"))
        .bearer_auth(bearer)
        .send()
        .expect("disposable server-state read failed");
    assert!(
        response.status().is_success(),
        "disposable server-state status {}",
        response.status()
    );
    let body: Value = response.json().expect("disposable sync JSON invalid");
    let mut ciphers = body["ciphers"]
        .as_array()
        .expect("disposable sync omitted cipher array")
        .clone();
    ciphers.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    ciphers
}

fn provision_cipher(
    client: &Client,
    base: &str,
    bearer: &str,
    account: &str,
    secret: &str,
) -> String {
    // Only this synthetic fixture client can mutate the disposable server.
    let body = fixture_cipher_payload(account, secret);
    let response = client
        .post(route(base, "api/ciphers"))
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .expect("fixture cipher creation request failed");
    assert!(
        response.status().is_success(),
        "disposable cipher creation status {}",
        response.status()
    );
    let reply: Value = response.json().unwrap();
    reply["id"]
        .as_str()
        .expect("created cipher missing upstream ID")
        .to_owned()
}

/// This write adapter belongs exclusively to disposable fixture setup.
fn fixture_replace_cipher(client: &Client, base: &str, bearer: &str, id: &str, body: &Value) {
    let endpoint = format!("api/ciphers/{id}");
    let response = client
        .put(route(base, &endpoint))
        .bearer_auth(bearer)
        .json(body)
        .send()
        .expect("disposable fixture cipher replacement failed");
    assert!(
        response.status().is_success(),
        "disposable fixture cipher replacement status {}",
        response.status()
    );
}

fn fixture_update_password(
    client: &Client,
    base: &str,
    bearer: &str,
    account: &str,
    id: &str,
    new_secret: &str,
) {
    let body = fixture_cipher_payload(account, new_secret);
    fixture_replace_cipher(client, base, bearer, id, &body);
}

fn fixture_cipher_action(client: &Client, base: &str, bearer: &str, id: &str, action: &str) {
    assert!(
        matches!(action, "archive" | "unarchive" | "delete"),
        "only fixture lifecycle actions are allowed"
    );
    let endpoint = format!("api/ciphers/{id}/{action}");
    let response = client
        .put(route(base, &endpoint))
        .bearer_auth(bearer)
        .send()
        .expect("disposable lifecycle request failed");
    assert!(
        response.status().is_success(),
        "disposable lifecycle action status {}",
        response.status()
    );
}

/// HOTP/TOTP generator used only for disposable test-account provisioning.
fn synthetic_totp(secret_base32: &str, step_offset: i64) -> String {
    let key = BASE32
        .decode(secret_base32.as_bytes())
        .expect("server's synthetic TOTP key must be Base32");
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock predates epoch")
        .as_secs();
    let counter = i64::try_from(seconds / 30).unwrap() + step_offset;
    assert!(counter >= 0);
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).unwrap();
    mac.update(&(counter as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", binary % 1_000_000)
}

/// The fixture-only client enables TOTP on its disposable test account.
/// No Passflick method can modify the server's MFA configuration.
fn fixture_enable_totp(client: &Client, base: &str, bearer: &str) -> String {
    let id = identity();
    let request = client
        .post(route(base, "api/two-factor/get-authenticator"))
        .bearer_auth(bearer)
        .json(&json!({
            "masterPasswordHash": rbw::base64::encode(id.master_password_hash.hash())
        }))
        .send()
        .expect("synthetic MFA enrollment request failed");
    assert!(
        request.status().is_success(),
        "synthetic MFA enrollment request status {}",
        request.status()
    );
    let reply: Value = request.json().expect("MFA enrollment reply was not JSON");
    let key = reply["authenticator"]["key"]
        .as_str()
        .expect("MFA enrollment did not contain a TOTP key")
        .to_owned();
    let verification = reply["userVerificationToken"]
        .as_str()
        .expect("MFA enrollment did not contain verification token");
    // Activate on the previous 30-second step. The server accepts one
    // step of drift, so the immediately following login can use the
    // current step, which is strictly greater than the activation step.
    let activation = synthetic_totp(&key, -1);
    let response = client
        .post(route(base, "api/two-factor/authenticator"))
        .bearer_auth(bearer)
        .json(&json!({
            "key": key,
            "token": activation,
            "userVerificationToken": verification
        }))
        .send()
        .expect("synthetic TOTP activation failed");
    assert!(
        response.status().is_success(),
        "synthetic TOTP activation status {}",
        response.status()
    );
    key
}

#[test]
#[ignore = "requires disposable localhost Vaultwarden over synthetic trusted TLS"]
fn disposable_server_auth_sync_encrypted_offline() {
    let url = std::env::var("PASSFLICK_DISPOSABLE_URL")
        .expect("disposable test URL must be provided by CI");
    assert_eq!(url, FIXTURE_URL, "test must never target a real account");
    let ca_path =
        std::env::var("PASSFLICK_DISPOSABLE_CA").expect("disposable test root CA path missing");
    let ca_pem = fs::read(Path::new(&ca_path)).unwrap();
    let client = fixture_client(&ca_pem);
    let transport = ReadOnlySyncTransport::with_additional_root_pem(&ca_pem).unwrap();
    let endpoint = ServerEndpoint::parse(&url).unwrap();

    register(&client, &url);
    let (mut session, decoder) = transport
        .authenticate(&endpoint, EMAIL, PASSWORD, DEVICE_ID, None)
        .expect("native password-grant against disposable Vaultwarden failed");

    let initial =
        update::prepare_initial_sync(&transport, &mut session, &endpoint, 1_800_000_000, &decoder)
            .expect("native authenticated initial account discovery failed");
    assert!(initial.items().is_empty());
    let account = initial.account_id().to_owned();
    assert_eq!(initial.server_identity(), endpoint.server_identity());

    let bearer = session.bearer_token().unwrap();

    let first_id = provision_cipher(&client, &url, bearer, &account, "  🗝️ contraseña  ");
    let second_id = provision_cipher(&client, &url, bearer, &account, "second secret");
    assert_ne!(first_id, second_id);
    // Capture exact upstream encrypted records (including IDs and revision
    // metadata) before any native Passflick sync or CLI operations.
    let upstream_initial = fixture_server_cipher_state(&client, &url, bearer);
    assert_eq!(upstream_initial.len(), 2);
    // Require the real disposable server to retain the encrypted TOTP
    // field. Otherwise this test would silently pass on a stripped fixture.
    assert!(upstream_initial.iter().all(|cipher| {
        cipher["login"]["totp"]
            .as_str()
            .is_some_and(|value| value.starts_with("2."))
    }));

    // Native bootstrap now owns account discovery *and* the first complete
    // credential projection. The fixture-only writer never supplies the ID.
    let first_projection =
        update::prepare_initial_sync(&transport, &mut session, &endpoint, 1_800_000_001, &decoder)
            .expect("native first populated sync failed");
    assert_eq!(first_projection.account_id(), account);
    assert_eq!(first_projection.items().len(), 2);
    assert!(
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap())
            == upstream_initial,
        "native initial sync changed disposable upstream cipher state"
    );

    // This runs the actual preview executable through a controlling pseudo-
    // terminal. Fixture registration is separate from Passflick's read-only
    // code; all supplied credentials are fictional.
    #[cfg(feature = "vaultwarden-preview")]
    let cli_directory = PrivateDirectory::new();
    #[cfg(feature = "vaultwarden-preview")]
    {
        let binary = std::env::var("PASSFLICK_PREVIEW_BINARY")
            .expect("explicit CLI executable path is required in disposable CI");
        let binary = Path::new(&binary);
        let data = &cli_directory.0;
        let passflick_dir = data.join("passflick");
        DirBuilder::new()
            .mode(0o700)
            .create(&passflick_dir)
            .unwrap();
        let legacy = passflick_dir.join("vault.passvault");
        let original_legacy = b"fictional historical ciphertext unchanged";
        fs::write(&legacy, original_legacy).unwrap();
        let local = std::str::from_utf8(LOCAL_PASSPHRASE).unwrap();
        let ca = ca_path.as_str();
        // Install one inherited Linux session keyring in the parent BEFORE
        // invoking separate CLI children. Each process must see the same
        // authenticated key and explicit manual-lock marker.
        let _shared_keyring = linux_keyutils::KeyRing::from_special_id(
            linux_keyutils::KeyRingIdentifier::Session,
            true,
        )
        .expect("disposable runner cannot initialize the Linux session keyring");
        super::terminal_acceptance::run_cli(
            binary,
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                ("Vaultwarden master password: ", PASSWORD),
                ("Custom trusted CA PEM path (empty for system trust): ", ca),
                (
                    "New independent local projection passphrase (12–1024 characters): ",
                    local,
                ),
                ("Confirm local projection passphrase: ", local),
            ],
            true,
        );
        let path = passflick_dir.join("projection.pfsnapshot");
        let keypath = passflick_dir.join("projection.pfkey");
        let devicepath = passflick_dir.join("projection.pfdevice");
        let device = fs::read(&devicepath).unwrap();
        let first_bytes = fs::read(&path).unwrap();
        let first_keywrap_bytes = fs::read(&keypath).unwrap();
        // Real CLI invocation must persist only an outcome/time hint, never
        // account identity, plaintext or encrypted projection bytes.
        let first_report = super::refresh_status::read(&path).unwrap().unwrap();
        assert_eq!(
            first_report.outcome,
            super::refresh_status::Outcome::Success
        );
        assert_eq!(
            fs::metadata(passflick_dir.join("projection.pfrefresh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(device.len(), 32);
        let first_key = keywrap::unlock(
            &keypath,
            LOCAL_PASSPHRASE,
            endpoint.server_identity(),
            &account,
        )
        .unwrap();
        let first =
            cache_store::load(&path, &first_key, endpoint.server_identity(), &account).unwrap();
        assert_eq!(first.items().len(), 2);
        // The raw upstream login includes an encrypted TOTP seed, but our
        // password-only projection schema must not contain its decrypted
        // otpauth URI or the seed itself, even while in-memory plaintext.
        let projection_json = first.encode_json().unwrap();
        assert!(
            !projection_json
                .windows(LOGIN_TOTP.len())
                .any(|w| w == LOGIN_TOTP.as_bytes())
        );
        assert!(
            !projection_json
                .windows(b"JBSWY3DPEHPK3PXP".len())
                .any(|w| w == b"JBSWY3DPEHPK3PXP")
        );

        // The disposable server presents a private certificate. Without
        // the explicitly configured CA, the TLS prelogin must fail before
        // remote authentication, with a distinct non-secret network category.
        super::terminal_acceptance::run_cli(
            binary,
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                ("Vaultwarden master password: ", PASSWORD),
                ("Custom trusted CA PEM path (empty for system trust): ", ""),
            ],
            false,
        );
        let untrusted_tls = super::refresh_status::read(&path).unwrap().unwrap();
        assert_eq!(untrusted_tls.outcome, super::refresh_status::Outcome::Sync);
        assert!(untrusted_tls.at >= first_report.at);
        assert_eq!(fs::read(&path).unwrap(), first_bytes);
        assert_eq!(fs::read(&keypath).unwrap(), first_keywrap_bytes);
        assert_eq!(fs::read(&devicepath).unwrap(), device);
        assert_eq!(fs::read(&legacy).unwrap(), original_legacy);

        super::terminal_acceptance::run_cli(
            binary,
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                ("Vaultwarden master password: ", PASSWORD),
                ("Custom trusted CA PEM path (empty for system trust): ", ca),
                (
                    "Local projection passphrase: ",
                    "fictional incorrect passphrase",
                ),
            ],
            false,
        );
        assert_eq!(fs::read(&path).unwrap(), first_bytes);
        assert_eq!(fs::read(&devicepath).unwrap(), device);
        let failed_report = super::refresh_status::read(&path).unwrap().unwrap();
        assert_eq!(failed_report.outcome, super::refresh_status::Outcome::Local);
        assert!(failed_report.at >= untrusted_tls.at);

        super::terminal_acceptance::run_cli(
            binary,
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                ("Vaultwarden master password: ", PASSWORD),
                ("Custom trusted CA PEM path (empty for system trust): ", ca),
                ("Local projection passphrase: ", local),
            ],
            true,
        );
        assert_ne!(fs::read(&path).unwrap(), first_bytes);
        assert_eq!(fs::read(&devicepath).unwrap(), device);
        let recovered_report = super::refresh_status::read(&path).unwrap().unwrap();
        assert_eq!(
            recovered_report.outcome,
            super::refresh_status::Outcome::Success
        );
        assert!(recovered_report.at >= failed_report.at);
        assert_eq!(fs::read(&legacy).unwrap(), original_legacy);
        assert!(
            fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap())
                == upstream_initial,
            "native CLI success or failed local update mutated upstream ciphers"
        );

        // Separate executable invocations must cooperate via the SAME
        // session ring. The remote server is never contacted by these
        // commands: only the encrypted projection and local keywrap exist.
        let invoke = |action: &str, input: &[(&str, &str)], success: bool, expected: &str| {
            super::terminal_acceptance::run_projection_cli(
                binary, data, &legacy, action, input, success, expected,
            );
        };
        invoke(
            "status",
            &[],
            true,
            "Offline projection not unlocked in this Linux keyring session.",
        );
        invoke(
            "unlock",
            &[("Independent local projection passphrase: ", local)],
            true,
            "Offline projection unlocked: 2 login items.",
        );
        invoke(
            "status",
            &[],
            true,
            "Offline projection unlocked: 2 login items.",
        );
        invoke("lock", &[], true, "Offline projection manually locked.");
        invoke("status", &[], true, "Offline projection manually locked.");
        invoke(
            "unlock",
            &[(
                "Independent local projection passphrase: ",
                "fictional incorrect passphrase",
            )],
            false,
            "offline projection keyring or cache authentication failed",
        );
        invoke("status", &[], true, "Offline projection manually locked.");
        invoke(
            "unlock",
            &[("Independent local projection passphrase: ", local)],
            true,
            "Offline projection unlocked: 2 login items.",
        );
        invoke(
            "status",
            &[],
            true,
            "Last successful remote sync (Unix seconds):",
        );
        // Also run the *populated* preview as a native Wayland client using
        // nested Weston. X11/Xvfb only carries keyboard input into Weston;
        // the application and real sensitive wl-copy/wl-paste use Wayland.
        // The fixture still holds an unlocked Linux session keyring here.
        let mut native = std::process::Command::new("bash");
        native
            .arg("ci/wayland-populated-smoke.sh")
            .env("PASSFLICK_PREVIEW_BINARY", binary)
            .env("PASSFLICK_DISPOSABLE_TEST_DATA", data)
            .env("PASSFLICK_DISPOSABLE_TEST_LEGACY", &legacy)
            .env("PASSFLICK_NATIVE_LOCAL_PASSPHRASE", local)
            .env(
                "PASSFLICK_NATIVE_FIRST_PASSWORD",
                if first_id < second_id {
                    "first"
                } else {
                    "second"
                },
            );
        let status = native
            .status()
            .expect("native Wayland populated picker acceptance did not start");
        assert!(
            status.success(),
            "native Wayland populated picker acceptance failed"
        );

        // Read and copy actual fictional remote credentials through a real
        // egui process under Xvfb, then lock that process from another CLI.
        super::gui_acceptance::run(binary, data, &legacy, &first_id, &second_id, local, || {
            // Only the disposable fixture client may edit the upstream
            // synthetic Vaultwarden account. A separate real Passflick
            // update process publishes the replacement local snapshot
            // while the GUI remains open with the *old* selected row.
            let selected_id = if first_id < second_id {
                &first_id
            } else {
                &second_id
            };
            fixture_update_password(
                &client,
                &url,
                session.bearer_token().unwrap(),
                &account,
                selected_id,
                "fictional-UPDATED-password",
            );
            super::terminal_acceptance::run_cli(
                binary,
                data,
                &legacy,
                &[
                    ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                    ("Vaultwarden login email: ", EMAIL),
                    ("Vaultwarden master password: ", PASSWORD),
                    ("Custom trusted CA PEM path (empty for system trust): ", ca),
                    ("Local projection passphrase: ", local),
                ],
                true,
            );
            // A failed refresh or lost session would also block copy, so
            // explicitly verify the new secret really exists in the
            // authenticated snapshot *and* the keyring remains unlocked.
            let updated_key = keywrap::unlock(
                &keypath,
                LOCAL_PASSPHRASE,
                endpoint.server_identity(),
                &account,
            )
            .unwrap();
            let updated =
                cache_store::load(&path, &updated_key, endpoint.server_identity(), &account)
                    .unwrap();
            assert_eq!(updated.items().len(), 2);
            let selected = updated
                .items()
                .iter()
                .find(|item| item.id() == selected_id.as_str())
                .expect("selected fictional upstream record disappeared");
            assert_eq!(selected.password(), "fictional-UPDATED-password");
            super::terminal_acceptance::run_projection_cli(
                binary,
                data,
                &legacy,
                "status",
                &[],
                true,
                "Offline projection unlocked: 2 login items.",
            );
        });
        assert_eq!(fs::read(&devicepath).unwrap(), device);
        assert_eq!(fs::read(&legacy).unwrap(), original_legacy);
    }
    let private_dir = PrivateDirectory::new();
    let keywrap_path = private_dir.keywrap();
    let path = private_dir.cache();
    let count = update::install_initial_projection(
        &first_projection,
        &path,
        &keywrap_path,
        LOCAL_PASSPHRASE,
    )
    .expect("initial native encrypted projection installation failed");
    assert_eq!(count, 2);
    assert!(matches!(
        update::install_initial_projection(
            &first_projection,
            &path,
            &keywrap_path,
            LOCAL_PASSPHRASE,
        ),
        Err(update::UpdateError::Cache(
            cache_store::CacheError::AlreadyExists
        ))
    ));

    // Simulate a new process: recover only from the local passphrase and
    // independent encrypted keywrap. No network session is required.
    let cache_key = keywrap::unlock(
        &keywrap_path,
        LOCAL_PASSPHRASE,
        endpoint.server_identity(),
        &account,
    )
    .expect("independent offline keywrap failed to unlock");
    let offline = cache_store::load(&path, &cache_key, endpoint.server_identity(), &account)
        .expect("encrypted offline projection failed to reopen");
    assert_eq!(offline.items().len(), 2);
    let first_snapshot = fs::read(&path).unwrap();
    let first_keywrap = fs::read(&keywrap_path).unwrap();
    assert!(
        keywrap::unlock(
            &keywrap_path,
            b"fictional incorrect offline secret",
            endpoint.server_identity(),
            &account,
        )
        .is_err(),
        "wrong local passphrase must not expose cached secrets"
    );
    assert!(
        keywrap::unlock(
            &keywrap_path,
            LOCAL_PASSPHRASE,
            endpoint.server_identity(),
            "different-fictional-account",
        )
        .is_err(),
        "local keywrap must bind to the authenticated account"
    );
    assert_eq!(fs::read(&path).unwrap(), first_snapshot);
    assert_eq!(fs::read(&keywrap_path).unwrap(), first_keywrap);
    let ids: Vec<_> = offline.items().iter().map(|item| item.id()).collect();
    assert!(ids.contains(&first_id.as_str()));
    assert!(ids.contains(&second_id.as_str()));
    assert!(offline.items().iter().all(|item| {
        item.title() == "Synthetic Vaultwarden Login"
            && item.username() == "mañana用户"
            && item.uris().len() == 2
    }));
    let secrets: Vec<_> = offline.items().iter().map(|item| item.password()).collect();
    assert!(secrets.contains(&"  🗝️ contraseña  "));
    assert!(secrets.contains(&"second secret"));
    let ciphertext = fs::read(&path).unwrap();
    assert!(!ciphertext.windows(6).any(|w| w == b"second"));

    #[cfg(feature = "vaultwarden-preview")]
    {
        // The preview publication path performs an authenticated full sync,
        // then insists on the independent local keywrap and existing AEAD.
        let refreshed = update::prepare_initial_sync(
            &transport,
            &mut session,
            &endpoint,
            1_800_000_001,
            &decoder,
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            super::command::publish_candidate(
                &refreshed,
                &path,
                b"fictional incorrect local passphrase",
                false
            ),
            Err(super::command::PreviewError::Local)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            super::command::publish_candidate(&refreshed, &path, LOCAL_PASSPHRASE, false).unwrap(),
            2
        );
        let reopened = cache_store::load(
            &path,
            &keywrap::unlock(
                &keywrap_path,
                LOCAL_PASSPHRASE,
                endpoint.server_identity(),
                &account,
            )
            .unwrap(),
            endpoint.server_identity(),
            &account,
        )
        .unwrap();
        assert_eq!(reopened.items().len(), 2);
    }

    // Simulate local token expiry and exercise the *actual* remote refresh
    // grant from the explicit-update entrypoint, with no upstream cipher write.
    // The GUI acceptance above legitimately changes one fictional password
    // through the *fixture writer*, so compare with the server state after
    // that intentional edit rather than with the original two-item baseline.
    let upstream_before_token_refresh =
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap());
    session.expire_for_test();
    assert!(session.bearer_token().is_none());
    assert_eq!(
        update::refresh_explicit(
            &transport,
            &mut session,
            UpdateRequest {
                endpoint: &endpoint,
                expected_account: &account,
                timestamp: 1_800_000_002,
                decoder: &decoder,
                key: &cache_key,
                path: &path,
            },
        )
        .expect("real refresh-token grant or refreshed /sync failed"),
        2
    );
    assert!(session.bearer_token().is_some());
    assert!(
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap())
            == upstream_before_token_refresh,
        "native refresh grant or read-only update mutated upstream ciphers"
    );

    // A malicious or damaged encrypted login on the *real* disposable
    // server must abort a full refresh even when another login decrypts.
    // The fixture writer alone installs invalid ciphertext; Passflick never
    // sends any credential mutation request.
    let last_good_ciphertext = fs::read(&path).unwrap();
    let last_good_keywrap = fs::read(&keywrap_path).unwrap();
    let last_good_sync_time =
        cache_store::load(&path, &cache_key, endpoint.server_identity(), &account)
            .unwrap()
            .last_success_at();
    let mut malformed = fixture_cipher_payload(&account, "fictional corrupted login");
    malformed["login"]["password"] = json!("2.bad|ciphertext|mac");
    fixture_replace_cipher(
        &client,
        &url,
        session.bearer_token().unwrap(),
        &second_id,
        &malformed,
    );
    let upstream_corrupt =
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap());
    assert!(
        upstream_corrupt.iter().any(|cipher| {
            cipher["id"] == second_id && cipher["login"]["password"] == "2.bad|ciphertext|mac"
        }),
        "disposable server did not retain the deliberately corrupt cipher"
    );
    assert!(matches!(
        update::refresh_explicit(
            &transport,
            &mut session,
            UpdateRequest {
                endpoint: &endpoint,
                expected_account: &account,
                timestamp: 1_800_000_003,
                decoder: &decoder,
                key: &cache_key,
                path: &path,
            },
        ),
        Err(update::UpdateError::Projection(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), last_good_ciphertext);
    assert_eq!(fs::read(&keywrap_path).unwrap(), last_good_keywrap);
    let preserved =
        cache_store::load(&path, &cache_key, endpoint.server_identity(), &account).unwrap();
    assert_eq!(preserved.items().len(), 2);
    assert_eq!(preserved.last_success_at(), last_good_sync_time);
    assert!(
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap())
            == upstream_corrupt,
        "rejected native refresh mutated disposable upstream ciphers"
    );

    #[cfg(feature = "vaultwarden-preview")]
    {
        // Exercise the actual masked CLI's failed remote-sync path as well:
        // no local-passphrase prompt, cache overwrite, keywrap change or
        // implicit fallback to a partial single-login snapshot is permitted.
        let binary = std::env::var("PASSFLICK_PREVIEW_BINARY").unwrap();
        let data = &cli_directory.0;
        let legacy = data.join("passflick").join("vault.passvault");
        let cli_snapshot = data.join("passflick").join("projection.pfsnapshot");
        let cli_keywrap = data.join("passflick").join("projection.pfkey");
        let old_cli_snapshot = fs::read(&cli_snapshot).unwrap();
        let old_cli_keywrap = fs::read(&cli_keywrap).unwrap();
        super::terminal_acceptance::run_cli(
            Path::new(&binary),
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                ("Vaultwarden master password: ", PASSWORD),
                (
                    "Custom trusted CA PEM path (empty for system trust): ",
                    ca_path.as_str(),
                ),
            ],
            false,
        );
        assert_eq!(fs::read(&cli_snapshot).unwrap(), old_cli_snapshot);
        assert_eq!(fs::read(&cli_keywrap).unwrap(), old_cli_keywrap);
    }

    // Repair the disposable account through its separate fixture writer.
    // The immediately following successful native refresh must accept the
    // now-valid full response and retain the repaired item after unarchive.
    fixture_update_password(
        &client,
        &url,
        session.bearer_token().unwrap(),
        &account,
        &second_id,
        "fictional-restored-after-malformed",
    );

    // All mutations below are made exclusively by the *fixture provisioner*.
    // Passflick only fetches a complete, read-only sync after each mutation.
    let bearer = session.bearer_token().unwrap();
    fixture_update_password(
        &client,
        &url,
        bearer,
        &account,
        &first_id,
        "edited 🔐 contraseña 🧪",
    );
    fixture_cipher_action(&client, &url, bearer, &second_id, "archive");
    assert_eq!(
        update::refresh_explicit(
            &transport,
            &mut session,
            UpdateRequest {
                endpoint: &endpoint,
                expected_account: &account,
                timestamp: 1_800_000_003,
                decoder: &decoder,
                key: &cache_key,
                path: &path,
            },
        )
        .expect("refresh after edit and archive failed"),
        1
    );
    let edited = cache_store::load(&path, &cache_key, endpoint.server_identity(), &account)
        .expect("changed snapshot could not be reopened offline");
    assert_eq!(edited.items()[0].id(), first_id);
    assert_eq!(edited.items()[0].password(), "edited 🔐 contraseña 🧪");

    let bearer = session.bearer_token().unwrap();
    fixture_cipher_action(&client, &url, bearer, &second_id, "unarchive");
    assert_eq!(
        update::refresh_explicit(
            &transport,
            &mut session,
            UpdateRequest {
                endpoint: &endpoint,
                expected_account: &account,
                timestamp: 1_800_000_004,
                decoder: &decoder,
                key: &cache_key,
                path: &path,
            },
        )
        .expect("refresh after restore failed"),
        2
    );
    let restored = cache_store::load(&path, &cache_key, endpoint.server_identity(), &account)
        .expect("restored snapshot could not be reopened offline");
    let recovered = restored
        .items()
        .iter()
        .find(|item| item.id() == second_id)
        .expect("repaired login did not return after unarchive");
    assert_eq!(recovered.password(), "fictional-restored-after-malformed");

    let bearer = session.bearer_token().unwrap();
    fixture_cipher_action(&client, &url, bearer, &second_id, "delete");
    assert_eq!(
        update::refresh_explicit(
            &transport,
            &mut session,
            UpdateRequest {
                endpoint: &endpoint,
                expected_account: &account,
                timestamp: 1_800_000_005,
                decoder: &decoder,
                key: &cache_key,
                path: &path,
            },
        )
        .expect("refresh after soft deletion failed"),
        1
    );
    let final_snapshot = cache_store::load(&path, &cache_key, endpoint.server_identity(), &account)
        .expect("final projection could not be reopened offline");
    assert_eq!(final_snapshot.items()[0].id(), first_id);
    assert_eq!(
        final_snapshot.items()[0].password(),
        "edited 🔐 contraseña 🧪"
    );

    // A real authenticated response with the wrong account binding must not
    // overwrite the last successful encrypted snapshot.
    let upstream_before_rejected_sync =
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap());
    let last_good_bytes = fs::read(&path).unwrap();
    assert!(
        update::refresh_explicit(
            &transport,
            &mut session,
            UpdateRequest {
                endpoint: &endpoint,
                expected_account: "another-fictional-account",
                timestamp: 1_800_000_006,
                decoder: &decoder,
                key: &cache_key,
                path: &path,
            },
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), last_good_bytes);
    assert!(
        fixture_server_cipher_state(&client, &url, session.bearer_token().unwrap())
            == upstream_before_rejected_sync,
        "failed native sync changed disposable upstream ciphers"
    );

    // Enable TOTP through *fixture-only* account administration. Native
    // Passflick must report the MFA challenge instead of silently logging in.
    let bearer = session.bearer_token().unwrap();
    let totp_key = fixture_enable_totp(&client, &url, bearer);
    assert!(matches!(
        transport.authenticate(&endpoint, EMAIL, PASSWORD, "passflick-second-device", None,),
        Err(AuthError::MfaRequired)
    ));
    assert!(
        transport
            .authenticate(
                &endpoint,
                EMAIL,
                PASSWORD,
                "passflick-second-device",
                Some(MfaChallenge {
                    provider: MfaProvider::Totp,
                    code: "invalid-otp",
                })
            )
            .is_err(),
        "an invalid TOTP must never authenticate"
    );
    #[cfg(feature = "vaultwarden-preview")]
    {
        // The real CLI must recognize the challenge and request the second
        // factor without displaying or persisting it.
        let binary = std::env::var("PASSFLICK_PREVIEW_BINARY").unwrap();
        let data = &cli_directory.0;
        let dir = data.join("passflick");
        let path = dir.join("projection.pfsnapshot");
        let legacy = dir.join("vault.passvault");
        let devicepath = dir.join("projection.pfdevice");
        let original = fs::read(&devicepath).unwrap();
        let current_code = synthetic_totp(&totp_key, 0);
        super::terminal_acceptance::run_cli(
            Path::new(&binary),
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                ("Vaultwarden master password: ", PASSWORD),
                (
                    "Custom trusted CA PEM path (empty for system trust): ",
                    ca_path.as_str(),
                ),
                ("MFA method (totp/email): ", "totp"),
                ("MFA code: ", &current_code),
                (
                    "Local projection passphrase: ",
                    std::str::from_utf8(LOCAL_PASSPHRASE).unwrap(),
                ),
            ],
            true,
        );
        assert_eq!(fs::read(&devicepath).unwrap(), original);
        let key = keywrap::unlock(
            &dir.join("projection.pfkey"),
            LOCAL_PASSPHRASE,
            endpoint.server_identity(),
            &account,
        )
        .unwrap();
        let actual = cache_store::load(&path, &key, endpoint.server_identity(), &account).unwrap();
        assert_eq!(actual.items().len(), 1);
        assert_eq!(actual.items()[0].password(), "edited 🔐 contraseña 🧪");
    }
    // Vaultwarden may reject replaying a TOTP code within the same time
    // window. The preview-enabled branch above already exercised a complete
    // successful MFA login and sync through the real CLI. Retain the direct
    // native MFA acceptance for non-preview test builds only.
    #[cfg(not(feature = "vaultwarden-preview"))]
    {
        let current_code = synthetic_totp(&totp_key, 0);
        let (mfa_session, _) = transport
            .authenticate(
                &endpoint,
                EMAIL,
                PASSWORD,
                "passflick-second-device",
                Some(MfaChallenge {
                    provider: MfaProvider::Totp,
                    code: &current_code,
                }),
            )
            .expect("native TOTP authentication failed against disposable server");
        let renewed = transport
            .fetch_sync(
                &endpoint,
                mfa_session.bearer_token().expect("MFA session is expired"),
                &account,
            )
            .expect("native read-only sync after TOTP authentication failed");
        assert!(renewed["ciphers"].as_array().is_some());
        drop(mfa_session);
    }

    // Closing remote sessions cannot make a local passphrase unusable.
    // This is documented offline behavior, not instant remote revocation.
    drop(session);
    drop(decoder);
    drop(cache_key);
    let local_key = keywrap::unlock(
        &keywrap_path,
        LOCAL_PASSPHRASE,
        endpoint.server_identity(),
        &account,
    )
    .expect("offline passphrase unlock failed after remote session drop");
    let local_snapshot = cache_store::load(&path, &local_key, endpoint.server_identity(), &account)
        .expect("offline ciphertext missing after dropping remote sessions");
    assert_eq!(local_snapshot.items().len(), 1);
    assert_eq!(
        local_snapshot.items()[0].password(),
        "edited 🔐 contraseña 🧪"
    );

    // A genuinely Argon2id-configured account exercises *both* the native
    // prelogin KDF settings and master-password/key-unwrapping path. A
    // wrong password must be rejected without creating an authenticated
    // session. Its login IDs remain isolated from the PBKDF2 test account.
    register_argon_account(&client, &url);
    let (mut argon_session, argon_decoder) = transport
        .authenticate(
            &endpoint,
            ARGON_EMAIL,
            PASSWORD,
            "passflick-argon-correct-device",
            None,
        )
        .expect("real disposable Argon2id password-grant or key-unwrapping failed");
    let argon_empty = update::prepare_initial_sync(
        &transport,
        &mut argon_session,
        &endpoint,
        1_800_000_000,
        &argon_decoder,
    )
    .expect("Argon2id account initial native sync failed");
    assert!(argon_empty.items().is_empty());
    let argon_account = argon_empty.account_id().to_owned();
    assert_ne!(argon_account, account, "distinct KDF accounts shared an ID");
    let argon_id = provision_cipher(
        &client,
        &url,
        argon_session.bearer_token().unwrap(),
        &argon_account,
        "fictional Argon2id 🗝️ password",
    );
    let argon_populated = update::prepare_initial_sync(
        &transport,
        &mut argon_session,
        &endpoint,
        1_800_000_001,
        &argon_decoder,
    )
    .expect("native Argon2id login decryption failed after real HTTPS sync");
    assert_eq!(argon_populated.account_id(), argon_account);
    assert_eq!(argon_populated.items().len(), 1);
    assert_eq!(argon_populated.items()[0].id(), argon_id);
    assert_eq!(
        argon_populated.items()[0].password(),
        "fictional Argon2id 🗝️ password"
    );
    assert_eq!(argon_populated.items()[0].uris().len(), 2);
    assert!(argon_session.bearer_token().is_some());
    drop(argon_populated);
    drop(argon_session);
    drop(argon_decoder);

    // A deliberately wrong password can trigger server-side throttling.
    // Verify correct login/decryption first, then reject the wrong password
    // without making any later successful login depend on the rate limit.
    assert!(matches!(
        transport.authenticate(
            &endpoint,
            ARGON_EMAIL,
            "fictional wrong Argon2id master password",
            "passflick-argon-wrong-device",
            None,
        ),
        Err(AuthError::Rejected)
    ));

    // Keep deliberate rejected logins at the END of disposable acceptance:
    // Vaultwarden may rate-limit an IP after failed password grants, which
    // would otherwise cause valid later Argon2id and MFA tests to fail.
    #[cfg(feature = "vaultwarden-preview")]
    {
        let binary = std::env::var("PASSFLICK_PREVIEW_BINARY").unwrap();
        let data = &cli_directory.0;
        let root = data.join("passflick");
        let snapshot = root.join("projection.pfsnapshot");
        let legacy = root.join("vault.passvault");
        let keywrap = root.join("projection.pfkey");
        let old_snapshot = fs::read(&snapshot).unwrap();
        let old_keywrap = fs::read(&keywrap).unwrap();
        let before = super::refresh_status::read(&snapshot).unwrap().unwrap();
        assert_eq!(before.outcome, super::refresh_status::Outcome::Success);

        super::terminal_acceptance::run_cli(
            Path::new(&binary),
            data,
            &legacy,
            &[
                ("Vaultwarden HTTPS server URL: ", FIXTURE_URL),
                ("Vaultwarden login email: ", EMAIL),
                (
                    "Vaultwarden master password: ",
                    "fictional incorrect remote master password",
                ),
                (
                    "Custom trusted CA PEM path (empty for system trust): ",
                    ca_path.as_str(),
                ),
            ],
            false,
        );
        let rejected = super::refresh_status::read(&snapshot).unwrap().unwrap();
        assert_eq!(
            rejected.outcome,
            super::refresh_status::Outcome::Authentication
        );
        assert!(rejected.at >= before.at);
        assert_eq!(fs::read(&snapshot).unwrap(), old_snapshot);
        assert_eq!(fs::read(&keywrap).unwrap(), old_keywrap);
        assert_eq!(
            fs::read(&legacy).unwrap(),
            b"fictional historical ciphertext unchanged"
        );
    }
}
