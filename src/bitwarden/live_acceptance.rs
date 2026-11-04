//! Opt-in end-to-end acceptance against a disposable real Vaultwarden 1.37.x.
//! Only the disposable fixture provisioning client performs upstream writes.
//! Passflick's transport remains read-only. Synthetic credentials only.
//! The test is ignored by ordinary cargo test and hard-bound to localhost.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use rbw::api::KdfType;
use rbw::cipherstring::CipherString;
use rbw::identity::Identity;
use rbw::locked::{Keys, Password};
use reqwest::{Certificate, Url, blocking::Client, redirect::Policy};
use serde_json::{Value, json};

use super::{
    cache_store::{self, CacheKey},
    transport::{ReadOnlySyncTransport, ServerEndpoint},
    update::{self, UpdateRequest},
};

const EMAIL: &str = "passflick-disposable@example.test";
const PASSWORD: &str = "fictional-passflick-master-2026";
const DEVICE_ID: &str = "passflick-disposable-acceptance";
const ACCOUNT_KEY: [u8; 64] = [71; 64];
const FIXTURE_URL: &str = "https://localhost:18443/";

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

fn initial_account_id(client: &Client, base: &str, bearer: &str) -> String {
    // Read-only fixture provisioning shortcut used only to obtain the
    // server-issued account ID; the real adapter enforces envelope admission.
    let response = client
        .get(route(base, "api/sync"))
        .bearer_auth(bearer)
        .send()
        .expect("fixture initial sync failed");
    assert!(
        response.status().is_success(),
        "fixture initial sync rejected"
    );
    let body: Value = response.json().unwrap();
    body["profile"]["id"]
        .as_str()
        .or_else(|| body["Profile"]["Id"].as_str())
        .expect("Vaultwarden response has no profile ID")
        .to_owned()
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
            "uris": [
                {"uri":encrypted("https://example.test/one")},
                {"uri":encrypted("https://alternative.example.test/two")}
            ]
        }
    })
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

fn fixture_update_password(
    client: &Client,
    base: &str,
    bearer: &str,
    account: &str,
    id: &str,
    new_secret: &str,
) {
    let endpoint = format!("api/ciphers/{id}");
    let response = client
        .put(route(base, &endpoint))
        .bearer_auth(bearer)
        .json(&fixture_cipher_payload(account, new_secret))
        .send()
        .expect("disposable password edit request failed");
    assert!(
        response.status().is_success(),
        "disposable password edit status {}",
        response.status()
    );
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

    let bearer = session.bearer_token().unwrap();
    let account = initial_account_id(&client, &url, bearer);
    let initial = transport
        .fetch_sync(&endpoint, bearer, &account)
        .expect("native initial read-only /sync failed");
    assert!(initial["ciphers"].as_array().is_some());

    let first_id = provision_cipher(&client, &url, bearer, &account, "  🗝️ contraseña  ");
    let second_id = provision_cipher(&client, &url, bearer, &account, "second secret");
    assert_ne!(first_id, second_id);

    let private_dir = PrivateDirectory::new();
    let cache_key = CacheKey::from_slice(&[83; 32]).unwrap();
    let path = private_dir.cache();
    let count = update::refresh_explicit(
        &transport,
        &mut session,
        UpdateRequest {
            endpoint: &endpoint,
            expected_account: &account,
            timestamp: 1_800_000_001,
            decoder: &decoder,
            key: &cache_key,
            path: &path,
        },
    )
    .expect("full native read-only sync/decrypt/publish failed");
    assert_eq!(count, 2);

    let offline = cache_store::load(&path, &cache_key, endpoint.server_identity(), &account)
        .expect("encrypted offline projection failed to reopen");
    assert_eq!(offline.items().len(), 2);
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

    // Simulate local token expiry and exercise the *actual* remote refresh
    // grant from the explicit-update entrypoint, with no upstream cipher write.
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
    let bearer = session.bearer_token().unwrap();

    // All mutations below are made exclusively by the *fixture provisioner*.
    // Passflick only fetches a complete, read-only sync after each mutation.
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
    assert!(restored.items().iter().any(|item| item.id() == second_id));

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
    assert_eq!(fs::read(path).unwrap(), last_good_bytes);
}
