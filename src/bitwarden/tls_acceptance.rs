//! Disposable, self-contained TLS trust acceptance using OpenSSL's HTTPS test
//! server. No real Vaultwarden, home endpoint, account or credentials are used.
//!
//! A locally generated CA signs a localhost-only leaf. The system-only client
//! must reject the chain; an explicitly trusted test root must connect; that
//! same root must not allow a mismatched IP hostname. This is deliberately
//! different from disabling TLS verification.

use std::fs::{self, DirBuilder};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use super::transport::{ReadOnlySyncTransport, ServerEndpoint, TransportError};

struct TlsFixture {
    directory: PathBuf,
    server: Child,
    port: u16,
    ca_pem: Vec<u8>,
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn openssl(directory: &Path, args: &[&str]) {
    let result = Command::new("openssl")
        .current_dir(directory)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("OpenSSL CLI is required for synthetic TLS acceptance tests");
    assert!(result.success(), "OpenSSL fixture generation failed");
}

impl TlsFixture {
    fn new() -> Self {
        let mut unique = [0_u8; 8];
        getrandom::fill(&mut unique).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "passflick-local-ca-{:016x}",
            u64::from_le_bytes(unique)
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();

        openssl(
            &directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                "ca.key",
                "-out",
                "ca.crt",
                "-subj",
                "/CN=Passflick Synthetic CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        openssl(
            &directory,
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-subj",
                "/CN=localhost",
            ],
        );
        fs::write(
            directory.join("server.ext"),
            concat!(
                "subjectAltName=DNS:localhost\n",
                "basicConstraints=critical,CA:FALSE\n",
                "keyUsage=critical,digitalSignature,keyEncipherment\n",
                "extendedKeyUsage=serverAuth\n"
            ),
        )
        .unwrap();
        openssl(
            &directory,
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "server.crt",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                "server.ext",
            ],
        );

        // Reserve a random local ephemeral port and immediately release it
        // before the OpenSSL subprocess binds. The test confirms readiness.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let server = Command::new("openssl")
            .arg("s_server")
            .arg("-accept")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-cert")
            .arg("server.crt")
            .arg("-key")
            .arg("server.key")
            .arg("-www")
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("could not start local synthetic TLS listener");
        let ca_pem = fs::read(directory.join("ca.crt")).unwrap();
        let mut fixture = Self {
            directory,
            server,
            port,
            ca_pem,
        };
        let mut ready = false;
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                ready = true;
                break;
            }
            assert!(
                fixture.server.try_wait().unwrap().is_none(),
                "synthetic TLS server exited before accepting connections"
            );
            thread::sleep(Duration::from_millis(25));
        }
        assert!(ready, "synthetic TLS listener did not become ready");
        fixture
    }

    fn endpoint(&self, hostname: &str) -> ServerEndpoint {
        ServerEndpoint::parse(&format!("https://{hostname}:{}", self.port)).unwrap()
    }
}

#[test]
fn tls_system_trust_custom_ca_and_hostname_mismatch() {
    let fixture = TlsFixture::new();
    let endpoint = fixture.endpoint("localhost");
    let untrusted = ReadOnlySyncTransport::new().unwrap();
    assert!(matches!(
        untrusted.fetch_sync(&endpoint, "synthetic-token", "fixture-account"),
        Err(TransportError::Network)
    ));

    let trusted = ReadOnlySyncTransport::with_additional_root_pem(&fixture.ca_pem).unwrap();
    // OpenSSL's -www response is deliberately HTML, not a Bitwarden sync.
    // Passing through to JSON admission proves successful TLS verification
    // without falsely accepting the response as valid credentials.
    assert!(matches!(
        trusted.fetch_sync(&endpoint, "synthetic-token", "fixture-account"),
        Err(TransportError::Admission(_))
    ));

    let wrong_host = fixture.endpoint("127.0.0.1");
    assert!(matches!(
        trusted.fetch_sync(&wrong_host, "synthetic-token", "fixture-account"),
        Err(TransportError::Network)
    ));
}

#[test]
fn unavailable_https_server_fails_closed_without_local_or_plaintext_fallback() {
    // An unused loopback port cannot accept HTTPS. No real endpoint or
    // account is contacted and the native client must not fall back to HTTP.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let endpoint = ServerEndpoint::parse(&format!("https://127.0.0.1:{port}")).unwrap();
    let client = ReadOnlySyncTransport::new().unwrap();
    assert!(matches!(
        client.fetch_sync(&endpoint, "fictional-bearer", "fixture-account"),
        Err(TransportError::Network)
    ));
}

#[test]
fn invalid_extra_ca_never_enables_an_insecure_fallback() {
    assert!(matches!(
        ReadOnlySyncTransport::with_additional_root_pem(b"not a certificate"),
        Err(TransportError::ClientSetup)
    ));
}
