//! An actual Linux controlling-PTY driver for fictional acceptance accounts.
//! This is never shipped in the Passflick binary. Avoid printing captured
//! terminal bytes: a regression could cause the mock secrets to be echoed.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const LIMIT: usize = 32 * 1024;
const DEADLINE: Duration = Duration::from_secs(100);

/// Drive each prompt after observing its echo policy: non-secret settings
/// must be visible and credentials must remain hidden. Never print output.
pub(super) fn run_cli(
    binary: &Path,
    data_dir: &Path,
    legacy: &Path,
    answers: &[(&str, &str)],
    should_succeed: bool,
) {
    run_arguments(
        binary,
        data_dir,
        legacy,
        &["update"],
        answers,
        should_succeed,
        None,
    );
}

/// Exercise a *new* process per offline action, with the same synthetic
/// data directory and inherited kernel session keyring as its parent.
/// No credential or protected identity is supplied through argv.
pub(super) fn run_projection_cli(
    binary: &Path,
    data_dir: &Path,
    legacy: &Path,
    operation: &str,
    answers: &[(&str, &str)],
    should_succeed: bool,
    expected_output: &str,
) {
    assert!(matches!(operation, "lock" | "unlock" | "status"));
    run_arguments(
        binary,
        data_dir,
        legacy,
        &["projection", operation],
        answers,
        should_succeed,
        Some(expected_output),
    );
}

fn is_visible_configuration_prompt(prompt: &str) -> bool {
    matches!(
        prompt,
        "Vaultwarden HTTPS server URL: "
            | "Vaultwarden login email: "
            | "Custom trusted CA PEM path (empty for system trust): "
            | "MFA method (totp/email): "
    )
}

fn run_arguments(
    binary: &Path,
    data_dir: &Path,
    legacy: &Path,
    arguments: &[&str],
    answers: &[(&str, &str)],
    should_succeed: bool,
    expected_output: Option<&str>,
) {
    assert!(binary.is_absolute());
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: initialized fd outputs, no nullable optional buffers dereferenced.
    let opened = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(opened, 0, "PTY allocation failed");
    // SAFETY: each descriptor was freshly returned by openpty and is owned once.
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };

    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env("XDG_DATA_HOME", data_dir)
        .env("PASSFLICK_VAULT", legacy)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));

    // SAFETY: pre_exec runs after fork and before exec; only async-signal-safe
    // syscalls are used. The child needs a controlling TTY for rpassword.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("preview process could not launch");
    drop(slave);

    let cutoff = Instant::now() + DEADLINE;
    let mut transcript = Zeroizing::new(Vec::<u8>::new());
    let mut next = 0_usize;
    let mut buf = [0_u8; 4096];
    loop {
        if Instant::now() >= cutoff {
            let _ = child.kill();
            let _ = child.wait();
            panic!("preview PTY timed out at prompt index {next}");
        }
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pointer to one valid initialized pollfd for the call.
        let poll = unsafe { libc::poll(&mut descriptor, 1, 200) };
        if poll < 0 {
            assert_eq!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted
            );
            continue;
        }
        if poll == 0 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            continue;
        }
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                assert!(
                    transcript.len() + n <= LIMIT,
                    "unexpected terminal output volume"
                );
                transcript.extend_from_slice(&buf[..n]);
                if let Some((prompt, reply)) = answers.get(next)
                    && transcript
                        .windows(prompt.len())
                        .any(|window| window == prompt.as_bytes())
                {
                    let mut current = std::mem::MaybeUninit::<libc::termios>::uninit();
                    // SAFETY: master is the controlling PTY and current is
                    // valid writable storage for tcgetattr.
                    assert_eq!(
                        unsafe { libc::tcgetattr(master.as_raw_fd(), current.as_mut_ptr()) },
                        0,
                        "TTY state was unavailable"
                    );
                    // SAFETY: the preceding tcgetattr succeeded.
                    let current = unsafe { current.assume_init() };
                    if is_visible_configuration_prompt(prompt) {
                        assert_ne!(
                            current.c_lflag & libc::ECHO,
                            0,
                            "non-secret configuration prompt must allow visible input"
                        );
                    } else {
                        assert_eq!(
                            current.c_lflag & (libc::ECHO | libc::ECHONL),
                            0,
                            "secret prompt appeared before echo was disabled"
                        );
                    }
                    master.write_all(reply.as_bytes()).unwrap();
                    master.write_all(b"\n").unwrap();
                    next += 1;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => panic!("PTY read failed"),
        }
    }
    let exit = child
        .wait()
        .expect("preview process could not be collected");
    if next != answers.len() {
        // Diagnostic contains ONLY a fixed, nonsecret CLI error category.
        // Never dump the PTY transcript: it contains echoed configuration
        // and potentially fictional or real-looking credential input.
        let categories = [
            ("Vaultwarden authentication or MFA failed", "authentication"),
            ("Vaultwarden authentication rate limited", "rate-limit"),
            ("Vaultwarden prelogin returned HTTP ", "identity-prelogin"),
            ("Vaultwarden token grant returned HTTP ", "identity-token"),
            (
                "Vaultwarden token refresh returned HTTP ",
                "identity-refresh",
            ),
            (
                "Vaultwarden HTTPS connection or certificate validation failed",
                "network",
            ),
            ("complete authenticated Vaultwarden sync failed", "sync"),
            (
                "local encrypted projection authentication or update failed",
                "local",
            ),
            (
                "local projection directory or certificate is inaccessible",
                "storage",
            ),
            (
                "trusted HTTPS transport could not be initialized",
                "transport",
            ),
            (
                "server differs from the existing offline projection",
                "server-mismatch",
            ),
            ("unsupported or invalid HTTPS endpoint", "endpoint"),
        ];
        let outcome = categories
            .iter()
            .find(|(message, _)| {
                transcript
                    .windows(message.len())
                    .any(|bytes| bytes == message.as_bytes())
            })
            .map_or("unclassified", |(_, outcome)| *outcome);
        eprintln!(
            "Synthetic CLI stopped before prompt {next}/{}; fixed error category: {outcome}; exited successfully: {}",
            answers.len(),
            exit.success()
        );
        // Extract only a three-digit status after one of our immutable
        // phase labels, not arbitrary text from the untrusted server.
        let http_status = [
            b"Vaultwarden prelogin returned HTTP ".as_slice(),
            b"Vaultwarden token grant returned HTTP ".as_slice(),
            b"Vaultwarden token refresh returned HTTP ".as_slice(),
        ]
        .iter()
        .find_map(|prefix| {
            transcript.windows(prefix.len() + 3).find_map(|window| {
                let prefix = *prefix;
                if !window.starts_with(prefix) {
                    return None;
                }
                let digits = &window[prefix.len()..];
                if digits.iter().all(|digit| digit.is_ascii_digit()) {
                    Some(
                        u16::from(digits[0] - b'0') * 100
                            + u16::from(digits[1] - b'0') * 10
                            + u16::from(digits[2] - b'0'),
                    )
                } else {
                    None
                }
            })
        })
        .filter(|status| (100..=599).contains(status));
        if let Some(status) = http_status {
            eprintln!("Synthetic CLI upstream response status: HTTP {status}");
        }
    }
    assert_eq!(
        next,
        answers.len(),
        "CLI did not reach all expected prompts"
    );
    assert_eq!(
        exit.success(),
        should_succeed,
        "CLI returned unexpected exit status"
    );
    if let Some(expected) = expected_output {
        assert!(
            transcript
                .windows(expected.len())
                .any(|part| part == expected.as_bytes()),
            "projection CLI did not report expected safe status"
        );
    }
    // Synthetic configuration is expected to echo. Secrets must not.
    // Never include the captured terminal transcript in test logs.
    for (prompt, reply) in answers {
        if !reply.is_empty() && reply.len() >= 8 {
            let was_echoed = transcript
                .windows(reply.len())
                .any(|window| window == reply.as_bytes());
            if is_visible_configuration_prompt(prompt) {
                assert!(was_echoed, "non-secret input was not visible");
            } else {
                assert!(!was_echoed, "secret input was echoed");
            }
        }
    }
    buf.fill(0);
}
