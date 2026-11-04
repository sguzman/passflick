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

/// Drive each masked prompt *after* observing it, rather than piping input
/// before rpassword has disabled terminal echo. Output is never printed.
pub(super) fn run_cli(
    binary: &Path,
    data_dir: &Path,
    legacy: &Path,
    answers: &[(&str, &str)],
    should_succeed: bool,
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
        .arg("update")
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
                    assert_eq!(
                        current.c_lflag & (libc::ECHO | libc::ECHONL),
                        0,
                        "a prompt appeared before terminal echo was disabled"
                    );
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
    // These inputs are fictional, but echoed input is still a terminal
    // privacy failure. Do not leak transcript bytes into assertions/logs.
    for (_, reply) in answers {
        if !reply.is_empty() && reply.len() >= 8 {
            assert!(
                !transcript
                    .windows(reply.len())
                    .any(|window| window == reply.as_bytes()),
                "terminal prompt leaked a supplied value"
            );
        }
    }
    buf.fill(0);
}
