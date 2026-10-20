// SPDX-License-Identifier: MIT
//! The PAM module loaded by the real libpam through `pamtester`, as root in a throwaway container
//! (the `pamtester` job in CI). These tests change `/etc/passwd`, `/etc/pam.d`,
//! `/var/lib/nyra/2fa` and `/dev/log`, so they are ignored by default. To run them:
//!
//! ```text
//! PAM_NYRA_TOTP=/path/to/libpam_nyra_totp.so <this test binary> --ignored --test-threads=1
//! ```

use pam_totp::state::{STATE_DIR, State, Store};
use pam_totp::totp::{self, Algorithm, PERIOD};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SERVICE: &str = "nyra-totp-test";
/// The same module with an option, which it must refuse.
const SERVICE_WITH_OPTION: &str = "nyra-totp-test-option";
const RHOST: &str = "192.0.2.7";
const SECRET: [u8; 20] = *b"12345678901234567890";

/// Checks that this runs as root, installs the test PAM services and takes over `/dev/log`, once.
fn setup() -> &'static UnixDatagram {
    static LOG: OnceLock<UnixDatagram> = OnceLock::new();
    LOG.get_or_init(|| {
        assert!(
            rustix::process::geteuid().is_root(),
            "these tests need root in a throwaway container"
        );
        let module = std::env::var("PAM_NYRA_TOTP").expect("PAM_NYRA_TOTP is the module's path");
        std::fs::write(
            format!("/etc/pam.d/{SERVICE}"),
            format!("auth required {module}\n"),
        )
        .unwrap();
        std::fs::write(
            format!("/etc/pam.d/{SERVICE_WITH_OPTION}"),
            format!("auth required {module} nullok\n"),
        )
        .unwrap();
        let _ = std::fs::remove_file("/dev/log");
        let log = UnixDatagram::bind("/dev/log").unwrap();
        log.set_nonblocking(true).unwrap();
        log
    })
}

/// Adds a local user (the module only reads `/etc/passwd`).
fn add_user(name: &str, uid: u32) {
    setup();
    let mut passwd = std::fs::OpenOptions::new()
        .append(true)
        .open("/etc/passwd")
        .unwrap();
    writeln!(
        passwd,
        "{name}:x:{uid}:{uid}::/nonexistent:/usr/sbin/nologin"
    )
    .unwrap();
}

/// Turns two-step authentication on for `uid` with the test secret, as `2fa enable` would, and
/// returns the recovery codes.
fn enable(uid: u32) -> Vec<String> {
    let (state, codes) = State::new(Algorithm::Sha1, SECRET.to_vec(), 0).unwrap();
    Store::system()
        .update(uid, |slot| {
            *slot = Some(state);
            Ok(())
        })
        .unwrap();
    codes
}

fn state(uid: u32) -> State {
    Store::system().read(uid).unwrap().unwrap()
}

fn state_file(uid: u32) -> PathBuf {
    PathBuf::from(STATE_DIR).join(uid.to_string())
}

/// Now, but not in the last seconds of a step, so a code made here is still for the current step
/// when the module checks it.
fn now() -> u64 {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now % PERIOD < PERIOD - 4 {
            return now;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn app(now: u64) -> String {
    totp::code(&SECRET, Algorithm::Sha1, now).unwrap()
}

/// A six-digit code that is right for none of the steps near `now`.
fn wrong(now: u64) -> String {
    let near: Vec<String> = (0..5).map(|i| app(now + i * PERIOD - 2 * PERIOD)).collect();
    (1..)
        .map(|n: u64| format!("{:06}", (n * 7919) % 1_000_000))
        .find(|c| !near.contains(c))
        .unwrap()
}

/// What one pamtester run did.
struct Attempt {
    success: bool,
    /// The module's lines in the system log during the run.
    log: Vec<String>,
}

/// Starts `pamtester` for `user` on `service`, typing `answer` (or closing its input at once).
fn start(service: &str, user: &str, answer: Option<&str>) -> std::process::Child {
    let mut child = Command::new("pamtester")
        .args([
            "-I",
            &format!("rhost={RHOST}"),
            service,
            user,
            "authenticate",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("pamtester is installed");
    let mut stdin = child.stdin.take().unwrap();
    if let Some(answer) = answer {
        // pamtester may stop reading early (a long answer); that is not an error here.
        let _ = stdin.write_all(format!("{answer}\n").as_bytes());
    }
    drop(stdin);
    child
}

/// The module's log lines received so far.
fn drain_log() -> Vec<String> {
    let mut lines = Vec::new();
    let mut buffer = [0u8; 4096];
    while let Ok(n) = setup().recv(&mut buffer) {
        let line = String::from_utf8_lossy(&buffer[..n]).into_owned();
        if let Some(at) = line.find("pam_nyra_totp(") {
            lines.push(line[at..].to_string());
        }
    }
    lines
}

/// One login attempt; also checks what the module logged about it.
fn login_on(service: &str, user: &str, answer: Option<&str>) -> Attempt {
    setup();
    drain_log();
    let success = start(service, user, answer).wait().unwrap().success();
    let log = drain_log();
    assert_eq!(log.len(), 1, "one log line per attempt: {log:?}");
    let line = &log[0];
    let expected = if success { "accepted" } else { "refused" };
    assert!(
        line.contains(&format!(": {expected} for user {user} from {RHOST}: ")),
        "{line}"
    );
    if let Some(answer) = answer.map(str::trim).filter(|a| !a.is_empty()) {
        assert!(!line.contains(answer), "the code is in the log: {line}");
    }
    Attempt { success, log }
}

fn login(user: &str, answer: &str) -> Attempt {
    login_on(SERVICE, user, Some(answer))
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn right_code_is_accepted_and_recorded() {
    add_user("good", 2001);
    enable(2001);
    let now = now();
    let attempt = login("good", &app(now));
    assert!(attempt.success);
    assert!(attempt.log[0].ends_with(": app code"), "{:?}", attempt.log);
    assert_eq!(state(2001).last_step, now / PERIOD);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn wrong_code_is_refused() {
    add_user("wrong", 2002);
    enable(2002);
    let attempt = login("wrong", &wrong(now()));
    assert!(!attempt.success);
    assert!(attempt.log[0].ends_with(": the code is wrong"));
    assert_eq!(state(2002).last_step, 0);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn reused_code_is_refused() {
    add_user("reused", 2003);
    enable(2003);
    let code = app(now());
    assert!(login("reused", &code).success);
    let again = login("reused", &code);
    assert!(!again.success);
    assert!(again.log[0].ends_with(": the code was already used"));
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn neighbour_steps_are_accepted_and_further_ones_not() {
    add_user("before", 2004);
    enable(2004);
    assert!(login("before", &app(now() - PERIOD)).success);
    add_user("after", 2005);
    enable(2005);
    assert!(login("after", &app(now() + PERIOD)).success);
    add_user("far", 2006);
    enable(2006);
    let now = now();
    assert!(!login("far", &app(now - 2 * PERIOD)).success);
    assert!(!login("far", &app(now + 2 * PERIOD)).success);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn no_state_means_no_login() {
    add_user("nostate", 2007);
    let attempt = login("nostate", &app(now()));
    assert!(!attempt.success);
    assert!(attempt.log[0].ends_with(": two-step authentication is not on for the user"));
    // Nor for a user who does not exist.
    assert!(!login("ghost", &app(now())).success);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn wrong_mode_or_owner_is_refused() {
    add_user("perms", 2008);
    enable(2008);
    let file = state_file(2008);
    for mode in [0o644, 0o640, 0o400] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(!login("perms", &app(now())).success, "mode {mode:o}");
    }
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::chown(&file, Some(2008), None).unwrap();
    assert!(!login("perms", &app(now())).success, "owned by the user");
    std::os::unix::fs::chown(&file, Some(0), None).unwrap();

    std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o755)).unwrap();
    let open_dir = login("perms", &app(now()));
    std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!open_dir.success, "directory mode 0755");

    // Nothing above used the code.
    assert!(login("perms", &app(now())).success);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn symlink_is_refused() {
    add_user("link", 2009);
    enable(2009);
    let real = PathBuf::from("/var/lib/nyra/real-2009");
    std::fs::rename(state_file(2009), &real).unwrap();
    std::os::unix::fs::symlink(&real, state_file(2009)).unwrap();
    assert!(!login("link", &app(now())).success);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn broken_file_is_refused() {
    add_user("broken", 2010);
    enable(2010);
    std::fs::write(state_file(2010), "version=1\nsecret=???\n").unwrap();
    assert!(!login("broken", &app(now())).success);
    std::fs::write(state_file(2010), b"\xff\xfe\x00garbage").unwrap();
    assert!(!login("broken", &app(now())).success);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn recovery_code_works_once() {
    add_user("recovery", 2011);
    let codes = enable(2011);
    let attempt = login("recovery", &codes[4]);
    assert!(attempt.success);
    assert!(attempt.log[0].ends_with(": recovery code, 9 left"));
    assert!(!login("recovery", &codes[4]).success);
    assert_eq!(state(2011).recovery.len(), 9);
    assert!(login("recovery", &codes[5].to_lowercase()).success);
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn non_digit_empty_and_long_answers_are_refused() {
    add_user("input", 2012);
    let codes = enable(2012);
    let long = "7".repeat(10_000);
    for answer in ["abcdef", "12345a", "١٢٣٤٥٦", "", " ", &long] {
        assert!(!login("input", answer).success, "accepted {answer:?}");
    }
    // No answer at all.
    assert!(!login_on(SERVICE, "input", None).success);
    let before = state(2012);
    assert_eq!((before.last_step, before.recovery.len()), (0, codes.len()));
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn module_options_are_refused() {
    add_user("option", 2013);
    enable(2013);
    let attempt = login_on(SERVICE_WITH_OPTION, "option", Some(&app(now())));
    assert!(!attempt.success);
    assert!(attempt.log[0].contains("the module takes no options"));
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn one_code_for_one_of_many_concurrent_logins() {
    add_user("race", 2014);
    enable(2014);
    let code = app(now());
    drain_log();
    let children: Vec<_> = (0..8)
        .map(|_| start(SERVICE, "race", Some(&code)))
        .collect();
    let accepted = children
        .into_iter()
        .filter_map(|mut child| child.wait().unwrap().success().then_some(()))
        .count();
    assert_eq!(accepted, 1);
    assert_eq!(drain_log().len(), 8);
}

/// A minimal PAM application, for what pamtester cannot do: start a transaction with no user set.
/// It records every message of the conversation and answers each prompt with `ANSWER`.
mod app {
    use std::ffi::{CStr, c_char, c_int, c_void};

    pub const ANSWER: &CStr = c"123456";
    const PAM_SUCCESS: c_int = 0;
    const PAM_BUF_ERR: c_int = 5;
    const PAM_CONV_ERR: c_int = 19;

    #[repr(C)]
    struct Message {
        style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct Response {
        resp: *mut c_char,
        retcode: c_int,
    }

    #[repr(C)]
    struct Conv {
        conv: extern "C" fn(c_int, *mut *const Message, *mut *mut Response, *mut c_void) -> c_int,
        appdata: *mut c_void,
    }

    #[link(name = "libpam.so.0", kind = "dylib", modifiers = "+verbatim")]
    unsafe extern "C" {
        fn pam_start(
            service: *const c_char,
            user: *const c_char,
            conv: *const Conv,
            pamh: *mut *mut c_void,
        ) -> c_int;
        fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
        fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
    }

    unsafe extern "C" {
        fn calloc(count: usize, size: usize) -> *mut c_void;
        fn strdup(s: *const c_char) -> *mut c_char;
    }

    /// Records (style, text) of each message in the `Vec` behind `appdata` and answers them all.
    extern "C" fn conversation(
        num: c_int,
        messages: *mut *const Message,
        responses: *mut *mut Response,
        appdata: *mut c_void,
    ) -> c_int {
        let Ok(num) = usize::try_from(num) else {
            return PAM_CONV_ERR;
        };
        // SAFETY: libpam passes `num` valid messages (Linux-PAM layout: an array of pointers),
        // a valid out-pointer for the responses, and the `appdata` given to pam_start below,
        // which points to a live `Vec`. The responses are allocated with the C allocator, as
        // libpam frees them.
        unsafe {
            let seen = &mut *appdata.cast::<Vec<(c_int, String)>>();
            let out = calloc(num, std::mem::size_of::<Response>()).cast::<Response>();
            if out.is_null() {
                return PAM_BUF_ERR;
            }
            for i in 0..num {
                let message = &**messages.add(i);
                let text = CStr::from_ptr(message.msg).to_string_lossy().into_owned();
                seen.push((message.style, text));
                (*out.add(i)).resp = strdup(ANSWER.as_ptr());
            }
            *responses = out;
        }
        PAM_SUCCESS
    }

    /// Runs pam_authenticate on `service` with no user set. Returns its status and the
    /// conversation's messages.
    pub fn authenticate_without_user(service: &CStr) -> (c_int, Vec<(c_int, String)>) {
        let mut seen: Vec<(c_int, String)> = Vec::new();
        let conv = Conv {
            conv: conversation,
            appdata: (&raw mut seen).cast(),
        };
        let mut pamh = std::ptr::null_mut();
        // SAFETY: valid C strings and pointers that outlive the transaction, which ends here.
        let status = unsafe {
            assert_eq!(
                pam_start(service.as_ptr(), std::ptr::null(), &conv, &mut pamh),
                PAM_SUCCESS
            );
            let status = pam_authenticate(pamh, 0);
            pam_end(pamh, status);
            status
        };
        (status, seen)
    }
}

#[test]
#[ignore = "needs root, pamtester and the built module"]
fn no_user_set_gets_only_the_code_prompt() {
    setup();
    drain_log();
    let service = std::ffi::CString::new(SERVICE).unwrap();
    let (status, seen) = app::authenticate_without_user(&service);
    const PAM_AUTH_ERR: i32 = 7;
    const PAM_PROMPT_ECHO_OFF: i32 = 1;
    assert_eq!(status, PAM_AUTH_ERR);
    // Only the module's own prompt, with echo off: no "login:" from libpam, no error text.
    assert_eq!(
        seen,
        vec![(PAM_PROMPT_ECHO_OFF, "Verification code: ".to_string())]
    );
    let log = drain_log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].ends_with(": refused for user (none) from (unknown): no valid user name"),
        "{log:?}"
    );
    let answer = app::ANSWER.to_str().unwrap();
    assert!(!log[0].contains(answer), "{log:?}");
}
