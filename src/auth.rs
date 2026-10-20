// SPDX-License-Identifier: MIT
//! What the PAM module `pam_nyra_totp` decides, in safe Rust and without PAM: the module's FFI
//! layer only fetches the user name, the remote host and the typed code, calls [`authenticate`]
//! and logs the [`Outcome`].
//!
//! Rules:
//! - The code is asked for first, for every user, so the prompt does not tell whether the user
//!   exists or has two-step authentication on (the password module before this one must be
//!   `required`, not `requisite`, for the same reason).
//! - The conversation happens before the state is locked; the lock is held only to check the code
//!   and write the new state ([`Store::update`]), so two logins cannot both use one code.
//! - Any error (no state, unreadable or unsafe state, a clock before 1970, a failed write) is a
//!   refusal. The user sees no reason; the reason only goes to the system log, without the code
//!   or the secret.

use crate::passwd;
use crate::state::{self, State, Store};
use crate::totp;
use std::path::Path;

/// The longest answer to the prompt that is looked at: a recovery code with dashes and spaces is
/// well under it. Longer answers are refused without being parsed or copied further.
pub const MAX_INPUT: usize = 64;
/// The longest user name or remote host name that is used.
pub const MAX_NAME: usize = 256;

/// What the user typed at the prompt, at most [`MAX_INPUT`] bytes in a fixed buffer that is wiped
/// when dropped.
pub struct Input {
    bytes: [u8; MAX_INPUT],
    len: usize,
}

impl Input {
    /// `None` if `bytes` is longer than [`MAX_INPUT`].
    pub fn new(bytes: &[u8]) -> Option<Input> {
        let mut input = Input {
            bytes: [0; MAX_INPUT],
            len: bytes.len(),
        };
        input.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(input)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Input {
    fn wipe(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
        // Keeps the compiler from removing the wipe as a dead store.
        std::hint::black_box(&self.bytes);
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Everything the decision takes from the system, so the tests can replace it.
pub struct Env<'a> {
    pub store: &'a Store,
    pub passwd: &'a Path,
    pub now: &'a dyn Fn() -> Result<u64, state::Error>,
}

/// How a code was accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// A code from the authenticator app.
    App,
    /// A recovery code; this many are left.
    Recovery(usize),
}

/// The result of one login attempt and its reason, for the system log only.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub success: bool,
    pub reason: String,
}

impl Outcome {
    pub fn failure(reason: impl Into<String>) -> Outcome {
        Outcome {
            success: false,
            reason: reason.into(),
        }
    }

    /// The line for the system log. `user` and `rhost` come from the client, so anything but
    /// printable ASCII is replaced and they are cut to [`MAX_NAME`] bytes.
    pub fn log_line(&self, user: Option<&str>, rhost: Option<&str>) -> String {
        format!(
            "{} for user {} from {}: {}",
            if self.success { "accepted" } else { "refused" },
            user.map_or_else(|| "(none)".to_string(), clean),
            rhost.map_or_else(|| "(unknown)".to_string(), clean),
            self.reason
        )
    }
}

/// Printable ASCII without spaces, at most [`MAX_NAME`] bytes; anything else becomes `?`.
fn clean(text: &str) -> String {
    text.bytes()
        .take(MAX_NAME)
        .map(|b| {
            if b.is_ascii_graphic() {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

/// One login attempt for `user`: asks for the code with `ask` (always, and before anything else),
/// then checks it under the user's lock and records its use.
pub fn authenticate(
    env: &Env,
    user: Option<&str>,
    ask: impl FnOnce() -> Result<Input, &'static str>,
) -> Outcome {
    let input = match ask() {
        Ok(input) => input,
        Err(why) => return Outcome::failure(why),
    };
    let Some(user) = user.filter(|u| !u.is_empty() && u.len() <= MAX_NAME) else {
        return Outcome::failure("no valid user name");
    };
    let users = match std::fs::read_to_string(env.passwd) {
        Ok(users) => users,
        Err(e) => return Outcome::failure(format!("cannot read the user list: {e}")),
    };
    let Some(uid) = passwd::uid_of(&users, user) else {
        return Outcome::failure("no such local user");
    };
    let now = match (env.now)() {
        Ok(now) => now,
        Err(e) => return Outcome::failure(e.to_string()),
    };
    match env
        .store
        .update(uid, |state| check(state.as_mut(), input.as_bytes(), now))
    {
        Ok(Accepted::App) => Outcome {
            success: true,
            reason: "app code".to_string(),
        },
        Ok(Accepted::Recovery(left)) => Outcome {
            success: true,
            reason: format!("recovery code, {left} left"),
        },
        Err(e) => Outcome::failure(e.to_string()),
    }
}

/// Checks `input` against the state at time `now` and, if it is right, records its use in
/// `state`: the step of an app code, or the removal of a recovery code. On an error `state` is
/// left as it was. Six digits are an app code; anything else is tried as a recovery code.
pub fn check(state: Option<&mut State>, input: &[u8], now: u64) -> Result<Accepted, state::Error> {
    let state = state.ok_or(state::Error::Refused(
        "two-step authentication is not on for the user",
    ))?;
    let text = std::str::from_utf8(input)
        .map_err(|_| state::Error::Refused("the answer is not UTF-8"))?
        .trim();
    if text.is_empty() {
        return Err(state::Error::Refused("empty answer"));
    }
    if text.len() == totp::DIGITS && text.bytes().all(|b| b.is_ascii_digit()) {
        state.last_step = totp::verify(
            &state.secret,
            state.algorithm,
            text,
            now,
            Some(state.last_step),
        )?;
        Ok(Accepted::App)
    } else if state.use_recovery(text) {
        Ok(Accepted::Recovery(state.recovery.len()))
    } else {
        Err(state::Error::Refused(
            "neither a right app code nor an unused recovery code",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use crate::totp::{Algorithm, PERIOD};
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    const SECRET: [u8; 20] = *b"12345678901234567890";
    const NOW: u64 = 1_700_000_000;
    const UID: u32 = 1000;

    struct Fixture {
        tmp: TempDir,
        store: Store,
        recovery: Vec<String>,
    }

    impl Fixture {
        /// maria (uid 1000) with two-step authentication on, last used five steps ago.
        fn new() -> Fixture {
            let tmp = TempDir::new();
            std::fs::write(
                tmp.path().join("passwd"),
                "root:x:0:0::/root:/bin/sh\nmaria:x:1000:1000::/home/maria:/bin/sh\n\
                 ion:x:1001:1001::/home/ion:/bin/sh\n",
            )
            .unwrap();
            let store = Store::in_dir(&tmp.path().join("2fa"));
            let (state, recovery) =
                State::new(Algorithm::Sha1, SECRET.to_vec(), NOW / PERIOD - 5).unwrap();
            store
                .update(UID, |s| {
                    *s = Some(state);
                    Ok(())
                })
                .unwrap();
            Fixture {
                tmp,
                store,
                recovery,
            }
        }

        /// One attempt by `user` at `now`, typing `answer`. Also checks that the code was asked
        /// for exactly once.
        fn login_at(&self, user: Option<&str>, answer: &str, now: u64) -> Outcome {
            let asked = Cell::new(0);
            let passwd = self.tmp.path().join("passwd");
            let clock = move || Ok(now);
            let env = Env {
                store: &self.store,
                passwd: &passwd,
                now: &clock,
            };
            let outcome = authenticate(&env, user, || {
                asked.set(asked.get() + 1);
                Input::new(answer.as_bytes()).ok_or("the answer is too long")
            });
            assert_eq!(asked.get(), 1, "asked once");
            outcome
        }

        fn login(&self, answer: &str) -> Outcome {
            self.login_at(Some("maria"), answer, NOW)
        }

        fn state(&self) -> State {
            self.store.read(UID).unwrap().unwrap()
        }

        fn file(&self) -> std::path::PathBuf {
            self.tmp.path().join("2fa").join(UID.to_string())
        }
    }

    fn app(now: u64) -> String {
        totp::code(&SECRET, Algorithm::Sha1, now).unwrap()
    }

    /// A six-digit code that is right for none of the steps near `now`.
    fn wrong(now: u64) -> String {
        let near: Vec<String> = (0..5).map(|i| app(now + i * PERIOD - 2 * PERIOD)).collect();
        (0..)
            .map(|n| format!("{:06}", (n * 7919) % 1_000_000))
            .find(|c| !near.contains(c))
            .unwrap()
    }

    #[test]
    fn right_code_is_accepted_once() {
        let f = Fixture::new();
        let code = app(NOW);
        assert_eq!(
            f.login(&code),
            Outcome {
                success: true,
                reason: "app code".into()
            }
        );
        assert_eq!(f.state().last_step, NOW / PERIOD);
        let again = f.login(&code);
        assert!(!again.success);
        assert_eq!(again.reason, "the code was already used");
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let f = Fixture::new();
        assert!(f.login(&format!(" {}\t", app(NOW))).success);
    }

    #[test]
    fn neighbour_steps() {
        let f = Fixture::new();
        assert!(f.login(&app(NOW - PERIOD)).success);
        let f = Fixture::new();
        assert!(f.login(&app(NOW + PERIOD)).success);
        // Once a later step was used, an earlier one is refused.
        assert!(!f.login(&app(NOW)).success);
        let f = Fixture::new();
        assert!(!f.login(&app(NOW - 2 * PERIOD)).success);
        assert!(!f.login(&app(NOW + 2 * PERIOD)).success);
    }

    #[test]
    fn wrong_code_changes_nothing() {
        let f = Fixture::new();
        let before = f.state();
        let outcome = f.login(&wrong(NOW));
        assert_eq!(outcome, Outcome::failure("the code is wrong"));
        assert_eq!(f.state(), before);
    }

    #[test]
    fn recovery_code_works_once() {
        let f = Fixture::new();
        let code = f.recovery[2].clone();
        assert_eq!(
            f.login(&code),
            Outcome {
                success: true,
                reason: "recovery code, 9 left".into()
            }
        );
        assert!(!f.login(&code).success);
        assert_eq!(f.state().recovery.len(), 9);
        // Case and dashes do not matter, as for the command.
        assert!(
            f.login(&f.recovery[0].to_lowercase().replace('-', ""))
                .success
        );
    }

    #[test]
    fn bad_answers_are_refused_without_changes() {
        let f = Fixture::new();
        let before = f.state();
        let long = "1".repeat(MAX_INPUT + 1);
        for answer in [
            "",
            " ",
            "\n",
            "abcdef",
            "12345a",
            "12345",
            "1234567",
            "12 34 56",
            "١٢٣٤٥٦",
            &long,
        ] {
            let outcome = f.login(answer);
            assert!(!outcome.success, "accepted {answer:?}");
        }
        assert_eq!(f.state(), before);
        assert_eq!(f.login("").reason, "empty answer");
        assert_eq!(f.login(&long).reason, "the answer is too long");
    }

    #[test]
    fn non_utf8_is_refused() {
        let mut state = State::new(Algorithm::Sha1, SECRET.to_vec(), 0).unwrap().0;
        assert!(check(Some(&mut state), b"\xff12345", NOW).is_err());
    }

    #[test]
    fn no_state_unknown_or_missing_user_is_refused_after_asking() {
        let f = Fixture::new();
        let code = app(NOW);
        let ion = f.login_at(Some("ion"), &code, NOW);
        assert_eq!(
            ion,
            Outcome::failure("two-step authentication is not on for the user")
        );
        assert_eq!(
            f.login_at(Some("nobody"), &code, NOW),
            Outcome::failure("no such local user")
        );
        // No user set by the application: the code is still asked for (once, checked by
        // login_at), and refused without looking up anyone.
        assert_eq!(
            f.login_at(None, &code, NOW),
            Outcome::failure("no valid user name")
        );
        assert!(!f.login_at(Some(""), &code, NOW).success);
        assert!(
            !f.login_at(Some(&"m".repeat(MAX_NAME + 1)), &code, NOW)
                .success
        );
        // None of these used maria's code.
        assert!(f.login(&code).success);
    }

    #[test]
    fn unsafe_or_broken_state_is_refused() {
        let f = Fixture::new();
        let code = app(NOW);
        let set_mode = |mode| {
            std::fs::set_permissions(f.file(), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        set_mode(0o644);
        assert!(!f.login(&code).success);
        set_mode(0o600);

        let text = std::fs::read(f.file()).unwrap();
        let elsewhere = f.tmp.path().join("elsewhere");
        std::fs::rename(f.file(), &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, f.file()).unwrap();
        assert!(!f.login(&code).success);
        std::fs::remove_file(f.file()).unwrap();

        std::fs::write(f.file(), b"version=1\nsecret=\n").unwrap();
        set_mode(0o600);
        assert!(!f.login(&code).success);

        std::fs::write(f.file(), text).unwrap();
        assert!(f.login(&code).success);
    }

    #[test]
    fn wrong_owner_is_refused() {
        let f = Fixture::new();
        let other = Store::in_dir_owned_by(&f.tmp.path().join("2fa"), UID + 12345);
        let passwd = f.tmp.path().join("passwd");
        let clock = || Ok(NOW);
        let env = Env {
            store: &other,
            passwd: &passwd,
            now: &clock,
        };
        let outcome = authenticate(&env, Some("maria"), || {
            Ok(Input::new(app(NOW).as_bytes()).unwrap())
        });
        assert!(!outcome.success);
    }

    #[test]
    fn errors_are_refusals() {
        let f = Fixture::new();
        let code = app(NOW);
        let store = &f.store;
        let missing = f.tmp.path().join("no-passwd");
        let broken_clock = || Err(state::Error::Clock);
        let env = Env {
            store,
            passwd: &missing,
            now: &|| Ok(NOW),
        };
        let input = || Ok(Input::new(code.as_bytes()).unwrap());
        assert!(!authenticate(&env, Some("maria"), input).success);
        let passwd = f.tmp.path().join("passwd");
        let env = Env {
            store,
            passwd: &passwd,
            now: &broken_clock,
        };
        assert_eq!(
            authenticate(&env, Some("maria"), input),
            Outcome::failure("the system clock is before 1970")
        );
        let env = Env {
            store,
            passwd: &passwd,
            now: &|| Ok(NOW),
        };
        assert_eq!(
            authenticate(&env, Some("maria"), || Err("the conversation failed")),
            Outcome::failure("the conversation failed")
        );
        // Still unused.
        assert!(authenticate(&env, Some("maria"), input).success);
    }

    #[test]
    fn one_code_for_one_of_many_concurrent_logins() {
        let f = Fixture::new();
        let code = app(NOW);
        let accepted = std::sync::atomic::AtomicUsize::new(0);
        let passwd = f.tmp.path().join("passwd");
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let env = Env {
                        store: &f.store,
                        passwd: &passwd,
                        now: &|| Ok(NOW),
                    };
                    let input = || Ok(Input::new(code.as_bytes()).unwrap());
                    if authenticate(&env, Some("maria"), input).success {
                        accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(accepted.into_inner(), 1);
    }

    #[test]
    fn log_line_has_no_code_and_no_control_characters() {
        let f = Fixture::new();
        let code = app(NOW);
        let outcome = f.login(&code);
        let line = outcome.log_line(Some("maria\nfake: accepted"), Some("192.0.2.7"));
        assert_eq!(
            line,
            "accepted for user maria?fake:?accepted from 192.0.2.7: app code"
        );
        let refused = f.login(&code);
        let line = refused.log_line(None, None);
        assert_eq!(
            line,
            "refused for user (none) from (unknown): the code was already used"
        );
        assert!(!line.contains(&code));
        let long = "x".repeat(MAX_NAME * 2);
        assert_eq!(
            refused.log_line(Some(&long), None).len(),
            line.len() - "(none)".len() + MAX_NAME
        );
    }

    #[test]
    fn input_is_bounded_and_wiped() {
        assert!(Input::new(&[b'1'; MAX_INPUT]).is_some());
        assert!(Input::new(&[b'1'; MAX_INPUT + 1]).is_none());
        let input = Input::new(b"123456").unwrap();
        assert_eq!(input.as_bytes(), b"123456");
        let mut input = input;
        input.wipe();
        assert_eq!(input.bytes, [0; MAX_INPUT]);
        assert_eq!(input.as_bytes(), b"");
    }
}
