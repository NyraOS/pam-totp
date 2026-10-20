// SPDX-License-Identifier: MIT
//! The `2fa` command: `enable`, `status`, `disable` and `recovery` for one user.

use crate::state::{self, State, Store};
use crate::totp::{self, Algorithm};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use std::error::Error;
use std::io::Write;
use std::path::Path;

pub const USAGE: &str = "\
Usage: 2fa enable [USER]     turn on two-step authentication (needs root)
       2fa status [USER]     show if it is on and how many recovery codes are left (needs root)
       2fa disable [USER]    turn it off (needs root)
       2fa recovery [USER]   make new recovery codes; the old ones stop working (needs root)
USER defaults to you (the user who ran sudo).";

const ISSUER: &str = "Nyra OS";
const ATTEMPTS: usize = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Enable,
    Status,
    Disable,
    Recovery,
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    pub action: Action,
    pub user: Option<String>,
}

/// Parses the arguments after the program name. The error is the text to show.
pub fn parse_args(args: &[String]) -> Result<Command, String> {
    let action = match args.first().map(String::as_str) {
        Some("enable") => Action::Enable,
        Some("status") => Action::Status,
        Some("disable") => Action::Disable,
        Some("recovery") => Action::Recovery,
        Some("-h" | "--help" | "help") => Action::Help,
        Some(other) => return Err(format!("unknown command `{other}`\n{USAGE}")),
        None => return Err(USAGE.to_string()),
    };
    if action == Action::Help {
        return Ok(Command { action, user: None });
    }
    match &args[1..] {
        [] => Ok(Command { action, user: None }),
        [user] if !user.starts_with('-') && !user.is_empty() => Ok(Command {
            action,
            user: Some(user.clone()),
        }),
        _ => Err(format!("expected at most one user name\n{USAGE}")),
    }
}

/// Everything the command takes from outside, so the tests can replace it.
pub struct Env<'a> {
    pub store: &'a Store,
    pub is_root: bool,
    /// The real uid of whoever runs the command.
    pub caller_uid: u32,
    /// `$SUDO_USER`: under sudo the real uid is root, so this is who asked.
    pub sudo_user: Option<String>,
    pub passwd: &'a Path,
    pub hostname: String,
    pub now: &'a dyn Fn() -> Result<u64, state::Error>,
    /// One line typed by the user, or `None` at the end of the input.
    pub ask: &'a mut dyn FnMut() -> Option<String>,
    pub out: &'a mut dyn Write,
}

struct Target {
    name: String,
    uid: u32,
}

pub fn run(command: Command, env: &mut Env) -> Result<(), Box<dyn Error>> {
    if command.action == Action::Help {
        writeln!(env.out, "{USAGE}")?;
        return Ok(());
    }
    if command.action != Action::Status && !env.is_root {
        return Err("this needs root; run it with sudo".into());
    }
    let target = resolve(&command, env)?;
    match command.action {
        Action::Enable => enable(env, &target),
        Action::Status => status(env, &target),
        Action::Disable => disable(env, &target),
        Action::Recovery => recovery(env, &target),
        Action::Help => unreachable!("handled above"),
    }
}

fn resolve(command: &Command, env: &Env) -> Result<Target, Box<dyn Error>> {
    let users = std::fs::read_to_string(env.passwd)
        .map_err(|e| format!("cannot read the user list: {e}"))?;
    let entries = users.lines().filter_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let uid = fields.nth(1)?.parse::<u32>().ok()?;
        Some(Target {
            name: name.to_string(),
            uid,
        })
    });
    let by_name = command.user.as_deref().or(if env.is_root {
        env.sudo_user.as_deref()
    } else {
        None
    });
    let found = match by_name {
        Some(name) => entries.into_iter().find(|t| t.name == name),
        None => entries.into_iter().find(|t| t.uid == env.caller_uid),
    };
    found.ok_or_else(|| format!("no such user: {}", by_name.unwrap_or("(you)")).into())
}

fn enable(env: &mut Env, target: &Target) -> Result<(), Box<dyn Error>> {
    let Target { name, uid } = target;
    match env.store.read(*uid) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(format!(
                "two-step authentication is already on for {name}; to start over run `2fa disable {name}` first"
            )
            .into());
        }
        Err(e) => {
            return Err(format!(
                "the existing state of {name} cannot be used ({e}); run `2fa disable {name}` first"
            )
            .into());
        }
    }

    let secret = totp::generate_secret()?;
    let account = format!("{name}@{}", env.hostname);
    let uri = totp::otpauth_uri(&secret, Algorithm::Sha1, ISSUER, &account)?;
    // Light modules on a dark terminal are what scanners expect, so the colours are swapped.
    let qr = QrCode::new(uri.as_bytes())?
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build();
    writeln!(env.out, "Scan this with your authenticator app:\n\n{qr}\n")?;
    writeln!(
        env.out,
        "Or enter this secret by hand (SHA1, 6 digits, 30 seconds):"
    )?;
    writeln!(env.out, "Secret: {}", totp::encode_secret(&secret))?;
    writeln!(env.out, "Link: {uri}\n")?;

    let mut step = None;
    for _ in 0..ATTEMPTS {
        write!(env.out, "Enter the code from the app: ")?;
        env.out.flush()?;
        let line = (env.ask)().ok_or("no code was entered; two-step authentication is not on")?;
        match totp::verify(&secret, Algorithm::Sha1, line.trim(), (env.now)()?, None) {
            Ok(accepted) => {
                step = Some(accepted);
                break;
            }
            Err(_) => writeln!(
                env.out,
                "That code is not right. Check the app and try again."
            )?,
        }
    }
    let step = step.ok_or("no right code was entered; two-step authentication is not on")?;

    let (state, codes) = State::new(Algorithm::Sha1, secret.to_vec(), step)?;
    env.store.update(*uid, |current| {
        if current.is_some() {
            return Err(state::Error::Refused(
                "two-step authentication was turned on meanwhile",
            ));
        }
        *current = Some(state);
        Ok(())
    })?;
    writeln!(env.out, "Two-step authentication is on for {name}.")?;
    print_codes(env, &codes)
}

fn print_codes(env: &mut Env, codes: &[String]) -> Result<(), Box<dyn Error>> {
    writeln!(
        env.out,
        "Recovery codes. Each works once, instead of an app code."
    )?;
    writeln!(
        env.out,
        "Keep them somewhere other than this server; they are not shown again:\n"
    )?;
    for code in codes {
        writeln!(env.out, "  {code}")?;
    }
    Ok(())
}

fn status(env: &mut Env, target: &Target) -> Result<(), Box<dyn Error>> {
    let name = &target.name;
    match env.store.read(target.uid) {
        Ok(Some(state)) => writeln!(
            env.out,
            "Two-step authentication is on for {name}. Recovery codes left: {}.",
            state.recovery.len()
        )?,
        Ok(None) => writeln!(env.out, "Two-step authentication is not on for {name}.")?,
        Err(state::Error::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err("only root can read this; run `sudo 2fa status`".into());
        }
        Err(e) => return Err(format!("cannot read the state of {name}: {e}").into()),
    }
    Ok(())
}

fn disable(env: &mut Env, target: &Target) -> Result<(), Box<dyn Error>> {
    let name = &target.name;
    if env.store.remove(target.uid)? {
        writeln!(env.out, "Two-step authentication is off for {name}.")?;
    } else {
        writeln!(env.out, "Two-step authentication was not on for {name}.")?;
    }
    Ok(())
}

fn recovery(env: &mut Env, target: &Target) -> Result<(), Box<dyn Error>> {
    let codes = env.store.update(target.uid, |current| match current {
        Some(state) => state.renew_recovery(),
        None => Err(state::Error::Refused(
            "two-step authentication is not on for this user",
        )),
    })?;
    writeln!(
        env.out,
        "New recovery codes for {}; the old ones no longer work.",
        target.name
    )?;
    print_codes(env, &codes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::cell::RefCell;
    use std::rc::Rc;

    const NOW: u64 = 1_700_000_000;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_arguments() {
        let cmd = |action, user: Option<&str>| {
            Ok(Command {
                action,
                user: user.map(String::from),
            })
        };
        assert_eq!(parse_args(&args("enable")), cmd(Action::Enable, None));
        assert_eq!(
            parse_args(&args("status maria")),
            cmd(Action::Status, Some("maria"))
        );
        assert_eq!(
            parse_args(&args("disable maria")),
            cmd(Action::Disable, Some("maria"))
        );
        assert_eq!(parse_args(&args("recovery")), cmd(Action::Recovery, None));
        assert_eq!(parse_args(&args("--help")), cmd(Action::Help, None));
        for bad in ["", "frobnicate", "enable a b", "enable --x", "status -1"] {
            assert!(parse_args(&args(bad)).is_err(), "accepted: {bad}");
        }
        assert!(parse_args(&["enable".into(), String::new()]).is_err());
    }

    #[derive(Clone, Default)]
    struct Shared(Rc<RefCell<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap()
        }

        fn after(&self, label: &str) -> String {
            let text = self.text();
            let rest = &text[text.rfind(label).unwrap() + label.len()..];
            rest.lines().next().unwrap().to_string()
        }
    }

    struct Fixture {
        tmp: TempDir,
        store: Store,
    }

    impl Fixture {
        fn new() -> Fixture {
            let tmp = TempDir::new();
            std::fs::write(
                tmp.path().join("passwd"),
                "root:x:0:0::/root:/bin/sh\nmaria:x:1000:1000::/home/maria:/bin/sh\n",
            )
            .unwrap();
            let store = Store::in_dir(&tmp.path().join("2fa"));
            Fixture { tmp, store }
        }

        /// Runs a command as root (or not) with the app typing `answers` in order; an answer
        /// `"APP"` stands for the right code from the secret shown so far.
        fn run(&self, line: &str, is_root: bool, answers: &[&str]) -> (Result<(), String>, Shared) {
            let out = Shared::default();
            let shown = out.clone();
            let mut answers = answers
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .into_iter();
            let mut ask = move || {
                let answer = answers.next()?;
                if answer != "APP" {
                    return Some(answer);
                }
                let secret = totp::decode_secret(&shown.after("Secret: ")).unwrap();
                Some(totp::code(&secret, Algorithm::Sha1, NOW).unwrap())
            };
            let passwd = self.tmp.path().join("passwd");
            let now = || Ok(NOW);
            let mut sink = out.clone();
            let mut env = Env {
                store: &self.store,
                is_root,
                caller_uid: 1000,
                sudo_user: Some("maria".into()),
                passwd: &passwd,
                hostname: "box".into(),
                now: &now,
                ask: &mut ask,
                out: &mut sink,
            };
            let result = run(parse_args(&args(line)).unwrap(), &mut env).map_err(|e| e.to_string());
            (result, out)
        }
    }

    #[test]
    fn enable_status_recovery_disable() {
        let f = Fixture::new();
        let (result, out) = f.run("enable", true, &["APP"]);
        result.unwrap();
        let text = out.text();
        assert!(text.contains("otpauth://totp/Nyra%20OS:maria%40box?secret="));
        assert!(text.contains('█') || text.contains('▀') || text.contains('▄'));
        assert!(text.contains("Two-step authentication is on for maria."));
        let first: Vec<_> = text
            .lines()
            .filter(|l| l.starts_with("  ") && l.len() == 13)
            .collect();
        assert_eq!(first.len(), 10);
        let state = f.store.read(1000).unwrap().unwrap();
        assert_eq!(state.recovery.len(), 10);
        assert_eq!(state.last_step, NOW / totp::PERIOD);

        // The same app code cannot be used again right after enabling.
        let secret = totp::decode_secret(&out.after("Secret: ")).unwrap();
        let code = totp::code(&secret, Algorithm::Sha1, NOW).unwrap();
        assert!(totp::verify(&secret, Algorithm::Sha1, &code, NOW, Some(state.last_step)).is_err());

        let (result, out) = f.run("status", false, &[]);
        result.unwrap();
        assert!(
            out.text()
                .contains("on for maria. Recovery codes left: 10.")
        );

        assert!(
            f.run("enable", true, &[])
                .0
                .unwrap_err()
                .contains("already on")
        );

        let (result, out) = f.run("recovery", true, &[]);
        result.unwrap();
        let new_first = out
            .text()
            .lines()
            .find(|l| l.starts_with("  "))
            .unwrap()
            .trim()
            .to_string();
        let mut state = f.store.read(1000).unwrap().unwrap();
        assert!(state.use_recovery(&new_first));

        let (result, out) = f.run("disable", true, &[]);
        result.unwrap();
        assert!(out.text().contains("off for maria"));
        assert!(f.store.read(1000).unwrap().is_none());
        assert!(
            f.run("status", false, &[])
                .1
                .text()
                .contains("not on for maria")
        );
        assert!(
            f.run("recovery", true, &[])
                .0
                .unwrap_err()
                .contains("not on")
        );
        assert!(f.run("disable", true, &[]).1.text().contains("was not on"));
    }

    #[test]
    fn enable_needs_a_right_code() {
        let f = Fixture::new();
        let wrong = f
            .run("enable", true, &["000000", "abc", "12"])
            .0
            .unwrap_err();
        assert!(wrong.contains("not on"));
        assert!(f.store.read(1000).unwrap().is_none());
        assert!(
            f.run("enable", true, &[])
                .0
                .unwrap_err()
                .contains("no code")
        );
        // A wrong try does not spoil the next one.
        f.run("enable", true, &["000000", "APP"]).0.unwrap();
        assert!(f.store.read(1000).unwrap().is_some());
    }

    #[test]
    fn root_is_needed_except_for_status() {
        let f = Fixture::new();
        for line in ["enable", "disable", "recovery"] {
            assert!(
                f.run(line, false, &[])
                    .0
                    .unwrap_err()
                    .contains("needs root")
            );
        }
        assert!(f.run("status", false, &[]).0.is_ok());
        assert!(
            f.run("status nobody", false, &[])
                .0
                .unwrap_err()
                .contains("no such user")
        );
    }

    #[test]
    fn unreadable_state_for_a_user_says_to_use_sudo() {
        // Root bypasses the directory mode, so this only shows without root.
        if rustix::process::geteuid().as_raw() == 0 {
            return;
        }
        let f = Fixture::new();
        f.run("enable", true, &["APP"]).0.unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            f.tmp.path().join("2fa"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        assert!(
            f.run("status", false, &[])
                .0
                .unwrap_err()
                .contains("sudo 2fa status")
        );
        std::fs::set_permissions(
            f.tmp.path().join("2fa"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn a_broken_state_can_be_disabled_then_enabled() {
        let f = Fixture::new();
        f.run("enable", true, &["APP"]).0.unwrap();
        std::fs::write(f.tmp.path().join("2fa/1000"), b"junk").unwrap();
        assert!(
            f.run("enable", true, &[])
                .0
                .unwrap_err()
                .contains("cannot be used")
        );
        f.run("disable", true, &[]).0.unwrap();
        f.run("enable", true, &["APP"]).0.unwrap();
    }
}
