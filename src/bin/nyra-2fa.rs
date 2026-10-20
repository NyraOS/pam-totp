// SPDX-License-Identifier: MIT
//! `/usr/libexec/nyra-2fa`, which the image links to as `2fa`.

use pam_totp::cli::{self, Env};
use pam_totp::state::{self, Store};
use std::io::BufRead;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse_args(&args) {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };

    let mut ask = || {
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line),
        }
    };
    let store = Store::system();
    let now = state::unix_now;
    let mut env = Env {
        store: &store,
        is_root: rustix::process::geteuid().is_root(),
        caller_uid: rustix::process::getuid().as_raw(),
        sudo_user: std::env::var("SUDO_USER").ok(),
        passwd: std::path::Path::new(pam_totp::passwd::PASSWD),
        hostname: rustix::system::uname()
            .nodename()
            .to_string_lossy()
            .into_owned(),
        now: &now,
        ask: &mut ask,
        out: &mut std::io::stdout(),
    };
    match cli::run(command, &mut env) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("2fa: {e}");
            ExitCode::FAILURE
        }
    }
}
