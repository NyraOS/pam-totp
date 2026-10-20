// SPDX-License-Identifier: MIT
//! `pam_nyra_totp.so`: asks for the TOTP code (or a recovery code) after the password.
//!
//! ```text
//! auth required pam_nyra_totp.so
//! ```
//!
//! The decision is [`pam_totp::auth::authenticate`]; this crate only connects it to libpam. All
//! `unsafe` code is in [`ffi`]. The module takes no options: any option is a refusal, so a typo
//! (or a `nullok` copied from another module) cannot weaken it. Only the `auth` functions are
//! exported, so a line for another management group fails instead of passing.

#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod ffi;

use pam_totp::auth::{self, Env, MAX_NAME, Outcome};
use pam_totp::passwd::PASSWD;
use pam_totp::state::{self, Store};
use std::ffi::c_int;

const PROMPT: &std::ffi::CStr = c"Verification code: ";

/// One `pam_sm_authenticate` call. Returns `PAM_SUCCESS` only for a right code.
fn authenticate(pam: &ffi::Handle, argc: c_int) -> c_int {
    let user = pam.user(MAX_NAME);
    let rhost = pam.rhost(MAX_NAME);
    let outcome = if argc != 0 {
        Outcome::failure("the module takes no options; check the PAM configuration")
    } else {
        let store = Store::system();
        let env = Env {
            store: &store,
            passwd: std::path::Path::new(PASSWD),
            now: &state::unix_now,
        };
        auth::authenticate(&env, user.as_deref(), || pam.ask(PROMPT))
    };
    let line = outcome.log_line(user.as_deref(), rhost.as_deref());
    if outcome.success {
        pam.log(ffi::LOG_INFO, &line);
        ffi::PAM_SUCCESS
    } else {
        pam.log(ffi::LOG_NOTICE, &line);
        ffi::PAM_AUTH_ERR
    }
}
