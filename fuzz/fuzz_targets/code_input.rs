// SPDX-License-Identifier: MIT
//! The path of a typed answer through the PAM module's decision: the bound on its length
//! ([`Input::new`]) and the check against a state ([`auth::check`]), at any time and with any last
//! used step. Besides finding panics, it checks that a refusal leaves the state as it was and that
//! an acceptance is a real code.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pam_totp::auth::{self, Accepted, Input, MAX_INPUT};
use pam_totp::state::State;
use pam_totp::totp::{self, Algorithm, PERIOD};
use sha2::{Digest, Sha256};

const SECRET: [u8; 20] = *b"12345678901234567890";
const RECOVERY: [&str; 3] = ["ABCDE23456", "QQQQQ77777", "ZYXWVUTSRQ"];

fuzz_target!(|data: &[u8]| {
    // 8 bytes of time, 1 byte for how many steps ago the last code was used, then the answer.
    let Some((time, rest)) = data.split_first_chunk::<8>() else {
        return;
    };
    let Some((&ago, answer)) = rest.split_first() else {
        return;
    };
    let now = u64::from_le_bytes(*time);
    let Some(input) = Input::new(answer) else {
        assert!(answer.len() > MAX_INPUT);
        return;
    };
    assert_eq!(input.as_bytes(), answer);
    let mut state = State {
        algorithm: Algorithm::Sha1,
        secret: SECRET.to_vec(),
        last_step: (now / PERIOD).saturating_sub(u64::from(ago)),
        recovery: RECOVERY
            .iter()
            .map(|code| Sha256::digest(code.as_bytes()).into())
            .collect(),
    };
    let before = state.clone();
    match auth::check(Some(&mut state), input.as_bytes(), now) {
        Err(_) => assert_eq!(state, before),
        Ok(Accepted::App) => {
            let typed = std::str::from_utf8(answer).unwrap().trim();
            assert!(state.last_step > before.last_step);
            assert!(state.last_step.abs_diff(now / PERIOD) <= 1);
            let expected = totp::code(&SECRET, Algorithm::Sha1, state.last_step * PERIOD).unwrap();
            assert_eq!(typed, expected);
            assert_eq!(state.recovery, before.recovery);
        }
        Ok(Accepted::Recovery(left)) => {
            assert_eq!(left, before.recovery.len() - 1);
            assert_eq!(state.recovery.len(), left);
            assert_eq!(state.last_step, before.last_step);
        }
    }
    // Without a state, nothing is accepted.
    assert!(auth::check(None, input.as_bytes(), now).is_err());
});
