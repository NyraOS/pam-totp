// SPDX-License-Identifier: MIT
//! TOTP (RFC 6238) two-factor for SSH password logins on Nyra OS servers.
//!
//! The TOTP logic lives in [`totp`]; the PAM module `pam_nyra_totp` and the `nyra-2fa` command
//! will be built on it.

pub mod totp;
