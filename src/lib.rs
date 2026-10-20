// SPDX-License-Identifier: MIT
//! TOTP (RFC 6238) two-factor for SSH password logins on Nyra OS servers.
//!
//! The TOTP logic lives in [`totp`], the per-user state file in [`state`], the `2fa` command in
//! [`cli`] and what the PAM module decides in [`auth`]. The module itself (`pam/`) is only a thin
//! FFI layer over [`auth`]; this library has no `unsafe` code.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cli;
pub mod passwd;
pub mod state;
#[cfg(test)]
mod testutil;
pub mod totp;
