# pam-totp

TOTP two-factor authentication for SSH password logins on Nyra OS servers: a PAM module
(`pam_nyra_totp`) that asks for the one-time code, and the `2fa` command (`nyra-2fa`) to set it up.

**Status: early development.** Done: the TOTP library (`src/totp.rs`): RFC 6238 codes (SHA1 by
default, SHA256 and SHA512 supported; 6 digits, 30 s), base32 secrets, verification of the current
step and one either side with no reuse of a step, and the `otpauth://` URI; the per-user state file
(`src/state.rs`); the `2fa` command (`nyra-2fa`); and the PAM module (`pam/`, decision logic in
`src/auth.rs`).

## The `2fa` command

```
sudo 2fa enable [USER]     QR code, secret and link; turns on after one right code; shows 10 recovery codes
sudo 2fa status [USER]     on or off, and how many recovery codes are left
sudo 2fa disable [USER]    turns it off
sudo 2fa recovery [USER]   new recovery codes; the old ones stop working
```

The state of each user is `/var/lib/nyra/2fa/<uid>`, in a `0700` directory, as a `0600` file, both
owned by root, so users cannot read or remove their own. It is opened without following symlinks,
changed under a per-user lock, and replaced atomically. The format is text, one `key=value` per
line: `version=1`, `algorithm`, `secret` (base32), `last_step` and one `recovery` line (SHA-256 of
the code) per unused recovery code.

## The PAM module

`cargo build --release -p pam_nyra_totp` builds `target/release/libpam_nyra_totp.so`, which is
installed as `pam_nyra_totp.so` in the PAM module directory (`/usr/lib/x86_64-linux-gnu/security`
on Debian). It only provides `auth` and takes no options:

```
auth required pam_unix.so
auth required pam_nyra_totp.so
```

On each call it asks `Verification code: ` (echo off) and accepts a 6-digit code from the app or an
unused recovery code. It answers success only for a right code that was not used before, and
records its use under the user's lock before answering. Everything else is a refusal: no state file
for the user (so the password alone never works), an unknown user, an unsafe or broken state file,
a clock before 1970, an answer over 64 bytes, a failed conversation, a module option, or an
internal error (panics are caught at the FFI boundary). It asks for the code before looking at the
user, so the prompt does not tell whether the user exists or has two-step authentication on. The
user name is the one the application set (sshd always sets it); the module never asks for one. It
sends no error text to the user and shows nothing on stdout or stderr: the result and its reason go
to the system log (authpriv), with the user and the remote host but never the code. sshd limits the
attempts per connection; the module checks one answer per call.

For whoever configures the PAM stack:

- The module goes after `pam_unix` and both are `required`, never `requisite` or `sufficient`.
  `requisite` would stop at a wrong password before the code prompt, telling an attacker the
  password was wrong; `sufficient` on either would let one factor alone in.
- The module does not know whether the password was right. A right code sent with a wrong password
  is still recorded as used, so that code no longer works and the user waits for the next one.

The user's uid is looked up in `/etc/passwd`, as the `2fa` command does. Only Linux-PAM is
supported. All `unsafe` code of the module is in `pam/src/ffi.rs`; the library has none
(`forbid(unsafe_code)`).

## Credit

The TOTP core is ported from [MrTuNNe/GoTOTP](https://github.com/MrTuNNe/GoTOTP) (MIT), by the same owner. Changes from it: SHA1 is the default,
constant-time comparison, a ±1 step window, refusal of a reused step, a 160-bit secret, secrets under 128 bits refused, no panics.

## Development

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The minimum supported Rust is 1.85, the one in Debian 13.

The tests in `tests/pamtester.rs` load the built module into the real libpam through
`pamtester`. They change `/etc/passwd`, `/etc/pam.d`, `/var/lib/nyra/2fa` and `/dev/log`, so they
are ignored by default and CI runs them as root in a throwaway Debian 13 container (the
`pamtester` job):

```
PAM_NYRA_TOTP=/path/to/libpam_nyra_totp.so <test binary> --ignored --test-threads=1
```

One of them, `no_memory_is_leaked`, runs thousands of logins of every kind (right, wrong, empty,
too long or missing answers, a failing conversation, missing or unusable user names, broken state
files) and fails if the resident memory of the process grows. The `leaks` job runs the same loop
under valgrind, which must report no definite or indirect loss.

### Fuzzing

`fuzz/` holds the [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets, in a workspace of
their own because they need nightly Rust. `code_input` runs any typed answer, at any time and with
any last used step, through the length bound and the check of the PAM module, and checks that a
refusal changes nothing and an acceptance is a real code:

```
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run code_input -- -max_total_time=600 -max_len=128
```

A scheduled CI workflow will run it nightly for 10 minutes on the nightly toolchain, keeping the
corpus between runs as a cache and uploading any crash as an artifact; it is not set up yet.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

MIT, see [LICENSE](LICENSE).
