# pam-totp

TOTP two-factor authentication for SSH password logins on Nyra OS servers: a PAM module
(`pam_nyra_totp`) that asks for the one-time code, and the `2fa` command (`nyra-2fa`) to set it up.

**Status: early development.** Done: the TOTP library (`src/totp.rs`): RFC 6238 codes (SHA1 by
default, SHA256 and SHA512 supported; 6 digits, 30 s), base32 secrets, verification of the current
step and one either side with no reuse of a step, and the `otpauth://` URI; the per-user state file
(`src/state.rs`); and the `2fa` command (`nyra-2fa`). The PAM module is not written yet.

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

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

MIT, see [LICENSE](LICENSE).
