# pam-totp

TOTP two-factor authentication for SSH password logins on Nyra OS servers: a PAM module
(`pam_nyra_totp`) that asks for the one-time code, and the `2fa` command (`nyra-2fa`) to set it up.

**Status: early development.** Only the TOTP library (`src/totp.rs`) exists so far: RFC 6238 codes
(SHA1 by default, SHA256 and SHA512 supported; 6 digits, 30 s), base32 secrets, verification of the
current step and one either side with no reuse of a step, and the `otpauth://` URI. The PAM module
and the `2fa` command are not written yet.

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
