# pam-totp

TOTP two-factor authentication for SSH password logins on Nyra OS servers: a PAM module
(`pam_nyra_totp`) that asks for the one-time code, and the `2fa` command (`nyra-2fa`) to set it up.

**Status: early development.** Only the package skeleton exists so far.

## Credit

The TOTP core is ported from [MrTuNNe/GoTOTP](https://github.com/MrTuNNe/GoTOTP) (MIT).

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
