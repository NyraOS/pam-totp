# AGENTS.md

Guide for coding agents and people working in this repository. What the project is and how it behaves: [README.md](README.md).

## What this is

TOTP two-factor authentication for SSH password logins on Nyra OS servers: a PAM module (`pam_nyra_totp`) that asks for the one-time code, and the `2fa` command (`nyra-2fa`) that sets it up. Rust. The module runs as root in the login path.

## Map (read in this order)

1. `README.md`: the `2fa` command, the PAM module, how to configure the PAM stack.
2. `src/totp.rs`: RFC 6238 codes, base32 secrets, the `otpauth://` URI.
3. `src/state.rs`: the per-user state file under `/var/lib/nyra/2fa/`. `src/passwd.rs`: user names and uids.
4. `src/auth.rs`: what the module decides, in safe Rust and without PAM. `src/cli.rs` and `src/bin/nyra-2fa.rs`: the `2fa` command.
5. `pam/src/lib.rs`, `pam/src/ffi.rs`: the thin PAM module. `ffi.rs` holds all the `unsafe` code.
6. `tests/pamtester.rs`: the module loaded into the real libpam. `fuzz/`: cargo-fuzz targets (own workspace, nightly Rust).

## Build, test, lint

Rust 1.85 or newer. Run what CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo +1.85 test --locked      # the oldest supported Rust
cargo deny --locked check      # needs cargo-deny
```

- `tests/pamtester.rs` needs root, `pamtester` and the built module. It changes `/etc/passwd`, `/etc/pam.d`, `/var/lib/nyra/2fa` and `/dev/log`, so its tests are ignored by default and CI runs them in a throwaway Debian 13 container (`--ignored --test-threads=1`, see README). Never run them on a machine you care about. CI also runs the `state::`, `cli::` and `auth::` unit tests again as root.
- The valgrind leak check (`leaks` job) and fuzzing (`fuzz/`, see README) are separate; run them when you change `pam/src/ffi.rs` or the code `code_input` covers.

## Working rules

- Work on a branch, never on `main` (it is protected). One small, focused change per pull request, with a clear reason.
- Before you start, read the recent changes (`git log`) and the docs of the area.
- Commit messages: a short imperative subject in plain English. The only trailer is `Co-Authored-By: <model name> <noreply@anthropic.com>`. No "Generated with ..." line and no session link in commits or pull request text.
- A test that fails sometimes is a bug: find the cause, do not rerun until green. Never weaken or skip a test to make it pass.
- Dependencies are pinned with `=`: the code that runs as root in the login path changes only by a reviewed bump.
- Pin what CI runs: actions by commit SHA, container images by digest.
- English for code, comments, commits and docs. New files start with an SPDX header (`MIT`).

## Code rules (KISS: code a person can read)

- Read top to bottom. Functions about 50 lines at most, files short. Each file starts with a short header saying what it does and why it exists.
- Plain `match` and loops instead of long iterator chains. No macros.
- No generics, explicit lifetimes or `dyn` unless needed, with the reason written next to them.
- No `unsafe` outside `pam/src/ffi.rs`: the library has `#![forbid(unsafe_code)]` and the module `#![deny(unsafe_code)]`. Each `unsafe` block there says why it is sound. Keep the PAM decisions in `src/auth.rs`, not in the FFI layer.
- Never set `panic = "abort"`: the module catches panics at its exported functions.
- Comments explain why, not what.
- A dependency that makes the code clearer is fine, with its reason; `cargo deny` must stay green. Do not write your own replacement without a reason (crypto especially).
- No options or layers "for later": the module takes no options on purpose.

## Security-sensitive areas

All of this repository: it decides who may log in. Changes need a security review before merge, in particular `src/auth.rs` (every doubt is a refusal), `src/state.rs` (file modes, ownership, links, locking, atomic replace), `src/totp.rs` (constant-time comparison, no reuse of a step), recovery codes, and `pam/src/ffi.rs`. Never put secrets, keys or tokens in the repository, tests or logs; test secrets are throwaway. The module never logs a code. Report vulnerabilities privately: [SECURITY.md](SECURITY.md).

## Docs

`README.md` (command, module, PAM configuration, tests, fuzzing).
