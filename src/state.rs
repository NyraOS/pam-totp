// SPDX-License-Identifier: MIT
//! The per-user state file `/var/lib/nyra/2fa/<uid>`: the secret, the last accepted step and the
//! recovery code hashes.
//!
//! The directory is `0700` and the files are `0600`, both owned by root, so a user cannot read,
//! change or delete their own state. Every open is relative to the directory's file descriptor and
//! refuses symlinks. Writers hold an exclusive lock for the whole read, check and write, and
//! replace the file atomically (temporary file, `fsync`, `rename`, `fsync` of the directory).
//!
//! The text format is one `key=value` per line: `version=1`, `algorithm=SHA1|SHA256|SHA512`,
//! `secret=<base32>`, `last_step=<u64>` and any number of `recovery=<64 hex digits>`.

use crate::totp::{self, Algorithm, BASE32};
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

/// Where the state lives on a Nyra OS server.
pub const STATE_DIR: &str = "/var/lib/nyra/2fa";

/// A state file is a few hundred bytes; anything bigger is not ours.
const MAX_SIZE: u64 = 4096;
const MAX_RECOVERY: usize = 32;
pub const RECOVERY_COUNT: usize = 10;
const RECOVERY_CHARS: usize = 10;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The directory or the file has the wrong type, owner, mode or size.
    Unsafe(&'static str),
    /// The file is not in the expected format.
    Malformed(&'static str),
    Totp(totp::Error),
    /// A change was refused by the caller, with the reason.
    Refused(&'static str),
    /// The clock is before 1970.
    Clock,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Unsafe(why) => write!(f, "unsafe state file or directory: {why}"),
            Error::Malformed(why) => write!(f, "malformed state file: {why}"),
            Error::Totp(e) => write!(f, "{e}"),
            Error::Refused(why) => f.write_str(why),
            Error::Clock => f.write_str("the system clock is before 1970"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Io(e.into())
    }
}

impl From<totp::Error> for Error {
    fn from(e: totp::Error) -> Self {
        Error::Totp(e)
    }
}

/// Seconds since the Unix epoch. A clock before it is an error, never 0.
pub fn unix_now() -> Result<u64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Clock)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub algorithm: Algorithm,
    pub secret: Vec<u8>,
    /// The last accepted step; a code for this step or an earlier one is refused.
    pub last_step: u64,
    /// SHA-256 of each unused recovery code.
    pub recovery: Vec<[u8; 32]>,
}

impl State {
    /// A fresh state with the given secret and `last_step`, and new recovery codes. Returns the
    /// codes to show to the user; this is the only time they exist in clear.
    pub fn new(
        algorithm: Algorithm,
        secret: Vec<u8>,
        last_step: u64,
    ) -> Result<(State, Vec<String>), Error> {
        let mut state = State {
            algorithm,
            secret,
            last_step,
            recovery: Vec::new(),
        };
        let codes = state.renew_recovery()?;
        Ok((state, codes))
    }

    /// Replaces all recovery codes with new ones and returns them as `xxxxx-xxxxx`.
    pub fn renew_recovery(&mut self) -> Result<Vec<String>, Error> {
        let mut codes = Vec::with_capacity(RECOVERY_COUNT);
        self.recovery.clear();
        for _ in 0..RECOVERY_COUNT {
            let mut random = [0u8; RECOVERY_CHARS];
            getrandom::fill(&mut random).map_err(|_| totp::Error::Random)?;
            // 256 is a multiple of 32, so the low five bits are unbiased.
            let plain: String = random
                .iter()
                .map(|b| char::from(BASE32[usize::from(b & 31)]))
                .collect();
            self.recovery.push(hash_recovery(&plain));
            codes.push(format!("{}-{}", &plain[..5], &plain[5..]));
        }
        Ok(codes)
    }

    /// Uses a recovery code: true, and the code is gone, if it is one of the unused ones. Case,
    /// dashes and spaces are ignored.
    pub fn use_recovery(&mut self, input: &str) -> bool {
        let plain: String = input
            .chars()
            .filter(|c| !matches!(c, '-' | ' '))
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if plain.len() != RECOVERY_CHARS || !plain.bytes().all(|b| BASE32.contains(&b)) {
            return false;
        }
        let hash = hash_recovery(&plain);
        // Every stored hash is compared, whether or not an earlier one matched.
        let mut found = None;
        for (i, stored) in self.recovery.iter().enumerate() {
            if bool::from(stored.ct_eq(&hash)) {
                found = Some(i);
            }
        }
        match found {
            Some(i) => {
                self.recovery.remove(i);
                true
            }
            None => false,
        }
    }

    fn to_text(&self) -> String {
        let mut text = format!(
            "version=1\nalgorithm={}\nsecret={}\nlast_step={}\n",
            self.algorithm.name(),
            totp::encode_secret(&self.secret),
            self.last_step
        );
        for hash in &self.recovery {
            text.push_str("recovery=");
            for byte in hash {
                text.push_str(&format!("{byte:02x}"));
            }
            text.push('\n');
        }
        text
    }

    fn parse(text: &str) -> Result<State, Error> {
        let (mut version, mut algorithm, mut secret, mut last_step) = (false, None, None, None);
        let mut recovery = Vec::new();
        let body = text
            .strip_suffix('\n')
            .ok_or(Error::Malformed("no final newline"))?;
        for line in body.split('\n') {
            let (key, value) = line
                .split_once('=')
                .ok_or(Error::Malformed("line without ="))?;
            match key {
                "version" if !version && value == "1" => version = true,
                "algorithm" if algorithm.is_none() => {
                    algorithm = Some(match value {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(Error::Malformed("unknown algorithm")),
                    })
                }
                "secret" if secret.is_none() => {
                    secret = Some(
                        totp::decode_secret(value).map_err(|_| Error::Malformed("bad secret"))?,
                    )
                }
                "last_step" if last_step.is_none() => {
                    last_step = Some(
                        value
                            .parse()
                            .map_err(|_| Error::Malformed("bad last_step"))?,
                    )
                }
                "recovery" if recovery.len() < MAX_RECOVERY => recovery.push(parse_hash(value)?),
                _ => return Err(Error::Malformed("unknown, repeated or invalid key")),
            }
        }
        match (version, algorithm, secret, last_step) {
            (true, Some(algorithm), Some(secret), Some(last_step)) => Ok(State {
                algorithm,
                secret,
                last_step,
                recovery,
            }),
            _ => Err(Error::Malformed("a required key is missing")),
        }
    }
}

fn hash_recovery(plain: &str) -> [u8; 32] {
    Sha256::digest(plain.as_bytes()).into()
}

fn parse_hash(hex: &str) -> Result<[u8; 32], Error> {
    let bad = Error::Malformed("bad recovery hash");
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| Error::Malformed("bad recovery hash"))?;
    }
    Ok(out)
}

/// The directory holding the state files and the uid that must own it and them.
pub struct Store {
    dir: PathBuf,
    owner: u32,
}

impl Store {
    /// The real store: `/var/lib/nyra/2fa`, owned by root.
    pub fn system() -> Store {
        Store {
            dir: PathBuf::from(STATE_DIR),
            owner: 0,
        }
    }

    /// A store in another directory, owned by whoever runs the tests.
    #[cfg(test)]
    pub fn in_dir(dir: &std::path::Path) -> Store {
        Store {
            dir: dir.to_owned(),
            owner: rustix::process::geteuid().as_raw(),
        }
    }

    /// A store whose files must be owned by another uid than the one running the tests.
    #[cfg(test)]
    pub fn in_dir_owned_by(dir: &std::path::Path, owner: u32) -> Store {
        Store {
            dir: dir.to_owned(),
            owner,
        }
    }

    /// The state of `uid`, or `None` if there is none.
    pub fn read(&self, uid: u32) -> Result<Option<State>, Error> {
        let Some(dir) = self.open_dir(false)? else {
            return Ok(None);
        };
        self.read_in(&dir, uid)
    }

    /// Reads the state of `uid` under the exclusive lock, lets `change` look at it and change it,
    /// and writes it back if `change` succeeded and altered it. Setting it to `None` deletes the
    /// file. If `change` fails nothing is written. The lock is held until this returns, so two
    /// callers cannot both act on the same state.
    pub fn update<T>(
        &self,
        uid: u32,
        change: impl FnOnce(&mut Option<State>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let dir = self
            .open_dir(true)?
            .ok_or(Error::Unsafe("directory missing"))?;
        let _lock = lock(&dir, uid)?;
        let before = self.read_in(&dir, uid)?;
        let mut after = before.clone();
        let result = change(&mut after)?;
        if after != before {
            match &after {
                Some(state) => write_in(&dir, uid, state)?,
                None => remove_in(&dir, uid)?,
            }
        }
        Ok(result)
    }

    /// Deletes the state of `uid` even if it is unreadable or malformed. True if there was one.
    pub fn remove(&self, uid: u32) -> Result<bool, Error> {
        let dir = self
            .open_dir(true)?
            .ok_or(Error::Unsafe("directory missing"))?;
        let _lock = lock(&dir, uid)?;
        match remove_in(&dir, uid) {
            Ok(()) => Ok(true),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Opens the directory without following a symlink and checks owner and mode. With `create`
    /// a missing directory is made; without it `None` means it does not exist.
    fn open_dir(&self, create: bool) -> Result<Option<OwnedFd>, Error> {
        if create {
            if let Some(parent) = self.dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new().mode(0o700).create(&self.dir) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
                _ => {}
            }
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match rustix::fs::open(&self.dir, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if !create => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let stat = rustix::fs::fstat(&fd)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(Error::Unsafe("not a directory"));
        }
        if stat.st_uid != self.owner {
            return Err(Error::Unsafe("directory has the wrong owner"));
        }
        if stat.st_mode & 0o7777 != 0o700 {
            return Err(Error::Unsafe("directory mode is not 0700"));
        }
        Ok(Some(fd))
    }

    fn read_in(&self, dir: &OwnedFd, uid: u32) -> Result<Option<State>, Error> {
        // NONBLOCK: a FIFO in place of the file would hang the open until a writer shows up.
        let flags =
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match rustix::fs::openat(dir, uid.to_string(), flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let stat = rustix::fs::fstat(&fd)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(Error::Unsafe("not a regular file"));
        }
        if stat.st_uid != self.owner {
            return Err(Error::Unsafe("file has the wrong owner"));
        }
        if stat.st_mode & 0o7777 != 0o600 {
            return Err(Error::Unsafe("file mode is not 0600"));
        }
        if u64::try_from(stat.st_size).map_or(true, |size| size > MAX_SIZE) {
            return Err(Error::Unsafe("file is too big"));
        }
        let mut bytes = Vec::new();
        // The limit is checked again on what is read, in case the file grew after the fstat.
        File::from(fd).take(MAX_SIZE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SIZE {
            return Err(Error::Unsafe("file is too big"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::Malformed("not UTF-8"))?;
        State::parse(text).map(Some)
    }
}

/// Takes the per-uid exclusive lock; it is released when the returned file is dropped.
fn lock(dir: &OwnedFd, uid: u32) -> Result<File, Error> {
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(
        dir,
        format!("{uid}.lock"),
        flags,
        Mode::from_raw_mode(0o600),
    )?;
    loop {
        match rustix::fs::flock(&fd, FlockOperation::LockExclusive) {
            Err(Errno::INTR) => continue,
            other => break other?,
        }
    }
    Ok(File::from(fd))
}

fn write_in(dir: &OwnedFd, uid: u32, state: &State) -> Result<(), Error> {
    let temp = format!("{uid}.tmp");
    // We hold the lock, so a temporary file that exists is left over from a crash.
    match rustix::fs::unlinkat(dir, &temp, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => return Err(e.into()),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(dir, &temp, flags, Mode::from_raw_mode(0o600))?;
    // Not left to the umask.
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600))?;
    let mut file = File::from(fd);
    file.write_all(state.to_text().as_bytes())?;
    file.sync_all()?;
    rustix::fs::renameat(dir, &temp, dir, uid.to_string())?;
    rustix::fs::fsync(dir.as_fd())?;
    Ok(())
}

fn remove_in(dir: &OwnedFd, uid: u32) -> Result<(), Error> {
    rustix::fs::unlinkat(dir, uid.to_string(), AtFlags::empty())?;
    rustix::fs::fsync(dir.as_fd())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::{PermissionsExt, symlink};

    const SECRET: [u8; 20] = *b"12345678901234567890";

    fn sample() -> State {
        State::new(Algorithm::Sha256, SECRET.to_vec(), 7).unwrap().0
    }

    fn secret_line() -> String {
        format!("secret={}", totp::encode_secret(&SECRET))
    }

    fn put(slot: &mut Option<State>, state: Option<State>) -> Result<(), Error> {
        *slot = state;
        Ok(())
    }

    fn store() -> (TempDir, Store) {
        let tmp = TempDir::new();
        let store = Store::in_dir(&tmp.path().join("2fa"));
        (tmp, store)
    }

    fn file_path(tmp: &TempDir, uid: u32) -> PathBuf {
        tmp.path().join("2fa").join(uid.to_string())
    }

    #[test]
    fn round_trip() {
        let (tmp, store) = store();
        assert!(store.read(1000).unwrap().is_none());
        let state = sample();
        store.update(1000, |s| put(s, Some(state.clone()))).unwrap();
        assert_eq!(store.read(1000).unwrap(), Some(state));
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(file_path(&tmp, 1000)), 0o600);
        assert_eq!(mode(tmp.path().join("2fa")), 0o700);
        assert!(!tmp.path().join("2fa/1000.tmp").exists());
    }

    #[test]
    fn text_format() {
        let mut state = sample();
        state.recovery.truncate(1);
        let text = state.to_text();
        let expected = format!(
            "version=1\nalgorithm=SHA256\n{}\nlast_step=7\nrecovery=",
            secret_line()
        );
        assert!(text.starts_with(&expected));
        assert_eq!(State::parse(&text).unwrap(), state);
    }

    #[test]
    fn malformed_is_refused() {
        let ok = format!(
            "version=1\nalgorithm=SHA1\n{}\nlast_step=0\n",
            secret_line()
        );
        assert!(State::parse(&ok).is_ok());
        let hash = "a".repeat(64);
        let cases = [
            String::new(),
            ok.trim_end().to_string(),
            ok.replace("version=1", "version=2"),
            ok.replace("SHA1", "MD5"),
            ok.replace("last_step=0", "last_step=-1"),
            ok.replace(&secret_line(), "secret=AAAAA"),
            ok.replace(&secret_line(), "secret=1!!!"),
            format!("{ok}extra=1\n"),
            format!("{ok}last_step=1\n"),
            format!("{ok}recovery={}\n", "A".repeat(64)),
            format!("{ok}recovery={}\n", &hash[1..]),
            format!("{ok}nonsense\n"),
            format!("{ok}\n"),
            ok.replace("version=1\n", ""),
            format!(
                "{ok}{}",
                format!("recovery={hash}\n").repeat(MAX_RECOVERY + 1)
            ),
        ];
        for case in cases {
            assert!(State::parse(&case).is_err(), "accepted: {case:?}");
        }
    }

    #[test]
    fn refuses_symlink() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        let real = tmp.path().join("real");
        std::fs::rename(file_path(&tmp, 1), &real).unwrap();
        symlink(&real, file_path(&tmp, 1)).unwrap();
        assert!(store.read(1).is_err());

        // A symlink in place of the directory.
        let moved = tmp.path().join("moved");
        std::fs::rename(tmp.path().join("2fa"), &moved).unwrap();
        symlink(&moved, tmp.path().join("2fa")).unwrap();
        assert!(store.read(1).is_err());
    }

    #[test]
    fn refuses_wrong_mode() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        for mode in [0o644, 0o640, 0o400, 0o700] {
            std::fs::set_permissions(file_path(&tmp, 1), std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(
                matches!(store.read(1), Err(Error::Unsafe(_))),
                "mode {mode:o}"
            );
        }
        std::fs::set_permissions(file_path(&tmp, 1), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(store.read(1).is_ok());
        std::fs::set_permissions(
            tmp.path().join("2fa"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(matches!(store.read(1), Err(Error::Unsafe(_))));
    }

    #[test]
    fn refuses_wrong_owner() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        let other = Store::in_dir_owned_by(&tmp.path().join("2fa"), store.owner + 1);
        assert!(matches!(other.read(1), Err(Error::Unsafe(_))));
    }

    #[test]
    fn refuses_wrong_owner_of_file() {
        // Needs root to give a file to another user; skipped otherwise.
        if rustix::process::geteuid().as_raw() != 0 {
            return;
        }
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        std::os::unix::fs::chown(file_path(&tmp, 1), Some(12345), None).unwrap();
        assert!(matches!(
            store.read(1),
            Err(Error::Unsafe("file has the wrong owner"))
        ));
    }

    #[test]
    fn refuses_oversize_and_non_files() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        let path = file_path(&tmp, 1);
        let mut text = sample().to_text();
        text.push_str(&"#".repeat(MAX_SIZE as usize));
        std::fs::write(&path, text).unwrap();
        assert!(matches!(
            store.read(1),
            Err(Error::Unsafe("file is too big"))
        ));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.read(1),
            Err(Error::Unsafe("not a regular file"))
        ));
    }

    #[test]
    fn refuses_a_fifo_without_blocking() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        let path = file_path(&tmp, 1);
        std::fs::remove_file(&path).unwrap();
        let dir = rustix::fs::open(
            tmp.path().join("2fa"),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        rustix::fs::mknodat(&dir, &path, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        assert!(matches!(
            store.read(1),
            Err(Error::Unsafe("not a regular file"))
        ));
    }

    #[test]
    fn refuses_garbage_on_disk() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        std::fs::write(file_path(&tmp, 1), b"\xff\xfe").unwrap();
        assert!(matches!(store.read(1), Err(Error::Malformed(_))));
    }

    #[test]
    fn failed_change_writes_nothing_and_none_deletes() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        let failed: Result<(), Error> = store.update(1, |s| {
            s.as_mut().unwrap().last_step = 99;
            Err(totp::Error::WrongCode.into())
        });
        assert!(failed.is_err());
        assert_eq!(store.read(1).unwrap().unwrap().last_step, 7);
        store.update(1, |s| put(s, None)).unwrap();
        assert!(!file_path(&tmp, 1).exists());
        assert!(!store.remove(1).unwrap());
    }

    #[test]
    fn remove_works_on_a_broken_file() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        std::fs::write(file_path(&tmp, 1), b"junk").unwrap();
        assert!(store.remove(1).unwrap());
        assert!(store.read(1).unwrap().is_none());
    }

    #[test]
    fn stale_temp_file_does_not_block() {
        let (tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        std::fs::write(tmp.path().join("2fa/1.tmp"), b"left over").unwrap();
        store
            .update(1, |s| {
                s.as_mut().unwrap().last_step = 8;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.read(1).unwrap().unwrap().last_step, 8);
    }

    #[test]
    fn concurrent_updates_do_not_lose_any() {
        let (_tmp, store) = store();
        store.update(1, |s| put(s, Some(sample()))).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..5 {
                        store
                            .update(1, |s| {
                                let state = s.as_mut().unwrap();
                                let seen = state.last_step;
                                std::thread::sleep(std::time::Duration::from_millis(2));
                                state.last_step = seen + 1;
                                Ok(())
                            })
                            .unwrap();
                    }
                });
            }
        });
        assert_eq!(store.read(1).unwrap().unwrap().last_step, 7 + 40);
    }

    #[test]
    fn one_code_works_for_one_of_many_concurrent_logins() {
        let (_tmp, store) = store();
        let mut state = sample();
        state.algorithm = Algorithm::Sha1;
        state.last_step = 0;
        store.update(1, |s| put(s, Some(state.clone()))).unwrap();
        let now = 1_700_000_000;
        let code = totp::code(&SECRET, Algorithm::Sha1, now).unwrap();
        let accepted = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let result = store.update(1, |s| {
                        let state = s.as_mut().unwrap();
                        state.last_step = totp::verify(
                            &state.secret,
                            state.algorithm,
                            &code,
                            now,
                            Some(state.last_step),
                        )?;
                        Ok(())
                    });
                    if result.is_ok() {
                        accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(accepted.into_inner(), 1);
    }

    #[test]
    fn recovery_code_works_once() {
        let (mut state, codes) = State::new(Algorithm::Sha1, SECRET.to_vec(), 0).unwrap();
        assert_eq!(codes.len(), RECOVERY_COUNT);
        assert_eq!(state.recovery.len(), RECOVERY_COUNT);
        for code in &codes {
            assert_eq!(code.len(), 11);
            assert_eq!(code.as_bytes()[5], b'-');
        }
        assert!(!state.use_recovery("AAAAA-AAAAA"));
        assert!(!state.use_recovery(""));
        assert!(!state.use_recovery(&codes[0][..10]));
        assert!(state.use_recovery(&codes[3].to_lowercase()));
        assert!(!state.use_recovery(&codes[3]));
        assert_eq!(state.recovery.len(), RECOVERY_COUNT - 1);
        assert!(state.use_recovery(&codes[0].replace('-', " ")));
        let old = codes[1].clone();
        let new_codes = state.renew_recovery().unwrap();
        assert_ne!(new_codes, codes);
        assert!(!state.use_recovery(&old));
        assert!(state.use_recovery(&new_codes[0]));
    }
}
