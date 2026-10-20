// SPDX-License-Identifier: MIT
//! The only `unsafe` code of the module: the two functions libpam calls, the few libpam functions
//! the module calls, and safe wrappers around them.
//!
//! The declarations are written by hand from Linux-PAM's public headers (`security/_pam_types.h`,
//! `security/pam_modules.h` and `security/pam_ext.h`), whose ABI has been stable for two decades.
//! Only Linux-PAM is supported (`pam_prompt` and `pam_syslog` are its extensions).
//!
//! Rules kept here:
//! - Every exported function catches panics (`catch_unwind`) and turns them into a refusal; a
//!   silent panic hook keeps them off stderr. The hook is this library's own: a cdylib carries its
//!   own copy of `std`, so the host and other Rust modules keep theirs.
//! - Strings from libpam are read with a bound and copied right away; nothing longer than the
//!   bound is copied or kept.
//! - The typed code is wiped in libpam's buffer before that buffer is freed.

use pam_totp::auth::Input;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// `pam_handle_t`, opaque.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

// security/_pam_types.h
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
const PAM_RHOST: c_int = 4;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

// syslog.h; pam_syslog adds the LOG_AUTHPRIV facility itself.
pub const LOG_ERR: c_int = 3;
pub const LOG_NOTICE: c_int = 5;
pub const LOG_INFO: c_int = 6;

// libpam.so.0 is named in full so that building needs only the runtime library, not the -dev
// package; its soname has not changed since Linux-PAM 0.75.
#[link(name = "libpam.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    /// `int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);`
    /// On success `*user` points to libpam's own copy of the name, valid until it is changed.
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;

    /// `int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);`
    /// For `PAM_RHOST` the item is a C string owned by libpam, or NULL.
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;

    /// `int pam_prompt(pam_handle_t *pamh, int style, char **response, const char *fmt, ...);`
    /// Runs the application's conversation function with one message. `*response` is set to NULL
    /// or to a `malloc`ed string the caller must free, also when the call fails.
    fn pam_prompt(
        pamh: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;

    /// `void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...);`
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

unsafe extern "C" {
    /// The C library's `free`, for the response `pam_prompt` hands over.
    fn free(ptr: *mut c_void);
}

/// The handle libpam passed to the current call. It is only used during that call.
pub struct Handle(*mut PamHandle);

impl Handle {
    /// The user name, if libpam has one that is valid UTF-8 and at most `max` bytes.
    pub fn user(&self, max: usize) -> Option<String> {
        let mut user: *const c_char = std::ptr::null();
        // SAFETY: `self.0` is the live handle of this call. A NULL prompt asks libpam for its
        // default; sshd always sets the user at pam_start, so no prompt happens there.
        let status = unsafe { pam_get_user(self.0, &mut user, std::ptr::null()) };
        if status != PAM_SUCCESS {
            return None;
        }
        // SAFETY: on success `user` is NULL or a C string owned by libpam, unchanged during
        // this call.
        unsafe { copy_bounded(user, max) }
    }

    /// The remote host as sshd set it, if it is valid UTF-8 and at most `max` bytes.
    pub fn rhost(&self, max: usize) -> Option<String> {
        let mut item: *const c_void = std::ptr::null();
        // SAFETY: `self.0` is the live handle of this call and `item` a valid out-pointer.
        let status = unsafe { pam_get_item(self.0, PAM_RHOST, &mut item) };
        if status != PAM_SUCCESS {
            return None;
        }
        // SAFETY: the PAM_RHOST item is NULL or a C string owned by libpam, unchanged during
        // this call.
        unsafe { copy_bounded(item.cast(), max) }
    }

    /// Asks `prompt` with echo off and returns the answer, or why there is none.
    pub fn ask(&self, prompt: &CStr) -> Result<Input, &'static str> {
        let mut response: *mut c_char = std::ptr::null_mut();
        // SAFETY: `self.0` is the live handle of this call, `response` a valid out-pointer, and
        // the format "%s" takes exactly the one C string passed after it.
        let status = unsafe {
            pam_prompt(
                self.0,
                PAM_PROMPT_ECHO_OFF,
                &mut response,
                c"%s".as_ptr(),
                prompt.as_ptr(),
            )
        };
        if response.is_null() {
            return Err(if status == PAM_SUCCESS {
                "no answer"
            } else {
                "the conversation failed"
            });
        }
        // SAFETY: a non-NULL response is a NUL-terminated string from the application's
        // conversation function, now ours to read, wipe and free. It is read before it is wiped
        // and freed exactly once, here.
        let input = unsafe {
            let input = bounded(response, pam_totp::auth::MAX_INPUT).and_then(Input::new);
            wipe(response);
            free(response.cast());
            input
        };
        if status != PAM_SUCCESS {
            return Err("the conversation failed");
        }
        input.ok_or("the answer is too long")
    }

    /// Writes `message` to the system log (authpriv), prefixed by libpam with the module name,
    /// the service and the call.
    pub fn log(&self, priority: c_int, message: &str) {
        let Ok(message) = std::ffi::CString::new(message) else {
            return;
        };
        // SAFETY: `self.0` is the live handle of this call, and the format "%s" takes exactly
        // the one C string passed after it.
        unsafe { pam_syslog(self.0, priority, c"%s".as_ptr(), message.as_ptr()) };
    }
}

/// The bytes of the C string at `ptr` (without its NUL) if it has at most `max` of them. Reads at
/// most `max + 1` bytes, so a long string is not scanned to its end.
///
/// # Safety
/// `ptr` is NULL or points to a NUL-terminated string that stays valid and unchanged while the
/// returned slice lives.
unsafe fn bounded<'a>(ptr: *const c_char, max: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    for len in 0..=max {
        // SAFETY: every byte before `len` was not NUL, so the string goes on at least to `len`.
        if unsafe { *ptr.add(len) } == 0 {
            // SAFETY: the `len` bytes before the NUL are part of the string.
            return Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) });
        }
    }
    None
}

/// A copy of the C string at `ptr` if it is valid UTF-8 and at most `max` bytes long.
///
/// # Safety
/// As for [`bounded`], during this call.
unsafe fn copy_bounded(ptr: *const c_char, max: usize) -> Option<String> {
    // SAFETY: passed on from the caller.
    let bytes = unsafe { bounded(ptr, max) }?;
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Overwrites the C string at `ptr` with zeros, up to its NUL.
///
/// # Safety
/// `ptr` points to a writable NUL-terminated string that nothing else is reading or holding a
/// reference to.
unsafe fn wipe(ptr: *mut c_char) {
    // SAFETY: passed on from the caller; the length is found before any byte is changed.
    let len = unsafe { CStr::from_ptr(ptr) }.count_bytes();
    for i in 0..len {
        // SAFETY: `i` is inside the string. Volatile, so the writes are not removed as dead
        // stores before `free`.
        unsafe { ptr.add(i).write_volatile(0) };
    }
}

/// Runs `body` with the silent panic hook; a panic becomes `PAM_AUTH_ERR`.
fn guard(body: impl FnOnce() -> c_int) -> c_int {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(PAM_AUTH_ERR)
}

/// Called by libpam for the `auth` line of the module.
///
/// # Safety
/// libpam calls it with the live handle of the transaction; `argv` is not read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guard(|| {
        if pamh.is_null() {
            return PAM_AUTH_ERR;
        }
        let handle = Handle(pamh);
        match catch_unwind(AssertUnwindSafe(|| crate::authenticate(&handle, argc))) {
            Ok(status) => status,
            Err(_) => {
                // The reason of a panic was not logged yet.
                handle.log(LOG_ERR, "refused: internal error");
                PAM_AUTH_ERR
            }
        }
    })
}

/// Called by libpam after authentication to set credentials; this module has none to set.
///
/// # Safety
/// No argument is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guard(|| PAM_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reads() {
        let text = c"123456";
        // SAFETY: `text` is a static C string.
        unsafe {
            assert_eq!(bounded(text.as_ptr(), 6), Some(&b"123456"[..]));
            assert_eq!(bounded(text.as_ptr(), 5), None);
            assert_eq!(bounded(c"".as_ptr(), 0), Some(&b""[..]));
            assert_eq!(bounded(std::ptr::null(), 10), None);
            assert_eq!(
                copy_bounded(c"maria".as_ptr(), 256).as_deref(),
                Some("maria")
            );
            assert_eq!(copy_bounded(c"\xffx".as_ptr(), 256), None);
        }
    }

    #[test]
    fn wipe_zeroes_up_to_the_nul() {
        let mut buffer = *b"secret\0tail";
        // SAFETY: `buffer` is a writable NUL-terminated string owned here.
        unsafe { wipe(buffer.as_mut_ptr().cast()) };
        assert_eq!(&buffer, b"\0\0\0\0\0\0\0tail");
    }

    #[test]
    fn panics_become_refusals() {
        assert_eq!(guard(|| panic!("boom")), PAM_AUTH_ERR);
        assert_eq!(guard(|| PAM_SUCCESS), PAM_SUCCESS);
    }
}
