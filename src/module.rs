//! Functions for use in pam modules.

use libc::c_char;
use std::ffi::{CStr, CString};

use constants::{PamFlag, PamResultCode};
use items::ItemType;

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[repr(C)]
pub struct PamHandle {
    _data: [u8; 0],
}

#[link(name = "pam")]
extern "C" {
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: &mut *const libc::c_void,
    ) -> PamResultCode;

    fn pam_set_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut libc::c_void,
        cleanup: extern "C" fn(
            pamh: *const PamHandle,
            data: *mut libc::c_void,
            error_status: PamResultCode,
        ),
    ) -> PamResultCode;

    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: ItemType,
        item: &mut *const libc::c_void,
    ) -> PamResultCode;

    fn pam_set_item(
        pamh: *mut PamHandle,
        item_type: ItemType,
        item: *const libc::c_void,
    ) -> PamResultCode;

    fn pam_get_user(
        pamh: *const PamHandle,
        user: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_get_authtok(
        pamh: *const PamHandle,
        item_type: ItemType,
        data: &*mut c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

}

pub extern "C" fn cleanup<T>(_: *const PamHandle, c_data: *mut libc::c_void, _: PamResultCode) {
    unsafe {
        let _data: Box<T> = Box::from_raw(c_data.cast::<T>());
    }
}

pub type PamResult<T> = Result<T, PamResultCode>;

impl PamHandle {
    /// Gets some value, identified by `key`, that has been set by the module
    /// previously.
    ///
    /// See the [`pam_get_data` manual page](
    /// https://www.man7.org/linux/man-pages/man3/pam_get_data.3.html).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Safety
    ///
    /// The data stored under the provided key must be of type `T` otherwise the
    /// behaviour of this function is undefined.
    pub unsafe fn get_data<T>(&self, key: &str) -> PamResult<&T> {
        let c_key = CString::new(key).unwrap();
        let mut ptr: *const libc::c_void = std::ptr::null();
        let res = pam_get_data(self, c_key.as_ptr(), &mut ptr);
        if PamResultCode::PAM_SUCCESS == res && !ptr.is_null() {
            let typed_ptr = ptr.cast::<T>();
            let data: &T = &*typed_ptr;
            Ok(data)
        } else {
            Err(res)
        }
    }

    /// Stores a value that can be retrieved later with `get_data`.  The value lives
    /// as long as the current pam cycle.
    ///
    /// See the [`pam_set_data` manual page](
    /// https://www.man7.org/linux/man-pages/man3/pam_set_data.3.html).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn set_data<T>(&self, key: &str, data: Box<T>) -> PamResult<()> {
        let c_key = CString::new(key).unwrap();
        let res = unsafe {
            pam_set_data(
                self,
                c_key.as_ptr(),
                Box::into_raw(data).cast::<libc::c_void>(),
                cleanup::<T>,
            )
        };
        to_result(res)
    }

    /// Retrieves a value that has been set, possibly by the pam client.  This is
    /// particularly useful for getting a `PamConv` reference.
    ///
    /// See the [`pam_get_item` manual page](
    /// https://www.man7.org/linux/man-pages/man3/pam_get_item.3.html).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    pub fn get_item<T: crate::items::Item>(&self) -> PamResult<Option<T>> {
        let mut ptr: *const libc::c_void = std::ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self, T::type_id(), &mut ptr);
            let typed_ptr = ptr.cast::<T::Raw>();
            let t = if typed_ptr.is_null() {
                None
            } else {
                Some(T::from_raw(typed_ptr))
            };
            (r, t)
        };
        match res {
            PamResultCode::PAM_SUCCESS => Ok(item),
            other => Err(other),
        }
    }

    /// Sets a value in the pam context. The value can be retrieved using
    /// `get_item`.
    ///
    /// Note that all items are strings, except `PAM_CONV` and `PAM_FAIL_DELAY`.
    ///
    /// See the [`pam_set_item` manual page](
    /// https://www.man7.org/linux/man-pages/man3/pam_set_item.3.html).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Panics
    ///
    /// Panics if the provided item key contains a nul byte.
    pub fn set_item_str<T: crate::items::Item>(&mut self, item: T) -> PamResult<()> {
        let res =
            unsafe { pam_set_item(self, T::type_id(), item.into_raw().cast::<libc::c_void>()) };
        to_result(res)
    }

    /// Retrieves the name of the user who is authenticating or logging in.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See the [`pam_get_user` manual page](
    /// https://www.man7.org/linux/man-pages/man3/pam_get_user.3.html).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Panics
    ///
    /// Panics if the provided prompt string contains a nul byte.
    pub fn get_user(&self, prompt: Option<&str>) -> PamResult<String> {
        let prompt_string;
        let c_prompt = match prompt {
            Some(p) => {
                prompt_string = CString::new(p).unwrap();
                prompt_string.as_ptr()
            }
            None => std::ptr::null(),
        };
        let output: *mut c_char = std::ptr::null_mut();
        let res = unsafe { pam_get_user(self, &output, c_prompt) };
        match res {
            PamResultCode::PAM_SUCCESS => copy_pam_string(output),
            otherwise => Err(otherwise),
        }
    }

    /// Retrieves the authentication token from the user.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See the [`pam_get_authtok` manual page](
    /// https://www.man7.org/linux/man-pages/man3/pam_get_authtok.3.html).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PAM function call fails.
    ///
    /// # Panics
    ///
    /// Panics if the provided prompt string contains a nul byte.
    pub fn get_authtok(&self, prompt: Option<&str>) -> PamResult<String> {
        let prompt_string;
        let c_prompt = match prompt {
            Some(p) => {
                prompt_string = CString::new(p).unwrap();
                prompt_string.as_ptr()
            }
            None => std::ptr::null(),
        };
        let output: *mut c_char = std::ptr::null_mut();
        let res = unsafe { pam_get_authtok(self, ItemType::AuthTok, &output, c_prompt) };
        match res {
            PamResultCode::PAM_SUCCESS => copy_pam_string(output),
            otherwise => Err(otherwise),
        }
    }
}

/// Creates an owned copy of a string that is returned from a
/// <code>pam_get_<var>whatever</var></code> function.
fn copy_pam_string(result_ptr: *const c_char) -> PamResult<String> {
    // We really shouldn't get a null pointer back here, but if we do, return nothing.
    if result_ptr.is_null() {
        return Ok(String::from(""));
    }
    let bytes = unsafe { CStr::from_ptr(result_ptr).to_bytes() };
    String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_CONV_ERR)
}

/// Convenience to transform a `PamResultCode` into a unit `PamResult`.
fn to_result(result: PamResultCode) -> PamResult<()> {
    match result {
        PamResultCode::PAM_SUCCESS => Ok(()),
        otherwise => Err(otherwise),
    }
}

/// Provides functions that are invoked by the entrypoints generated by the
/// [`pam_hooks!` macro](../macro.pam_hooks.html).
///
/// All hooks are ignored by PAM dispatch by default given the default return value of `PAM_IGNORE`.
/// Override any functions that you want to handle with your module. See [PAM’s root manual page](
/// https://www.man7.org/linux/man-pages/man3/pam.3.html).
#[allow(unused_variables)]
pub trait PamHooks {
    /// This function performs the task of establishing whether the user is permitted to gain access at
    /// this time. It should be understood that the user has previously been validated by an
    /// authentication module. This function checks for other things. Such things might be: the time of
    /// day or the date, the terminal line, remote hostname, etc. This function may also determine
    /// things like the expiration on passwords, and respond that the user change it before continuing.
    fn acct_mgmt(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is used to (re-)set the authentication token of the user.
    ///
    /// The PAM library calls this function twice in succession. The first time with
    /// `PAM_PRELIM_CHECK` and then, if the module does not return `PAM_TRY_AGAIN`, subsequently with
    /// `PAM_UPDATE_AUTHTOK`. It is only on the second call that the authorization token is
    /// (possibly) changed.
    fn sm_chauthtok(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to terminate a session.
    fn sm_close_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to commence a session.
    fn sm_open_session(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of altering the credentials of the user with respect to the
    /// corresponding authorization scheme. Generally, an authentication module may have access to more
    /// information about a user than their authentication token. This function is used to make such
    /// information available to the application. It should only be called after the user has been
    /// authenticated but before a session has been established.
    fn sm_setcred(pamh: &mut PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}
