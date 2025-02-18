
use pamsm::PamError::*;
use std::ffi::{c_int, c_char, c_void, CStr};
use std::ptr;

// The pamsm crate does not implement get_oldauthtok() so we have to do it ourselves

const PAM_OLDAUTHTOK: c_int = 7;

type PamHandlePtr = *const c_void;

extern "C" {
    fn pam_get_authtok(
        pamh: PamHandlePtr,
        item: c_int,
        authok_ptr: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

pub(super) fn get_oldauthtok(pamh: &pamsm::Pam) -> pamsm::PamResult<&CStr> {
    // Internally, pamsm::Pamh is simply a PamHandlePtr
    let pamh_ptr = ptr::from_ref(pamh) as *const PamHandlePtr;
    let mut authtok: *const c_char = ptr::null();
    let ret = unsafe {
        pam_get_authtok(*pamh_ptr, PAM_OLDAUTHTOK, &mut authtok, ptr::null())
    };

    match ret {
        e if e == SUCCESS as i32 => {
            // On SUCCESS this pointer should never be null
            if authtok.is_null() {
                Err(SYSTEM_ERR)
            } else {
                Ok(unsafe { CStr::from_ptr(authtok) })
            }
        },
        e if e == AUTH_ERR    as i32 => Err(AUTH_ERR),
        e if e == AUTHTOK_ERR as i32 => Err(AUTHTOK_ERR),
        // PAM_OLDAUTHTOK should not return any other error codes
        _ => Err(SYSTEM_ERR),
    }
}
