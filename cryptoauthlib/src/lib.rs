use cryptoauthlib_sys;
mod c2rust;
mod rust2c;

include!("./types.rs");

/// Creates a global ATCADevice object used by Basic API.
pub fn atcab_init(r_iface_cfg: AtcaIfaceCfg) -> AtcaStatus {
    let mut c_iface_cfg = match rust2c::r2c_atca_iface_cfg(r_iface_cfg) {
        Some(x) => x,
        None => return AtcaStatus::AtcaUnimplemented,
    };
	return c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_init( &mut c_iface_cfg) });
}

/// Use the SHA command to compute a SHA-256 digest.
pub fn atcab_sha(length: u16, message: *const u8, digest: *mut u8) -> AtcaStatus {
    return c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_sha(length, message, digest) });
}

/// Get the global device object
pub fn atcab_get_device() -> AtcaDevice {
    return unsafe { cryptoauthlib_sys::atcab_get_device() };
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
