use cryptoauthlib_sys;
mod c2rust;

include!("./types.rs");

pub fn atcab_init(cfg: *mut cryptoauthlib_sys::ATCAIfaceCfg) -> AtcaStatus {
	return c2rust::cal_enum_status(unsafe { cryptoauthlib_sys::atcab_init(cfg) });
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
