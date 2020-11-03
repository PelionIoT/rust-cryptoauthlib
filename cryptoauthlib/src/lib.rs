use cryptoauthlib_sys;
mod c2rust;
mod rust2c;

include!("./types.rs");

pub fn atcab_init(r_iface_cfg: AtcaIfaceCfg) -> AtcaStatus {
    let mut c_iface_cfg = rust2c::rcal_atca_iface_cfg(r_iface_cfg).unwrap();
	return c2rust::cal_enum_status(unsafe { cryptoauthlib_sys::atcab_init( &mut c_iface_cfg) });
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
