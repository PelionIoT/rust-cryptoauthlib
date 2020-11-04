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
    use serde::Deserialize;
    use std::path::Path;
    use std::fs::read_to_string;
    use toml;
    // use strum_macros;

    #[derive(Deserialize)]
    struct Config {
        pub device: Device,
        pub interface: Interface,
    }
    
    #[derive(Deserialize)]
    struct Device {
        pub device_type: String,
        pub iface_type: String,
        pub wake_delay: u16,
        pub rx_retries: i32,
    }

    #[derive(Deserialize)]
    struct Interface {
        pub slave_address: u8,
        pub bus: u8, 
        pub baud: u32,
    }

    #[allow(dead_code)]
    fn atca_iface_setup() -> Option<super::AtcaIfaceCfg> {
        let config_path = Path::new("config.toml");
        let config_string = read_to_string(config_path).expect("file not found");
        let config: Config = toml::from_str(&config_string).unwrap();
        let interface_type = match config.device.iface_type.as_str() {
            "i2c" => super::AtcaIfaceType::AtcaI2cIface,
            _ => super::AtcaIfaceType::AtcaUnknownIface,
        };
        let atca_iface_cfg = super::AtcaIfaceCfg {
            iface_type: interface_type,
            devtype: match config.device.device_type.as_ref() {
                "atecc608a" => super::AtcaDeviceType::ATECC608A,
                _ => super::AtcaDeviceType::AtcaDevUnknown,
            },
            iface: match interface_type {
                super::AtcaIfaceType::AtcaI2cIface => super::AtcaIface {
                    atcai2c: super::AtcaIfaceI2c {
                        slave_address: config.interface.slave_address,
                        bus: config.interface.bus,
                        baud: config.interface.baud,
                    },
                },
                _ => return None,
            },
            rx_retries: config.device.rx_retries,
            wake_delay: config.device.wake_delay,
        };
        return Some(atca_iface_cfg);
    }
    #[test]
    fn atcab_init() {
        let atca_iface_cfg = atca_iface_setup();
        match atca_iface_cfg {
            Some(x) => {
                assert_eq!(x.wake_delay,1500);
                assert_eq!(x.rx_retries,20);
                assert_eq!(unsafe{x.iface.atcai2c.slave_address},192);
                assert_eq!(unsafe{x.iface.atcai2c.bus},2);
                assert_eq!(unsafe{x.iface.atcai2c.baud},400000);
                let atca_status = super::atcab_init(x);
                match atca_status {
                    super::AtcaStatus::AtcaSuccess => {
                        println!("atcab_init() succeeded");
                        assert_eq!(0,0);
                    }
                    _ => {
                        println!("atcab_init() failed with error");
                        assert_eq!(1,0);
                    },
                }
            }
            None => {
                println!("could not read from config.toml file");
                assert_eq!(1,0);
            },
        };
    }
}
