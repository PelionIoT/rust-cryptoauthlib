mod c2rust;
mod rust2c;

include!("./types.rs");

/// Creates a global ATCADevice object used by Basic API.
pub fn atcab_init(r_iface_cfg: AtcaIfaceCfg) -> AtcaStatus {
    let mut c_iface_cfg = match rust2c::r2c_atca_iface_cfg(r_iface_cfg) {
        Some(x) => x,
        None => return AtcaStatus::AtcaUnimplemented,
    };
    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_init(&mut c_iface_cfg) })
}

/// Use the SHA command to compute a SHA-256 digest.
pub fn atcab_sha(length: u16, message: *const u8, digest: *mut u8) -> AtcaStatus {
    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_sha(length, message, digest) })
}

/// Get the global device object
pub fn atcab_get_device() -> AtcaDevice {
    AtcaDevice {
        dev: unsafe { cryptoauthlib_sys::atcab_get_device() },
    }
}

pub fn atcab_random(rand_out: *mut u8) -> AtcaStatus {
    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_random(rand_out) })
}
pub fn atcab_release() -> AtcaStatus {
    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_release() })
}

// Left for compatibility reasons - will be removed soon!
pub fn atca_iface_setup(
    device_type: String,
    iface_type: String,
    wake_delay: u16,
    rx_retries: i32,
    // I2C parameter
    slave_address: Option<u8>,
    // I2C or SWI parameter
    bus: Option<u8>,
    // I2C parameter
    baud: Option<u32>,
    // UART parameter
    _port: Option<i32>,
    // UART parameter
    _wordsize: Option<u8>,
    // UART parameter
    _parity: Option<u8>,
    // UART parameter
    _stopbits: Option<u8>,
) -> Result<AtcaIfaceCfg, String> {
    let interface_type = match iface_type.as_str() {
        "i2c" => AtcaIfaceType::AtcaI2cIface,
        _ => {
            let e = "Unsupported interface type ".to_owned() + iface_type.as_str();
            return Err(e);
        }
    };
    let atca_iface_cfg = AtcaIfaceCfg {
        iface_type: interface_type,
        devtype: match device_type.as_str() {
            "atecc608a" => AtcaDeviceType::ATECC608A,
            "atecc508a" => AtcaDeviceType::ATECC508A,
            _ => {
                let e = "Unsupported device type ".to_owned() + device_type.as_str();
                return Err(e);
            }
        },
        iface: match interface_type {
            AtcaIfaceType::AtcaI2cIface => AtcaIface {
                atcai2c: AtcaIfaceI2c {
                    // unwrap_or_else_return()?
                    slave_address: match slave_address {
                        Some(x) => x,
                        _ => return Err("missing i2c slave address".to_owned()),
                    },
                    bus: match bus {
                        Some(x) => x,
                        _ => return Err("missing i2c bus".to_owned()),
                    },
                    baud: match baud {
                        Some(x) => x,
                        _ => return Err("missing i2c baud rate".to_owned()),
                    },
                },
            },
            _ => {
                let e = "Unexpected interface type ".to_owned() + iface_type.as_str();
                return Err(e);
            }
        },
        rx_retries,
        wake_delay,
    };
    Ok(atca_iface_cfg)
}

pub fn atca_iface_setup_i2c(
    device_type: String,
    wake_delay: u16,
    rx_retries: i32,
    // I2C salve address
    slave_address: Option<u8>,
    // I2C bus number
    bus: Option<u8>,
    // I2C baud rate
    baud: Option<u32>,
) -> Result<AtcaIfaceCfg, String> {
    let atca_iface_cfg = AtcaIfaceCfg {
        iface_type: AtcaIfaceType::AtcaI2cIface,
        devtype: match device_type.as_str() {
            "atecc608a" => AtcaDeviceType::ATECC608A,
            "atecc508a" => AtcaDeviceType::ATECC508A,
            _ => {
                let e = "Unsupported device type ".to_owned() + device_type.as_str();
                return Err(e);
            }
        },
        iface: AtcaIface {
            atcai2c: AtcaIfaceI2c {
                // unwrap_or_else_return()?
                slave_address: match slave_address {
                    Some(x) => x,
                    _ => return Err("missing i2c slave address".to_owned()),
                },
                bus: match bus {
                    Some(x) => x,
                    _ => return Err("missing i2c bus".to_owned()),
                },
                baud: match baud {
                    Some(x) => x,
                    _ => return Err("missing i2c baud rate".to_owned()),
                },
            },
        },
        rx_retries,
        wake_delay,
    };
    Ok(atca_iface_cfg)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use std::fs::read_to_string;
    use std::path::Path;
    use toml;

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
    fn atca_iface_setup() -> Result<super::AtcaIfaceCfg, String> {
        let config_path = Path::new("config.toml");
        let config_string = read_to_string(config_path).expect("file not found");
        let config: Config = toml::from_str(&config_string).unwrap();
        match config.device.iface_type.as_str() {
            "i2c" => super::atca_iface_setup_i2c(
                config.device.device_type,
                config.device.wake_delay,
                config.device.rx_retries,
                Some(config.interface.slave_address),
                Some(config.interface.bus),
                Some(config.interface.baud),
            ),
            _ => Err("unsupported interface type".to_owned()),
        }
    }
    #[test]
    fn atcab_init() {
        let atca_iface_cfg = atca_iface_setup();
        match atca_iface_cfg {
            Ok(x) => {
                assert_eq!(x.iface_type.to_string(), "AtcaI2cIface");
                assert_eq!(x.devtype.to_string(), "ATECC508A");
                assert_eq!(x.wake_delay, 1500);
                assert_eq!(x.rx_retries, 20);
                assert_eq!(unsafe { x.iface.atcai2c.slave_address }, 192);
                assert_eq!(unsafe { x.iface.atcai2c.bus }, 1);
                assert_eq!(unsafe { x.iface.atcai2c.baud }, 400000);
                assert_eq!(super::atcab_init(x).to_string(), "AtcaSuccess");
            }
            Err(e) => {
                panic!("Error reading config.toml file: {}", e);
            }
        };
        assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
    }
    #[test]
    fn atcab_sha() {
        let atca_iface_cfg = atca_iface_setup();
        let mut digest = Vec::with_capacity(64);
        assert_eq!(atca_iface_cfg.is_ok(), true);
        assert_eq!(
            super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
            "AtcaSuccess"
        );
        assert_eq!(
            super::atcab_sha(12, "Test message".as_ptr(), digest.as_mut_ptr()).to_string(),
            "AtcaSuccess"
        );
        assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
    }
    #[test]
    fn atcab_random() {
        let atca_iface_cfg = atca_iface_setup();
        let mut rand_out = Vec::with_capacity(32);
        assert_eq!(atca_iface_cfg.is_ok(), true);
        assert_eq!(
            super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
            "AtcaSuccess"
        );
        assert_eq!(
            super::atcab_random(rand_out.as_mut_ptr()).to_string(),
            "AtcaSuccess"
        );
        assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
    }
}
