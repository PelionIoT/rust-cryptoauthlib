use serde::Deserialize;
use std::fs::read_to_string;
use std::path::Path;

// Types
use super::{AtcaIface, AtcaIfaceCfg, AtcaIfaceI2c, AtcaStatus, AteccDevice};
// Constants
use super::ATCA_ZONE_CONFIG;
// Functions
use super::setup_atecc_device;

#[derive(Deserialize)]
struct Config {
    pub device: Device,
    pub interface: Option<Interface>,
}

#[derive(Deserialize)]
struct Device {
    pub device_type: String,
    pub iface_type: String,
    pub wake_delay: Option<u16>,
    pub rx_retries: Option<i32>,
}

#[derive(Deserialize, Copy, Clone)]
struct Interface {
    pub slave_address: u8,
    pub bus: u8,
    pub baud: u32,
}

pub(crate) fn is_chip_version_608(device: &AteccDevice) -> Result<bool, AtcaStatus> {
    const LEN: u8 = 4;
    const OFFSET_REV: u8 = 1;
    const INDEX_OF_REV: usize = 2;

    let mut data: Vec<u8> = Vec::with_capacity(LEN as usize);

    let result_dev_type = device.read_zone(ATCA_ZONE_CONFIG, 0, 0, OFFSET_REV, &mut data, LEN);

    match result_dev_type {
        AtcaStatus::AtcaSuccess => Ok((data[INDEX_OF_REV] & 0xF0) == 0x60),
        _ => Err(result_dev_type),
    }
}

fn iface_setup(config_file: String) -> Result<AtcaIfaceCfg, String> {
    let config_path = Path::new(&config_file);
    let config_string = read_to_string(config_path).expect("file not found");
    let config: Config = toml::from_str(&config_string).unwrap();
    let iface_cfg = AtcaIfaceCfg::default();

    match config.device.iface_type.as_str() {
        "i2c" => Ok(iface_cfg
            .set_iface_type("i2c".to_owned())
            .set_devtype(config.device.device_type)
            .set_wake_delay(config.device.wake_delay.unwrap())
            .set_rx_retries(config.device.rx_retries.unwrap())
            .set_iface(
                AtcaIface::default().set_atcai2c(
                    AtcaIfaceI2c::default()
                        .set_slave_address(config.interface.unwrap().slave_address)
                        .set_bus(config.interface.unwrap().bus)
                        .set_baud(config.interface.unwrap().baud),
                ),
            )),
        "test-interface" => Ok(iface_cfg
            .set_iface_type("test-interface".to_owned())
            .set_devtype(config.device.device_type.as_str().to_owned())),
        _ => Err("unsupported interface type".to_owned()),
    }
}

/// Setup tests.
pub(crate) fn test_setup() -> AteccDevice {
    let result_iface_cfg = iface_setup("config.toml".to_owned());
    assert!(result_iface_cfg.is_ok());

    let iface_cfg = result_iface_cfg.unwrap();
    assert_eq!(iface_cfg.iface_type.to_string(), "AtcaI2cIface");

    let result = setup_atecc_device(iface_cfg);
    match result {
        Ok(_) => (),
        Err(err) => panic!("{}", err),
    };

    result.unwrap()
}

// test_teardown() is not needed, it is a one-liner and if it fails, then
// there is a larger problem - elsewhere...
