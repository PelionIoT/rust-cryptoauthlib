use serde::Deserialize;
use std::cmp::max;
use std::fs::read_to_string;
use std::path::Path;

// Types
use super::{AtcaIface, AtcaIfaceCfg, AtcaIfaceI2c, AtcaStatus, AteccDevice};
// Constants
use super::{ATCA_BLOCK_SIZE, ATCA_KEY_SIZE, ATCA_ZONE_CONFIG};
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

pub(crate) const WRITE_KEY: &[u8] = &[
    0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD, 0x05,
    0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49, 0x66, 0x45,
];

pub(crate) fn is_chip_version_608(device: &AteccDevice) -> Result<bool, AtcaStatus> {
    const LEN: usize = 4;
    const OFFSET_REV: u8 = 1;
    const INDEX_OF_REV: usize = 2;

    let mut data: [u8; LEN] = [0x00; LEN];

    let result_dev_type = device.read_zone(ATCA_ZONE_CONFIG, 0, 0, OFFSET_REV, &mut data);

    match result_dev_type {
        AtcaStatus::AtcaSuccess => Ok((data[INDEX_OF_REV] & 0xF0) == 0x60),
        _ => Err(result_dev_type),
    }
}

pub(crate) fn io_decrypt(device: &AteccDevice, message: &mut [u8], nonce: &[u8]) -> AtcaStatus {
    const CHUNK: usize = ATCA_BLOCK_SIZE / 2;

    if !((nonce.len() == (CHUNK * 2)) || (nonce.len() == CHUNK))
        || !((message.len() == (CHUNK * 4))
            || (message.len() == (CHUNK * 2))
            || (message.len() == CHUNK))
    {
        return AtcaStatus::AtcaBadParam;
    }

    let mut digest: Vec<u8> = Vec::new();
    let loops: usize = max(1, (message.len() / ATCA_BLOCK_SIZE) as usize);
    let max_idx: usize = ((message.len() >= ATCA_BLOCK_SIZE) as usize + 1) * CHUNK;

    for i in 0..loops {
        let start_pos_nonce: usize = i * CHUNK;
        let start_pos_data: usize = start_pos_nonce * 2;
        let mut buffer: Vec<u8> = WRITE_KEY.to_vec();
        buffer.extend_from_slice(&nonce[start_pos_nonce..(start_pos_nonce + CHUNK)]);

        let result = device.sha(buffer, &mut digest);
        if AtcaStatus::AtcaSuccess != result {
            return result;
        };

        for idx in 0..max_idx {
            message[start_pos_data + idx] ^= digest[idx];
        }
    }

    AtcaStatus::AtcaSuccess
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
