use serde::Deserialize;
use serial_test::serial;
use std::fs::read_to_string;
use std::path::Path;

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
#[serial]
fn atcab_init() {
    let atca_iface_cfg = atca_iface_setup();
    match atca_iface_cfg {
        Ok(x) => {
            assert_eq!(x.iface_type.to_string(), "AtcaI2cIface");
            assert_eq!(super::atcab_init(x).to_string(), "AtcaSuccess");
        }
        Err(e) => {
            panic!("Error reading config.toml file: {}", e);
        }
    };
    assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
}
#[test]
#[serial]
fn atcab_sha() {
    let atca_iface_cfg = atca_iface_setup();
    let mut digest: Vec<u8> = Vec::with_capacity(64);
    assert_eq!(atca_iface_cfg.is_ok(), true);
    assert_eq!(
        super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
        "AtcaSuccess"
    );

    let test_message = "TestMessage";
    let message = test_message.as_bytes().to_vec();

    assert_eq!(
        super::atcab_sha(message, &mut digest).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
}
#[test]
#[serial]
fn atcab_random() {
    let atca_iface_cfg = atca_iface_setup();
    let mut rand_out = Vec::with_capacity(32);
    assert_eq!(atca_iface_cfg.is_ok(), true);
    assert_eq!(
        super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(
        super::atcab_random(&mut rand_out).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
}
#[test]
#[serial]
fn atcab_read_config_zone() {
    use crate::ATCA_ATECC_CONFIG_BUFFER_SIZE;
    let atca_iface_cfg = atca_iface_setup();
    let mut config_data = Vec::with_capacity(1024);
    assert_eq!(atca_iface_cfg.is_ok(), true);
    assert_eq!(
        super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(
        super::atcab_read_config_zone(&mut config_data).to_string(),
        "AtcaSuccess"
    );
    match super::atcab_get_device_type() {
        super::AtcaDeviceType::ATECC508A
        | super::AtcaDeviceType::ATECC608A
        | super::AtcaDeviceType::ATECC108A => {
            assert_eq!(config_data.len(), ATCA_ATECC_CONFIG_BUFFER_SIZE);
            assert_eq!(config_data[0], 0x01);
            assert_eq!(config_data[1], 0x23);
        }
        _ => (),
    };
    assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
}
#[test]
#[serial]
fn atcab_cmp_config_zone() {
    let atca_iface_cfg = atca_iface_setup();
    let mut config_data = Vec::with_capacity(1024);
    assert_eq!(atca_iface_cfg.is_ok(), true);
    assert_eq!(
        super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(
        super::atcab_read_config_zone(&mut config_data).to_string(),
        "AtcaSuccess"
    );
    let mut same_config = false;
    assert_eq!(
        super::atcab_cmp_config_zone(&mut config_data, &mut same_config).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(same_config, true);
    assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
}
#[test]
#[serial]
fn atcab_configuration_is_locked() {
    let atca_iface_cfg = atca_iface_setup();
    assert_eq!(atca_iface_cfg.is_ok(), true);
    assert_eq!(
        super::atcab_init(atca_iface_cfg.unwrap()).to_string(),
        "AtcaSuccess"
    );
    let mut is_locked = false;
    assert_eq!(
        super::atcab_configuration_is_locked(&mut is_locked).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(is_locked, true);
    assert_eq!(super::atcab_release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_new() {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);
    
    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");
    
    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);

    let atecc_device = result.unwrap();
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_sha() {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);
    
    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");
    
    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);

    let atecc_device = result.unwrap();

    let test_message = "TestMessage";
    let message = test_message.as_bytes().to_vec();
    let mut digest: Vec<u8> = Vec::new();

    assert_eq!(
        atecc_device.sha(message, &mut digest).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_random() {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);
    
    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");
    
    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);

    let atecc_device = result.unwrap();
    let mut rand_out = Vec::new();

    assert_eq!(
        atecc_device.random(&mut rand_out).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_read_config_zone() {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);
    
    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");
    
    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);

    let atecc_device = result.unwrap();

    use crate::ATCA_ATECC_CONFIG_BUFFER_SIZE;
    let mut config_data = Vec::new();
    assert_eq!(
        atecc_device.read_config_zone(&mut config_data).to_string(),
        "AtcaSuccess"
    );
    match atecc_device.get_device_type() {
        super::AtcaDeviceType::ATECC508A
        | super::AtcaDeviceType::ATECC608A
        | super::AtcaDeviceType::ATECC108A => {
            assert_eq!(config_data.len(), ATCA_ATECC_CONFIG_BUFFER_SIZE);
            assert_eq!(config_data[0], 0x01);
            assert_eq!(config_data[1], 0x23);
        }
        _ => (),
    };
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_cmp_config_zone() {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);
    
    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");
    
    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);

    let atecc_device = result.unwrap();

    let mut config_data = Vec::new();
    assert_eq!(
        atecc_device.read_config_zone(&mut config_data).to_string(),
        "AtcaSuccess"
    );
    let mut same_config = false;
    assert_eq!(
        atecc_device.cmp_config_zone(&mut config_data, &mut same_config).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(same_config, true);
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_configuration_is_locked() {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);
    
    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");
    
    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);

    let atecc_device = result.unwrap();

    let mut is_locked = false;
    assert_eq!(
        atecc_device.configuration_is_locked(&mut is_locked).to_string(),
        "AtcaSuccess"
    );
    assert_eq!(is_locked, true);
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}