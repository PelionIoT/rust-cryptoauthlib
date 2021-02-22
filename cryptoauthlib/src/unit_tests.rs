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

fn atecc_test_setup() -> super::AteccDevice {
    let result = atca_iface_setup();
    assert_eq!(result.is_ok(), true);

    let atca_iface_cfg = result.unwrap();
    assert_eq!(atca_iface_cfg.iface_type.to_string(), "AtcaI2cIface");

    let result = super::AteccDevice::new(atca_iface_cfg);
    assert_eq!(result.is_ok(), true);
    result.unwrap()
}

// atecc_test_teardown() is not needed, it is one-liner and if that fails, then
// there is a large problem - elsewhere...

#[test]
#[serial]
fn atecc_new() {
    let atecc_device = atecc_test_setup();
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_sha() {
    let atecc_device = atecc_test_setup();

    let test_message = "TestMessage";
    let test_message_hash = [
        4, 107, 166, 242, 219, 151, 158, 146, 86, 241, 25, 188, 21, 209, 126, 62, 168, 136, 241,
        235, 157, 226, 70, 49, 81, 80, 208, 170, 247, 231, 0, 115,
    ];
    let message = test_message.as_bytes().to_vec();
    let mut digest: Vec<u8> = Vec::new();
    let atecc_device_sha = atecc_device.sha(message, &mut digest);

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(atecc_device_sha.to_string(), "AtcaSuccess");
    assert_eq!(digest, test_message_hash);
}

#[test]
#[serial]
fn atecc_random() {
    let atecc_device = atecc_test_setup();

    let mut rand_out = Vec::new();
    let atecc_device_random = atecc_device.random(&mut rand_out);

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(atecc_device_random.to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn aes_enabled() {
    const LEN: u8 = 4;
    const OFFSET_REV: u8 = 1;
    const INDEX_OF_REV: usize = 2;

    let atecc_device = atecc_test_setup();

    let mut data: Vec<u8> = Vec::with_capacity(LEN as usize);
    let result_dev_type =
        atecc_device.read_zone(super::ATCA_ZONE_CONFIG, 0, 0, OFFSET_REV, &mut data, LEN);

    let expected: bool = matches!(data[INDEX_OF_REV] & 0xF0, 0x60);

    let mut aes_check_result = super::AtcaStatus::AtcaSuccess;
    let mut aes_enabled: bool = false;
    match atecc_device.aes_enabled() {
        Ok(val) => aes_enabled = val,
        Err(err) => aes_check_result = err,
    };

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(result_dev_type.to_string(), "AtcaSuccess");
    assert_eq!(aes_check_result.to_string(), "AtcaSuccess");
    assert_eq!(aes_enabled, expected);
}

#[test]
#[serial]
fn atecc_gen_key() {
    const LEN: u8 = 4;
    const OFFSET_REV: u8 = 1;
    const INDEX_OF_REV: usize = 2;

    let atecc_device = atecc_test_setup();

    let mut data: Vec<u8> = Vec::with_capacity(LEN as usize);
    let result_dev_type =
        atecc_device.read_zone(super::ATCA_ZONE_CONFIG, 0, 0, OFFSET_REV, &mut data, LEN);

    let mut expected: super::AtcaStatus = super::AtcaStatus::AtcaBadParam;
    if (data[INDEX_OF_REV] & 0xF0) == 0x60 {
        expected = super::AtcaStatus::AtcaSuccess;
    }

    let aes_check_result = match atecc_device.aes_enabled() {
        Err(err) => err,
        Ok(_) => super::AtcaStatus::AtcaSuccess,
    };

    let atecc_device_gen_key_bad_1 =
        atecc_device.gen_key(super::KeyType::Aes, super::ATCA_ATECC_SLOTS_COUNT + 1);
    let atecc_device_gen_key_bad_2 = atecc_device.gen_key(super::KeyType::Aes, 9);
    let atecc_device_gen_key_bad_3 =
        atecc_device.gen_key(super::KeyType::P256EccKey, super::ATCA_ATECC_SLOTS_COUNT);
    let atecc_device_gen_key_bad_4 = atecc_device.gen_key(super::KeyType::ShaOrText, 0);
    let atecc_device_gen_key_ok_1 = atecc_device.gen_key(super::KeyType::P256EccKey, 0);

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(result_dev_type.to_string(), "AtcaSuccess");
    assert_eq!(aes_check_result.to_string(), "AtcaSuccess");
    assert_eq!(atecc_device_gen_key_bad_1.to_string(), "AtcaBadParam");
    assert_eq!(atecc_device_gen_key_bad_2, expected);
    assert_eq!(atecc_device_gen_key_bad_3.to_string(), "AtcaBadParam");
    assert_eq!(atecc_device_gen_key_bad_4.to_string(), "AtcaBadParam");
    assert_eq!(atecc_device_gen_key_ok_1.to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn atecc_read_config_zone() {
    let atecc_device = atecc_test_setup();

    let mut config_data = Vec::new();
    let atecc_device_read_config_zone = atecc_device.read_config_zone(&mut config_data);
    let atecc_device_get_device_type = atecc_device.get_device_type();

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(atecc_device_read_config_zone.to_string(), "AtcaSuccess");
    match atecc_device_get_device_type {
        super::AtcaDeviceType::ATECC508A
        | super::AtcaDeviceType::ATECC608A
        | super::AtcaDeviceType::ATECC108A => {
            assert_eq!(config_data.len(), super::ATCA_ATECC_CONFIG_BUFFER_SIZE);
            assert_eq!(config_data[0], 0x01);
            assert_eq!(config_data[1], 0x23);
        }
        _ => panic!("Unknown device type."),
    };
}

#[test]
#[serial]
fn atecc_cmp_config_zone() {
    let atecc_device = atecc_test_setup();

    let mut config_data = Vec::new();
    let atecc_device_read_config_zone = atecc_device.read_config_zone(&mut config_data);
    let mut same_config = false;
    let atecc_device_cmp_config_zone =
        atecc_device.cmp_config_zone(&mut config_data, &mut same_config);

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(atecc_device_read_config_zone.to_string(), "AtcaSuccess");
    assert_eq!(atecc_device_cmp_config_zone.to_string(), "AtcaSuccess");
    assert_eq!(same_config, true);
}

#[test]
#[serial]
fn atecc_configuration_is_locked() {
    let atecc_device = atecc_test_setup();
    let mut is_locked = false;
    let atecc_device_configuration_is_locked = atecc_device.configuration_is_locked(&mut is_locked);
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(
        atecc_device_configuration_is_locked.to_string(),
        "AtcaSuccess"
    );
    assert_eq!(is_locked, true);
}

#[test]
#[serial]
fn atecc_get_config_from_config_zone() {
    let mut config_data = Vec::new();
    let atecc_device = atecc_test_setup();
    let atecc_device_atcab_read_config_zone = atecc_device.read_config_zone(&mut config_data);

    config_data[88] = 0b10111111;
    config_data[89] = 0b01111111;
    config_data[20] = 0b10000000;
    config_data[22] = 0b00000000;
    let mut atca_slots: Vec<super::AtcaSlot> = Vec::new();
    super::atcab_get_config_from_config_zone(&config_data, &mut atca_slots);

    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(
        atecc_device_atcab_read_config_zone.to_string(),
        "AtcaSuccess"
    );
    assert_eq!(atca_slots.len(), usize::from(super::ATCA_ATECC_SLOTS_COUNT));
    assert_eq!(atca_slots[0].id, 0);
    assert_eq!(atca_slots[15].id, 15);
    assert_eq!(atca_slots[0].is_locked, false);
    assert_eq!(atca_slots[6].is_locked, true);
    assert_eq!(atca_slots[15].is_locked, true);
    assert_eq!(atca_slots[0].config.is_secret, true);
    assert_eq!(atca_slots[1].config.is_secret, false);
}

#[test]
#[serial]
fn atecc_get_config() {
    let atecc_device = atecc_test_setup();
    let mut atca_slots: Vec<super::AtcaSlot> = Vec::new();
    let atecc_get_config = atecc_device.get_config(&mut atca_slots);
    assert_eq!(atecc_device.release().to_string(), "AtcaSuccess");
    assert_eq!(atecc_get_config.to_string(), "AtcaSuccess");
}
